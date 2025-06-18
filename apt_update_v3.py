#!/usr/bin/env python3

import time
import os
import sys
import json
import tempfile
import requests
import zipfile
import logging
import hashlib
from git import Repo
from datetime import datetime
from logging.handlers import RotatingFileHandler

# --- Logging Setup ---
LOG_DIR = "/var/log/zabbix-auto-update"
LOG_FILE = os.path.join(LOG_DIR, "zabbix_auto_update.log")
MAX_LOG_SIZE = 5 * 1024 * 1024  # 5MB
BACKUP_COUNT = 3

class ZippingRotatingFileHandler(RotatingFileHandler):
    def doRollover(self):
        super().doRollover()
        log_filename = f"{self.baseFilename}.1"
        if os.path.exists(log_filename):
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            zip_filename = f"{log_filename}_{timestamp}.zip"
            with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
                zipf.write(log_filename, os.path.basename(log_filename))
            os.remove(log_filename)

def setup_logging():
    os.makedirs(LOG_DIR, exist_ok=True)
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    handler = ZippingRotatingFileHandler(LOG_FILE, maxBytes=MAX_LOG_SIZE, backupCount=BACKUP_COUNT)
    formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s', '%Y-%m-%d %H:%M:%S')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger

logger = setup_logging()

# Load config
config_path = sys.argv[1] if len(sys.argv) > 1 else 'auto_update_config_v3.json'
with open(config_path) as f:
    CONFIG = json.load(f)

CATEGORIES = [cat.strip() for cat in CONFIG.get("category", "").split(",") if cat.strip()]
UTIL_FILE = ".zabbix_util_cache.json"

# Utility functions to compute file hash
def compute_file_hash(filepath):
    hash_func = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            hash_func.update(chunk)
    return hash_func.hexdigest()

def load_util_file():
    if os.path.exists(UTIL_FILE):
        with open(UTIL_FILE, "r") as f:
            return json.load(f)
    return {}

def save_util_file(data):
    with open(UTIL_FILE, "w") as f:
        json.dump(data, f, indent=2)

# --- Zabbix Login ---
def zabbix_login():
    payload = {
        "jsonrpc": "2.0",
        "method": "user.login",
        "params": {
            "username": CONFIG['zabbix']['user'],
            "password": CONFIG['zabbix']['password']
        },
        "id": 1
    }
    res = requests.post(CONFIG['zabbix']['url'], json=payload, headers={"Content-Type": "application/json"})
    result = res.json()
    if 'result' in result:
        logger.info("Zabbix login successful.")
        return result['result']
    else:
        logger.error(f"Zabbix login failed: {result}")
        sys.exit(1)

# --- Compare Git and Util Data ---
def compare_and_update(git_dir, util_data, key, update_func):
    updated_hashes = {}
    for cat in CATEGORIES:
        subdir = os.path.join(git_dir, cat)
        if not os.path.exists(subdir):
            continue
        for fname in os.listdir(subdir):
            fpath = os.path.join(subdir, fname)
            if not os.path.isfile(fpath):
                continue
            hash_val = compute_file_hash(fpath)
            identifier = f"{cat}/{fname}"
            if util_data.get(key, {}).get(identifier) != hash_val:
                logger.info(f"[UPDATE] {key}: {identifier}")
                update_func(fpath)
            updated_hashes[identifier] = hash_val
    return updated_hashes

# --- Import Template, Script, Dashboard ---
def import_zabbix_template_wrapper(auth_token):
    def inner(path):
        ext = path.split('.')[-1].lower()
        format_map = {"xml": "xml", "json": "json", "yaml": "yaml", "yml": "yaml"}
        if ext not in format_map:
            logger.warning(f"Unsupported template format: {path}")
            return
        with open(path, 'r', encoding='utf-8') as file:
            source = file.read()
        payload = {
            "jsonrpc": "2.0",
            "method": "configuration.import",
            "params": {
                "format": format_map[ext],
                "rules": CONFIG.get("template_rules", {}),
                "source": source
            },
            "auth": auth_token,
            "id": 2
        }
        headers = {"Content-Type": "application/json"}
        res = requests.post(CONFIG['zabbix']['url'], json=payload, headers=headers)
        try:
            response_json = res.json()
            if "error" in response_json:
                logger.error(f"Import failed for {os.path.basename(path)}: {response_json['error']['data']}")
            else:
                logger.info(f"Successfully imported {os.path.basename(path)}")
        except ValueError:
            logger.error(f"Invalid response for {os.path.basename(path)}: {res.text}")
    return inner

def copy_external_script(path):
    dst_path = os.path.join(CONFIG['externalscript_path'], os.path.basename(path))
    os.system(f'cp {path} {dst_path}')
    if dst_path.endswith((".sh", ".py")):
        os.system(f'chmod +x {dst_path}')
    logger.info(f"Script copied: {dst_path}")

def upload_grafana_dashboard(path):
    with open(path, 'r') as file:
        dashboard_json = json.load(file)
    payload = {"dashboard": dashboard_json, "overwrite": True}
    headers = {
        "Authorization": f"Bearer {CONFIG['grafana']['api_key']}",
        "Content-Type": "application/json"
    }
    res = requests.post(f"{CONFIG['grafana']['url']}/api/dashboards/db", headers=headers, json=payload)
    logger.info(f"Upload {os.path.basename(path)}: {res.status_code}")

# --- Git Pull with Commit Detection ---
def clone_or_pull(repo_url, local_dir):
    if os.path.exists(local_dir):
        repo = Repo(local_dir)
        commits_before = set(c.hexsha for c in repo.iter_commits('origin/main'))
        repo.remotes.origin.pull()
        commits_after = set(c.hexsha for c in repo.iter_commits('origin/main'))
        new_commits = list(commits_after - commits_before)
        return local_dir, new_commits
    else:
        Repo.clone_from(repo_url, local_dir)
        return local_dir, []

# --- Main Execution ---
def main():
    logger.info("Starting Zabbix auto-update process...")
    util_data = load_util_file()
    util_data.setdefault("templates", {})
    util_data.setdefault("scripts", {})
    util_data.setdefault("dashboards", {})

    temp_dir = tempfile.mkdtemp()
    zbx_tpl_dir, _ = clone_or_pull(CONFIG['git_repos']['zabbix_templates'], os.path.join(temp_dir, 'zbx_tpl'))
    zbx_scr_dir, _ = clone_or_pull(CONFIG['git_repos']['zabbix_scripts'], os.path.join(temp_dir, 'zbx_scr'))
    graf_dir, _ = clone_or_pull(CONFIG['git_repos']['grafana_dashboards'], os.path.join(temp_dir, 'graf_dash'))

    auth_token = zabbix_login()

    util_data["templates"] = compare_and_update(zbx_tpl_dir, util_data, "templates", import_zabbix_template_wrapper(auth_token))
    util_data["scripts"] = compare_and_update(zbx_scr_dir, util_data, "scripts", copy_external_script)
    util_data["dashboards"] = compare_and_update(graf_dir, util_data, "dashboards", upload_grafana_dashboard)

    save_util_file(util_data)
    logger.info("[✔] Auto-update with comparison completed.")

if __name__ == "__main__":
    main()
