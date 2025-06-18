#!/usr/bin/env python3

import os
import sys
import json
import requests
import tempfile
import hashlib
import zipfile
import logging
from git import Repo
from datetime import datetime
from logging.handlers import RotatingFileHandler

# --- Logging Setup ---
LOG_DIR = "/var/log/zabbix-auto-update"
LOG_FILE = os.path.join(LOG_DIR, "zabbix_auto_update.log")
MAX_LOG_SIZE = 5 * 1024 * 1024
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
    formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger

logger = setup_logging()

# Load config
CONFIG_PATH = sys.argv[1] if len(sys.argv) > 1 else 'auto_update_config_v2.json'
with open(CONFIG_PATH) as f:
    CONFIG = json.load(f)

UTIL_PATH = CONFIG.get("util_file", "current_util_state.json")

# --- Zabbix Authentication ---
def zabbix_auth():
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
    return res.json().get("result")

# --- Get existing Zabbix templates ---
def fetch_existing_templates(auth_token):
    payload = {
        "jsonrpc": "2.0",
        "method": "template.get",
        "params": {"output": ["host"]},
        "auth": auth_token,
        "id": 2
    }
    res = requests.post(CONFIG['zabbix']['url'], json=payload, headers={"Content-Type": "application/json"})
    return set([tpl["host"] for tpl in res.json().get("result", [])])

# --- Get existing external scripts ---
def fetch_existing_scripts():
    path = CONFIG['externalscript_path']
    return set(os.listdir(path)) if os.path.isdir(path) else set()

# --- Get existing Grafana dashboards ---
def fetch_existing_dashboards():
    headers = {"Authorization": f"Bearer {CONFIG['grafana']['api_key']}"}
    res = requests.get(f"{CONFIG['grafana']['url']}/api/search?type=dash-db", headers=headers)
    return set(d['uid'] for d in res.json())

# --- Load Git state and previous commit ---
def get_last_commit():
    return CONFIG.get("last_commit", "")

def update_last_commit(repo_path):
    repo = Repo(repo_path)
    last_commit = repo.head.commit.hexsha
    CONFIG['last_commit'] = last_commit
    with open(CONFIG_PATH, 'w') as f:
        json.dump(CONFIG, f, indent=4)

# --- Load Git files by category ---
def load_git_files(git_dir):
    files_by_cat = {"templates": set(), "scripts": set(), "dashboards": set()}
    for root, _, files in os.walk(git_dir):
        for f in files:
            if f.endswith(('.xml', '.yaml', '.json', '.yml')):
                files_by_cat['templates'].add(f)
            elif f.endswith(('.py', '.sh')):
                files_by_cat['scripts'].add(f)
            elif f.endswith(".json") and 'dashboards' in root:
                files_by_cat['dashboards'].add(f)
    return files_by_cat

# --- Apply missing files ---
def apply_templates(missing, auth_token, template_dir):
    for file in missing:
        path = os.path.join(template_dir, file)
        ext = file.split('.')[-1].lower()
        fmt = "yaml" if ext in ["yaml", "yml"] else ext
        with open(path, 'r') as f:
            content = f.read()
        payload = {
            "jsonrpc": "2.0",
            "method": "configuration.import",
            "params": {
                "format": fmt,
                "rules": {"templates": {"createMissing": True, "updateExisting": True}},
                "source": content
            },
            "auth": auth_token,
            "id": 3
        }
        res = requests.post(CONFIG['zabbix']['url'], json=payload, headers={"Content-Type": "application/json"})
        logger.info(f"Template {file} import: {res.status_code}")

def apply_scripts(missing, script_dir):
    dst = CONFIG['externalscript_path']
    for file in missing:
        src_path = os.path.join(script_dir, file)
        dst_path = os.path.join(dst, file)
        os.system(f'cp "{src_path}" "{dst_path}"')
        os.system(f'chmod +x "{dst_path}"')
        logger.info(f"Script deployed: {file}")

def apply_dashboards(missing, dashboard_dir):
    headers = {
        "Authorization": f"Bearer {CONFIG['grafana']['api_key']}",
        "Content-Type": "application/json"
    }
    for file in missing:
        with open(os.path.join(dashboard_dir, file)) as f:
            data = json.load(f)
        payload = {"dashboard": data, "overwrite": True}
        res = requests.post(f"{CONFIG['grafana']['url']}/api/dashboards/db", headers=headers, json=payload)
        logger.info(f"Dashboard {file} upload: {res.status_code}")

# --- Main Execution ---
def main():
    logger.info("[Start] Sync process")
    auth_token = zabbix_auth()

    live_templates = fetch_existing_templates(auth_token)
    live_scripts = fetch_existing_scripts()
    live_dashboards = fetch_existing_dashboards()

    temp_dir = tempfile.mkdtemp()
    repo_dir = os.path.join(temp_dir, 'repo')
    Repo.clone_from(CONFIG['git_repos']['main'], repo_dir)
    git_files = load_git_files(repo_dir)

    # Compare and apply only missing
    missing_tpl = git_files['templates'] - live_templates
    missing_scr = git_files['scripts'] - live_scripts
    missing_dash = git_files['dashboards'] - live_dashboards

    apply_templates(missing_tpl, auth_token, repo_dir)
    apply_scripts(missing_scr, repo_dir)
    apply_dashboards(missing_dash, repo_dir)

    update_last_commit(repo_dir)
    logger.info("[✔] Sync completed successfully")

if __name__ == "__main__":
    main()
