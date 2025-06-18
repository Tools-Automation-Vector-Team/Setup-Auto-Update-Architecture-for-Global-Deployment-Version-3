#!/usr/bin/env python3

import os
import sys
import json
import time
import zipfile
import logging
import tempfile
import requests
import subprocess
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

# --- Load Config ---
config_path = sys.argv[1] if len(sys.argv) > 1 else 'auto_update_config_v3.json'
with open(config_path) as f:
    CONFIG = json.load(f)

CATEGORIES = [cat.strip() for cat in CONFIG.get("category", "").split(",") if cat.strip()]

# --- Utility Snapshot Setup ---
UTIL_FILE = "util_snapshot.json"
def save_util_snapshot(data):
    with open(UTIL_FILE, 'w') as f:
        json.dump(data, f, indent=2)

def load_util_snapshot():
    return json.load(open(UTIL_FILE)) if os.path.exists(UTIL_FILE) else {}

def create_util_snapshot(git_dirs):
    snapshot = {"templates": [], "scripts": [], "dashboards": []}
    for cat in CATEGORIES:
        tpl_dir = os.path.join(git_dirs['zbx_tpl'], cat)
        scr_dir = os.path.join(git_dirs['zbx_scr'], cat)
        dash_dir = os.path.join(git_dirs['graf_dash'], cat)

        snapshot['templates'] += [f for f in os.listdir(tpl_dir) if f.endswith(('.xml', '.json', '.yaml', '.yml'))] if os.path.exists(tpl_dir) else []
        snapshot['scripts'] += os.listdir(scr_dir) if os.path.exists(scr_dir) else []
        snapshot['dashboards'] += [f for f in os.listdir(dash_dir) if f.endswith(".json")] if os.path.exists(dash_dir) else []
    save_util_snapshot(snapshot)
    return snapshot

# --- Git Helpers ---
def clone_or_pull(repo_url, local_dir):
    if os.path.exists(local_dir):
        repo = Repo(local_dir)
        repo.remotes.origin.pull()
    else:
        repo = Repo.clone_from(repo_url, local_dir)
    return repo

def check_diff(repo, path):
    changed = []
    commits = list(repo.iter_commits('main', paths=path, max_count=5))
    for commit in commits:
        changed += commit.stats.files.keys()
    return list(set(changed))

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

# --- Import Zabbix Template ---
def import_zabbix_template(auth_token, template_path):
    ext = template_path.split('.')[-1].lower()
    format_map = {"xml": "xml", "json": "json", "yaml": "yaml", "yml": "yaml"}

    if ext not in format_map:
        logger.warning(f"Unsupported template format: {template_path}")
        return

    with open(template_path, 'r', encoding='utf-8') as file:
        source = file.read()

    payload = {
        "jsonrpc": "2.0",
        "method": "configuration.import",
        "params": {
            "format": format_map[ext],
            "rules": {
                "templates": {"createMissing": True, "updateExisting": True},
                "items": {"createMissing": True, "updateExisting": True},
                "triggers": {"createMissing": True, "updateExisting": True},
                "discoveryRules": {"createMissing": True, "updateExisting": True},
                "graphs": {"createMissing": True, "updateExisting": True},
                "valueMaps": {"createMissing": True, "updateExisting": True},
                "httptests": {"createMissing": True, "updateExisting": True}
            },
            "source": source
        },
        "id": 2
    }

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {auth_token}"
    }

    res = requests.post(CONFIG['zabbix']['url'], json=payload, headers=headers)
    try:
        response_json = res.json()
        if "error" in response_json:
            logger.error(f"Import failed for {os.path.basename(template_path)}: {response_json['error']['data']}")
        else:
            logger.info(f"Imported {os.path.basename(template_path)}")
    except ValueError:
        logger.error(f"Invalid response for {os.path.basename(template_path)}: {res.text}")

# --- Copy External Script ---
def copy_external_script(src_path):
    dst_path = os.path.join(CONFIG['externalscript_path'], os.path.basename(src_path))
    subprocess.run(['cp', src_path, dst_path])
    if dst_path.endswith((".sh", ".py")):
        subprocess.run(['chmod', '+x', dst_path])
    logger.info(f"Copied script: {dst_path}")

# --- Upload Grafana Dashboard ---
def upload_grafana_dashboard(json_path):
    with open(json_path, 'r') as file:
        dashboard_json = json.load(file)
    payload = {"dashboard": dashboard_json, "overwrite": True}
    headers = {
        "Authorization": f"Bearer {CONFIG['grafana']['api_key']}",
        "Content-Type": "application/json"
    }
    res = requests.post(f"{CONFIG['grafana']['url']}/api/dashboards/db", headers=headers, json=payload)
    logger.info(f"Upload {os.path.basename(json_path)}: {res.status_code}")

# --- Install Grafana Plugins ---
def install_grafana_plugins(plugin_file):
    if not os.path.exists(plugin_file):
        logger.warning(f"Grafana plugin file not found: {plugin_file}")
        return
    with open(plugin_file, "r") as f:
        plugins = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    plugin_installed = False
    for plugin in plugins:
        logger.info(f"Installing Grafana plugin: {plugin}")
        exit_code = os.system(f"grafana-cli plugins install {plugin}")
        if exit_code == 0:
            logger.info(f"Successfully installed: {plugin}")
            plugin_installed = True
        else:
            logger.warning(f"Plugin failed or exists: {plugin}")
    if plugin_installed:
        os.system("systemctl restart grafana-server")

# --- Add Zabbix Datasource ---
def add_zabbix_datasource_provisioned():
    logger.info("Provisioning Zabbix datasource to Grafana...")
    grafana_url = CONFIG['zabbix']['url'].replace("/api_jsonrpc.php", "")
    file_path = "/etc/grafana/provisioning/datasources/zabbix.yaml"
    content = f"""apiVersion: 1
datasources:
  - name: Zabbix
    type: alexanderzobnin-zabbix-datasource
    access: proxy
    url: {grafana_url}/api_jsonrpc.php
    isDefault: true
    editable: true
    jsonData:
      username: {CONFIG['zabbix']['user']}
      trends: true
      trendsFrom: '7d'
      trendsRange: '4d'
      alerting: true
    secureJsonData:
      password: {CONFIG['zabbix']['password']}
"""
    try:
        with open(file_path, "w") as f:
            f.write(content)
        os.system("systemctl restart grafana-server")
        time.sleep(10)
        logger.info("Zabbix datasource provisioned.")
    except Exception as e:
        logger.error(f"Datasource provision failed: {e}")

# --- Main Execution ---
def main():
    logger.info("Starting Auto-Update Process...")

    temp_dir = tempfile.mkdtemp()
    git_dirs = {
        'zbx_tpl': os.path.join(temp_dir, 'zbx_tpl'),
        'zbx_scr': os.path.join(temp_dir, 'zbx_scr'),
        'graf_dash': os.path.join(temp_dir, 'graf_dash')
    }

    repos = {
        'zbx_tpl': clone_or_pull(CONFIG['git_repos']['zabbix_templates'], git_dirs['zbx_tpl']),
        'zbx_scr': clone_or_pull(CONFIG['git_repos']['zabbix_scripts'], git_dirs['zbx_scr']),
        'graf_dash': clone_or_pull(CONFIG['git_repos']['grafana_dashboards'], git_dirs['graf_dash'])
    }

    snapshot = create_util_snapshot(git_dirs)
    prev_snapshot = load_util_snapshot()
    auth_token = zabbix_login()

    for cat in CATEGORIES:
        tpl_dir = os.path.join(git_dirs['zbx_tpl'], cat)
        scr_dir = os.path.join(git_dirs['zbx_scr'], cat)
        dash_dir = os.path.join(git_dirs['graf_dash'], cat)

        for f in snapshot['templates']:
            tpl_path = os.path.join(tpl_dir, f)
            if f not in prev_snapshot.get('templates', []) or f in check_diff(repos['zbx_tpl'], tpl_path):
                import_zabbix_template(auth_token, tpl_path)

        for f in snapshot['scripts']:
            scr_path = os.path.join(scr_dir, f)
            if f not in prev_snapshot.get('scripts', []) or f in check_diff(repos['zbx_scr'], scr_path):
                copy_external_script(scr_path)

        for f in snapshot['dashboards']:
            dash_path = os.path.join(dash_dir, f)
            if f not in prev_snapshot.get('dashboards', []) or f in check_diff(repos['graf_dash'], dash_path):
                upload_grafana_dashboard(dash_path)

    install_grafana_plugins(os.path.join(git_dirs['graf_dash'], "grafana_plugins.txt"))
    add_zabbix_datasource_provisioned()

    if CONFIG.get("venv_required", False):
        venv_dir = os.path.join(CONFIG['externalscript_path'], 'venv')
        subprocess.run(["python3", "-m", "venv", venv_dir], check=True)
        pip_path = os.path.join(venv_dir, "bin", "pip")
        subprocess.run([pip_path, "install", "--upgrade", "pip"], check=True)
        req_file = os.path.join(CONFIG['externalscript_path'], 'requirements.txt')
        if os.path.exists(req_file):
            subprocess.run([pip_path, "install", "-r", req_file], check=True)

    logger.info("✔ Auto-update completed.")

if __name__ == "__main__":
    main()
