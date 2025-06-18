#!/usr/bin/env python3

import os, sys, json, time, shutil, tempfile, zipfile, logging, requests
from git import Repo
from datetime import datetime
from logging.handlers import RotatingFileHandler

# --- Logging Setup ---
LOG_DIR = "/var/log/zabbix-auto-update"
LOG_FILE = os.path.join(LOG_DIR, "zabbix_auto_update.log")

class ZippingRotatingFileHandler(RotatingFileHandler):
    def doRollover(self):
        super().doRollover()
        log_filename = f"{self.baseFilename}.1"
        if os.path.exists(log_filename):
            ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            zipfile.ZipFile(f"{log_filename}_{ts}.zip", 'w').write(log_filename, os.path.basename(log_filename))
            os.remove(log_filename)

def setup_logging():
    os.makedirs(LOG_DIR, exist_ok=True)
    logger = logging.getLogger()
    handler = ZippingRotatingFileHandler(LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=3)
    handler.setFormatter(logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s'))
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    return logger

logger = setup_logging()

# --- Load Config ---
config_path = sys.argv[1] if len(sys.argv) > 1 else "auto_update_config_v3.json"
with open(config_path) as f:
    CONFIG = json.load(f)

CATEGORIES = [cat.strip() for cat in CONFIG.get("category", "").split(",") if cat.strip()]
UTIL_FILE = CONFIG.get("util_file", "util_record.json")

# --- Git Clone or Pull ---
def clone_or_pull(repo_url, dest_dir):
    if os.path.exists(dest_dir):
        Repo(dest_dir).remotes.origin.pull()
        logger.info(f"Pulled updates from {repo_url}")
    else:
        Repo.clone_from(repo_url, dest_dir)
        logger.info(f"Cloned {repo_url}")
    return dest_dir

# --- Util File Handling ---
def load_util():
    if os.path.exists(UTIL_FILE):
        with open(UTIL_FILE) as f:
            return json.load(f)
    return {"templates": [], "scripts": [], "dashboards": []}

def save_util(data):
    with open(UTIL_FILE, "w") as f:
        json.dump(data, f, indent=2)

# --- Zabbix Login ---
def zabbix_login():
    payload = {
        "jsonrpc": "2.0", "method": "user.login",
        "params": {"username": CONFIG['zabbix']['user'], "password": CONFIG['zabbix']['password']},
        "id": 1
    }
    r = requests.post(CONFIG['zabbix']['url'], json=payload)
    return r.json().get('result')

# --- Import Template ---
def import_template(token, path):
    ext = os.path.splitext(path)[1].lower().strip('.')
    format_map = {"json": "json", "xml": "xml", "yaml": "yaml", "yml": "yaml"}
    if ext not in format_map:
        logger.warning(f"Skipped unsupported: {path}")
        return
    with open(path, 'r') as f:
        source = f.read()
    payload = {
        "jsonrpc": "2.0", "method": "configuration.import",
        "params": {
            "format": format_map[ext],
            "rules": {
                "templates": {"createMissing": True, "updateExisting": True},
                "items": {"createMissing": True, "updateExisting": True},
                "triggers": {"createMissing": True, "updateExisting": True},
                "discoveryRules": {"createMissing": True, "updateExisting": True},
                "graphs": {"createMissing": True, "updateExisting": True},
                "httptests": {"createMissing": True, "updateExisting": True}
            },
            "source": source
        },
        "auth": token,
        "id": 2
    }
    res = requests.post(CONFIG['zabbix']['url'], json=payload)
    if 'error' in res.json():
        logger.error(f"Failed import: {path}")
    else:
        logger.info(f"Imported template: {path}")

# --- Sync External Scripts ---
def sync_external_scripts(src_dir):
    dest = CONFIG['zabbix'].get("externalscripts_dir", "/usr/lib/zabbix/externalscripts")
    os.makedirs(dest, exist_ok=True)
    for file in os.listdir(src_dir):
        src = os.path.join(src_dir, file)
        dst = os.path.join(dest, file)
        shutil.copy2(src, dst)
        os.chmod(dst, 0o755)
        logger.info(f"Copied: {file} to externalscripts")

# --- Add Zabbix Datasource to Grafana ---
def add_zabbix_datasource():
    file_path = "/etc/grafana/provisioning/datasources/zabbix.yaml"
    grafana_url = CONFIG['zabbix']['url'].replace("/api_jsonrpc.php", "")
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
      alerting: true
    secureJsonData:
      password: {CONFIG['zabbix']['password']}"""
    with open(file_path, 'w') as f:
        f.write(content)
    os.system("systemctl restart grafana-server")
    time.sleep(10)
    logger.info("Provisioned Grafana datasource")

# --- Import Grafana Dashboards ---
def import_dashboards(dashboard_dir):
    url = CONFIG['grafana']['url'].rstrip('/') + '/api/dashboards/db'
    headers = {
        "Authorization": f"Bearer {CONFIG['grafana']['token']}",
        "Content-Type": "application/json"
    }
    for file in os.listdir(dashboard_dir):
        if file.endswith('.json'):
            with open(os.path.join(dashboard_dir, file)) as f:
                data = json.load(f)
            payload = {"dashboard": data, "overwrite": True, "folderId": 0}
            r = requests.post(url, headers=headers, json=payload)
            if r.status_code == 200:
                logger.info(f"Imported dashboard: {file}")
            else:
                logger.error(f"Failed import {file}: {r.text}")

# --- Main ---
def main():
    logger.info("Starting auto-update...")
    util_data = load_util()
    temp_dir = tempfile.mkdtemp()
    zbx_tpl_dir = clone_or_pull(CONFIG['git_repos']['zabbix_templates'], os.path.join(temp_dir, 'tpl'))
    zbx_scr_dir = clone_or_pull(CONFIG['git_repos']['zabbix_scripts'], os.path.join(temp_dir, 'scr'))
    graf_dir = clone_or_pull(CONFIG['git_repos']['grafana_dashboards'], os.path.join(temp_dir, 'dash'))

    token = zabbix_login()

    new_templates = []
    new_scripts = []
    new_dashboards = []

    for cat in CATEGORIES:
        tpl_cat = os.path.join(zbx_tpl_dir, cat)
        scr_cat = os.path.join(zbx_scr_dir, cat)
        dash_cat = os.path.join(graf_dir, cat)

        if os.path.exists(tpl_cat):
            for f in os.listdir(tpl_cat):
                rel = f"{cat}/{f}"
                if rel not in util_data['templates']:
                    import_template(token, os.path.join(tpl_cat, f))
                    new_templates.append(rel)

        if os.path.exists(scr_cat):
            for f in os.listdir(scr_cat):
                rel = f"{cat}/{f}"
                if rel not in util_data['scripts']:
                    sync_external_scripts(scr_cat)
                    new_scripts.append(rel)

        if os.path.exists(dash_cat):
            for f in os.listdir(dash_cat):
                rel = f"{cat}/{f}"
                if rel not in util_data['dashboards']:
                    import_dashboards(dash_cat)
                    new_dashboards.append(rel)

    if new_templates or new_scripts or new_dashboards:
        util_data['templates'].extend(new_templates)
        util_data['scripts'].extend(new_scripts)
        util_data['dashboards'].extend(new_dashboards)
        save_util(util_data)
        logger.info("Updated util file with new entries")

    add_zabbix_datasource()
    logger.info("Auto-update completed.")

if __name__ == "__main__":
    main()
