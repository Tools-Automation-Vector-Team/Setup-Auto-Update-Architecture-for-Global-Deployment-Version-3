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
import subprocess
from git import Repo
from datetime import datetime
from logging.handlers import RotatingFileHandler
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# --- Logging Setup ---
LOG_DIR = "/var/log/zabbix-auto-update"
LOG_FILE = os.path.join(LOG_DIR, "zabbix_auto_update.log")
MAX_LOG_SIZE = 5 * 1024 * 1024  # 5MB
BACKUP_COUNT = 3

# --- State tracking file ---
STATE_FILE = "/var/log/zabbix-auto-update/deployment_state.json"

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

# Initialize logger globally
logger = setup_logging()

# Load config
config_path = sys.argv[1] if len(sys.argv) > 1 else 'auto_update_config_v3.json'
with open(config_path) as f:
    CONFIG = json.load(f)

CATEGORIES = [cat.strip() for cat in CONFIG.get("category", "").split(",") if cat.strip()]

# --- State Management ---
def load_deployment_state():
    """Load the current deployment state from file"""
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            logger.warning("Could not load deployment state, starting fresh")
    return {
        "templates": {},
        "scripts": {},
        "dashboards": {},
        "plugins": [],
        "last_commits": {}
    }

def save_deployment_state(state):
    """Save the deployment state to file"""
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f, indent=2)

def get_file_hash(file_path):
    """Get SHA256 hash of a file"""
    hash_sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

def get_repo_commit(repo_path):
    """Get the latest commit hash of a repository"""
    repo = Repo(repo_path)
    return repo.head.commit.hexsha

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

# --- Check if Zabbix template exists ---
def check_zabbix_template_exists(auth_token, template_name):
    """Check if a template already exists in Zabbix"""
    payload = {
        "jsonrpc": "2.0",
        "method": "template.get",
        "params": {
            "output": ["templateid", "name"],
            "filter": {"name": template_name}
        },
        "auth": auth_token,
        "id": 1
    }
    
    res = requests.post(CONFIG['zabbix']['url'], json=payload, headers={"Content-Type": "application/json"})
    result = res.json()
    
    if 'result' in result and len(result['result']) > 0:
        return True
    return False

def get_template_name_from_file(template_path):
    """Extract template name from template file"""
    try:
        if template_path.endswith('.xml'):
            import xml.etree.ElementTree as ET
            tree = ET.parse(template_path)
            root = tree.getroot()
            template_elem = root.find('.//template/name')
            if template_elem is not None:
                return template_elem.text
        elif template_path.endswith('.json'):
            with open(template_path, 'r') as f:
                data = json.load(f)
                if 'zabbix_export' in data and 'templates' in data['zabbix_export']:
                    templates = data['zabbix_export']['templates']
                    if templates and len(templates) > 0:
                        return templates[0].get('name', '')
    except Exception as e:
        logger.warning(f"Could not extract template name from {template_path}: {e}")
    
    # Fallback to filename
    return os.path.splitext(os.path.basename(template_path))[0]

# --- Import Zabbix Template ---
def import_zabbix_template(auth_token, template_path, force_update=False):
    template_name = get_template_name_from_file(template_path)
    
    if not force_update and check_zabbix_template_exists(auth_token, template_name):
        logger.info(f"Template {template_name} already exists, skipping import")
        return False
    
    ext = template_path.split('.')[-1].lower()
    format_map = {"xml": "xml", "json": "json", "yaml": "yaml", "yml": "yaml"}

    if ext not in format_map:
        logger.warning(f"Unsupported template format: {template_path}")
        return False

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
            return False
        else:
            logger.info(f"Successfully imported {os.path.basename(template_path)}")
            return True
    except ValueError:
        logger.error(f"Invalid response for {os.path.basename(template_path)}: {res.text}")
        return False

# --- Copy External Scripts ---
def copy_external_script(src_path, force_update=False):
    dst_path = os.path.join(CONFIG['externalscript_path'], os.path.basename(src_path))
    
    # Check if script already exists and hasn't changed
    if not force_update and os.path.exists(dst_path):
        src_hash = get_file_hash(src_path)
        dst_hash = get_file_hash(dst_path)
        if src_hash == dst_hash:
            logger.info(f"Script {os.path.basename(src_path)} already up to date, skipping")
            return False
    
    os.system(f'cp {src_path} {dst_path}')
    if dst_path.endswith((".sh", ".py")):
        os.system(f'chmod +x {dst_path}')
    logger.info(f"Script copied/updated: {dst_path}")
    return True

# --- Check if Grafana dashboard exists ---
def check_grafana_dashboard_exists(dashboard_title):
    """Check if a dashboard already exists in Grafana"""
    headers = {
        "Authorization": f"Bearer {CONFIG['grafana']['api_key']}",
        "Content-Type": "application/json"
    }
    
    try:
        res = requests.get(f"{CONFIG['grafana']['url']}/api/search?query={dashboard_title}", headers=headers)
        if res.status_code == 200:
            dashboards = res.json()
            return len(dashboards) > 0
    except Exception as e:
        logger.warning(f"Could not check dashboard existence: {e}")
    
    return False

def get_dashboard_title(json_path):
    """Extract dashboard title from JSON file"""
    try:
        with open(json_path, 'r') as file:
            dashboard_json = json.load(file)
            return dashboard_json.get('dashboard', {}).get('title', os.path.basename(json_path))
    except Exception:
        return os.path.basename(json_path)

# --- Upload Grafana Dashboards ---
def upload_grafana_dashboard(json_path, force_update=False):
    dashboard_title = get_dashboard_title(json_path)
    
    if not force_update and check_grafana_dashboard_exists(dashboard_title):
        logger.info(f"Dashboard {dashboard_title} already exists, skipping upload")
        return False
    
    with open(json_path, 'r') as file:
        dashboard_json = json.load(file)
    payload = {"dashboard": dashboard_json, "overwrite": True}
    headers = {
        "Authorization": f"Bearer {CONFIG['grafana']['api_key']}",
        "Content-Type": "application/json"
    }
    res = requests.post(f"{CONFIG['grafana']['url']}/api/dashboards/db", headers=headers, json=payload)
    
    if res.status_code in [200, 201]:
        logger.info(f"Successfully uploaded dashboard: {os.path.basename(json_path)}")
        return True
    else:
        logger.error(f"Failed to upload dashboard {os.path.basename(json_path)}: {res.status_code}")
        return False

# --- Clone or Pull Git Repos ---
def clone_or_pull(repo_url, local_dir):
    if os.path.exists(local_dir):
        repo = Repo(local_dir)
        repo.remotes.origin.pull()
        logger.info(f"Updated repository: {repo_url}")
    else:
        Repo.clone_from(repo_url, local_dir)
        logger.info(f"Cloned repository: {repo_url}")
    return local_dir

# --- Check if Grafana plugin is installed ---
def check_grafana_plugin_installed(plugin_name):
    """Check if a Grafana plugin is already installed"""
    try:
        result = subprocess.run(["grafana-cli", "plugins", "ls"], capture_output=True, text=True)
        if result.returncode == 0:
            return plugin_name in result.stdout
    except Exception as e:
        logger.warning(f"Could not check plugin status: {e}")
    return False

# --- Install Grafana Plugins ---
def install_grafana_plugins(plugin_file, state):
    if not os.path.exists(plugin_file):
        logger.warning(f"Grafana plugin file not found: {plugin_file}")
        return False

    with open(plugin_file, "r") as f:
        plugins = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    plugin_installed = False
    newly_installed_plugins = []

    for plugin in plugins:
        if plugin in state.get("plugins", []):
            if check_grafana_plugin_installed(plugin):
                logger.info(f"Plugin {plugin} already installed, skipping")
                continue
        
        logger.info(f"Installing Grafana plugin: {plugin}")
        exit_code = os.system(f"grafana-cli plugins install {plugin}")
        if exit_code == 0:
            logger.info(f"Successfully installed: {plugin}")
            plugin_installed = True
            newly_installed_plugins.append(plugin)
        else:
            logger.warning(f"Plugin might already be installed or failed: {plugin}")

    # Update state with newly installed plugins
    if newly_installed_plugins:
        if "plugins" not in state:
            state["plugins"] = []
        state["plugins"].extend(newly_installed_plugins)

    if plugin_installed:
        os.system("systemctl restart grafana-server")
        logger.info("Grafana server restarted after plugin installation.")
        time.sleep(15)  # Wait for Grafana to restart

    return plugin_installed

# --- Add Zabbix DataSource to Grafana ---
def add_zabbix_datasource_provisioned():
    logger.info("[*] Checking Zabbix data source provisioning...")

    grafana_url = CONFIG['zabbix']['url'].replace("/api_jsonrpc.php", "")
    zabbix_user = CONFIG['zabbix']['user']
    zabbix_password = CONFIG['zabbix']['password']
    file_path = "/etc/grafana/provisioning/datasources/zabbix.yaml"

    file_content = f"""apiVersion: 1

datasources:
  - name: Zabbix
    type: alexanderzobnin-zabbix-datasource
    access: proxy
    url: {grafana_url}/api_jsonrpc.php
    isDefault: true
    editable: true
    jsonData:
      username: {zabbix_user}
      trends: true
      trendsFrom: '7d'
      trendsRange: '4d'
      cacheTTL: '1h'
      alerting: true
      addThresholds: false
      alertingMinSeverity: 3
      disableReadOnlyUsersAck: true
      disableDataAlignment: false
      useZabbixValueMapping: true
    secureJsonData:
      password: {zabbix_password}
"""

    # Check if file exists and content is the same
    if os.path.exists(file_path):
        try:
            with open(file_path, 'r') as f:
                existing_content = f.read()
            if existing_content.strip() == file_content.strip():
                logger.info("[+] Zabbix data source already properly configured")
                return True
        except Exception as e:
            logger.warning(f"Could not read existing datasource file: {e}")

    try:
        with open(file_path, "w") as file:
            file.write(file_content)
        logger.info(f"[+] Provisioning file written at: {file_path}")
        logger.info("[*] Restarting Grafana to load the new data source...")
        os.system("systemctl restart grafana-server")
        time.sleep(15)
        logger.info("[✔] Zabbix data source provisioned successfully.")
        return True
    except Exception as e:
        logger.error(f"[!] Failed to write provisioning file: {e}")
        return False

# --- Setup Python Virtual Environment ---
def setup_virtualenv():
    import subprocess
    venv_dir = os.path.join(CONFIG['externalscript_path'], 'venv')
    requirements_file = os.path.join(CONFIG['externalscript_path'], 'requirements.txt')
    
    if not os.path.exists(venv_dir):
        logger.info("Creating virtual environment...")
        subprocess.run(["python3", "-m", "venv", venv_dir], check=True)
    else:
        logger.info("Virtual environment already exists")
    
    pip_path = os.path.join(venv_dir, "bin", "pip")
    subprocess.run([pip_path, "install", "--upgrade", "pip"], check=True)
    
    if os.path.exists(requirements_file):
        logger.info("Installing requirements...")
        subprocess.run([pip_path, "install", "-r", requirements_file], check=True)

# --- Main Execution ---
def main():
    logger.info("Starting intelligent Zabbix auto-update process...")

    # Load current state
    state = load_deployment_state()
    
    temp_dir = tempfile.mkdtemp()
    zbx_tpl_dir = clone_or_pull(CONFIG['git_repos']['zabbix_templates'], os.path.join(temp_dir, 'zbx_tpl'))
    zbx_scr_dir = clone_or_pull(CONFIG['git_repos']['zabbix_scripts'], os.path.join(temp_dir, 'zbx_scr'))
    graf_dir = clone_or_pull(CONFIG['git_repos']['grafana_dashboards'], os.path.join(temp_dir, 'graf_dash'))

    # Get current commit hashes
    current_commits = {
        'templates': get_repo_commit(zbx_tpl_dir),
        'scripts': get_repo_commit(zbx_scr_dir),
        'dashboards': get_repo_commit(graf_dir)
    }

    # Check if commits have changed
    commits_changed = {}
    for repo_type, commit in current_commits.items():
        last_commit = state.get("last_commits", {}).get(repo_type)
        commits_changed[repo_type] = (last_commit != commit)
        if commits_changed[repo_type]:
            logger.info(f"{repo_type.title()} repository has new commits ({last_commit} -> {commit})")
        else:
            logger.info(f"{repo_type.title()} repository unchanged (commit: {commit})")

    auth_token = zabbix_login()
    something_updated = False

    for cat in CATEGORIES:
        logger.info(f"Processing category: {cat}")
        subdir_tpl = os.path.join(zbx_tpl_dir, cat)
        subdir_scr = os.path.join(zbx_scr_dir, cat)
        subdir_graf = os.path.join(graf_dir, cat)

        # Process templates
        if os.path.exists(subdir_tpl):
            for f in os.listdir(subdir_tpl):
                if f.lower().endswith(('.xml', '.json', '.yaml', '.yml')):
                    file_path = os.path.join(subdir_tpl, f)
                    file_key = f"{cat}/{f}"
                    
                    # Check if we need to update this template
                    force_update = commits_changed['templates'] or file_key not in state.get("templates", {})
                    
                    if import_zabbix_template(auth_token, file_path, force_update):
                        state.setdefault("templates", {})[file_key] = get_file_hash(file_path)
                        something_updated = True

        # Process scripts
        if os.path.exists(subdir_scr):
            for f in os.listdir(subdir_scr):
                full_path = os.path.join(subdir_scr, f)
                if os.path.isfile(full_path):
                    file_key = f"{cat}/{f}"
                    
                    # Check if we need to update this script
                    force_update = commits_changed['scripts'] or file_key not in state.get("scripts", {})
                    
                    if copy_external_script(full_path, force_update):
                        state.setdefault("scripts", {})[file_key] = get_file_hash(full_path)
                        something_updated = True

        # Process dashboards
        if os.path.exists(subdir_graf):
            for f in os.listdir(subdir_graf):
                if f.endswith(".json"):
                    file_path = os.path.join(subdir_graf, f)
                    file_key = f"{cat}/{f}"
                    
                    # Check if we need to update this dashboard
                    force_update = commits_changed['dashboards'] or file_key not in state.get("dashboards", {})
                    
                    if upload_grafana_dashboard(file_path, force_update):
                        state.setdefault("dashboards", {})[file_key] = get_file_hash(file_path)
                        something_updated = True

    # Process plugins (always check as they might be manually removed)
    plugin_file_path = os.path.join(graf_dir, "grafana_plugins.txt")
    if install_grafana_plugins(plugin_file_path, state):
        something_updated = True

    # Ensure Zabbix data source exists
    add_zabbix_datasource_provisioned()

    # Set up venv if required
    if CONFIG.get("venv_required", False):
        logger.info("Setting up virtual environment...")
        setup_virtualenv()

    # Update state with current commits
    state["last_commits"] = current_commits
    
    # Save updated state
    save_deployment_state(state)

    if something_updated:
        logger.info("[✔] Auto-update process completed with updates applied.")
    else:
        logger.info("[✔] Auto-update process completed - everything was already up to date.")

# --- Entry Point ---
if __name__ == "__main__":
    main()
