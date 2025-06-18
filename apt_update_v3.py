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
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

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

# Initialize logger globally
logger = setup_logging()

# Load config
config_path = sys.argv[1] if len(sys.argv) > 1 else 'auto_update_config_v2.json'
with open(config_path) as f:
    CONFIG = json.load(f)

CATEGORIES = [cat.strip() for cat in CONFIG.get("category", "").split(",") if cat.strip()]
UTIL_FILE = os.path.join(os.path.dirname(config_path), 'zabbix_util_tracking.json')

# --- Utility File Management ---
def load_util_file():
    """Load the utility tracking file or create empty structure"""
    if os.path.exists(UTIL_FILE):
        with open(UTIL_FILE, 'r') as f:
            return json.load(f)
    else:
        return {
            'templates': {},
            'external_scripts': {},
            'grafana_dashboards': {},
            'last_commits': {},
            'initialized': False
        }

def save_util_file(util_data):
    """Save the utility tracking file"""
    with open(UTIL_FILE, 'w') as f:
        json.dump(util_data, f, indent=2)
    logger.info(f"Utility file updated: {UTIL_FILE}")

def get_file_hash(file_path):
    """Calculate MD5 hash of a file"""
    hash_md5 = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except Exception as e:
        logger.error(f"Error calculating hash for {file_path}: {e}")
        return None

def get_latest_commit_hash(repo_path):
    """Get the latest commit hash from a git repository"""
    try:
        repo = Repo(repo_path)
        return repo.head.commit.hexsha
    except Exception as e:
        logger.error(f"Error getting commit hash for {repo_path}: {e}")
        return None

# --- Zabbix API Functions ---
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

def get_existing_zabbix_templates(auth_token):
    """Fetch all existing Zabbix templates"""
    payload = {
        "jsonrpc": "2.0",
        "method": "template.get",
        "params": {
            "output": ["templateid", "name", "host"]
        },
        "auth": auth_token,
        "id": 1
    }
    
    headers = {"Content-Type": "application/json"}
    res = requests.post(CONFIG['zabbix']['url'], json=payload, headers=headers)
    result = res.json()
    
    if 'result' in result:
        templates = {}
        for template in result['result']:
            templates[template['host']] = {
                'templateid': template['templateid'],
                'name': template['name']
            }
        logger.info(f"Retrieved {len(templates)} existing Zabbix templates")
        return templates
    else:
        logger.error(f"Failed to get Zabbix templates: {result}")
        return {}

def get_existing_external_scripts():
    """Get list of existing external scripts"""
    scripts = {}
    script_path = CONFIG['externalscript_path']
    
    if os.path.exists(script_path):
        for filename in os.listdir(script_path):
            file_path = os.path.join(script_path, filename)
            if os.path.isfile(file_path):
                scripts[filename] = {
                    'path': file_path,
                    'hash': get_file_hash(file_path),
                    'modified': os.path.getmtime(file_path)
                }
        logger.info(f"Found {len(scripts)} existing external scripts")
    
    return scripts

def get_existing_grafana_dashboards():
    """Fetch all existing Grafana dashboards"""
    headers = {
        "Authorization": f"Bearer {CONFIG['grafana']['api_key']}",
        "Content-Type": "application/json"
    }
    
    try:
        res = requests.get(f"{CONFIG['grafana']['url']}/api/search?type=dash-db", headers=headers)
        if res.status_code == 200:
            dashboards = {}
            for dashboard in res.json():
                dashboards[dashboard['title']] = {
                    'uid': dashboard['uid'],
                    'id': dashboard['id'],
                    'uri': dashboard['uri']
                }
            logger.info(f"Retrieved {len(dashboards)} existing Grafana dashboards")
            return dashboards
        else:
            logger.error(f"Failed to get Grafana dashboards: {res.status_code}")
            return {}
    except Exception as e:
        logger.error(f"Error fetching Grafana dashboards: {e}")
        return {}

def initialize_util_file(auth_token):
    """Initialize utility file with existing resources"""
    logger.info("Initializing utility file with existing resources...")
    
    util_data = {
        'templates': get_existing_zabbix_templates(auth_token),
        'external_scripts': get_existing_external_scripts(),
        'grafana_dashboards': get_existing_grafana_dashboards(),
        'last_commits': {},
        'initialized': True,
        'last_updated': datetime.now().isoformat()
    }
    
    save_util_file(util_data)
    return util_data

def detect_deleted_resources(util_data, auth_token):
    """Detect resources that were deleted from live environment"""
    logger.info("Checking for deleted resources in live environment...")
    
    deleted_items = {
        'templates': [],
        'scripts': [],
        'dashboards': []
    }
    
    # Check for deleted Zabbix templates
    current_templates = get_existing_zabbix_templates(auth_token)
    for template_name in util_data['templates'].keys():
        if template_name not in current_templates:
            deleted_items['templates'].append(template_name)
            logger.warning(f"Template '{template_name}' found in util file but missing from Zabbix")
    
    # Check for deleted external scripts
    current_scripts = get_existing_external_scripts()
    for script_name in util_data['external_scripts'].keys():
        if script_name not in current_scripts:
            deleted_items['scripts'].append(script_name)
            logger.warning(f"Script '{script_name}' found in util file but missing from filesystem")
    
    # Check for deleted Grafana dashboards
    current_dashboards = get_existing_grafana_dashboards()
    for dashboard_name in util_data['grafana_dashboards'].keys():
        if dashboard_name not in current_dashboards:
            deleted_items['dashboards'].append(dashboard_name)
            logger.warning(f"Dashboard '{dashboard_name}' found in util file but missing from Grafana")
    
    total_deleted = len(deleted_items['templates']) + len(deleted_items['scripts']) + len(deleted_items['dashboards'])
    if total_deleted > 0:
        logger.info(f"Found {total_deleted} deleted resources that need to be restored")
    
    return deleted_items

def restore_deleted_resources(util_data, deleted_items, repo_dirs, auth_token):
    """Restore deleted resources from repository"""
    logger.info("Restoring deleted resources from repository...")
    
    restored_count = 0
    
    # Restore deleted templates
    for template_name in deleted_items['templates']:
        template_info = util_data['templates'][template_name]
        category = template_info.get('category', '')
        
        # Find template file in repository
        template_dir = os.path.join(repo_dirs['templates'], category)
        if os.path.exists(template_dir):
            for filename in os.listdir(template_dir):
                if filename.lower().endswith(('.xml', '.json', '.yaml', '.yml')):
                    if os.path.splitext(filename)[0] == template_name:
                        template_path = os.path.join(template_dir, filename)
                        logger.info(f"Restoring template: {template_name}")
                        import_zabbix_template(auth_token, template_path)
                        util_data['templates'][template_name]['restored'] = datetime.now().isoformat()
                        restored_count += 1
                        break
    
    # Restore deleted scripts
    for script_name in deleted_items['scripts']:
        script_info = util_data['external_scripts'][script_name]
        category = script_info.get('category', '')
        
        # Find script file in repository
        script_dir = os.path.join(repo_dirs['scripts'], category)
        if os.path.exists(script_dir):
            script_path = os.path.join(script_dir, script_name)
            if os.path.exists(script_path):
                logger.info(f"Restoring script: {script_name}")
                copy_external_script(script_path)
                util_data['external_scripts'][script_name]['restored'] = datetime.now().isoformat()
                util_data['external_scripts'][script_name]['hash'] = get_file_hash(script_path)
                restored_count += 1
    
    # Restore deleted dashboards
    for dashboard_name in deleted_items['dashboards']:
        dashboard_info = util_data['grafana_dashboards'][dashboard_name]
        category = dashboard_info.get('category', '')
        
        # Find dashboard file in repository
        dashboard_dir = os.path.join(repo_dirs['dashboards'], category)
        if os.path.exists(dashboard_dir):
            dashboard_path = os.path.join(dashboard_dir, f"{dashboard_name}.json")
            if os.path.exists(dashboard_path):
                logger.info(f"Restoring dashboard: {dashboard_name}")
                upload_grafana_dashboard(dashboard_path)
                util_data['grafana_dashboards'][dashboard_name]['restored'] = datetime.now().isoformat()
                restored_count += 1
    
    if restored_count > 0:
        logger.info(f"Successfully restored {restored_count} deleted resources")
        save_util_file(util_data)
    else:
        logger.info("No resources needed restoration")
    
    return util_data, restored_count

def compare_and_sync_missing_items(util_data, repo_dirs, auth_token):
    """Compare util file with git repos and add missing items"""
    logger.info("Comparing utility file with git repositories...")
    
    missing_items = {
        'templates': [],
        'scripts': [],
        'dashboards': []
    }
    
    # Check for missing templates
    for cat in CATEGORIES:
        template_dir = os.path.join(repo_dirs['templates'], cat)
        if os.path.exists(template_dir):
            for filename in os.listdir(template_dir):
                if filename.lower().endswith(('.xml', '.json', '.yaml', '.yml')):
                    template_path = os.path.join(template_dir, filename)
                    template_name = os.path.splitext(filename)[0]
                    
                    # Check if template exists in util file
                    if template_name not in util_data['templates']:
                        missing_items['templates'].append({
                            'path': template_path,
                            'name': template_name,
                            'category': cat
                        })
    
    # Check for missing external scripts
    for cat in CATEGORIES:
        script_dir = os.path.join(repo_dirs['scripts'], cat)
        if os.path.exists(script_dir):
            for filename in os.listdir(script_dir):
                script_path = os.path.join(script_dir, filename)
                if os.path.isfile(script_path):
                    if filename not in util_data['external_scripts']:
                        missing_items['scripts'].append({
                            'path': script_path,
                            'name': filename,
                            'category': cat
                        })
    
    # Check for missing dashboards
    for cat in CATEGORIES:
        dashboard_dir = os.path.join(repo_dirs['dashboards'], cat)
        if os.path.exists(dashboard_dir):
            for filename in os.listdir(dashboard_dir):
                if filename.endswith('.json'):
                    dashboard_path = os.path.join(dashboard_dir, filename)
                    dashboard_name = os.path.splitext(filename)[0]
                    
                    if dashboard_name not in util_data['grafana_dashboards']:
                        missing_items['dashboards'].append({
                            'path': dashboard_path,
                            'name': dashboard_name,
                            'category': cat
                        })
    
    # Process missing items
    total_missing = len(missing_items['templates']) + len(missing_items['scripts']) + len(missing_items['dashboards'])
    if total_missing > 0:
        logger.info(f"Found {total_missing} missing items to sync")
        
        # Add missing templates
        for item in missing_items['templates']:
            import_zabbix_template(auth_token, item['path'])
            util_data['templates'][item['name']] = {
                'category': item['category'],
                'added': datetime.now().isoformat()
            }
        
        # Add missing scripts
        for item in missing_items['scripts']:
            copy_external_script(item['path'])
            util_data['external_scripts'][item['name']] = {
                'category': item['category'],
                'hash': get_file_hash(item['path']),
                'added': datetime.now().isoformat()
            }
        
        # Add missing dashboards
        for item in missing_items['dashboards']:
            upload_grafana_dashboard(item['path'])
            util_data['grafana_dashboards'][item['name']] = {
                'category': item['category'],
                'added': datetime.now().isoformat()
            }
        
        save_util_file(util_data)
        logger.info("Missing items synchronized successfully")
    else:
        logger.info("No missing items found")
    
    return util_data

def check_for_new_commits(util_data, repo_dirs):
    """Check if there are new commits in any repository"""
    new_commits = {}
    
    for repo_type, repo_path in repo_dirs.items():
        current_commit = get_latest_commit_hash(repo_path)
        last_commit = util_data['last_commits'].get(repo_type)
        
        if current_commit and current_commit != last_commit:
            new_commits[repo_type] = {
                'current': current_commit,
                'previous': last_commit,
                'path': repo_path
            }
            logger.info(f"New commit detected in {repo_type}: {current_commit}")
    
    return new_commits

def process_incremental_changes(util_data, new_commits, auth_token):
    """Process only the changed files based on new commits"""
    logger.info("Processing incremental changes...")
    
    for repo_type, commit_info in new_commits.items():
        repo_path = commit_info['path']
        repo = Repo(repo_path)
        
        # Get changed files between commits
        if commit_info['previous']:
            changed_files = repo.git.diff('--name-only', f"{commit_info['previous']}..{commit_info['current']}").split('\n')
        else:
            # If no previous commit, get all files (first run)
            changed_files = []
            for root, dirs, files in os.walk(repo_path):
                for file in files:
                    rel_path = os.path.relpath(os.path.join(root, file), repo_path)
                    changed_files.append(rel_path)
        
        changed_files = [f for f in changed_files if f.strip()]
        logger.info(f"Found {len(changed_files)} changed files in {repo_type}")
        
        # Process changed files based on repository type
        for file_path in changed_files:
            full_path = os.path.join(repo_path, file_path)
            
            if not os.path.exists(full_path):
                continue
            
            # Check if file belongs to monitored categories
            path_parts = file_path.split('/')
            if len(path_parts) < 2:
                continue
                
            category = path_parts[0]
            if category not in CATEGORIES:
                continue
            
            filename = os.path.basename(file_path)
            
            if repo_type == 'templates' and filename.lower().endswith(('.xml', '.json', '.yaml', '.yml')):
                logger.info(f"Processing changed template: {filename}")
                import_zabbix_template(auth_token, full_path)
                template_name = os.path.splitext(filename)[0]
                util_data['templates'][template_name] = {
                    'category': category,
                    'updated': datetime.now().isoformat()
                }
            
            elif repo_type == 'scripts' and os.path.isfile(full_path):
                logger.info(f"Processing changed script: {filename}")
                copy_external_script(full_path)
                util_data['external_scripts'][filename] = {
                    'category': category,
                    'hash': get_file_hash(full_path),
                    'updated': datetime.now().isoformat()
                }
            
            elif repo_type == 'dashboards' and filename.endswith('.json'):
                logger.info(f"Processing changed dashboard: {filename}")
                upload_grafana_dashboard(full_path)
                dashboard_name = os.path.splitext(filename)[0]
                util_data['grafana_dashboards'][dashboard_name] = {
                    'category': category,
                    'updated': datetime.now().isoformat()
                }
        
        # Update last commit hash
        util_data['last_commits'][repo_type] = commit_info['current']
    
    save_util_file(util_data)
    return util_data

# --- Original Functions (Modified) ---
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
            logger.info(f"Successfully imported {os.path.basename(template_path)}")
    except ValueError:
        logger.error(f"Invalid response for {os.path.basename(template_path)}: {res.text}")

def copy_external_script(src_path):
    dst_path = os.path.join(CONFIG['externalscript_path'], os.path.basename(src_path))
    os.system(f'cp {src_path} {dst_path}')
    if dst_path.endswith((".sh", ".py")):
        os.system(f'chmod +x {dst_path}')
    logger.info(f"Script copied: {dst_path}")

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

def clone_or_pull(repo_url, local_dir):
    if os.path.exists(local_dir):
        repo = Repo(local_dir)
        repo.remotes.origin.pull()
        logger.info(f"Pulled latest changes for {repo_url}")
    else:
        Repo.clone_from(repo_url, local_dir)
        logger.info(f"Cloned repository {repo_url}")
    return local_dir

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
            logger.warning(f"Plugin might already be installed or failed: {plugin}")

    if plugin_installed:
        os.system("systemctl restart grafana-server")
        logger.info("Grafana server restarted after plugin installation.")

    try:
        add_zabbix_datasource_provisioned()
    except Exception as e:
        logger.error(f"Failed to add Zabbix data source: {e}")

def add_zabbix_datasource_provisioned():
    logger.info("[*] Writing Zabbix data source provisioning file...")

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

def setup_virtualenv():
    import subprocess
    venv_dir = os.path.join(CONFIG['externalscript_path'], 'venv')
    requirements_file = os.path.join(CONFIG['externalscript_path'], 'requirements.txt')
    if not os.path.exists(venv_dir):
        subprocess.run(["python3", "-m", "venv", venv_dir], check=True)
    pip_path = os.path.join(venv_dir, "bin", "pip")
    subprocess.run([pip_path, "install", "--upgrade", "pip"], check=True)
    if os.path.exists(requirements_file):
        subprocess.run([pip_path, "install", "-r", requirements_file], check=True)

# --- Enhanced Main Execution ---
def main():
    logger.info("Starting Enhanced Zabbix auto-update process...")

    # Create temporary directory and clone/pull repositories
    temp_dir = tempfile.mkdtemp()
    repo_dirs = {
        'templates': clone_or_pull(CONFIG['git_repos']['zabbix_templates'], os.path.join(temp_dir, 'zbx_tpl')),
        'scripts': clone_or_pull(CONFIG['git_repos']['zabbix_scripts'], os.path.join(temp_dir, 'zbx_scr')),
        'dashboards': clone_or_pull(CONFIG['git_repos']['grafana_dashboards'], os.path.join(temp_dir, 'graf_dash'))
    }

    # Login to Zabbix
    auth_token = zabbix_login()

    # Load or initialize utility file
    util_data = load_util_file()
    
    if not util_data.get('initialized', False):
        logger.info("First run - initializing utility file...")
        util_data = initialize_util_file(auth_token)
    
    # Compare and sync missing items
    util_data = compare_and_sync_missing_items(util_data, repo_dirs, auth_token)
    
    # Detect and restore deleted resources
    deleted_items = detect_deleted_resources(util_data, auth_token)
    needs_grafana_restart = False
    
    if any(deleted_items.values()):  # If any resources were deleted
        util_data, restored_count = restore_deleted_resources(util_data, deleted_items, repo_dirs, auth_token)
        if deleted_items['dashboards']:  # If dashboards were restored
            needs_grafana_restart = True
    
    # Check for new commits
    new_commits = check_for_new_commits(util_data, repo_dirs)
    
    if new_commits:
        logger.info(f"Processing {len(new_commits)} repositories with new commits...")
        util_data = process_incremental_changes(util_data, new_commits, auth_token)
        
        # Handle Grafana plugins only if dashboard repo has changes
        if 'dashboards' in new_commits:
            plugin_file_path = os.path.join(repo_dirs['dashboards'], "grafana_plugins.txt")
            install_grafana_plugins(plugin_file_path)
            needs_grafana_restart = True
        
        # Restart Grafana if needed (either from new commits or restored dashboards)
        if needs_grafana_restart:
            logger.info("Restarting Grafana to apply changes...")
            os.system("systemctl restart grafana-server")
            time.sleep(15)
            
            # Ensure Zabbix data source exists
            add_zabbix_datasource_provisioned()
    else:
        logger.info("No new commits found - skipping incremental processing")
        
        # Still restart Grafana if dashboards were restored
        if needs_grafana_restart:
            logger.info("Restarting Grafana due to restored dashboards...")
            os.system("systemctl restart grafana-server")
            time.sleep(15)
            add_zabbix_datasource_provisioned()
    
    # Set up venv if required and scripts were updated
    if CONFIG.get("venv_required", False) and ('scripts' in new_commits or not util_data.get('initialized', True)):
        logger.info("Setting up virtual environment...")
        setup_virtualenv()

    # Update final timestamp
    util_data['last_updated'] = datetime.now().isoformat()
    save_util_file(util_data)

    logger.info("[✔] Enhanced auto-update process completed successfully.")

# --- Entry Point ---
if __name__ == "__main__":
    main()
