#!/bin/bash
set -e

echo "[*] Updating package list..."
sudo apt update

echo "[*] Installing Python 3, pip, and venv..."
sudo apt install -y python3 python3-pip python3-venv

# Create venv in /usr/lib/zabbix/externalscripts/venv (used by apt_update_v3.py)
VENV_PATH="/usr/lib/zabbix/externalscripts/venv"

echo "[*] Creating Python virtual environment at $VENV_PATH..."

# Create parent directory if it doesn't exist
sudo mkdir -p "$VENV_PATH"
sudo chown -R $(whoami) "$VENV_PATH"

# Create venv only if it doesn't already exist
if [[ ! -f "$VENV_PATH/bin/activate" ]]; then
    python3 -m venv "$VENV_PATH"
    echo "[✓] Virtual environment created."
else
    echo "[i] Virtual environment already exists at $VENV_PATH"
fi

# Activate venv
source "$VENV_PATH/bin/activate"

# Install packages
if [[ -f "requirements.txt" ]]; then
    echo "[*] Installing packages from requirements.txt..."
    pip install --upgrade pip
    pip install -r requirements.txt
else
    echo "[!] requirements.txt not found. Installing essential packages manually..."
    pip install --upgrade pip
    pip install requests==2.31.0 GitPython==3.1.43
fi

# Make Python script executable
if [[ -f "apt_update_v3.py" ]]; then
    chmod +x apt_update_v3.py
    echo "[✓] Made apt_update_v3.py executable."

    echo "[*] Running apt_update_v3.py..."
    python3 apt_update_v3.py
else
    echo "[✗] apt_update_v3.py not found!"
fi

# Optional: Make config executable (not required, but retained)
if [[ -f "auto_update_config_v3.json" ]]; then
    chmod +x auto_update_config_v3.json
    echo "[✓] Made auto_update_config_v3.json executable."
fi

echo "[✔] Python environment setup complete."
