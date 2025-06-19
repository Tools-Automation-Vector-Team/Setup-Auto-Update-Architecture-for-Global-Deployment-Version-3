#!/bin/bash
set -e

echo "[*] Updating package list..."
sudo apt update

echo "[*] Installing Python 3, pip, and venv..."
sudo apt install -y python3 python3-pip python3-venv

echo "[*] Creating virtual environment at ./venv..."
python3 -m venv venv

echo "[*] Activating virtual environment..."
source venv/bin/activate

# Install from requirements.txt if exists
if [[ -f "requirements.txt" ]]; then
    echo "[*] Installing packages from requirements.txt..."
    pip install --upgrade pip
    pip install -r requirements.txt
else
    echo "[!] requirements.txt not found. Installing essential packages manually..."
    pip install --upgrade pip
    pip install requests==2.31.0 GitPython==3.1.43
fi

# Set executable permissions for script and config
if [[ -f "apt_update_v3.py" ]]; then
    chmod +x apt_update_v3.py
    echo "[✓] Made apt_update_v3.py executable."

    echo "[*] Running apt_update_v3.py..."
    python3 apt_update_v3.py
else
    echo "[✗] apt_update_v3.py not found!"
fi

if [[ -f "auto_update_config_v3.json" ]]; then
    chmod +x auto_update_config_v3.json
    echo "[✓] Made auto_update_config_v3.json executable."
fi

echo "[✔] Python environment setup complete."

