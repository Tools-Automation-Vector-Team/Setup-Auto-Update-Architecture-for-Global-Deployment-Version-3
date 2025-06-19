# #!/bin/bash
# set -e

# echo "[*] Updating package list..."
# sudo apt update

# echo "[*] Installing Python 3, pip, and venv..."
# sudo apt install -y python3 python3-pip python3-venv

# # Define venv path
# VENV_PATH="/usr/lib/zabbix/externalscripts/venv"

# echo "[*] Ensuring clean Python virtual environment at $VENV_PATH..."

# # Remove broken or old venv
# if [[ -d "$VENV_PATH" ]]; then
#     echo "[!] Removing old venv at $VENV_PATH"
#     sudo rm -rf "$VENV_PATH"
# fi

# # Create new venv
# sudo mkdir -p $(dirname "$VENV_PATH")
# sudo python3 -m venv "$VENV_PATH"
# sudo chown -R $(whoami) "$VENV_PATH"

# echo "[✓] Virtual environment created."

# # Activate venv
# source "$VENV_PATH/bin/activate"

# # Install packages
# if [[ -f "requirements.txt" ]]; then
#     echo "[*] Installing packages from requirements.txt..."
#     pip install --upgrade pip
#     pip install -r requirements.txt
# else
#     echo "[!] requirements.txt not found. Installing essential packages manually..."
#     pip install --upgrade pip
#     pip install requests==2.31.0 GitPython==3.1.43
# fi

# # Make Python script executable
# if [[ -f "apt_update_v3.py" ]]; then
#     chmod +x apt_update_v3.py
#     echo "[✓] Made apt_update_v3.py executable."

#     echo "[*] Running apt_update_v3.py..."
#     python3 apt_update_v3.py
# else
#     echo "[✗] apt_update_v3.py not found!"
# fi

# # Optional: Make config executable
# if [[ -f "auto_update_config_v2.json" ]]; then
#     chmod +x auto_update_config_v2.json
#     echo "[✓] Made auto_update_config_v2.json executable."
# fi

# echo "[✔] Python environment setup complete."











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

