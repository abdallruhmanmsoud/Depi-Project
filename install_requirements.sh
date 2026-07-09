#!/usr/bin/env bash
# ==============================================================================
# Forensic Dashboard - Requirements Installer
# This script installs all system prerequisites and Python dependencies.
# Target OS: Linux (Ubuntu/Debian)
# ==============================================================================

set -euo pipefail

# Ensure script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "Error: Please run this script with sudo or as root."
  exit 1
fi

echo "=== Updating Package Lists ==="
apt-get update -y

echo "=== Installing Core System Tools ==="
apt-get install -y \
  python3 \
  python3-pip \
  python3-venv \
  binutils \
  file \
  yara \
  tshark \
  tcpflow \
  sleuthkit \
  bulk-extractor \
  dc3dd \
  ewf-tools \
  mysql-client \
  percona-toolkit \
  postgresql-client \
  icoutils \
  upx-ucl \
  zeek || {
    echo "Warning: Some packages could not be installed directly via default apt repositories."
  }

# Plaso installation (requires custom gift PPA)
echo "=== Installing Plaso (log2timeline & psort) ==="
if ! command -v add-apt-repository &> /dev/null; then
  apt-get install -y software-properties-common
fi
add-apt-repository -y ppa:gift/stable
apt-get update -y
apt-get install -y plaso-tools || {
  echo "Warning: plaso-tools installation failed. You may need to install it manually."
}

# Python virtual environment and dependencies setup
echo "=== Setting up Python Dependencies ==="
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

# If requirements.txt exists, install python packages
if [ -f "requirements.txt" ]; then
  echo "Installing Python pip packages from requirements.txt..."
  pip3 install -r requirements.txt
else
  echo "Warning: requirements.txt not found."
fi

# Volatility 3 pip installation
echo "=== Installing Volatility 3 ==="
pip3 install volatility3 || {
  echo "Warning: volatility3 pip installation failed."
}

echo "=== Prerequisites Installation Complete! ==="
echo "All system tools and Python requirements have been installed."
echo "You can now run the dashboard with: python app.py"
