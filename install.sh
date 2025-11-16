#!/bin/bash
# Quick Install Script for Local VirusTotal
# One-command installation for macOS

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo "=============================================="
echo "   Virus Scanner - Quick Installer"
echo "=============================================="
echo -e "${NC}"

# Check for macOS
if [[ "$OSTYPE" != "darwin"* ]]; then
    echo -e "${RED}This installer is for macOS only.${NC}"
    echo "For Linux, please follow manual installation in README.md"
    exit 1
fi

# Check for Homebrew
echo -e "${GREEN}[1/7] Checking Homebrew...${NC}"
if ! command -v brew &> /dev/null; then
    echo -e "${YELLOW}Installing Homebrew...${NC}"
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi

# Install system dependencies
echo -e "${GREEN}[2/7] Installing system dependencies...${NC}"
brew install libmagic clamav yara exiftool ffmpeg 2>/dev/null || true

# Set up Python virtual environment
echo -e "${GREEN}[3/7] Setting up Python environment...${NC}"
python3 -m venv venv
source venv/bin/activate

# Install Python packages
echo -e "${GREEN}[4/7] Installing Python packages...${NC}"
pip install --upgrade pip > /dev/null
pip install -r requirements.txt > /dev/null

# Configure ClamAV
echo -e "${GREEN}[5/7] Configuring ClamAV...${NC}"
FRESHCLAM_CONF="/opt/homebrew/etc/clamav/freshclam.conf"
FRESHCLAM_SAMPLE="/opt/homebrew/etc/clamav/freshclam.conf.sample"

if [[ -f "$FRESHCLAM_SAMPLE" ]] && [[ ! -f "$FRESHCLAM_CONF" ]]; then
    cp "$FRESHCLAM_SAMPLE" "$FRESHCLAM_CONF"
    sed -i '' 's/^Example/#Example/' "$FRESHCLAM_CONF"
fi

echo -e "${YELLOW}Downloading virus definitions (this may take a minute)...${NC}"
freshclam 2>/dev/null || echo -e "${YELLOW}Note: Run 'sudo freshclam' if this failed${NC}"

# Make scripts executable
echo -e "${GREEN}[6/7] Setting up scripts...${NC}"
chmod +x scan start-monitor.sh start-secure.sh monitor-control.sh scanner.py monitor.py secure_downloads.py media_scanner.py

# Create secure download directories
echo -e "${GREEN}[7/7] Creating secure directories...${NC}"
mkdir -p ~/SecureDownloads/Staging
mkdir -p ~/SecureDownloads/Quarantine
mkdir -p quarantine

echo ""
echo -e "${CYAN}=============================================="
echo -e "   Installation Complete!"
echo -e "==============================================${NC}"
echo ""
echo -e "${GREEN}Quick Start:${NC}"
echo ""
echo "  1. Scan a file:"
echo -e "     ${YELLOW}./scan /path/to/file${NC}"
echo ""
echo "  2. Start auto-scanning downloads:"
echo -e "     ${YELLOW}./monitor-control.sh start${NC}"
echo ""
echo "  3. For maximum security (quarantine-first):"
echo -e "     ${YELLOW}./start-secure.sh --setup${NC}"
echo ""
echo -e "${GREEN}Optional: Add to PATH for global access${NC}"
echo "  echo 'export PATH=\"\$HOME/local-virustotal:\$PATH\"' >> ~/.zshrc"
echo "  source ~/.zshrc"
echo ""
echo -e "${GREEN}Optional: Set VirusTotal API key${NC}"
echo "  Get free key: https://www.virustotal.com/gui/my-apikey"
echo "  echo 'export VT_API_KEY=\"your-key\"' >> ~/.zshrc"
echo ""
echo -e "${CYAN}Stay safe! Scan before you trust.${NC}"
