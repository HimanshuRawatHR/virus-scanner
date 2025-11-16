#!/bin/bash
# Setup script for Local VirusTotal

set -e

echo "========================================="
echo "  Local VirusTotal Setup"
echo "========================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check if Homebrew is installed (macOS)
if [[ "$OSTYPE" == "darwin"* ]]; then
    if ! command -v brew &> /dev/null; then
        echo -e "${YELLOW}Homebrew not found. Installing...${NC}"
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
fi

# Install system dependencies
echo -e "${GREEN}[1/5] Installing system dependencies...${NC}"

if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    brew install libmagic || true
    brew install clamav || true
    brew install yara || true
elif [[ -f /etc/debian_version ]]; then
    # Debian/Ubuntu
    sudo apt-get update
    sudo apt-get install -y libmagic1 clamav yara
elif [[ -f /etc/redhat-release ]]; then
    # RHEL/CentOS
    sudo yum install -y file-libs clamav yara
fi

# Create virtual environment
echo -e "${GREEN}[2/5] Creating Python virtual environment...${NC}"
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
echo -e "${GREEN}[3/5] Installing Python dependencies...${NC}"
pip install --upgrade pip
pip install -r requirements.txt

# Setup ClamAV database
echo -e "${GREEN}[4/5] Setting up ClamAV database...${NC}"
if command -v freshclam &> /dev/null; then
    echo "Updating ClamAV virus definitions..."

    # Create config if needed (macOS)
    if [[ "$OSTYPE" == "darwin"* ]]; then
        CLAMAV_CONFIG="/opt/homebrew/etc/clamav/freshclam.conf"
        if [[ -f "${CLAMAV_CONFIG}.sample" ]] && [[ ! -f "$CLAMAV_CONFIG" ]]; then
            sudo cp "${CLAMAV_CONFIG}.sample" "$CLAMAV_CONFIG"
            sudo sed -i '' 's/^Example/#Example/' "$CLAMAV_CONFIG"
        fi
    fi

    sudo freshclam || echo -e "${YELLOW}Warning: Could not update ClamAV database. You may need to run 'sudo freshclam' manually.${NC}"
else
    echo -e "${YELLOW}Warning: freshclam not found. ClamAV scanning will be unavailable.${NC}"
fi

# Make scanner executable
echo -e "${GREEN}[5/5] Making scanner executable...${NC}"
chmod +x scanner.py

# Create convenience wrapper
cat > scan << 'EOF'
#!/bin/bash
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$SCRIPT_DIR/venv/bin/activate"
python3 "$SCRIPT_DIR/scanner.py" "$@"
EOF
chmod +x scan

echo ""
echo "========================================="
echo -e "${GREEN}  Setup Complete!${NC}"
echo "========================================="
echo ""
echo "Usage:"
echo "  ./scan <file>                    # Basic scan"
echo "  ./scan -o report.json <file>     # Export to JSON"
echo "  ./scan --vt-api KEY <file>       # With VirusTotal lookup"
echo ""
echo "Or activate the environment and run directly:"
echo "  source venv/bin/activate"
echo "  python scanner.py <file>"
echo ""
echo "Optional: Set your VirusTotal API key:"
echo "  export VT_API_KEY='your-api-key'"
echo ""
