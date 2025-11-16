# Local VirusTotal

A powerful local file scanning tool that provides VirusTotal-like functionality directly on your system. Scan files for malware, detect hidden threats in images/videos, and protect downloads automatically.

## Features

- **Multi-Engine Scanning**
  - ClamAV antivirus integration (8.7M+ signatures)
  - YARA rules for pattern matching
  - VirusTotal API integration (optional)

- **File Analysis**
  - MD5, SHA1, SHA256 hash calculation
  - Entropy analysis (detect packed/encrypted files)
  - String extraction and analysis
  - Suspicious pattern detection (IPs, URLs, commands)

- **Media File Security**
  - Steganography detection in images
  - Embedded executable detection
  - EXIF metadata analysis
  - Polyglot file detection
  - Hidden data after file markers
  - Video/audio stream analysis

- **Real-Time Protection**
  - Auto-scan downloads from any source (browser, email, WhatsApp, etc.)
  - macOS desktop notifications
  - Automatic quarantine of malicious files
  - Quarantine-first mode (files can't execute until scanned)

## Installation

### Quick Install

```bash
git clone https://github.com/YOUR_USERNAME/local-virustotal.git
cd local-virustotal
./install.sh
```

### Manual Installation

1. **Clone the repository:**
```bash
git clone https://github.com/YOUR_USERNAME/local-virustotal.git
cd local-virustotal
```

2. **Install system dependencies (macOS):**
```bash
brew install libmagic clamav yara exiftool ffmpeg
```

3. **Set up Python environment:**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

4. **Configure ClamAV:**
```bash
cp /opt/homebrew/etc/clamav/freshclam.conf.sample /opt/homebrew/etc/clamav/freshclam.conf
sed -i '' 's/^Example/#Example/' /opt/homebrew/etc/clamav/freshclam.conf
sudo freshclam
```

5. **Make scripts executable:**
```bash
chmod +x scan start-monitor.sh start-secure.sh monitor-control.sh
```

## Usage

### Basic File Scanning

```bash
# Scan any file
./scan /path/to/file

# Scan with JSON output
./scan -o report.json /path/to/file

# Scan with VirusTotal lookup
./scan --vt-api YOUR_API_KEY /path/to/file

# Use custom YARA rules
./scan --yara-rules /path/to/rules.yar /path/to/file
```

### Auto-Scan Downloads (Recommended)

Monitor your Downloads folder and automatically scan new files:

```bash
# Start the monitor
./monitor-control.sh start

# Check status
./monitor-control.sh status

# View live logs
./monitor-control.sh log

# Stop monitoring
./monitor-control.sh stop

# Enable auto-start on login
./monitor-control.sh enable-autostart
```

### Quarantine-First Protection (Maximum Security)

Files are held in staging until verified safe:

1. **Set up staging folder:**
```bash
./start-secure.sh --setup
```

2. **Configure your browser's download location:**
   - Safari: Safari > Settings > General > File download location → `~/SecureDownloads/Staging`
   - Chrome: Settings > Downloads > Location → `~/SecureDownloads/Staging`
   - Firefox: Settings > Downloads > Save files to → `~/SecureDownloads/Staging`

3. **Start secure downloads:**
```bash
./start-secure.sh
```

**How it works:**
- Downloads go to Staging folder first
- Files are scanned immediately
- Safe files → moved to Downloads
- Malicious files → quarantined (can't execute)

### Managing Quarantine

```bash
# View quarantined files
./monitor-control.sh quarantine

# Clear quarantine (use with caution)
./monitor-control.sh clear-quarantine

# Manually check quarantine
ls -la ~/local-virustotal/quarantine/
# or
ls -la ~/SecureDownloads/Quarantine/
```

## Configuration

### VirusTotal API Key (Optional)

Get a free API key from [VirusTotal](https://www.virustotal.com/gui/my-apikey):

```bash
# Add to shell profile
echo 'export VT_API_KEY="your-api-key"' >> ~/.zshrc
source ~/.zshrc

# Or use directly
./scan --vt-api YOUR_KEY /path/to/file
```

### Custom YARA Rules

Create custom rules for specific threat detection:

```bash
./scan --yara-rules /path/to/custom_rules.yar /path/to/file
```

## What It Detects

### Executables & Scripts
- Malware signatures (ClamAV)
- Backdoors and shells
- Command injection patterns
- Encoded payloads (Base64)
- Suspicious system calls

### Images
- Steganography (hidden data in images)
- Embedded executables
- Malicious EXIF metadata
- Polyglot files (valid as multiple formats)
- Hidden data after file markers
- Extension mismatches

### Videos & Audio
- Suspicious metadata
- Hidden data streams
- Embedded attachments
- Malicious codec exploits

### Network Indicators
- Suspicious URLs
- IP addresses
- C2 server patterns
- Download/upload commands

## Example Output

```
============================================================
  LOCAL VIRUSTOTAL - File Analysis Report
============================================================

[*] Extracting file metadata...
[*] Calculating file hashes...
[*] Calculating file entropy...
[*] Scanning with ClamAV...
[*] Scanning with YARA rules...
[*] Analyzing strings...
[*] Analyzing image file for hidden threats...

============================================================
  SCAN RESULTS
============================================================

FILE INFORMATION:
  Name:        suspicious_image.jpg
  Size:        2.45 MB (2568432 bytes)
  Type:        JPEG image data
  MIME:        image/jpeg

FILE HASHES:
  MD5:         d41d8cd98f00b204e9800998ecf8427e
  SHA1:        da39a3ee5e6b4b0d3255bfef95601890afd80709
  SHA256:      e3b0c44298fc1c149afbf4c8996fb924...

ENTROPY ANALYSIS:
  Entropy:     7.9527 - High (possibly encrypted/packed)

SECURITY SCANS:
  ClamAV:      ✓ No threats detected
  YARA:        ✗ Matched rules: SuspiciousStrings, PotentialBackdoor

MEDIA FILE ANALYSIS (IMAGE):
  ✗ SUSPICIOUS CONTENT DETECTED:
    - Embedded Executable
    - Steganography Detection
  • Embedded Executable: Found suspicious signatures: MZ, #!/
  • Steganography Detection: Found F5 signature

============================================================
  ⚠️  WARNING: 2/3 engines detected threats!
============================================================

Scan completed in 3.45 seconds
```

## Project Structure

```
local-virustotal/
├── scanner.py              # Main scanning engine
├── media_scanner.py        # Image/video/audio analysis
├── monitor.py              # Downloads folder monitor
├── secure_downloads.py     # Quarantine-first protection
├── scan                    # CLI wrapper script
├── start-monitor.sh        # Start downloads monitor
├── start-secure.sh         # Start secure downloads
├── monitor-control.sh      # Monitor management
├── setup.sh                # Full setup script
├── install.sh              # Quick installer
├── requirements.txt        # Python dependencies
├── README.md               # This file
├── LICENSE                 # MIT License
└── .gitignore              # Git ignore rules
```

## Requirements

### System
- macOS (tested on macOS Sequoia)
- Python 3.8+
- Homebrew

### Dependencies
- libmagic - File type detection
- ClamAV - Antivirus engine
- YARA - Pattern matching
- exiftool - Metadata extraction
- ffmpeg - Media analysis

### Python Packages
- python-magic
- yara-python
- requests
- watchdog

## Limitations

- ClamAV requires periodic database updates (`sudo freshclam`)
- VirusTotal API has rate limits (free tier: 4 requests/minute)
- Large files may take longer to scan
- Some steganography techniques may not be detected
- macOS notifications require proper permissions

## Security Considerations

- This tool is for **defensive security purposes**
- Quarantined files have restricted permissions (read-only)
- Always keep ClamAV signatures updated
- Consider using with a VirusTotal API key for cloud verification
- Not a replacement for comprehensive endpoint protection

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [ClamAV](https://www.clamav.net/) - Open source antivirus engine
- [YARA](https://virustotal.github.io/yara/) - Pattern matching tool
- [VirusTotal](https://www.virustotal.com/) - Online malware scanning service
- [ExifTool](https://exiftool.org/) - Metadata extraction
- [FFmpeg](https://ffmpeg.org/) - Media processing

## Author

**Himanshu Rawat**

## Disclaimer

This tool is provided for educational and defensive security purposes only. The author is not responsible for any misuse of this software. Always ensure you have proper authorization before scanning files that don't belong to you.

---

**Stay safe! Scan before you trust.**
