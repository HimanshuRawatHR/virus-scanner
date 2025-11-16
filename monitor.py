#!/usr/bin/env python3
"""
Downloads Folder Monitor - Auto-scans new files for malware
Monitors ~/Downloads and scans any new file automatically
"""

import os
import sys
import time
import json
import subprocess
from pathlib import Path
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scanner import LocalVirusTotal, Colors


class DownloadMonitor(FileSystemEventHandler):
    def __init__(self, quarantine_dir=None, vt_api_key=None):
        self.quarantine_dir = quarantine_dir or os.path.expanduser("~/local-virustotal/quarantine")
        self.vt_api_key = vt_api_key
        self.scanned_files = set()
        self.log_file = os.path.expanduser("~/local-virustotal/scan_log.json")

        # Create quarantine directory
        os.makedirs(self.quarantine_dir, exist_ok=True)

        # Load scan history
        self.load_history()

        print(f"{Colors.CYAN}{Colors.BOLD}")
        print("=" * 60)
        print("  LOCAL VIRUSTOTAL - Download Monitor Active")
        print("=" * 60)
        print(f"{Colors.END}")
        print(f"{Colors.GREEN}Monitoring: ~/Downloads{Colors.END}")
        print(f"{Colors.GREEN}Quarantine: {self.quarantine_dir}{Colors.END}")
        print(f"{Colors.YELLOW}All new downloads will be automatically scanned{Colors.END}")
        print(f"{Colors.CYAN}Press Ctrl+C to stop monitoring{Colors.END}\n")

    def load_history(self):
        """Load scan history to avoid re-scanning"""
        try:
            if os.path.exists(self.log_file):
                with open(self.log_file, 'r') as f:
                    data = json.load(f)
                    self.scanned_files = set(data.get('scanned_files', []))
        except:
            self.scanned_files = set()

    def save_history(self):
        """Save scan history"""
        try:
            with open(self.log_file, 'w') as f:
                json.dump({
                    'scanned_files': list(self.scanned_files),
                    'last_updated': datetime.now().isoformat()
                }, f, indent=2)
        except Exception as e:
            print(f"{Colors.RED}Error saving history: {e}{Colors.END}")

    def send_notification(self, title, message, sound="default"):
        """Send macOS notification"""
        try:
            # Use osascript for macOS notifications
            script = f'''
            display notification "{message}" with title "{title}" sound name "{sound}"
            '''
            subprocess.run(['osascript', '-e', script], capture_output=True, timeout=5)
        except Exception as e:
            print(f"{Colors.YELLOW}Could not send notification: {e}{Colors.END}")

    def quarantine_file(self, file_path):
        """Move malicious file to quarantine"""
        try:
            filename = os.path.basename(file_path)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            quarantine_name = f"{timestamp}_{filename}"
            quarantine_path = os.path.join(self.quarantine_dir, quarantine_name)

            # Move file to quarantine
            os.rename(file_path, quarantine_path)

            # Remove execute permissions
            os.chmod(quarantine_path, 0o400)

            return quarantine_path
        except Exception as e:
            print(f"{Colors.RED}Error quarantining file: {e}{Colors.END}")
            return None

    def scan_file(self, file_path):
        """Scan a file and take action if malicious"""
        # Skip if already scanned
        if file_path in self.scanned_files:
            return

        # Skip temporary/partial downloads
        if file_path.endswith('.crdownload') or file_path.endswith('.part') or file_path.endswith('.download'):
            return

        # Skip hidden files
        if os.path.basename(file_path).startswith('.'):
            return

        # Wait a moment for file to finish writing
        time.sleep(1)

        # Check if file still exists and is complete
        if not os.path.exists(file_path):
            return

        # Skip if file is still being written
        try:
            initial_size = os.path.getsize(file_path)
            time.sleep(0.5)
            if os.path.getsize(file_path) != initial_size:
                # File still downloading, will catch it when complete
                return
        except:
            return

        print(f"\n{Colors.BLUE}{Colors.BOLD}[NEW DOWNLOAD DETECTED]{Colors.END}")
        print(f"{Colors.CYAN}File: {os.path.basename(file_path)}{Colors.END}")
        print(f"{Colors.YELLOW}Scanning...{Colors.END}")

        # Perform scan
        scanner = LocalVirusTotal(vt_api_key=self.vt_api_key)
        results = scanner.scan_file(file_path)

        if 'error' in results:
            print(f"{Colors.RED}Scan error: {results['error']}{Colors.END}")
            return

        # Mark as scanned
        self.scanned_files.add(file_path)
        self.save_history()

        # Check for threats
        is_malicious = False
        threats = []

        # Check ClamAV result
        if 'clamav' in results and results['clamav'].get('status') == 'detected':
            is_malicious = True
            threats.append(f"ClamAV: {results['clamav']['result']}")

        # Check YARA result
        if 'yara' in results and results['yara'].get('status') == 'detected':
            is_malicious = True
            threats.append(f"YARA: {', '.join(results['yara']['result'])}")

        # Check entropy (high entropy can indicate packed malware)
        if 'entropy' in results and results['entropy'] > 7.8:
            # Only flag as suspicious if combined with other factors
            if any(key in str(results.get('strings', {})) for key in ['eval', 'exec', 'system', 'shell']):
                threats.append("High entropy with suspicious strings")

        # Print results
        scanner.print_results()

        # Take action based on results
        if is_malicious:
            print(f"\n{Colors.RED}{Colors.BOLD}⚠️  MALICIOUS FILE DETECTED! ⚠️{Colors.END}")
            print(f"{Colors.RED}Threats: {', '.join(threats)}{Colors.END}")

            # Send alert notification
            self.send_notification(
                "⚠️ MALWARE DETECTED!",
                f"File: {os.path.basename(file_path)}\nThreats: {', '.join(threats)}",
                "Basso"
            )

            # Quarantine the file
            quarantine_path = self.quarantine_file(file_path)
            if quarantine_path:
                print(f"{Colors.YELLOW}File quarantined: {quarantine_path}{Colors.END}")
                self.send_notification(
                    "File Quarantined",
                    f"{os.path.basename(file_path)} moved to quarantine",
                    "Purr"
                )
            else:
                print(f"{Colors.RED}WARNING: Could not quarantine file!{Colors.END}")
                print(f"{Colors.RED}Please delete manually: {file_path}{Colors.END}")
        else:
            print(f"{Colors.GREEN}{Colors.BOLD}✓ File appears safe{Colors.END}")
            # Send safe notification
            self.send_notification(
                "✓ Download Scanned",
                f"{os.path.basename(file_path)} - No threats detected",
                "Pop"
            )

        print(f"\n{Colors.CYAN}Continuing to monitor downloads...{Colors.END}")

    def on_created(self, event):
        """Handle new file creation"""
        if not event.is_directory:
            self.scan_file(event.src_path)

    def on_moved(self, event):
        """Handle file moves (some downloads move from temp location)"""
        if not event.is_directory:
            self.scan_file(event.dest_path)


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Monitor Downloads folder for new files and scan them')
    parser.add_argument('--watch-dir', default=os.path.expanduser('~/Downloads'),
                       help='Directory to monitor (default: ~/Downloads)')
    parser.add_argument('--quarantine-dir', default=os.path.expanduser('~/local-virustotal/quarantine'),
                       help='Directory for quarantined files')
    parser.add_argument('--vt-api', help='VirusTotal API key')
    parser.add_argument('--scan-existing', action='store_true',
                       help='Scan all existing files in the directory first')

    args = parser.parse_args()

    # Get API key from environment if not provided
    vt_api_key = args.vt_api or os.environ.get('VT_API_KEY')

    # Create event handler
    event_handler = DownloadMonitor(
        quarantine_dir=args.quarantine_dir,
        vt_api_key=vt_api_key
    )

    # Scan existing files if requested
    if args.scan_existing:
        print(f"{Colors.YELLOW}Scanning existing files in {args.watch_dir}...{Colors.END}\n")
        for item in os.listdir(args.watch_dir):
            file_path = os.path.join(args.watch_dir, item)
            if os.path.isfile(file_path):
                event_handler.scan_file(file_path)

    # Set up file system observer
    observer = Observer()
    observer.schedule(event_handler, args.watch_dir, recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Stopping monitor...{Colors.END}")
        observer.stop()

    observer.join()
    print(f"{Colors.GREEN}Monitor stopped.{Colors.END}")


if __name__ == '__main__':
    main()
