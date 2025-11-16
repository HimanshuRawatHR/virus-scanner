#!/usr/bin/env python3
"""
Secure Downloads - Quarantine-First Download Protection
Files are held in staging until scanned and verified safe
"""

import os
import sys
import time
import json
import shutil
import subprocess
from pathlib import Path
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scanner import LocalVirusTotal, Colors


class SecureDownloadHandler(FileSystemEventHandler):
    """
    Quarantine-first approach:
    1. Files download to STAGING folder (not Downloads)
    2. Each file is scanned immediately
    3. If SAFE -> moved to Downloads
    4. If MALICIOUS -> stays in quarantine with warning
    """

    def __init__(self, staging_dir=None, safe_dir=None, quarantine_dir=None, vt_api_key=None):
        self.staging_dir = staging_dir or os.path.expanduser("~/SecureDownloads/Staging")
        self.safe_dir = safe_dir or os.path.expanduser("~/Downloads")
        self.quarantine_dir = quarantine_dir or os.path.expanduser("~/SecureDownloads/Quarantine")
        self.vt_api_key = vt_api_key
        self.processing = set()  # Files currently being processed
        self.log_file = os.path.expanduser("~/local-virustotal/secure_downloads.log")

        # Create directories
        os.makedirs(self.staging_dir, exist_ok=True)
        os.makedirs(self.quarantine_dir, exist_ok=True)

        self._print_banner()

    def _print_banner(self):
        print(f"{Colors.CYAN}{Colors.BOLD}")
        print("=" * 60)
        print("  SECURE DOWNLOADS - Quarantine-First Protection")
        print("=" * 60)
        print(f"{Colors.END}")
        print(f"{Colors.GREEN}Staging Folder:    {self.staging_dir}{Colors.END}")
        print(f"{Colors.GREEN}Safe Downloads:    {self.safe_dir}{Colors.END}")
        print(f"{Colors.RED}Quarantine:        {self.quarantine_dir}{Colors.END}")
        print()
        print(f"{Colors.YELLOW}{Colors.BOLD}HOW IT WORKS:{Colors.END}")
        print(f"  1. Set your browser's download location to: {self.staging_dir}")
        print(f"  2. All downloads go to staging first")
        print(f"  3. Files are scanned BEFORE you can access them")
        print(f"  4. Safe files -> moved to {self.safe_dir}")
        print(f"  5. Malicious files -> quarantined (can't execute)")
        print()
        print(f"{Colors.CYAN}Press Ctrl+C to stop{Colors.END}\n")
        print(f"{Colors.YELLOW}Waiting for downloads...{Colors.END}\n")

    def send_notification(self, title, message, sound="default"):
        """Send macOS notification"""
        try:
            script = f'display notification "{message}" with title "{title}" sound name "{sound}"'
            subprocess.run(['osascript', '-e', script], capture_output=True, timeout=5)
        except Exception:
            pass

    def log_event(self, event_type, file_path, result, details=""):
        """Log scan events"""
        try:
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'event': event_type,
                'file': os.path.basename(file_path),
                'path': file_path,
                'result': result,
                'details': details
            }

            with open(self.log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception:
            pass

    def is_download_complete(self, file_path):
        """Check if file has finished downloading"""
        # Skip temporary download files
        temp_extensions = ['.crdownload', '.part', '.download', '.tmp', '.partial']
        if any(file_path.endswith(ext) for ext in temp_extensions):
            return False

        # Skip hidden files
        if os.path.basename(file_path).startswith('.'):
            return False

        # Check if file size is stable
        try:
            if not os.path.exists(file_path):
                return False

            size1 = os.path.getsize(file_path)
            time.sleep(1)

            if not os.path.exists(file_path):
                return False

            size2 = os.path.getsize(file_path)

            return size1 == size2 and size1 > 0
        except Exception:
            return False

    def process_file(self, file_path):
        """Process a downloaded file"""
        if file_path in self.processing:
            return

        if not self.is_download_complete(file_path):
            return

        self.processing.add(file_path)

        try:
            filename = os.path.basename(file_path)
            print(f"\n{Colors.BLUE}{Colors.BOLD}{'='*60}{Colors.END}")
            print(f"{Colors.BLUE}{Colors.BOLD}NEW DOWNLOAD: {filename}{Colors.END}")
            print(f"{Colors.BLUE}{Colors.BOLD}{'='*60}{Colors.END}")
            print(f"{Colors.YELLOW}File is in STAGING - scanning before release...{Colors.END}")

            # Send notification that scan is starting
            self.send_notification(
                "Scanning Download",
                f"Checking {filename} for threats...",
                "Pop"
            )

            # Perform scan
            scanner = LocalVirusTotal(vt_api_key=self.vt_api_key)
            results = scanner.scan_file(file_path)

            if 'error' in results:
                print(f"{Colors.RED}Scan error: {results['error']}{Colors.END}")
                self.processing.discard(file_path)
                return

            # Determine if file is safe
            is_safe = True
            threats = []

            # Check ClamAV
            if results.get('clamav', {}).get('status') == 'detected':
                is_safe = False
                threats.append(f"ClamAV: {results['clamav']['result']}")

            # Check YARA
            if results.get('yara', {}).get('status') == 'detected':
                is_safe = False
                threats.append(f"YARA: {', '.join(results['yara']['result'])}")

            # Check media analysis
            if results.get('media_analysis', {}).get('suspicious'):
                is_safe = False
                threats.extend(results['media_analysis'].get('findings', []))

            # Check VirusTotal if available
            if results.get('virustotal', {}).get('status') == 'found':
                if results['virustotal'].get('malicious', 0) > 0:
                    is_safe = False
                    threats.append(f"VirusTotal: {results['virustotal']['malicious']} detections")

            # Print results
            scanner.print_results()

            # Take action
            if is_safe:
                # Move to safe downloads folder
                safe_path = os.path.join(self.safe_dir, filename)

                # Handle filename conflicts
                if os.path.exists(safe_path):
                    base, ext = os.path.splitext(filename)
                    timestamp = datetime.now().strftime("%H%M%S")
                    safe_path = os.path.join(self.safe_dir, f"{base}_{timestamp}{ext}")

                shutil.move(file_path, safe_path)

                print(f"{Colors.GREEN}{Colors.BOLD}✓ FILE IS SAFE - Released to Downloads{Colors.END}")
                print(f"{Colors.GREEN}Location: {safe_path}{Colors.END}")

                self.send_notification(
                    "✓ Download Safe",
                    f"{filename} passed all security checks",
                    "Glass"
                )

                self.log_event('released', file_path, 'safe', f'Moved to {safe_path}')

            else:
                # Keep in quarantine
                quarantine_name = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}"
                quarantine_path = os.path.join(self.quarantine_dir, quarantine_name)

                shutil.move(file_path, quarantine_path)

                # Remove execute permissions
                os.chmod(quarantine_path, 0o400)

                print(f"\n{Colors.RED}{Colors.BOLD}{'='*60}{Colors.END}")
                print(f"{Colors.RED}{Colors.BOLD}⚠️  MALICIOUS FILE BLOCKED! ⚠️{Colors.END}")
                print(f"{Colors.RED}{Colors.BOLD}{'='*60}{Colors.END}")
                print(f"{Colors.RED}Threats found:{Colors.END}")
                for threat in threats:
                    print(f"  - {Colors.RED}{threat}{Colors.END}")
                print(f"\n{Colors.YELLOW}File quarantined: {quarantine_path}{Colors.END}")
                print(f"{Colors.YELLOW}The file CANNOT execute from quarantine{Colors.END}")

                self.send_notification(
                    "⚠️ MALWARE BLOCKED!",
                    f"{filename} was quarantined!\nThreats: {', '.join(threats[:2])}",
                    "Basso"
                )

                self.log_event('quarantined', file_path, 'malicious', '; '.join(threats))

            print(f"\n{Colors.CYAN}Waiting for next download...{Colors.END}")

        except Exception as e:
            print(f"{Colors.RED}Error processing file: {e}{Colors.END}")
        finally:
            self.processing.discard(file_path)

    def on_created(self, event):
        """Handle new file in staging"""
        if not event.is_directory:
            # Give file time to finish downloading
            time.sleep(2)
            self.process_file(event.src_path)

    def on_moved(self, event):
        """Handle file moves"""
        if not event.is_directory:
            time.sleep(2)
            self.process_file(event.dest_path)


def setup_secure_downloads():
    """Set up the secure downloads system"""
    staging_dir = os.path.expanduser("~/SecureDownloads/Staging")
    quarantine_dir = os.path.expanduser("~/SecureDownloads/Quarantine")

    os.makedirs(staging_dir, exist_ok=True)
    os.makedirs(quarantine_dir, exist_ok=True)

    print(f"{Colors.CYAN}{Colors.BOLD}")
    print("=" * 60)
    print("  SECURE DOWNLOADS SETUP")
    print("=" * 60)
    print(f"{Colors.END}")

    print(f"{Colors.YELLOW}To enable quarantine-first protection:{Colors.END}\n")

    print(f"{Colors.GREEN}1. Change your browser's download location to:{Colors.END}")
    print(f"   {Colors.BOLD}{staging_dir}{Colors.END}\n")

    print(f"{Colors.GREEN}2. For Safari:{Colors.END}")
    print(f"   Safari > Settings > General > File download location")
    print(f"   Select: {staging_dir}\n")

    print(f"{Colors.GREEN}3. For Chrome:{Colors.END}")
    print(f"   Settings > Downloads > Location")
    print(f"   Change to: {staging_dir}\n")

    print(f"{Colors.GREEN}4. For Firefox:{Colors.END}")
    print(f"   Settings > Files and Applications > Downloads")
    print(f"   Save files to: {staging_dir}\n")

    print(f"{Colors.GREEN}5. For WhatsApp Desktop:{Colors.END}")
    print(f"   Files are saved to Downloads by default")
    print(f"   The monitor will catch them there\n")

    print(f"{Colors.YELLOW}After setup, run:{Colors.END}")
    print(f"   ~/local-virustotal/start-secure.sh\n")

    print(f"{Colors.CYAN}This ensures NO file can execute until scanned!{Colors.END}")


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Secure Downloads - Quarantine-First Protection')
    parser.add_argument('--setup', action='store_true', help='Show setup instructions')
    parser.add_argument('--staging-dir', default=os.path.expanduser('~/SecureDownloads/Staging'),
                       help='Staging directory for downloads')
    parser.add_argument('--safe-dir', default=os.path.expanduser('~/Downloads'),
                       help='Directory for safe files')
    parser.add_argument('--quarantine-dir', default=os.path.expanduser('~/SecureDownloads/Quarantine'),
                       help='Quarantine directory')
    parser.add_argument('--vt-api', help='VirusTotal API key')

    args = parser.parse_args()

    if args.setup:
        setup_secure_downloads()
        return

    # Get API key from environment if not provided
    vt_api_key = args.vt_api or os.environ.get('VT_API_KEY')

    # Create directories
    os.makedirs(args.staging_dir, exist_ok=True)
    os.makedirs(args.quarantine_dir, exist_ok=True)

    # Create event handler
    handler = SecureDownloadHandler(
        staging_dir=args.staging_dir,
        safe_dir=args.safe_dir,
        quarantine_dir=args.quarantine_dir,
        vt_api_key=vt_api_key
    )

    # Also monitor Downloads folder for files from apps that can't change location
    observer = Observer()
    observer.schedule(handler, args.staging_dir, recursive=False)

    # Monitor regular Downloads too (for WhatsApp, email attachments, etc.)
    downloads_handler = SecureDownloadHandler(
        staging_dir=args.safe_dir,  # Watch Downloads folder
        safe_dir=args.safe_dir,  # Keep safe files there
        quarantine_dir=args.quarantine_dir,
        vt_api_key=vt_api_key
    )
    downloads_handler._print_banner = lambda: None  # Don't print banner twice

    observer.schedule(downloads_handler, args.safe_dir, recursive=False)

    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Stopping Secure Downloads...{Colors.END}")
        observer.stop()

    observer.join()
    print(f"{Colors.GREEN}Secure Downloads stopped.{Colors.END}")


if __name__ == '__main__':
    main()
