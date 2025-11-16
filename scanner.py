#!/usr/bin/env python3
"""
Local VirusTotal - A local file scanning tool similar to VirusTotal
Scans files using multiple methods: hashes, ClamAV, YARA, and metadata analysis
"""

import argparse
import hashlib
import json
import magic
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from media_scanner import MediaScanner, get_media_type
    MEDIA_SCANNER_AVAILABLE = True
except ImportError:
    MEDIA_SCANNER_AVAILABLE = False


class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'


class LocalVirusTotal:
    def __init__(self, vt_api_key: Optional[str] = None):
        self.vt_api_key = vt_api_key
        self.results = {}
        self.detections = 0
        self.total_engines = 0

    def calculate_hashes(self, file_path: str) -> Dict[str, str]:
        """Calculate MD5, SHA1, and SHA256 hashes of the file"""
        hashes = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256()
        }

        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    for h in hashes.values():
                        h.update(chunk)

            return {name: h.hexdigest() for name, h in hashes.items()}
        except Exception as e:
            return {'error': str(e)}

    def get_file_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract file metadata"""
        try:
            stat = os.stat(file_path)
            file_magic = magic.Magic(mime=True)
            file_type_magic = magic.Magic()

            return {
                'name': os.path.basename(file_path),
                'path': os.path.abspath(file_path),
                'size': stat.st_size,
                'size_human': self._human_size(stat.st_size),
                'mime_type': file_magic.from_file(file_path),
                'file_type': file_type_magic.from_file(file_path),
                'created': datetime.fromtimestamp(stat.st_birthtime).isoformat() if hasattr(stat, 'st_birthtime') else 'N/A',
                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'accessed': datetime.fromtimestamp(stat.st_atime).isoformat(),
                'permissions': oct(stat.st_mode)[-3:]
            }
        except Exception as e:
            return {'error': str(e)}

    def _human_size(self, size: int) -> str:
        """Convert bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} PB"

    def scan_with_clamav(self, file_path: str) -> Dict[str, Any]:
        """Scan file with ClamAV if installed"""
        try:
            result = subprocess.run(
                ['clamscan', '--no-summary', file_path],
                capture_output=True,
                text=True,
                timeout=60
            )

            self.total_engines += 1

            if result.returncode == 0:
                return {
                    'engine': 'ClamAV',
                    'status': 'clean',
                    'result': 'No threats detected'
                }
            elif result.returncode == 1:
                self.detections += 1
                # Extract malware name from output
                match = re.search(r': (.+) FOUND', result.stdout)
                threat = match.group(1) if match else 'Unknown threat'
                return {
                    'engine': 'ClamAV',
                    'status': 'detected',
                    'result': threat
                }
            else:
                return {
                    'engine': 'ClamAV',
                    'status': 'error',
                    'result': result.stderr.strip()
                }
        except FileNotFoundError:
            return {
                'engine': 'ClamAV',
                'status': 'not_installed',
                'result': 'ClamAV not installed. Install with: brew install clamav'
            }
        except subprocess.TimeoutExpired:
            return {
                'engine': 'ClamAV',
                'status': 'timeout',
                'result': 'Scan timeout exceeded'
            }
        except Exception as e:
            return {
                'engine': 'ClamAV',
                'status': 'error',
                'result': str(e)
            }

    def scan_with_yara(self, file_path: str, rules_path: Optional[str] = None) -> Dict[str, Any]:
        """Scan file with YARA rules"""
        if not YARA_AVAILABLE:
            return {
                'engine': 'YARA',
                'status': 'not_installed',
                'result': 'YARA not installed. Install with: pip install yara-python'
            }

        try:
            if rules_path and os.path.exists(rules_path):
                rules = yara.compile(filepath=rules_path)
            else:
                # Use built-in suspicious patterns
                rules = yara.compile(source=self._get_default_yara_rules())

            matches = rules.match(file_path)
            self.total_engines += 1

            if matches:
                self.detections += 1
                return {
                    'engine': 'YARA',
                    'status': 'detected',
                    'result': [str(match) for match in matches]
                }
            else:
                return {
                    'engine': 'YARA',
                    'status': 'clean',
                    'result': 'No suspicious patterns detected'
                }
        except Exception as e:
            return {
                'engine': 'YARA',
                'status': 'error',
                'result': str(e)
            }

    def _get_default_yara_rules(self) -> str:
        """Default YARA rules for common malware patterns"""
        return '''
rule SuspiciousStrings {
    strings:
        $s1 = "cmd.exe" nocase
        $s2 = "powershell" nocase
        $s3 = "wget" nocase
        $s4 = "curl" nocase
        $s5 = "/etc/passwd"
        $s6 = "/etc/shadow"
        $s7 = "eval(" nocase
        $s8 = "exec(" nocase
        $s9 = "base64_decode" nocase
        $s10 = "system(" nocase
    condition:
        3 of them
}

rule PotentialBackdoor {
    strings:
        $net1 = "socket" nocase
        $net2 = "connect" nocase
        $net3 = "bind" nocase
        $cmd1 = "shell" nocase
        $cmd2 = "command" nocase
    condition:
        2 of ($net*) and 1 of ($cmd*)
}

rule EncryptedPayload {
    strings:
        $enc1 = { 4D 5A }  // PE header
        $enc2 = "AES" nocase
        $enc3 = "RSA" nocase
        $enc4 = "decrypt" nocase
    condition:
        $enc1 at 0 and 2 of ($enc2, $enc3, $enc4)
}
'''

    def analyze_strings(self, file_path: str) -> Dict[str, Any]:
        """Extract and analyze strings from the file"""
        try:
            result = subprocess.run(
                ['strings', '-n', '8', file_path],
                capture_output=True,
                text=True,
                timeout=30
            )

            strings = result.stdout.strip().split('\n')

            # Look for suspicious patterns
            suspicious = {
                'urls': [],
                'ips': [],
                'emails': [],
                'suspicious_commands': [],
                'base64_strings': []
            }

            url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
            ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
            email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
            base64_pattern = re.compile(r'^[A-Za-z0-9+/]{50,}={0,2}$')

            suspicious_cmds = ['cmd', 'powershell', 'bash', 'sh', 'python', 'perl', 'ruby', 'nc', 'netcat']

            for s in strings[:1000]:  # Limit to first 1000 strings
                if url_pattern.search(s):
                    suspicious['urls'].append(s.strip())
                if ip_pattern.search(s):
                    suspicious['ips'].append(ip_pattern.findall(s)[0])
                if email_pattern.search(s):
                    suspicious['emails'].append(email_pattern.findall(s)[0])
                if base64_pattern.match(s.strip()):
                    suspicious['base64_strings'].append(s.strip()[:100] + '...')
                for cmd in suspicious_cmds:
                    if cmd in s.lower():
                        suspicious['suspicious_commands'].append(s.strip()[:100])
                        break

            # Remove duplicates
            for key in suspicious:
                suspicious[key] = list(set(suspicious[key]))[:20]  # Limit to 20 items

            return {
                'total_strings': len(strings),
                'suspicious_findings': suspicious
            }
        except Exception as e:
            return {'error': str(e)}

    def check_virustotal(self, file_hash: str) -> Dict[str, Any]:
        """Check file hash against VirusTotal API"""
        if not self.vt_api_key:
            return {
                'status': 'no_api_key',
                'result': 'No VirusTotal API key provided. Get one at https://www.virustotal.com/gui/my-apikey'
            }

        if not REQUESTS_AVAILABLE:
            return {
                'status': 'not_installed',
                'result': 'requests library not installed. Install with: pip install requests'
            }

        try:
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            headers = {'x-apikey': self.vt_api_key}

            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                return {
                    'status': 'found',
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'undetected': stats.get('undetected', 0),
                    'harmless': stats.get('harmless', 0),
                    'total': sum(stats.values()),
                    'permalink': f"https://www.virustotal.com/gui/file/{file_hash}"
                }
            elif response.status_code == 404:
                return {
                    'status': 'not_found',
                    'result': 'File not found in VirusTotal database'
                }
            else:
                return {
                    'status': 'error',
                    'result': f"API error: {response.status_code}"
                }
        except Exception as e:
            return {
                'status': 'error',
                'result': str(e)
            }

    def entropy_analysis(self, file_path: str) -> float:
        """Calculate file entropy to detect packed/encrypted files"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()

            if len(data) == 0:
                return 0.0

            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1

            entropy = 0.0
            for count in byte_counts:
                if count > 0:
                    p = count / len(data)
                    entropy -= p * (p and (p > 0 and __import__('math').log2(p) or 0))

            return round(entropy, 4)
        except Exception as e:
            return -1.0

    def scan_file(self, file_path: str, yara_rules: Optional[str] = None) -> Dict[str, Any]:
        """Perform complete file scan"""
        if not os.path.exists(file_path):
            return {'error': f'File not found: {file_path}'}

        if not os.path.isfile(file_path):
            return {'error': f'Not a file: {file_path}'}

        print(f"\n{Colors.CYAN}{Colors.BOLD}{'='*60}{Colors.END}")
        print(f"{Colors.CYAN}{Colors.BOLD}  LOCAL VIRUSTOTAL - File Analysis Report{Colors.END}")
        print(f"{Colors.CYAN}{Colors.BOLD}{'='*60}{Colors.END}\n")

        # File metadata
        print(f"{Colors.BLUE}{Colors.BOLD}[*] Extracting file metadata...{Colors.END}")
        metadata = self.get_file_metadata(file_path)
        self.results['metadata'] = metadata

        # Hashes
        print(f"{Colors.BLUE}{Colors.BOLD}[*] Calculating file hashes...{Colors.END}")
        hashes = self.calculate_hashes(file_path)
        self.results['hashes'] = hashes

        # Entropy
        print(f"{Colors.BLUE}{Colors.BOLD}[*] Calculating file entropy...{Colors.END}")
        entropy = self.entropy_analysis(file_path)
        self.results['entropy'] = entropy

        # ClamAV scan
        print(f"{Colors.BLUE}{Colors.BOLD}[*] Scanning with ClamAV...{Colors.END}")
        clamav_result = self.scan_with_clamav(file_path)
        self.results['clamav'] = clamav_result

        # YARA scan
        print(f"{Colors.BLUE}{Colors.BOLD}[*] Scanning with YARA rules...{Colors.END}")
        yara_result = self.scan_with_yara(file_path, yara_rules)
        self.results['yara'] = yara_result

        # String analysis
        print(f"{Colors.BLUE}{Colors.BOLD}[*] Analyzing strings...{Colors.END}")
        strings_result = self.analyze_strings(file_path)
        self.results['strings'] = strings_result

        # Media file analysis (images, videos, audio)
        if MEDIA_SCANNER_AVAILABLE:
            media_type = get_media_type(file_path)
            if media_type != 'unknown':
                print(f"{Colors.BLUE}{Colors.BOLD}[*] Analyzing {media_type} file for hidden threats...{Colors.END}")
                media_scanner = MediaScanner()
                if media_type == 'image':
                    media_result = media_scanner.scan_image(file_path)
                elif media_type == 'video':
                    media_result = media_scanner.scan_video(file_path)
                elif media_type == 'audio':
                    media_result = media_scanner.scan_audio(file_path)
                else:
                    media_result = None

                if media_result:
                    self.results['media_analysis'] = media_result
                    if media_result.get('suspicious'):
                        self.detections += 1
                        self.total_engines += 1

        # VirusTotal check
        if self.vt_api_key and 'sha256' in hashes:
            print(f"{Colors.BLUE}{Colors.BOLD}[*] Checking VirusTotal database...{Colors.END}")
            vt_result = self.check_virustotal(hashes['sha256'])
            self.results['virustotal'] = vt_result

        return self.results

    def print_results(self):
        """Print formatted scan results"""
        print(f"\n{Colors.WHITE}{Colors.BOLD}{'='*60}{Colors.END}")
        print(f"{Colors.WHITE}{Colors.BOLD}  SCAN RESULTS{Colors.END}")
        print(f"{Colors.WHITE}{Colors.BOLD}{'='*60}{Colors.END}\n")

        # Metadata
        if 'metadata' in self.results:
            print(f"{Colors.YELLOW}{Colors.BOLD}FILE INFORMATION:{Colors.END}")
            meta = self.results['metadata']
            print(f"  Name:        {meta.get('name', 'N/A')}")
            print(f"  Path:        {meta.get('path', 'N/A')}")
            print(f"  Size:        {meta.get('size_human', 'N/A')} ({meta.get('size', 0)} bytes)")
            print(f"  Type:        {meta.get('file_type', 'N/A')}")
            print(f"  MIME:        {meta.get('mime_type', 'N/A')}")
            print(f"  Modified:    {meta.get('modified', 'N/A')}")
            print()

        # Hashes
        if 'hashes' in self.results:
            print(f"{Colors.YELLOW}{Colors.BOLD}FILE HASHES:{Colors.END}")
            hashes = self.results['hashes']
            print(f"  MD5:         {hashes.get('md5', 'N/A')}")
            print(f"  SHA1:        {hashes.get('sha1', 'N/A')}")
            print(f"  SHA256:      {hashes.get('sha256', 'N/A')}")
            print()

        # Entropy
        if 'entropy' in self.results:
            entropy = self.results['entropy']
            entropy_color = Colors.GREEN
            entropy_note = "Normal"
            if entropy > 7.5:
                entropy_color = Colors.RED
                entropy_note = "High (possibly encrypted/packed)"
            elif entropy > 6.5:
                entropy_color = Colors.YELLOW
                entropy_note = "Medium-High"

            print(f"{Colors.YELLOW}{Colors.BOLD}ENTROPY ANALYSIS:{Colors.END}")
            print(f"  Entropy:     {entropy_color}{entropy}{Colors.END} - {entropy_note}")
            print()

        # Security Scans
        print(f"{Colors.YELLOW}{Colors.BOLD}SECURITY SCANS:{Colors.END}")

        # ClamAV
        if 'clamav' in self.results:
            clam = self.results['clamav']
            status_color = Colors.GREEN if clam['status'] == 'clean' else Colors.RED if clam['status'] == 'detected' else Colors.YELLOW
            status_icon = '✓' if clam['status'] == 'clean' else '✗' if clam['status'] == 'detected' else '?'
            print(f"  ClamAV:      {status_color}{status_icon} {clam['result']}{Colors.END}")

        # YARA
        if 'yara' in self.results:
            yara_res = self.results['yara']
            status_color = Colors.GREEN if yara_res['status'] == 'clean' else Colors.RED if yara_res['status'] == 'detected' else Colors.YELLOW
            status_icon = '✓' if yara_res['status'] == 'clean' else '✗' if yara_res['status'] == 'detected' else '?'

            if yara_res['status'] == 'detected':
                print(f"  YARA:        {status_color}{status_icon} Matched rules: {', '.join(yara_res['result'])}{Colors.END}")
            else:
                print(f"  YARA:        {status_color}{status_icon} {yara_res['result']}{Colors.END}")
        print()

        # VirusTotal
        if 'virustotal' in self.results:
            vt = self.results['virustotal']
            print(f"{Colors.YELLOW}{Colors.BOLD}VIRUSTOTAL CHECK:{Colors.END}")
            if vt['status'] == 'found':
                detection_rate = f"{vt['malicious']}/{vt['total']}"
                if vt['malicious'] > 0:
                    print(f"  {Colors.RED}✗ MALICIOUS: {detection_rate} security vendors flagged this file{Colors.END}")
                else:
                    print(f"  {Colors.GREEN}✓ CLEAN: {detection_rate} security vendors flagged this file{Colors.END}")
                print(f"  Suspicious:  {vt['suspicious']}")
                print(f"  Harmless:    {vt['harmless']}")
                print(f"  Undetected:  {vt['undetected']}")
                print(f"  Link:        {vt['permalink']}")
            else:
                print(f"  {Colors.YELLOW}{vt.get('result', 'Unknown status')}{Colors.END}")
            print()

        # String Analysis
        if 'strings' in self.results and 'suspicious_findings' in self.results['strings']:
            findings = self.results['strings']['suspicious_findings']
            has_findings = any(findings.values())

            if has_findings:
                print(f"{Colors.YELLOW}{Colors.BOLD}SUSPICIOUS STRINGS:{Colors.END}")

                if findings['urls']:
                    print(f"  {Colors.RED}URLs found ({len(findings['urls'])}):{Colors.END}")
                    for url in findings['urls'][:5]:
                        print(f"    - {url}")

                if findings['ips']:
                    print(f"  {Colors.RED}IP addresses ({len(findings['ips'])}):{Colors.END}")
                    for ip in findings['ips'][:5]:
                        print(f"    - {ip}")

                if findings['suspicious_commands']:
                    print(f"  {Colors.RED}Suspicious commands ({len(findings['suspicious_commands'])}):{Colors.END}")
                    for cmd in findings['suspicious_commands'][:5]:
                        print(f"    - {cmd[:80]}")

                if findings['base64_strings']:
                    print(f"  {Colors.YELLOW}Base64 strings ({len(findings['base64_strings'])}):{Colors.END}")
                    for b64 in findings['base64_strings'][:3]:
                        print(f"    - {b64[:60]}...")
                print()

        # Media Analysis
        if 'media_analysis' in self.results:
            media = self.results['media_analysis']
            print(f"{Colors.YELLOW}{Colors.BOLD}MEDIA FILE ANALYSIS ({media.get('type', 'unknown').upper()}):{Colors.END}")

            if media.get('suspicious'):
                print(f"  {Colors.RED}✗ SUSPICIOUS CONTENT DETECTED:{Colors.END}")
                for finding in media.get('findings', []):
                    print(f"    - {Colors.RED}{finding}{Colors.END}")
            else:
                print(f"  {Colors.GREEN}✓ No hidden threats detected{Colors.END}")

            # Show detailed check results
            for check in media.get('checks', []):
                if check.get('suspicious'):
                    print(f"  {Colors.RED}• {check['name']}: {check.get('details', '')}{Colors.END}")
                elif 'not installed' in check.get('details', ''):
                    print(f"  {Colors.YELLOW}• {check['name']}: {check.get('details', '')}{Colors.END}")
            print()

        # Overall verdict
        print(f"{Colors.WHITE}{Colors.BOLD}{'='*60}{Colors.END}")
        if self.detections > 0:
            print(f"{Colors.RED}{Colors.BOLD}  ⚠️  WARNING: {self.detections}/{self.total_engines} engines detected threats!{Colors.END}")
        else:
            print(f"{Colors.GREEN}{Colors.BOLD}  ✓  File appears clean ({self.total_engines} engines checked){Colors.END}")
        print(f"{Colors.WHITE}{Colors.BOLD}{'='*60}{Colors.END}\n")

    def export_json(self, output_file: str):
        """Export results to JSON file"""
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        print(f"{Colors.GREEN}Results exported to: {output_file}{Colors.END}")


def main():
    parser = argparse.ArgumentParser(
        description='Local VirusTotal - Scan files for malware locally',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s /path/to/suspicious/file
  %(prog)s -o report.json /path/to/file
  %(prog)s --vt-api YOUR_API_KEY /path/to/file
  %(prog)s --yara-rules /path/to/rules.yar /path/to/file
        '''
    )

    parser.add_argument('file', help='File to scan')
    parser.add_argument('-o', '--output', help='Export results to JSON file')
    parser.add_argument('--vt-api', help='VirusTotal API key for online lookup')
    parser.add_argument('--yara-rules', help='Path to custom YARA rules file')
    parser.add_argument('--json', action='store_true', help='Output results as JSON only')

    args = parser.parse_args()

    # Check for API key in environment
    vt_api_key = args.vt_api or os.environ.get('VT_API_KEY')

    scanner = LocalVirusTotal(vt_api_key=vt_api_key)

    start_time = time.time()
    results = scanner.scan_file(args.file, args.yara_rules)
    scan_time = time.time() - start_time

    if 'error' in results:
        print(f"{Colors.RED}Error: {results['error']}{Colors.END}")
        sys.exit(1)

    if args.json:
        print(json.dumps(results, indent=2, default=str))
    else:
        scanner.print_results()
        print(f"{Colors.CYAN}Scan completed in {scan_time:.2f} seconds{Colors.END}")

    if args.output:
        scanner.export_json(args.output)


if __name__ == '__main__':
    main()
