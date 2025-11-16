#!/usr/bin/env python3
"""
Media File Scanner - Analyzes images, videos, and audio files for hidden threats
Detects steganography, malicious metadata, embedded executables, and more
"""

import os
import struct
import subprocess
from typing import Dict, Any, List


class MediaScanner:
    """Scanner for images, videos, and audio files"""

    def __init__(self):
        self.suspicious_findings = []

    def scan_image(self, file_path: str) -> Dict[str, Any]:
        """Analyze image files for hidden threats"""
        results = {
            'type': 'image',
            'checks': [],
            'suspicious': False,
            'findings': []
        }

        # Check file extension vs actual content
        results['checks'].append(self._check_extension_mismatch(file_path))

        # Check for embedded executables
        results['checks'].append(self._check_embedded_executable(file_path))

        # Check EXIF metadata
        results['checks'].append(self._check_exif_metadata(file_path))

        # Check for steganography indicators
        results['checks'].append(self._check_steganography(file_path))

        # Check for polyglot files (files that are valid as multiple formats)
        results['checks'].append(self._check_polyglot(file_path))

        # Check for trailing data after image end
        results['checks'].append(self._check_trailing_data(file_path))

        # Aggregate findings
        for check in results['checks']:
            if check.get('suspicious'):
                results['suspicious'] = True
                results['findings'].append(check['name'])

        return results

    def scan_video(self, file_path: str) -> Dict[str, Any]:
        """Analyze video files for hidden threats"""
        results = {
            'type': 'video',
            'checks': [],
            'suspicious': False,
            'findings': []
        }

        # Check file extension vs actual content
        results['checks'].append(self._check_extension_mismatch(file_path))

        # Check for embedded executables
        results['checks'].append(self._check_embedded_executable(file_path))

        # Check video metadata
        results['checks'].append(self._check_video_metadata(file_path))

        # Check for suspicious streams
        results['checks'].append(self._check_video_streams(file_path))

        # Check for polyglot files
        results['checks'].append(self._check_polyglot(file_path))

        # Aggregate findings
        for check in results['checks']:
            if check.get('suspicious'):
                results['suspicious'] = True
                results['findings'].append(check['name'])

        return results

    def scan_audio(self, file_path: str) -> Dict[str, Any]:
        """Analyze audio files for hidden threats"""
        results = {
            'type': 'audio',
            'checks': [],
            'suspicious': False,
            'findings': []
        }

        # Check file extension vs actual content
        results['checks'].append(self._check_extension_mismatch(file_path))

        # Check for embedded executables
        results['checks'].append(self._check_embedded_executable(file_path))

        # Check audio metadata (ID3 tags, etc.)
        results['checks'].append(self._check_audio_metadata(file_path))

        # Check for polyglot files
        results['checks'].append(self._check_polyglot(file_path))

        # Aggregate findings
        for check in results['checks']:
            if check.get('suspicious'):
                results['suspicious'] = True
                results['findings'].append(check['name'])

        return results

    def _check_extension_mismatch(self, file_path: str) -> Dict[str, Any]:
        """Check if file extension matches actual file type"""
        try:
            import magic
            mime = magic.Magic(mime=True)
            actual_type = mime.from_file(file_path)
            extension = os.path.splitext(file_path)[1].lower()

            # Map extensions to expected MIME types
            extension_map = {
                '.jpg': ['image/jpeg'],
                '.jpeg': ['image/jpeg'],
                '.png': ['image/png'],
                '.gif': ['image/gif'],
                '.bmp': ['image/bmp', 'image/x-ms-bmp'],
                '.webp': ['image/webp'],
                '.mp4': ['video/mp4'],
                '.avi': ['video/x-msvideo'],
                '.mov': ['video/quicktime'],
                '.mkv': ['video/x-matroska'],
                '.webm': ['video/webm'],
                '.mp3': ['audio/mpeg'],
                '.wav': ['audio/x-wav', 'audio/wav'],
                '.flac': ['audio/flac'],
                '.ogg': ['audio/ogg'],
                '.m4a': ['audio/mp4', 'audio/x-m4a'],
            }

            expected_types = extension_map.get(extension, [])

            if expected_types and actual_type not in expected_types:
                return {
                    'name': 'Extension Mismatch',
                    'suspicious': True,
                    'details': f"File claims to be {extension} but is actually {actual_type}"
                }

            return {
                'name': 'Extension Check',
                'suspicious': False,
                'details': f"Extension matches content type: {actual_type}"
            }
        except Exception as e:
            return {
                'name': 'Extension Check',
                'suspicious': False,
                'details': f"Could not verify: {str(e)}"
            }

    def _check_embedded_executable(self, file_path: str) -> Dict[str, Any]:
        """Check for executable code embedded in media files"""
        suspicious_signatures = [
            b'MZ',  # DOS/PE executable
            b'\x7fELF',  # ELF executable
            b'#!/',  # Script shebang
            b'<?php',  # PHP code
            b'<script',  # JavaScript
            b'powershell',  # PowerShell
            b'cmd.exe',  # Command prompt
            b'/bin/sh',  # Shell
            b'/bin/bash',  # Bash
        ]

        try:
            with open(file_path, 'rb') as f:
                # Read file in chunks
                chunk_size = 1024 * 1024  # 1MB chunks
                found_signatures = []

                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break

                    for sig in suspicious_signatures:
                        if sig in chunk:
                            found_signatures.append(sig.decode('utf-8', errors='ignore'))

                if found_signatures:
                    return {
                        'name': 'Embedded Executable',
                        'suspicious': True,
                        'details': f"Found suspicious signatures: {', '.join(set(found_signatures))}"
                    }

            return {
                'name': 'Embedded Executable Check',
                'suspicious': False,
                'details': 'No executable signatures found'
            }
        except Exception as e:
            return {
                'name': 'Embedded Executable Check',
                'suspicious': False,
                'details': f"Error checking: {str(e)}"
            }

    def _check_exif_metadata(self, file_path: str) -> Dict[str, Any]:
        """Check EXIF metadata for suspicious content"""
        try:
            result = subprocess.run(
                ['exiftool', '-json', file_path],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                import json
                metadata = json.loads(result.stdout)
                if metadata:
                    meta = metadata[0]
                    suspicious_fields = []

                    # Check for suspicious comments or descriptions
                    for field in ['Comment', 'UserComment', 'ImageDescription', 'XPComment']:
                        if field in meta:
                            value = str(meta[field]).lower()
                            if any(s in value for s in ['eval', 'exec', 'script', 'powershell', 'cmd', 'bash']):
                                suspicious_fields.append(f"{field}: {meta[field][:100]}")

                    # Check for embedded thumbnails that might contain malware
                    if meta.get('ThumbnailImage'):
                        # Thumbnail exists - could contain hidden data
                        suspicious_fields.append("Contains thumbnail (potential data hiding)")

                    if suspicious_fields:
                        return {
                            'name': 'Suspicious Metadata',
                            'suspicious': True,
                            'details': '; '.join(suspicious_fields)
                        }

                    return {
                        'name': 'EXIF Metadata',
                        'suspicious': False,
                        'details': 'No suspicious metadata found'
                    }
        except FileNotFoundError:
            return {
                'name': 'EXIF Metadata',
                'suspicious': False,
                'details': 'exiftool not installed (install with: brew install exiftool)'
            }
        except Exception as e:
            return {
                'name': 'EXIF Metadata',
                'suspicious': False,
                'details': f"Error checking: {str(e)}"
            }

        return {
            'name': 'EXIF Metadata',
            'suspicious': False,
            'details': 'Could not extract metadata'
        }

    def _check_steganography(self, file_path: str) -> Dict[str, Any]:
        """Check for steganography indicators in images"""
        indicators = []

        try:
            with open(file_path, 'rb') as f:
                data = f.read()

            # Check for common steganography tool signatures
            steg_signatures = [
                b'OPENSTEGO',
                b'steghide',
                b'outguess',
                b'jsteg',
                b'F5',
            ]

            for sig in steg_signatures:
                if sig in data:
                    indicators.append(f"Found {sig.decode()} signature")

            # Check for unusual LSB patterns (simplified check)
            # High randomness in LSBs can indicate steganography
            if len(data) > 1000:
                lsb_bytes = bytes([b & 1 for b in data[:10000]])
                ones = lsb_bytes.count(1)
                ratio = ones / len(lsb_bytes)
                # Perfect 50/50 distribution is suspicious
                if 0.498 < ratio < 0.502:
                    indicators.append("Suspicious LSB distribution (possible steganography)")

            # Check for appended data after image end markers
            if file_path.lower().endswith(('.jpg', '.jpeg')):
                # JPEG end marker
                end_marker = data.rfind(b'\xff\xd9')
                if end_marker != -1 and end_marker < len(data) - 2:
                    extra_bytes = len(data) - end_marker - 2
                    if extra_bytes > 100:
                        indicators.append(f"Found {extra_bytes} bytes after JPEG end marker")

            elif file_path.lower().endswith('.png'):
                # PNG end marker
                end_marker = data.rfind(b'IEND')
                if end_marker != -1 and end_marker < len(data) - 8:
                    extra_bytes = len(data) - end_marker - 8
                    if extra_bytes > 100:
                        indicators.append(f"Found {extra_bytes} bytes after PNG end marker")

            if indicators:
                return {
                    'name': 'Steganography Detection',
                    'suspicious': True,
                    'details': '; '.join(indicators)
                }

            return {
                'name': 'Steganography Check',
                'suspicious': False,
                'details': 'No steganography indicators found'
            }

        except Exception as e:
            return {
                'name': 'Steganography Check',
                'suspicious': False,
                'details': f"Error checking: {str(e)}"
            }

    def _check_polyglot(self, file_path: str) -> Dict[str, Any]:
        """Check if file is a polyglot (valid as multiple formats)"""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(1024)

            polyglot_indicators = []

            # Check for multiple file signatures
            signatures = {
                'PDF': b'%PDF',
                'ZIP': b'PK\x03\x04',
                'RAR': b'Rar!',
                'PE/EXE': b'MZ',
                'ELF': b'\x7fELF',
                'HTML': b'<!DOCTYPE',
                'JavaScript': b'<script',
            }

            found = []
            for name, sig in signatures.items():
                if sig in header:
                    found.append(name)

            if len(found) > 1:
                polyglot_indicators.append(f"Multiple format signatures: {', '.join(found)}")

            # Check for HTML/JS in image files
            if any(s in header for s in [b'<html', b'<script', b'javascript:']):
                polyglot_indicators.append("Contains HTML/JavaScript code")

            if polyglot_indicators:
                return {
                    'name': 'Polyglot File',
                    'suspicious': True,
                    'details': '; '.join(polyglot_indicators)
                }

            return {
                'name': 'Polyglot Check',
                'suspicious': False,
                'details': 'File is not a polyglot'
            }

        except Exception as e:
            return {
                'name': 'Polyglot Check',
                'suspicious': False,
                'details': f"Error checking: {str(e)}"
            }

    def _check_trailing_data(self, file_path: str) -> Dict[str, Any]:
        """Check for hidden data appended after file end"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()

            ext = os.path.splitext(file_path)[1].lower()
            trailing_data = 0

            if ext in ['.jpg', '.jpeg']:
                # Find JPEG end marker
                end = data.rfind(b'\xff\xd9')
                if end != -1:
                    trailing_data = len(data) - end - 2

            elif ext == '.png':
                # Find PNG end chunk
                end = data.rfind(b'IEND')
                if end != -1:
                    trailing_data = len(data) - end - 12  # IEND + CRC

            elif ext == '.gif':
                # GIF trailer
                if data.endswith(b'\x3b'):
                    trailing_data = 0
                else:
                    end = data.rfind(b'\x3b')
                    if end != -1:
                        trailing_data = len(data) - end - 1

            if trailing_data > 1000:  # More than 1KB of trailing data
                return {
                    'name': 'Hidden Trailing Data',
                    'suspicious': True,
                    'details': f"Found {trailing_data} bytes of hidden data after file end"
                }

            return {
                'name': 'Trailing Data Check',
                'suspicious': False,
                'details': 'No significant trailing data found'
            }

        except Exception as e:
            return {
                'name': 'Trailing Data Check',
                'suspicious': False,
                'details': f"Error checking: {str(e)}"
            }

    def _check_video_metadata(self, file_path: str) -> Dict[str, Any]:
        """Check video metadata for suspicious content"""
        try:
            result = subprocess.run(
                ['ffprobe', '-v', 'quiet', '-print_format', 'json', '-show_format', file_path],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                import json
                metadata = json.loads(result.stdout)
                suspicious = []

                # Check tags for suspicious content
                tags = metadata.get('format', {}).get('tags', {})
                for key, value in tags.items():
                    value_lower = str(value).lower()
                    if any(s in value_lower for s in ['eval', 'exec', 'script', 'powershell', 'cmd']):
                        suspicious.append(f"{key}: {value[:100]}")

                if suspicious:
                    return {
                        'name': 'Suspicious Video Metadata',
                        'suspicious': True,
                        'details': '; '.join(suspicious)
                    }

                return {
                    'name': 'Video Metadata',
                    'suspicious': False,
                    'details': 'No suspicious metadata found'
                }
        except FileNotFoundError:
            return {
                'name': 'Video Metadata',
                'suspicious': False,
                'details': 'ffprobe not installed (install with: brew install ffmpeg)'
            }
        except Exception as e:
            return {
                'name': 'Video Metadata',
                'suspicious': False,
                'details': f"Error checking: {str(e)}"
            }

    def _check_video_streams(self, file_path: str) -> Dict[str, Any]:
        """Check video streams for suspicious content"""
        try:
            result = subprocess.run(
                ['ffprobe', '-v', 'quiet', '-print_format', 'json', '-show_streams', file_path],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                import json
                data = json.loads(result.stdout)
                streams = data.get('streams', [])

                suspicious = []
                for stream in streams:
                    codec_type = stream.get('codec_type', '')
                    codec_name = stream.get('codec_name', '')

                    # Check for unusual codecs that might hide data
                    if codec_type == 'data':
                        suspicious.append(f"Contains data stream: {codec_name}")
                    if codec_type == 'attachment':
                        suspicious.append(f"Contains attachment: {stream.get('filename', 'unknown')}")

                if suspicious:
                    return {
                        'name': 'Suspicious Video Streams',
                        'suspicious': True,
                        'details': '; '.join(suspicious)
                    }

                return {
                    'name': 'Video Streams',
                    'suspicious': False,
                    'details': f'Found {len(streams)} normal streams'
                }
        except Exception as e:
            return {
                'name': 'Video Streams',
                'suspicious': False,
                'details': f"Error checking: {str(e)}"
            }

    def _check_audio_metadata(self, file_path: str) -> Dict[str, Any]:
        """Check audio file metadata for suspicious content"""
        try:
            result = subprocess.run(
                ['ffprobe', '-v', 'quiet', '-print_format', 'json', '-show_format', file_path],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                import json
                metadata = json.loads(result.stdout)
                suspicious = []

                # Check ID3 tags and other metadata
                tags = metadata.get('format', {}).get('tags', {})
                for key, value in tags.items():
                    value_lower = str(value).lower()
                    # Check for suspicious strings in metadata
                    if any(s in value_lower for s in ['eval', 'exec', 'script', 'powershell', 'cmd', '<script']):
                        suspicious.append(f"{key}: {value[:100]}")
                    # Check for URLs in metadata (could be C2)
                    if 'http://' in value_lower or 'https://' in value_lower:
                        suspicious.append(f"URL in {key}: {value[:100]}")

                if suspicious:
                    return {
                        'name': 'Suspicious Audio Metadata',
                        'suspicious': True,
                        'details': '; '.join(suspicious)
                    }

                return {
                    'name': 'Audio Metadata',
                    'suspicious': False,
                    'details': 'No suspicious metadata found'
                }
        except FileNotFoundError:
            return {
                'name': 'Audio Metadata',
                'suspicious': False,
                'details': 'ffprobe not installed (install with: brew install ffmpeg)'
            }
        except Exception as e:
            return {
                'name': 'Audio Metadata',
                'suspicious': False,
                'details': f"Error checking: {str(e)}"
            }


def get_media_type(file_path: str) -> str:
    """Determine if file is image, video, or audio"""
    ext = os.path.splitext(file_path)[1].lower()

    image_exts = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.tiff', '.ico', '.svg'}
    video_exts = {'.mp4', '.avi', '.mov', '.mkv', '.webm', '.flv', '.wmv', '.m4v', '.3gp'}
    audio_exts = {'.mp3', '.wav', '.flac', '.ogg', '.m4a', '.aac', '.wma', '.aiff'}

    if ext in image_exts:
        return 'image'
    elif ext in video_exts:
        return 'video'
    elif ext in audio_exts:
        return 'audio'
    else:
        return 'unknown'
