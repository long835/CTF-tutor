"""
forensics_toolkit.py

Passive reconnaissance toolkit for digital forensics challenges. Analyzes
disk images, memory dumps, network captures, and steganographic content
without actually extracting or recovering data.

All analysis is structural/metadata only — no carving, no decompression,
just evidence gathering for the decomposer.
"""

import re
import json
from typing import Optional, Dict, List


def _safe_read(path: str, max_size: int = 1024 * 1024) -> Optional[str]:
    """Safely read a file without blowing up the process on huge files."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read(max_size)
    except Exception:
        return None


def scan_pcap_metadata(path: str) -> Dict:
    """
    Analyze a .pcap file for network capture metadata.
    Returns info about protocols, packet count hints, traffic patterns.
    
    Example:
        scan_pcap_metadata("capture.pcap")
        # => {"is_pcap": True, "protocols": ["TCP", "UDP", "DNS"], ...}
    """
    content = _safe_read(path)
    if not content:
        return {"is_pcap": False}
    
    # PCAP magic bytes (little-endian or big-endian)
    is_pcap = b"\xa1\xb2\xc3\xd4" in content.encode('latin-1', errors='ignore') or \
              b"\xd4\xc3\xb2\xa1" in content.encode('latin-1', errors='ignore')
    
    protocols = {
        "TCP": False,
        "UDP": False,
        "DNS": False,
        "HTTP": False,
        "HTTPS/TLS": False,
        "SSH": False,
        "FTP": False,
        "SMTP": False,
        "POP3": False,
    }
    
    # Simple protocol detection from content
    if re.search(r"TCP|IPv4", content, re.IGNORECASE):
        protocols["TCP"] = True
    if re.search(r"UDP", content, re.IGNORECASE):
        protocols["UDP"] = True
    if re.search(r"DNS|domain", content, re.IGNORECASE):
        protocols["DNS"] = True
    if re.search(r"GET|POST|HTTP/1", content, re.IGNORECASE):
        protocols["HTTP"] = True
    if re.search(r"TLS|SSL|HTTPS", content, re.IGNORECASE):
        protocols["HTTPS/TLS"] = True
    
    return {
        "is_pcap": is_pcap,
        "detected_protocols": {k: v for k, v in protocols.items() if v},
        "likely_analysis": "Use wireshark or tshark to extract packets and inspect payloads",
    }


def scan_memory_dump_metadata(path: str) -> Dict:
    """
    Analyze a memory dump file for OS/architecture hints.
    Detects ELF headers, PE headers, common memory patterns.
    
    Example:
        scan_memory_dump_metadata("memory.img")
        # => {"detected_os": "Linux", "architecture": "x86-64", ...}
    """
    try:
        with open(path, "rb") as f:
            header = f.read(4096)
    except Exception:
        return {"error": "Could not read file"}
    
    analysis = {
        "detected_os": None,
        "architecture": None,
        "memory_artifacts": [],
    }
    
    # ELF header (Linux)
    if header.startswith(b'\x7fELF'):
        analysis["detected_os"] = "Linux/Unix"
        e_machine = int.from_bytes(header[18:20], 'little')
        if e_machine == 0x3e:
            analysis["architecture"] = "x86-64"
        elif e_machine == 0x03:
            analysis["architecture"] = "x86"
        elif e_machine == 0xb7:
            analysis["architecture"] = "ARM64"
    
    # PE header (Windows)
    if b'MZ' in header:
        analysis["detected_os"] = "Windows"
        # PE signature location
        if b'PE\x00\x00' in header:
            analysis["architecture"] = "Likely x86 or x86-64"
    
    # Mach-O header (macOS)
    if header.startswith(b'\xfe\xed\xfa'):
        analysis["detected_os"] = "macOS"
    
    # Common strings in memory dumps
    if b"volatility" in header.lower():
        analysis["memory_artifacts"].append("Volatility-compatible format")
    if b"pagesize" in header.lower():
        analysis["memory_artifacts"].append("Memory paging metadata present")
    
    return analysis


def scan_disk_image_metadata(path: str) -> Dict:
    """
    Analyze a disk image file for filesystem type and structure.
    
    Example:
        scan_disk_image_metadata("disk.img")
        # => {"filesystem": "ext4", "size_gb": 10, ...}
    """
    try:
        with open(path, "rb") as f:
            header = f.read(4096)
    except Exception:
        return {"error": "Could not read file"}
    
    filesystems = {
        "ext4": (b'\x53\xef', 1024),  # Superblock magic at offset 1024
        "ext3": (b'\x53\xef', 1024),
        "ext2": (b'\x53\xef', 1024),
        "NTFS": (b'NTFS', 3),
        "FAT32": (b'FAT32', 82),
        "ISO9660": (b'CD001', 32769),
        "HFS+": (b'H+', 1024),
    }
    
    analysis = {
        "detected_filesystem": None,
        "likely_tools": [],
    }
    
    for fs_name, (magic, offset) in filesystems.items():
        if len(header) > offset and header[offset:offset+len(magic)] == magic:
            analysis["detected_filesystem"] = fs_name
            break
    
    if analysis["detected_filesystem"] == "NTFS":
        analysis["likely_tools"].append("ntfsundelete, ntfswalk")
    elif "ext" in (analysis["detected_filesystem"] or ""):
        analysis["likely_tools"].append("extundelete, e2fsck")
    elif analysis["detected_filesystem"] == "FAT32":
        analysis["likely_tools"].append("fatcat, FAT recovery tools")
    
    return analysis


def scan_steganography_indicators(path: str) -> Dict:
    """
    Scan a file for common steganography indicators.
    Looks for LSB patterns, metadata anomalies, etc.
    
    Example:
        scan_steganography_indicators("image.png")
        # => {"suspect_lsb": True, "metadata_anomalies": [...], ...}
    """
    try:
        with open(path, "rb") as f:
            data = f.read(10000)
    except Exception:
        return {"error": "Could not read file"}
    
    indicators = {
        "file_magic": None,
        "is_image": False,
        "is_audio": False,
        "is_video": False,
        "metadata_tools_needed": [],
        "steg_tools_to_try": [],
    }
    
    # File type detection
    if data.startswith(b'\x89PNG'):
        indicators["file_magic"] = "PNG"
        indicators["is_image"] = True
        indicators["steg_tools_to_try"].append("zsteg")
        indicators["metadata_tools_needed"].append("exiftool")
    elif data.startswith(b'\xff\xd8\xff'):
        indicators["file_magic"] = "JPEG"
        indicators["is_image"] = True
        indicators["steg_tools_to_try"].append("jsteg")
        indicators["metadata_tools_needed"].append("exiftool")
    elif data.startswith(b'GIF87a') or data.startswith(b'GIF89a'):
        indicators["file_magic"] = "GIF"
        indicators["is_image"] = True
        indicators["metadata_tools_needed"].append("exiftool")
    elif data.startswith(b'ID3') or data.startswith(b'\xff\xfb'):
        indicators["file_magic"] = "MP3"
        indicators["is_audio"] = True
        indicators["steg_tools_to_try"].append("MP3stego")
    elif data.startswith(b'ftyp'):
        indicators["file_magic"] = "MP4/MOV"
        indicators["is_video"] = True
        indicators["metadata_tools_needed"].append("exiftool")
    
    # LSB pattern check (simple heuristic: high entropy in least-significant bits)
    if indicators["is_image"] and len(data) > 1000:
        lsb_entropy = sum(1 for i in range(1000) if data[i] & 1)
        if 400 < lsb_entropy < 600:  # ~50% LSBs set = possible steganography
            indicators["suspect_lsb"] = True
    
    return indicators


def scan_archive_metadata(path: str) -> Dict:
    """
    Analyze archive files for compression info and contents hints.
    
    Example:
        scan_archive_metadata("archive.zip")
        # => {"archive_type": "ZIP", "compression": ["stored", "deflate"], ...}
    """
    try:
        with open(path, "rb") as f:
            header = f.read(1000)
    except Exception:
        return {"error": "Could not read file"}
    
    analysis = {
        "archive_type": None,
        "likely_extraction_tools": [],
    }
    
    if header.startswith(b'PK\x03\x04'):
        analysis["archive_type"] = "ZIP"
        analysis["likely_extraction_tools"].append("unzip, 7z")
    elif header.startswith(b'\x1f\x8b\x08'):
        analysis["archive_type"] = "GZIP"
        analysis["likely_extraction_tools"].append("gunzip, 7z")
    elif header.startswith(b'BZh'):
        analysis["archive_type"] = "BZIP2"
        analysis["likely_extraction_tools"].append("bunzip2, 7z")
    elif header.startswith(b"7z\xbc\xaf\x27\x1c"):
        analysis["archive_type"] = "7Z"
        analysis["likely_extraction_tools"].append("7z")
    elif header.startswith(b'Rar!'):
        analysis["archive_type"] = "RAR"
        analysis["likely_extraction_tools"].append("unrar, 7z")
    
    return analysis


def analyze_forensics_file(path: str) -> Dict:
    """
    Comprehensive passive analysis of a forensics-related file.
    
    Example:
        analyze_forensics_file("memory_dump.img")
        # => Detailed forensics evidence for decomposer
    """
    return {
        "file_type": "forensics",
        "pcap_metadata": scan_pcap_metadata(path),
        "memory_dump_metadata": scan_memory_dump_metadata(path),
        "disk_image_metadata": scan_disk_image_metadata(path),
        "steganography_indicators": scan_steganography_indicators(path),
        "archive_metadata": scan_archive_metadata(path),
    }


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python -m tools.forensics_toolkit <forensics_file>")
        sys.exit(1)
    
    path = sys.argv[1]
    result = analyze_forensics_file(path)
    print(json.dumps(result, indent=2))
