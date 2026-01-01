#!/usr/bin/env python3
"""
Yamaha MBDFArchive extractor (GUI) with Firmware Analysis

- Extracts Yamaha "#YAMAHA MBDFArchive" containers supporting:
  - #FILE blocks (48-byte header, then filename, then zlib member)
  - #FIRMWARE blocks (metadata then zlib member; name may be absent)
- Smart XOR decryption with automatic key detection:
  - Detects encryption by looking for known signatures after XOR
  - Automatically discovers XOR keys by analyzing byte patterns
  - Recursive extraction with decryption at each level
- Known XOR keys (auto-detected):
  - 0xa9: Outer archive encryption (e.g., IGUW-UX firmware files)
  - 0xf1: Inner content encryption (extracted XML/config files)
  - 0x87, 0xf7, 0x78: Other Yamaha firmware keys
- Deep recursive extraction:
  - Extracts nested archives to maximum depth
  - Handles ZIP archives (including split archives)
  - Inspects file content to assign correct extensions
  - Identifies RTOS firmware (QNX, VxWorks, FreeRTOS, etc.)
  - Identifies Windows PE, ELF binaries, XML, and more
- Firmware analysis and reporting:
  - Detect OS signatures (QNX, VxWorks, Windows, Linux)
  - Identify CPU architectures (ARM, SH4, x86)
  - Find embedded Windows PE files
  - Extract strings from firmware binaries
  - Generate comprehensive extraction reports
"""

from __future__ import annotations

import hashlib
import io
import json
import lzma
import os
import re
import struct
import sys
import tarfile
import zipfile
import zlib
from dataclasses import dataclass, asdict, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

# GUI imports are optional - only needed when running the GUI
try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    HAS_TKINTER = True
except ImportError:
    HAS_TKINTER = False
    tk = None
    ttk = None
    filedialog = None
    messagebox = None


MAGIC_ARCHIVE = b"#YAMAHA MBDFArchive"
MAGIC_FILE = b"#FILE"
MAGIC_FIRMWARE = b"#FIRMWARE"
MAGIC_BACKUP = b"#YAMAHA MBDFBackup"
MAGIC_PROJECT = b"#YAMAHA MBDFProjectFile"
FILE_HDR_LEN = 48

ZLIB_HEADS = (b"\x78\x01", b"\x78\x9c", b"\x78\xda")
ZLIB_HEADS_PADDED = (b"\x00\x78\x01", b"\x00\x78\x9c", b"\x00\x78\xda")

MARKERS = (MAGIC_FILE, MAGIC_FIRMWARE)

# Known Yamaha signatures for detection
YAMAHA_SIGNATURES = [
    MAGIC_ARCHIVE,
    MAGIC_BACKUP,
    MAGIC_PROJECT,
    b"#YAMAHA",
    b"<?xml",
    b"<function",
    b"MZ",  # Windows PE
    b"\x7fELF",  # ELF binary
    b"PK\x03\x04",  # ZIP
    b"\xfd7zXZ",  # XZ compression
    b"\x1f\x8b\x08",  # GZIP
    b"TwinLAN",  # Yamaha TwinLAN ARM firmware
    b"YAMAHA",  # Generic Yamaha firmware header
]

# XOR encryption keys found in Yamaha firmware (ordered by frequency)
# Note: 0xa0 and 0xa7 are used for text files (scripts, batch files, etc.)
KNOWN_XOR_KEYS = [0xa9, 0xf1, 0x87, 0xf7, 0x78, 0xa0, 0xa7, 0x00]

# Audinate Dante Network firmware signature
MAGIC_DNT = b"AUDI"

# File type signatures for content inspection
FILE_SIGNATURES = {
    # Archives
    b"#YAMAHA MBDFArchive": ("yamaha_archive", ".bin"),
    b"#YAMAHA MBDFBackup": ("yamaha_backup", ".bin"),
    b"#YAMAHA MBDFProjectFile": ("yamaha_project", ".bin"),
    b"AUDI": ("dante_firmware", ".dnt"),  # Audinate Dante firmware
    b"PK\x03\x04": ("zip", ".zip"),
    b"PK\x05\x06": ("zip_empty", ".zip"),
    b"\x1f\x8b\x08": ("gzip", ".gz"),
    b"BZh": ("bzip2", ".bz2"),
    b"\xfd7zXZ\x00": ("xz", ".xz"),
    b"7z\xbc\xaf\x27\x1c": ("7zip", ".7z"),
    b"Rar!\x1a\x07": ("rar", ".rar"),
    
    # Executables
    b"MZ": ("pe_executable", ".exe"),
    b"\x7fELF": ("elf_binary", ".elf"),
    b"\xca\xfe\xba\xbe": ("macho_fat", ".macho"),
    b"\xfe\xed\xfa\xce": ("macho32", ".macho"),
    b"\xfe\xed\xfa\xcf": ("macho64", ".macho"),
    b"\xcf\xfa\xed\xfe": ("macho64_le", ".macho"),
    
    # RTOS and firmware signatures
    b"QNX": ("qnx_rtos", ".qnx"),
    b"IFS1": ("qnx_ifs", ".ifs"),
    b"VxWorks": ("vxworks_rtos", ".vxworks"),
    b"FreeRTOS": ("freertos", ".rtos"),
    b"RTOS": ("rtos_generic", ".rtos"),
    b"uCOS": ("ucos_rtos", ".rtos"),
    b"ThreadX": ("threadx_rtos", ".rtos"),
    b"Nucleus": ("nucleus_rtos", ".rtos"),
    b"eCos": ("ecos_rtos", ".rtos"),
    b"RTEMS": ("rtems_rtos", ".rtos"),
    b"Zephyr": ("zephyr_rtos", ".rtos"),
    b"NuttX": ("nuttx_rtos", ".rtos"),
    
    # DSP/Audio processor signatures
    b"SHARC": ("sharc_dsp", ".dsp"),
    b"TMS320": ("ti_dsp", ".dsp"),
    b"XMOS": ("xmos_firmware", ".xmos"),
    b"FPGA": ("fpga_bitstream", ".bit"),
    
    # Image formats
    b"\x89PNG\r\n\x1a\n": ("png", ".png"),
    b"\xff\xd8\xff": ("jpeg", ".jpg"),
    b"GIF87a": ("gif87", ".gif"),
    b"GIF89a": ("gif89", ".gif"),
    b"BM": ("bmp", ".bmp"),
    b"RIFF": ("riff", ".riff"),  # Could be WAV, AVI, etc.
    
    # Audio formats
    b"ID3": ("mp3_id3", ".mp3"),
    b"\xff\xfb": ("mp3", ".mp3"),
    b"OggS": ("ogg", ".ogg"),
    b"fLaC": ("flac", ".flac"),
    b"FORM": ("aiff", ".aiff"),
    
    # Document/Config formats
    b"<?xml": ("xml", ".xml"),
    b"<function": ("yamaha_xml", ".xml"),
    b"<!DOCTYPE": ("html_doctype", ".html"),
    b"<html": ("html", ".html"),
    b"<HTML": ("html", ".html"),
    b"{": ("json_maybe", ".json"),
    b"[": ("json_array_maybe", ".json"),
    
    # Database/Binary formats
    b"SQLite format 3": ("sqlite", ".db"),
    
    # Linux/Unix formats
    b"\x1f\x9d": ("compress_z", ".Z"),
    b"#!/": ("script", ".sh"),
    b"#!": ("script", ".sh"),
    
    # Certificate/Key formats
    b"-----BEGIN": ("pem", ".pem"),
}

# RTOS-specific patterns that may appear deeper in the file
RTOS_PATTERNS = [
    (b"QNX", "QNX Neutrino RTOS"),
    (b"IFS1", "QNX Image Filesystem"),
    (b"VxWorks", "VxWorks RTOS"),
    (b"FreeRTOS", "FreeRTOS"),
    (b"uC/OS", "Micrium uC/OS"),
    (b"ThreadX", "Azure ThreadX"),
    (b"Nucleus", "Mentor Nucleus"),
    (b"eCos", "eCos RTOS"),
    (b"RTEMS", "RTEMS"),
    (b"Zephyr", "Zephyr RTOS"),
    (b"NuttX", "NuttX RTOS"),
    (b"INTEGRITY", "Green Hills INTEGRITY"),
    (b"LynxOS", "LynxOS"),
    (b"OSEK", "OSEK/VDX"),
    (b"AUTOSAR", "AUTOSAR"),
    (b"SafeRTOS", "SafeRTOS"),
    (b"embOS", "SEGGER embOS"),
    (b"MQX", "Freescale MQX"),
    (b"mbed", "ARM Mbed OS"),
    (b"Contiki", "Contiki-NG"),
    (b"RIOT", "RIOT OS"),
    (b"TinyOS", "TinyOS"),
    (b"ChibiOS", "ChibiOS"),
]

# Architecture signatures
ARCH_PATTERNS = [
    (b"\x7fELF\x01\x01", "ELF 32-bit LSB"),
    (b"\x7fELF\x01\x02", "ELF 32-bit MSB"),
    (b"\x7fELF\x02\x01", "ELF 64-bit LSB"),
    (b"\x7fELF\x02\x02", "ELF 64-bit MSB"),
    (b"ARM\x00", "ARM architecture"),
    (b"SH4", "SuperH SH4"),
    (b"PowerPC", "PowerPC"),
    (b"MIPS", "MIPS"),
    (b"x86", "x86"),
    (b"AMD64", "AMD64/x86-64"),
]


def xor_decrypt(data: bytes, key: Union[int, bytes]) -> bytes:
    """
    Apply XOR decryption with a single-byte or multi-byte key.
    
    Args:
        data: Data to decrypt
        key: Single byte (int) or multi-byte key (bytes)
    
    Returns:
        Decrypted data
    """
    if isinstance(key, int):
        return bytes(b ^ key for b in data)
    else:
        # Multi-byte key
        key_len = len(key)
        return bytes(data[i] ^ key[i % key_len] for i in range(len(data)))


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data (0-8 bits)."""
    if not data:
        return 0.0
    from collections import Counter
    import math
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def is_likely_text(data: bytes) -> bool:
    """Check if data looks like text/XML."""
    if not data:
        return False
    # Check first 1KB
    sample = data[:1024]
    # Count printable ASCII
    printable = sum(1 for b in sample if 0x20 <= b < 0x7f or b in (0x09, 0x0a, 0x0d))
    return printable / len(sample) > 0.85


def is_mostly_printable(data: bytes, threshold: float = 0.75) -> bool:
    """
    Check if data is mostly printable ASCII (with configurable threshold).
    
    This is a more lenient check than is_likely_text, useful for files
    that contain some non-ASCII characters (e.g., Japanese text in comments).
    
    Args:
        data: Data to check
        threshold: Minimum ratio of printable chars (default 0.75 = 75%)
    
    Returns:
        True if printable ratio exceeds threshold
    """
    if not data:
        return False
    sample = data[:1024]
    printable = sum(1 for b in sample if 0x20 <= b < 0x7f or b in (0x09, 0x0a, 0x0d))
    return printable / len(sample) > threshold


def is_likely_utf16(data: bytes) -> bool:
    """
    Check if data looks like UTF-16 encoded text.
    
    UTF-16 text has:
    - BOM at start (0xFF 0xFE for LE, 0xFE 0xFF for BE)
    - Or roughly every other byte is 0x00 for ASCII text
    
    Args:
        data: Data to check
    
    Returns:
        True if data looks like UTF-16 text
    """
    if not data or len(data) < 4:
        return False
    
    # Check for BOM
    if data[:2] in (b'\xff\xfe', b'\xfe\xff'):
        # Check if rest looks like UTF-16
        sample = data[2:200]
        if len(sample) < 4:
            return True
        # For ASCII in UTF-16, every other byte should be null
        null_count = sum(1 for i, b in enumerate(sample) if b == 0 and i % 2 == 1)
        return null_count > len(sample) // 4
    
    # Check for UTF-16 without BOM (every other byte is null)
    sample = data[:200]
    null_in_odd = sum(1 for i, b in enumerate(sample) if b == 0 and i % 2 == 1)
    null_in_even = sum(1 for i, b in enumerate(sample) if b == 0 and i % 2 == 0)
    
    # Either odd or even positions should have many nulls
    return (null_in_odd > len(sample) // 4) or (null_in_even > len(sample) // 4)


# Pre-compiled regex for version number detection
VERSION_PATTERN = re.compile(r'v?\d+\.\d+')


def score_text_quality(data: bytes) -> int:
    """
    Score the quality of decrypted text - higher score means more likely correct.
    
    This helps distinguish between "random printable chars" and "actual readable text"
    by looking for common patterns in scripts, config files, and English text.
    
    Typical score ranges:
    - 0-20: Random or binary data
    - 20-50: Possibly text but uncertain
    - 50-100: Likely correct decryption (small files)
    - 100+: Very likely correct decryption (larger files with keywords)
    
    Args:
        data: Decrypted data to analyze
    
    Returns:
        Score (higher = more likely correct decryption, typically 0-500+)
    """
    if not data:
        return 0
    
    # Try to decode as UTF-8 first, then UTF-16 if that fails or looks like UTF-16
    text = None
    
    # Check for UTF-16 BOM or pattern
    if data[:2] in (b'\xff\xfe', b'\xfe\xff'):
        try:
            if data[:2] == b'\xff\xfe':
                text = data.decode('utf-16-le', errors='ignore').lower()
            else:
                text = data.decode('utf-16-be', errors='ignore').lower()
        except Exception:
            pass
    
    # Fall back to UTF-8
    if text is None:
        try:
            text = data.decode('utf-8', errors='ignore').lower()
        except Exception:
            return 0
    
    if not text:
        return 0
    
    score = 0
    
    # Common script/config keywords (high weight)
    # Note: Single chars like '$' are excluded to avoid false positives
    keywords = [
        # Batch file keywords
        'echo', 'rem ', 'set ', 'if ', 'for ', 'goto', 'call', 'exit',
        'pushd', 'popd', 'del ', 'mkdir', 'rmdir', '@echo', 'pause',
        # PowerShell specific (multi-char patterns)
        'function', 'param', 'begin', 'end', 'return', 'throw',
        'get-', 'set-', 'new-', 'write-', '-eq', '-ne', '-object',
        '$obj', '$var', '$path', '$env', '$null', '$true', '$false',
        # VBScript keywords
        'dim ', 'sub ', 'option', 'wscript', 'end sub', 'end function',
        'createobject', 'msgbox', 'inputbox', 'explicit',
        # XML keywords
        '<?xml', '<function', '<module', '</function', '</module',
        '="', '/>', '</', 'xmlns',
        # Common text patterns
        'copyright', 'version', 'all rights reserved', 'license',
        # Windows paths
        'c:\\', 'd:\\', 'windows', 'program', 'users\\',
        # Common English words
        'the ', ' is ', ' of ', ' to ', ' in ', ' and ', ' or ',
        # Config file patterns (e.g., Windows registry)
        'hex:', 'dword:', '=hex', '=dword',
    ]
    
    for kw in keywords:
        count = text.count(kw)
        score += count * 10
    
    # Bonus for proper line breaks (CRLF preferred over swapped)
    if '\r\n' in text:
        score += 25  # Proper Windows line ending
    elif '\n' in text:
        score += 10
    
    # Bonus for common file path patterns
    if ':\\' in text or ':/' in text:
        score += 30
    
    # Bonus for version number patterns (e.g., V1.32, v2.0.1)
    if VERSION_PATTERN.search(text):
        score += 40
    
    # Penalize unusual control characters (except common whitespace)
    unusual = sum(1 for c in text if ord(c) < 0x20 and c not in '\r\n\t')
    score -= unusual * 2
    
    return max(0, score)


def is_likely_binary_format(data: bytes) -> bool:
    """Check if data looks like a known binary format."""
    if len(data) < 4:
        return False
    # Check for known headers
    if data[:2] == b'MZ':  # PE
        return True
    if data[:4] == b'\x7fELF':  # ELF
        return True
    if data[:4] == b'PK\x03\x04':  # ZIP
        return True
    if data[:2] in ZLIB_HEADS:  # zlib
        return True
    return False


# Frequency analysis threshold: 10% of sample (100 out of 1000 bytes)
FREQUENCY_ANALYSIS_SAMPLE_SIZE = 1000
FREQUENCY_THRESHOLD = 100  # 10% of sample size


def detect_xor_key_smart(data: bytes, max_keys_to_try: int = 256) -> Optional[int]:
    """
    Smart XOR key detection that tries to find the encryption key.
    
    Strategy:
    1. First try known Yamaha keys against known signatures
    2. Score all known keys for text quality and pick the best one
    3. Brute force remaining keys (1-255) looking for known signatures
    4. Frequency analysis: if one byte appears very frequently (>10% of sample),
       assume it's XOR of 0x00 (null bytes are common in binary data) and test
       if decryption produces valid text or binary format
    
    Args:
        data: Potentially encrypted data
        max_keys_to_try: Maximum number of keys to try (default: all 256)
    
    Returns:
        Detected XOR key, or None if not encrypted / can't detect
    """
    if not data or len(data) < 2:
        return None
    
    # Check if already contains a known signature (not encrypted)
    for sig in YAMAHA_SIGNATURES:
        if data[:len(sig)] == sig:
            return None
    
    # Check if already valid readable text (not encrypted)
    if is_likely_text(data) and score_text_quality(data) > 50:
        return None
    
    # Try known keys first (most likely) - check for signatures
    for key in KNOWN_XOR_KEYS:
        if key == 0:
            continue
        decrypted = xor_decrypt(data[:100], key)
        for sig in YAMAHA_SIGNATURES:
            if decrypted[:len(sig)] == sig:
                return key
    
    # Score all known keys for text quality and pick the best one
    # This handles script files (.ps1, .bat, .vbs) that don't have binary signatures
    best_key = None
    best_score = 0
    sample_size = min(len(data), 1000)
    
    # For small files, use lower thresholds
    min_score_threshold = 50 if len(data) > 100 else 20
    
    for key in KNOWN_XOR_KEYS:
        if key == 0:
            continue
        decrypted = xor_decrypt(data[:sample_size], key)
        score = score_text_quality(decrypted)
        
        # Accept if score is high enough OR if it passes text-like checks
        # High score indicates correct decryption even with non-ASCII chars (Japanese text)
        if score > best_score:
            # For high scores, trust the score alone
            # For lower scores, require text-like content
            # Also check for UTF-16 encoded text
            if (score >= min_score_threshold or 
                is_likely_text(decrypted) or 
                is_mostly_printable(decrypted, threshold=0.70) or
                is_likely_utf16(decrypted)):
                best_score = score
                best_key = key
    
    # If we found a key with good text quality score, use it
    if best_score >= min_score_threshold:
        return best_key
    
    # If known keys didn't work, try brute force with signature detection
    if max_keys_to_try > len(KNOWN_XOR_KEYS):
        for key in range(1, min(256, max_keys_to_try)):
            if key in KNOWN_XOR_KEYS:
                continue
            decrypted = xor_decrypt(data[:100], key)
            for sig in YAMAHA_SIGNATURES:
                if decrypted[:len(sig)] == sig:
                    return key
    
    # Frequency analysis: if one byte dominates, it may be XOR of 0x00
    if len(data) >= FREQUENCY_ANALYSIS_SAMPLE_SIZE:
        from collections import Counter
        counts = Counter(data[:FREQUENCY_ANALYSIS_SAMPLE_SIZE])
        most_common_byte, count = counts.most_common(1)[0]
        # If one byte appears very frequently, assume it's encrypted 0x00
        if count > FREQUENCY_THRESHOLD:
            key = most_common_byte  # XOR with 0x00 is identity, so key = byte
            if key != 0:
                decrypted = xor_decrypt(data[:100], key)
                # Check if result looks more like valid data
                if is_likely_text(decrypted) or is_likely_binary_format(decrypted):
                    return key
    
    return None


def smart_decrypt(data: bytes) -> Tuple[bytes, Optional[int], str]:
    """
    Intelligently decrypt data, detecting and applying XOR if needed.
    
    Returns:
        Tuple of (decrypted_data, key_used, description)
        - key_used is None if no decryption was needed
        - description explains what was detected/done
    """
    if not data:
        return data, None, "empty data"
    
    # Detect encryption
    key = detect_xor_key_smart(data)
    
    if key is not None:
        decrypted = xor_decrypt(data, key)
        # Verify the decryption looks valid
        # Use is_mostly_printable for files with some non-ASCII chars (e.g., Japanese)
        # Use is_likely_utf16 for UTF-16 encoded text files
        if (is_likely_text(decrypted[:1000]) or 
            is_mostly_printable(decrypted[:1000], 0.75) or 
            is_likely_utf16(decrypted) or
            is_likely_binary_format(decrypted)):
            return decrypted, key, f"XOR decrypted with key 0x{key:02x}"
        # Check for Yamaha signature
        for sig in YAMAHA_SIGNATURES:
            if decrypted[:len(sig)] == sig:
                return decrypted, key, f"XOR decrypted with key 0x{key:02x} (found {sig[:10]})"
    
    return data, None, "not encrypted or unknown format"


def is_yamaha_archive(data: bytes) -> bool:
    """Check if data is a Yamaha MBDFArchive (encrypted or not)."""
    if not data or len(data) < 50:
        return False
    
    # Check unencrypted
    for sig in [MAGIC_ARCHIVE, MAGIC_BACKUP, MAGIC_PROJECT]:
        if sig in data[:2048]:
            return True
    
    # Check if XOR encrypted
    key = detect_xor_key_smart(data)
    if key is not None:
        decrypted = xor_decrypt(data[:2048], key)
        for sig in [MAGIC_ARCHIVE, MAGIC_BACKUP, MAGIC_PROJECT]:
            if sig in decrypted:
                return True
    
    return False


def recursive_smart_decrypt(data: bytes, max_depth: int = 3) -> Tuple[bytes, List[Tuple[int, str]]]:
    """
    Recursively decrypt data, handling multiple encryption layers.
    
    Args:
        data: Data to decrypt
        max_depth: Maximum recursion depth
    
    Returns:
        Tuple of (final_data, list of (key, description) for each layer)
    """
    layers = []
    current_data = data
    
    for _ in range(max_depth):
        decrypted, key, desc = smart_decrypt(current_data)
        if key is None:
            break
        layers.append((key, desc))
        current_data = decrypted
        
        # Check if we should continue (still looks encrypted)
        if is_likely_text(current_data[:1000]) or is_likely_binary_format(current_data):
            # Looks decrypted enough
            break
    
    return current_data, layers


def detect_file_type(data: bytes) -> Tuple[str, str, str]:
    """
    Detect file type by inspecting content (magic bytes).
    
    Args:
        data: File content to analyze
    
    Returns:
        Tuple of (file_type_name, recommended_extension, description)
    """
    if not data or len(data) < 4:
        return ("unknown", ".bin", "Unknown/Empty file")
    
    # Check against known signatures
    for sig, (type_name, ext) in FILE_SIGNATURES.items():
        if data[:len(sig)] == sig:
            # Special handling for certain types
            if type_name == "pe_executable":
                return _analyze_pe(data)
            elif type_name == "elf_binary":
                return _analyze_elf(data)
            elif type_name == "xml":
                return _analyze_xml(data)
            elif type_name == "dante_firmware":
                return _analyze_dnt(data)
            elif type_name == "json_maybe" or type_name == "json_array_maybe":
                # Verify it's actually JSON
                if _is_likely_json(data):
                    return ("json", ".json", "JSON data")
            return (type_name, ext, f"{type_name} file")
    
    # Check for raw firmware files (common patterns)
    raw_fw_info = _detect_raw_firmware(data)
    if raw_fw_info:
        return raw_fw_info
    
    # Check for RTOS signatures deeper in the file
    rtos_info = _detect_rtos(data)
    if rtos_info:
        return rtos_info
    
    # Check for zlib compressed data
    if data[:2] in ZLIB_HEADS:
        return ("zlib", ".zlib", "Zlib compressed data")
    
    # Check if it's text
    if is_likely_text(data):
        # Try to determine text type
        sample = data[:1024].decode('utf-8', errors='ignore')
        if '<?xml' in sample or '<function' in sample:
            return ("xml", ".xml", "XML document")
        elif '<html' in sample.lower():
            return ("html", ".html", "HTML document")
        elif sample.strip().startswith('{') or sample.strip().startswith('['):
            if _is_likely_json(data):
                return ("json", ".json", "JSON data")
        elif sample.startswith('#!'):
            return ("script", ".sh", "Shell script")
        return ("text", ".txt", "Plain text file")
    
    # Check entropy - high entropy might indicate encryption or compression
    entropy = calculate_entropy(data[:4096])
    if entropy > 7.5:
        return ("encrypted_or_compressed", ".bin", f"Possibly encrypted/compressed (entropy: {entropy:.2f})")
    
    return ("binary", ".bin", "Binary data")


def _analyze_pe(data: bytes) -> Tuple[str, str, str]:
    """Analyze a PE (Windows) executable."""
    if len(data) < 64:
        return ("pe_truncated", ".exe", "Truncated PE file")
    
    try:
        # Get PE header offset from DOS header
        pe_offset = struct.unpack('<I', data[0x3c:0x40])[0]
        
        if pe_offset + 6 > len(data):
            return ("pe_truncated", ".exe", "Truncated PE file")
        
        # Verify PE signature
        if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
            return ("pe_invalid", ".exe", "Invalid PE signature")
        
        # Get machine type
        machine = struct.unpack('<H', data[pe_offset+4:pe_offset+6])[0]
        machine_types = {
            0x14c: "x86",
            0x8664: "x64",
            0x1c0: "ARM",
            0xaa64: "ARM64",
            0x1c4: "ARM Thumb-2",
        }
        arch = machine_types.get(machine, f"unknown (0x{machine:04x})")
        
        # Get characteristics to determine if DLL or EXE
        if pe_offset + 22 <= len(data):
            characteristics = struct.unpack('<H', data[pe_offset+22:pe_offset+24])[0]
            is_dll = bool(characteristics & 0x2000)
            ext = ".dll" if is_dll else ".exe"
            type_name = "dll" if is_dll else "exe"
        else:
            ext = ".exe"
            type_name = "pe_executable"
        
        return (type_name, ext, f"Windows PE {arch} {'DLL' if ext == '.dll' else 'executable'}")
    except Exception:
        return ("pe_executable", ".exe", "Windows PE executable")


def _analyze_elf(data: bytes) -> Tuple[str, str, str]:
    """Analyze an ELF binary."""
    if len(data) < 20:
        return ("elf_truncated", ".elf", "Truncated ELF file")
    
    try:
        # ELF class (32/64 bit)
        elf_class = data[4]
        bits = "32-bit" if elf_class == 1 else "64-bit" if elf_class == 2 else "unknown"
        
        # Endianness
        endian = data[5]
        byte_order = "LSB" if endian == 1 else "MSB" if endian == 2 else "unknown"
        
        # Machine type (at offset 18 for both 32 and 64 bit)
        machine = struct.unpack('<H' if endian == 1 else '>H', data[18:20])[0]
        machine_types = {
            0x03: "x86",
            0x3e: "x86-64",
            0x28: "ARM",
            0xb7: "AArch64",
            0x08: "MIPS",
            0x14: "PowerPC",
            0x15: "PowerPC64",
            0x2a: "SuperH",
            0xf3: "RISC-V",
        }
        arch = machine_types.get(machine, f"arch-0x{machine:02x}")
        
        # ELF type
        elf_type = struct.unpack('<H' if endian == 1 else '>H', data[16:18])[0]
        type_names = {
            1: "relocatable",
            2: "executable",
            3: "shared object",
            4: "core dump",
        }
        elf_type_name = type_names.get(elf_type, "unknown")
        
        return ("elf", ".elf", f"ELF {bits} {byte_order} {elf_type_name} ({arch})")
    except Exception:
        return ("elf_binary", ".elf", "ELF binary")


def _analyze_xml(data: bytes) -> Tuple[str, str, str]:
    """Analyze XML content."""
    try:
        sample = data[:2048].decode('utf-8', errors='ignore')
        
        # Check for Yamaha-specific XML
        if '<function' in sample:
            return ("yamaha_xml", ".xml", "Yamaha function definition XML")
        elif '<module' in sample:
            return ("yamaha_module_xml", ".xml", "Yamaha module XML")
        elif '<console' in sample.lower():
            return ("yamaha_console_xml", ".xml", "Yamaha console config XML")
        elif '<backup' in sample.lower():
            return ("yamaha_backup_xml", ".xml", "Yamaha backup XML")
        elif '<scene' in sample.lower():
            return ("yamaha_scene_xml", ".xml", "Yamaha scene XML")
        elif '<project' in sample.lower():
            return ("yamaha_project_xml", ".xml", "Yamaha project XML")
        elif 'RIVAGE' in sample or 'rivage' in sample.lower():
            return ("yamaha_rivage_xml", ".xml", "Yamaha Rivage XML")
        
        return ("xml", ".xml", "XML document")
    except Exception:
        return ("xml", ".xml", "XML document")


def _detect_rtos(data: bytes) -> Optional[Tuple[str, str, str]]:
    """Detect RTOS signatures in firmware data."""
    # Check first 64KB for RTOS patterns
    sample = data[:65536]
    
    for pattern, rtos_name in RTOS_PATTERNS:
        if pattern in sample:
            return (rtos_name.lower().replace(' ', '_'), ".rtos", f"{rtos_name} firmware")
    
    # Check for ARM exception vector table (common in RTOS)
    if len(data) >= 32:
        # ARM vector table typically has branch instructions
        # Check for ARM mode (word-aligned branches)
        first_word = struct.unpack('<I', data[:4])[0]
        if (first_word & 0xff000000) == 0xea000000:  # ARM branch
            return ("arm_firmware", ".arm", "ARM firmware (possible RTOS)")
        
        # Check for Thumb mode
        first_halfword = struct.unpack('<H', data[:2])[0]
        if (first_halfword & 0xf800) == 0xf000:  # Thumb-2 branch
            return ("arm_thumb_firmware", ".arm", "ARM Thumb firmware (possible RTOS)")
    
    # Check for common firmware patterns
    if b'\xff' * 16 in data[:256] or b'\x00' * 16 in data[:256]:
        # Padding typical of firmware images
        arch = _detect_architecture(data)
        if arch:
            return (f"{arch}_firmware", ".fw", f"{arch} firmware image")
    
    return None


def _analyze_dnt(data: bytes) -> Tuple[str, str, str]:
    """Analyze an Audinate Dante firmware file."""
    if len(data) < 176:
        return ("dante_firmware_truncated", ".dnt", "Truncated Dante firmware file")
    
    try:
        # Get header size
        header_size = struct.unpack('>I', data[4:8])[0]
        
        # Look for manufacturer
        manufacturer = "Unknown"
        if b'Yamaha' in data[:256]:
            manufacturer = "Yamaha"
        elif b'Audinate' in data[:256]:
            manufacturer = "Audinate"
        
        # Look for bootloader identifier
        bootloader = ""
        uboot_pos = data.find(b'Audinate U-boot', 0, 256)
        if uboot_pos != -1:
            bootloader = " (U-boot)"
        
        return ("dante_firmware", ".dnt", f"Audinate Dante {manufacturer} firmware{bootloader}")
    except Exception:
        return ("dante_firmware", ".dnt", "Audinate Dante firmware file")


def _detect_raw_firmware(data: bytes) -> Optional[Tuple[str, str, str]]:
    """
    Detect raw firmware files that aren't in a container format.
    
    These are firmware images that aren't wrapped in Yamaha MBDFArchive or other
    container formats, but are still firmware (DSP code, microcontroller code, etc.).
    
    Common patterns:
    - Version string at start (e.g., "V590 ")
    - ARM vector table
    - DSP code with specific patterns
    """
    if len(data) < 16:
        return None
    
    # Check for version string at start (common in Yamaha firmware)
    # Pattern: V### or version number
    first_16 = data[:16]
    
    # Check for "V###" version pattern at start (e.g., "V590 ")
    if first_16[0:1] == b'V' and len(first_16) >= 4:
        # Check if next chars are digits
        version_chars = first_16[1:4]
        if all(chr(b).isdigit() for b in version_chars):
            version = first_16[:5].decode('ascii', errors='ignore').strip()
            return ("raw_firmware_versioned", ".bin", f"Raw firmware image ({version})")
    
    # Check for ARM Cortex-M vector table
    # Cortex-M starts with SP (stack pointer) and Reset vector
    # SP is usually a RAM address (0x20xxxxxx for STM32, etc.)
    # Reset vector is usually Flash address (0x08xxxxxx or 0x00xxxxxx)
    if len(data) >= 8:
        sp = struct.unpack('<I', data[0:4])[0]
        reset_vec = struct.unpack('<I', data[4:8])[0]
        
        # Check for typical Cortex-M SP and reset vector patterns
        if (0x10000000 <= sp <= 0x30000000) and (reset_vec & 0xFFF00000 in [0x00000000, 0x08000000, 0x00800000]):
            return ("arm_cortex_m_firmware", ".bin", "ARM Cortex-M firmware image")
    
    # Check for Motorola DSP56xxx patterns (common in Yamaha products)
    # Look for DSP-like instruction patterns
    
    # Check for SuperH (SH4) reset vector patterns
    # SH4 has reset vector at 0xA0000000
    if len(data) >= 4:
        # SH4 first instruction is often MOV.L or BRA
        first_inst = struct.unpack('>H', data[0:2])[0]
        if (first_inst & 0xF000) in [0x7000, 0xA000, 0xD000, 0xE000]:
            # Check for more SH patterns
            if b'SH4' in data[:1024] or b'SH-4' in data[:1024] or b'SuperH' in data[:1024]:
                return ("sh4_firmware", ".bin", "SuperH SH4 firmware image")
    
    # Check for Yamaha-specific firmware patterns
    # CL/QL series firmware often has specific headers
    if len(data) >= 64:
        # Look for typical Yamaha DSP patterns
        if data[12:16] == b'0009' or b'K+\x00\x09' in data[:64]:
            return ("yamaha_dsp_firmware", ".bin", "Yamaha DSP firmware image")
    
    return None


def _detect_architecture(data: bytes) -> Optional[str]:
    """Detect CPU architecture from binary patterns."""
    for pattern, arch_name in ARCH_PATTERNS:
        if pattern in data[:1024]:
            return arch_name
    return None


def _is_likely_json(data: bytes) -> bool:
    """Check if data is likely valid JSON."""
    try:
        import json as json_module
        sample = data[:10000].decode('utf-8', errors='ignore').strip()
        json_module.loads(sample)
        return True
    except Exception:
        return False


def get_extension_for_file(data: bytes, original_name: str = "") -> str:
    """
    Get the appropriate file extension based on content inspection.
    
    Args:
        data: File content
        original_name: Original filename (used as fallback)
    
    Returns:
        Appropriate file extension (including the dot)
    """
    file_type, ext, _ = detect_file_type(data)
    
    # If we detected a specific type, use that extension
    if ext != ".bin" or not original_name:
        return ext
    
    # Fallback to original extension if we couldn't detect type
    original_ext = Path(original_name).suffix
    if original_ext:
        return original_ext
    
    return ext


def fix_file_extension(filepath: Path, data: bytes, log_cb: Callable[[str], None] = None) -> Path:
    """
    Check file content and rename with correct extension if needed.
    
    Args:
        filepath: Current file path
        data: File content
        log_cb: Optional logging callback
    
    Returns:
        New file path (may be same as input if no change needed)
    """
    file_type, correct_ext, description = detect_file_type(data)
    current_ext = filepath.suffix.lower()
    
    # Don't change if already correct or if it's a generic type
    if current_ext == correct_ext.lower():
        return filepath
    
    # Don't change .bin to .bin
    if correct_ext == ".bin":
        return filepath
    
    # Create new path with correct extension
    new_name = filepath.stem + correct_ext
    new_path = filepath.parent / new_name
    
    # Handle conflicts
    if new_path.exists() and new_path != filepath:
        k = 1
        while True:
            candidate = filepath.parent / f"{filepath.stem}_{k}{correct_ext}"
            if not candidate.exists():
                new_path = candidate
                break
            k += 1
    
    # Rename the file
    if new_path != filepath:
        try:
            filepath.rename(new_path)
            if log_cb:
                log_cb(f"  [RENAME] {filepath.name} -> {new_path.name} ({description})")
            return new_path
        except Exception as e:
            if log_cb:
                log_cb(f"  [WARN] Could not rename {filepath.name}: {e}")
    
    return filepath


@dataclass
class EmbeddedFile:
    name: str
    start_offset: int
    end_offset: int
    marker_offset: int
    marker: bytes


def _safe_output_name(stored_name: str) -> str:
    base = stored_name.replace("\\", "/").split("/")[-1]
    if not base:
        base = "payload.bin"
    base = re.sub(r"[^A-Za-z0-9._+-]+", "_", base)
    return base


def _safe_folder_name(filename: str) -> str:
    name = Path(filename).name
    name = re.sub(r"[^A-Za-z0-9._+-]+", "_", name).strip("._ ")
    return name or "nested"


def _find_next_marker(data: bytes, start: int) -> Optional[Tuple[int, bytes]]:
    best_off = None
    best_m = None
    for m in MARKERS:
        off = data.find(m, start)
        if off != -1 and (best_off is None or off < best_off):
            best_off = off
            best_m = m
    if best_off is None:
        return None
    return best_off, best_m  # type: ignore


def _find_zlib_start(data: bytes, start: int, end: int, max_scan: int = 1024 * 1024) -> Optional[int]:
    scan_end = min(end, start + max_scan)
    window = data[start:scan_end]

    best = None
    for zh in ZLIB_HEADS:
        p = window.find(zh)
        if p != -1:
            best = p if best is None else min(best, p)
    for zh in ZLIB_HEADS_PADDED:
        p = window.find(zh)
        if p != -1:
            best = p if best is None else min(best, p)

    if best is None:
        return None
    return start + best


def _extract_printable_label(data: bytes, start: int, end: int, max_scan: int = 1024) -> Optional[str]:
    scan_end = min(end, start + max_scan)
    chunk = data[start:scan_end]

    m = re.search(rb"/[A-Za-z0-9._+-]{3,120}", chunk)
    if m:
        return m.group(0).decode("utf-8", errors="replace")

    m2 = re.search(rb"[A-Za-z0-9][A-Za-z0-9._+-]{6,120}", chunk)
    if m2:
        return m2.group(0).decode("utf-8", errors="replace")

    return None


def _try_decrypt_filename(raw_bytes: bytes) -> Optional[str]:
    """
    Try to decrypt a filename that may be XOR encrypted.
    
    Returns the decrypted filename or None if decryption fails.
    """
    if not raw_bytes or len(raw_bytes) < 2:
        return None
    
    # Strip trailing null bytes for analysis
    raw_bytes = raw_bytes.rstrip(b"\x00")
    if not raw_bytes:
        return None
    
    # First check if it's already a valid filename
    try:
        # Check if it's valid UTF-8 and looks like a filename
        test_decode = raw_bytes.decode("utf-8", errors="strict")
        # Check if most characters are printable
        printable_count = sum(1 for c in test_decode if c.isprintable() or c in "/-_.")
        if len(test_decode) > 2 and printable_count / len(test_decode) > 0.8:
            # Looks like a valid filename already
            return test_decode
    except Exception:
        pass
    
    # Try XOR decryption with known keys
    for xor_key in KNOWN_XOR_KEYS:
        if xor_key == 0:
            continue
        
        decrypted = bytes(b ^ xor_key for b in raw_bytes)
        
        try:
            name = decrypted.decode("utf-8", errors="strict")
            # Verify it looks like a valid filename
            printable_count = sum(1 for c in name if c.isprintable() or c in "/-_.")
            if len(name) > 2 and printable_count / len(name) > 0.8:
                # Additional validation: look for common filename patterns
                if any(ext in name.lower() for ext in ['.dll', '.exe', '.sys', '.xml', '.bin', '.txt', '.dat', '.cfg']):
                    return "/" + name if not name.startswith("/") else name
                elif name.startswith("/"):
                    return name
                # If it looks like a reasonable name, accept it
                if re.match(r'^[\w\-./]+$', name):
                    return "/" + name
        except Exception:
            continue
    
    # Try brute force - check each key 1-255 to find one that produces valid text
    best_name = None
    best_score = 0
    
    for key in range(1, 256):
        if key in KNOWN_XOR_KEYS:
            continue
        
        decrypted = bytes(b ^ key for b in raw_bytes)
        
        try:
            name = decrypted.decode("utf-8", errors="strict")
            # Score based on printable characters and valid filename chars
            score = sum(1 for c in name if c.isalnum() or c in "/-_.")
            if score > best_score and score / len(name) > 0.8:
                best_score = score
                best_name = name
        except Exception:
            continue
    
    if best_name and best_score / len(best_name) > 0.85:
        return "/" + best_name if not best_name.startswith("/") else best_name
    
    return None


def _guess_name_from_file_block(data: bytes, name_start: int, block_end: int) -> Tuple[Optional[str], Optional[int]]:
    scan_end = min(block_end, name_start + 512)
    window = data[name_start:scan_end]

    # First find where the payload (zlib) starts
    zlib_pos = None
    for zh in ZLIB_HEADS:
        pos = window.find(zh)
        if pos != -1:
            if zlib_pos is None or pos < zlib_pos:
                zlib_pos = pos
    
    for zh in ZLIB_HEADS_PADDED:
        pos = window.find(zh)
        if pos != -1:
            actual_pos = pos + 1  # Skip the padding byte
            if zlib_pos is None or actual_pos < zlib_pos:
                zlib_pos = actual_pos
    
    if zlib_pos is None:
        # No zlib header found, try to find null terminator
        nul = window.find(b"\x00")
        if nul != -1 and nul > 0:
            raw_name = window[:nul]
            name = _try_decrypt_filename(raw_name)
            if name:
                # Need to find actual payload start
                return name, None
        return None, None
    
    # Name bytes are before zlib header
    raw_name = window[:zlib_pos]
    
    # Remove any trailing nulls or padding
    raw_name = raw_name.rstrip(b"\x00")
    
    if not raw_name:
        return None, None
    
    # Try to decrypt/decode the filename
    name = _try_decrypt_filename(raw_name)
    
    if name:
        payload_start = name_start + zlib_pos
        return name, payload_start
    
    return None, None


def _decompress_zlib_member(data: bytes, start: int, end: int) -> Tuple[bytes, int]:
    blob = data[start:end]

    if len(blob) >= 3 and blob[0] == 0x00 and blob[1:3] in ZLIB_HEADS:
        start += 1
        blob = data[start:end]

    decomp = zlib.decompressobj()
    out = decomp.decompress(blob)
    out += decomp.flush()

    if not decomp.eof:
        raise zlib.error("zlib stream did not reach EOF within block bounds")

    compressed_len = len(blob) - len(decomp.unused_data)
    compressed_end = start + compressed_len
    return out, compressed_end


def _is_mbdf_archive_bytes(b: bytes) -> bool:
    """Check if data is a Yamaha MBDF archive (handles encrypted archives too)."""
    if not b or len(b) < 50:
        return False
    # Check unencrypted
    if MAGIC_ARCHIVE in b[:2048]:
        return True
    # Check if XOR encrypted - try to detect
    return is_yamaha_archive(b)


def parse_mbdf_archive(data: bytes) -> List[EmbeddedFile]:
    embedded: List[EmbeddedFile] = []
    cursor = 0
    firmware_counter = 0

    while True:
        hit = _find_next_marker(data, cursor)
        if hit is None:
            break

        m_off, marker = hit

        if marker == MAGIC_FILE:
            if m_off + FILE_HDR_LEN + 1 >= len(data):
                cursor = m_off + len(marker)
                continue

            next_hit = _find_next_marker(data, m_off + 1)
            block_bound = next_hit[0] if next_hit is not None else len(data)

            name_start = m_off + FILE_HDR_LEN
            name, payload_guess = _guess_name_from_file_block(data, name_start, block_bound)
            if not name or payload_guess is None:
                cursor = m_off + len(marker)
                continue

            zstart = _find_zlib_start(data, payload_guess, len(data), max_scan=64 * 1024)
            if zstart is None:
                cursor = m_off + len(marker)
                continue

            try:
                _payload, z_end = _decompress_zlib_member(data, zstart, len(data))
            except zlib.error:
                cursor = m_off + len(marker)
                continue

            embedded.append(
                EmbeddedFile(
                    name=name,
                    start_offset=zstart,
                    end_offset=z_end,
                    marker_offset=m_off,
                    marker=marker,
                )
            )
            cursor = z_end
            continue

        if marker == MAGIC_FIRMWARE:
            scan_start = m_off + len(MAGIC_FIRMWARE)

            label = _extract_printable_label(data, scan_start, min(len(data), scan_start + 4096))
            if not label:
                firmware_counter += 1
                label = f"/FIRMWARE_{firmware_counter:04d}.bin"

            zstart = _find_zlib_start(data, scan_start, len(data), max_scan=1024 * 1024)
            if zstart is None:
                cursor = m_off + len(marker)
                continue

            try:
                _payload, z_end = _decompress_zlib_member(data, zstart, len(data))
            except zlib.error:
                cursor = m_off + len(marker)
                continue

            embedded.append(
                EmbeddedFile(
                    name=label,
                    start_offset=zstart,
                    end_offset=z_end,
                    marker_offset=m_off,
                    marker=marker,
                )
            )
            cursor = z_end
            continue

        cursor = m_off + len(marker)

    return embedded


def extract_one(data: bytes, ef: EmbeddedFile) -> bytes:
    payload, _ = _decompress_zlib_member(data, ef.start_offset, ef.end_offset)
    return payload


def extract_archive_bytes_to_folder(data: bytes, outdir: Path, log_cb: Callable[[str], None], 
                                    decrypt_content: bool = True, 
                                    max_depth: int = 5, current_depth: int = 0) -> None:
    """
    Recursively extract archive contents with smart decryption.
    
    Args:
        data: Archive data (may be encrypted)
        outdir: Output directory
        log_cb: Logging callback function
        decrypt_content: Whether to auto-decrypt extracted content
        max_depth: Maximum recursion depth for nested archives
        current_depth: Current recursion depth (internal use)
    """
    if current_depth >= max_depth:
        log_cb(f"  [WARN] Max recursion depth ({max_depth}) reached, stopping")
        return
    
    outdir.mkdir(parents=True, exist_ok=True)
    
    # Smart decrypt the archive data first
    decrypted_data, layers = recursive_smart_decrypt(data)
    if layers:
        for key, desc in layers:
            log_cb(f"  [DECRYPT] Archive layer: {desc}")
        data = decrypted_data

    embedded = parse_mbdf_archive(data)
    log_cb(f"  {'  ' * current_depth}Archive: found {len(embedded)} embedded block(s).")

    for ef in embedded:
        safe = _safe_output_name(ef.name)
        out_path = outdir / safe

        if out_path.exists():
            stem = out_path.stem
            suf = out_path.suffix
            k = 1
            while True:
                candidate = outdir / f"{stem}_{k}{suf}"
                if not candidate.exists():
                    out_path = candidate
                    break
                k += 1

        try:
            payload = extract_one(data, ef)
        except zlib.error as e:
            raw_path = outdir / (out_path.name + ".raw")
            try:
                raw_path.write_bytes(data[ef.start_offset:ef.end_offset])
                log_cb(f"  [ERROR] zlib failed for {ef.name}: {e} (wrote {raw_path.name})")
            except Exception as we:
                log_cb(f"  [ERROR] zlib failed for {ef.name}: {e} (also failed writing raw: {we})")
            continue

        # Smart decrypt content
        if decrypt_content:
            payload, content_layers = recursive_smart_decrypt(payload)
            if content_layers:
                for key, desc in content_layers:
                    log_cb(f"  [DECRYPT] Content: {desc}")

        # Detect file type and get proper extension
        file_type, proper_ext, type_desc = detect_file_type(payload)
        
        # Update output path with proper extension if needed
        if proper_ext != ".bin" and not out_path.suffix.lower() == proper_ext.lower():
            new_name = out_path.stem + proper_ext
            out_path = outdir / new_name
            # Handle conflicts again
            if out_path.exists():
                k = 1
                while True:
                    candidate = outdir / f"{out_path.stem}_{k}{proper_ext}"
                    if not candidate.exists():
                        out_path = candidate
                        break
                    k += 1

        out_path.write_bytes(payload)
        log_cb(f"  [OK] {ef.name} -> {out_path.name} ({len(payload):,} bytes) [{type_desc}]")
        
        # Deep extraction: handle different extractable types
        extracted_nested = False
        
        # 1. Recursively extract nested Yamaha archives
        if _is_mbdf_archive_bytes(payload):
            subfolder = outdir / (_safe_folder_name(out_path.name) + "_extracted")
            log_cb(f"  {'  ' * current_depth}Detected nested Yamaha archive in {out_path.name} -> {subfolder.name}/")
            try:
                extract_archive_bytes_to_folder(
                    payload, subfolder, log_cb, 
                    decrypt_content=decrypt_content,
                    max_depth=max_depth,
                    current_depth=current_depth + 1
                )
                extracted_nested = True
            except Exception as e:
                log_cb(f"  [ERROR] Nested Yamaha extraction failed: {e}")
        
        # 2. Handle ZIP archives
        if not extracted_nested and file_type in ("zip", "zip_empty"):
            subfolder = outdir / (_safe_folder_name(out_path.name) + "_unzipped")
            log_cb(f"  {'  ' * current_depth}Detected ZIP archive in {out_path.name} -> {subfolder.name}/")
            try:
                extract_zip_to_folder(payload, subfolder, log_cb, decrypt_content, max_depth, current_depth + 1)
                extracted_nested = True
            except Exception as e:
                log_cb(f"  [ERROR] ZIP extraction failed: {e}")
        
        # 3. Try to decompress raw zlib data
        if not extracted_nested and file_type == "zlib":
            try:
                decompressed = zlib.decompress(payload)
                decomp_path = outdir / (out_path.stem + "_decompressed.bin")
                decompressed, _ = recursive_smart_decrypt(decompressed)
                
                # Detect type of decompressed content
                decomp_type, decomp_ext, decomp_desc = detect_file_type(decompressed)
                if decomp_ext != ".bin":
                    decomp_path = outdir / (out_path.stem + "_decompressed" + decomp_ext)
                
                decomp_path.write_bytes(decompressed)
                log_cb(f"  [DECOMPRESS] {out_path.name} -> {decomp_path.name} ({len(decompressed):,} bytes) [{decomp_desc}]")
                
                # Recursively process decompressed content
                if _is_mbdf_archive_bytes(decompressed):
                    subfolder = outdir / (_safe_folder_name(decomp_path.name) + "_extracted")
                    try:
                        extract_archive_bytes_to_folder(
                            decompressed, subfolder, log_cb,
                            decrypt_content=decrypt_content,
                            max_depth=max_depth,
                            current_depth=current_depth + 1
                        )
                    except Exception as e:
                        log_cb(f"  [ERROR] Decompressed archive extraction failed: {e}")
            except Exception:
                pass  # Not valid zlib or decompression failed


def extract_zip_to_folder(data: bytes, outdir: Path, log_cb: Callable[[str], None],
                          decrypt_content: bool = True, max_depth: int = 5, 
                          current_depth: int = 0) -> None:
    """
    Extract ZIP archive contents with recursive processing.
    
    Args:
        data: ZIP file content
        outdir: Output directory
        log_cb: Logging callback
        decrypt_content: Whether to auto-decrypt content
        max_depth: Maximum recursion depth
        current_depth: Current recursion depth
    """
    if current_depth >= max_depth:
        log_cb(f"  [WARN] Max recursion depth ({max_depth}) reached in ZIP extraction")
        return
    
    outdir.mkdir(parents=True, exist_ok=True)
    
    try:
        with zipfile.ZipFile(io.BytesIO(data), 'r') as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                
                try:
                    file_data = zf.read(info.filename)
                except Exception as e:
                    log_cb(f"  [ERROR] Failed to read {info.filename} from ZIP: {e}")
                    continue
                
                # Smart decrypt
                if decrypt_content:
                    file_data, layers = recursive_smart_decrypt(file_data)
                    if layers:
                        for key, desc in layers:
                            log_cb(f"  [DECRYPT] ZIP content: {desc}")
                
                # Get safe output name
                safe_name = _safe_output_name(info.filename)
                
                # Detect file type
                file_type, proper_ext, type_desc = detect_file_type(file_data)
                if proper_ext != ".bin":
                    safe_name = Path(safe_name).stem + proper_ext
                
                out_path = outdir / safe_name
                
                # Handle conflicts
                if out_path.exists():
                    k = 1
                    while True:
                        candidate = outdir / f"{out_path.stem}_{k}{out_path.suffix}"
                        if not candidate.exists():
                            out_path = candidate
                            break
                        k += 1
                
                out_path.write_bytes(file_data)
                log_cb(f"  [ZIP] {info.filename} -> {out_path.name} ({len(file_data):,} bytes) [{type_desc}]")
                
                # Recursively process extracted content
                if _is_mbdf_archive_bytes(file_data):
                    subfolder = outdir / (_safe_folder_name(out_path.name) + "_extracted")
                    log_cb(f"  Detected nested Yamaha archive in ZIP: {out_path.name}")
                    try:
                        extract_archive_bytes_to_folder(
                            file_data, subfolder, log_cb,
                            decrypt_content=decrypt_content,
                            max_depth=max_depth,
                            current_depth=current_depth + 1
                        )
                    except Exception as e:
                        log_cb(f"  [ERROR] Nested extraction from ZIP failed: {e}")
                
                elif file_type in ("zip", "zip_empty"):
                    subfolder = outdir / (_safe_folder_name(out_path.name) + "_unzipped")
                    log_cb(f"  Detected nested ZIP in ZIP: {out_path.name}")
                    try:
                        extract_zip_to_folder(
                            file_data, subfolder, log_cb,
                            decrypt_content=decrypt_content,
                            max_depth=max_depth,
                            current_depth=current_depth + 1
                        )
                    except Exception as e:
                        log_cb(f"  [ERROR] Nested ZIP extraction failed: {e}")
                        
    except zipfile.BadZipFile as e:
        log_cb(f"  [ERROR] Invalid ZIP file: {e}")
    except Exception as e:
        log_cb(f"  [ERROR] ZIP extraction error: {e}")


def extract_xz_to_folder(data: bytes, outdir: Path, log_cb: Callable[[str], None],
                         decrypt_content: bool = True, max_depth: int = 5,
                         current_depth: int = 0) -> None:
    """
    Extract XZ-compressed data with recursive processing.
    
    Args:
        data: XZ-compressed content
        outdir: Output directory
        log_cb: Logging callback
        decrypt_content: Whether to auto-decrypt content
        max_depth: Maximum recursion depth
        current_depth: Current recursion depth
    """
    if current_depth >= max_depth:
        log_cb(f"  [WARN] Max recursion depth ({max_depth}) reached in XZ extraction")
        return
    
    outdir.mkdir(parents=True, exist_ok=True)
    
    try:
        decompressed = lzma.decompress(data)
        log_cb(f"  [XZ] Decompressed {len(data):,} -> {len(decompressed):,} bytes")
        
        # Detect type of decompressed content
        file_type, proper_ext, type_desc = detect_file_type(decompressed)
        
        # Check if it's a TAR archive
        if decompressed[:2] == b'./' or decompressed[:5] == b'ustar' or _is_tar_archive(decompressed):
            log_cb(f"  [XZ] Detected TAR archive inside XZ")
            extract_tar_to_folder(
                decompressed, outdir, log_cb,
                decrypt_content=decrypt_content,
                max_depth=max_depth,
                current_depth=current_depth + 1
            )
        elif _is_mbdf_archive_bytes(decompressed):
            log_cb(f"  [XZ] Detected Yamaha archive inside XZ")
            extract_archive_bytes_to_folder(
                decompressed, outdir, log_cb,
                decrypt_content=decrypt_content,
                max_depth=max_depth,
                current_depth=current_depth + 1
            )
        elif file_type in ("zip", "zip_empty"):
            log_cb(f"  [XZ] Detected ZIP archive inside XZ")
            extract_zip_to_folder(
                decompressed, outdir, log_cb,
                decrypt_content=decrypt_content,
                max_depth=max_depth,
                current_depth=current_depth + 1
            )
        else:
            # Save decompressed content
            out_path = outdir / f"decompressed{proper_ext}"
            out_path.write_bytes(decompressed)
            log_cb(f"  [XZ] Saved decompressed content -> {out_path.name} ({len(decompressed):,} bytes) [{type_desc}]")
            
    except lzma.LZMAError as e:
        log_cb(f"  [ERROR] XZ decompression failed: {e}")
    except Exception as e:
        log_cb(f"  [ERROR] XZ extraction error: {e}")


def _is_tar_archive(data: bytes) -> bool:
    """Check if data is a TAR archive."""
    if len(data) < 512:
        return False
    
    # Check for TAR magic at offset 257
    if len(data) > 262 and data[257:262] == b'ustar':
        return True
    
    # Check if first bytes look like TAR header (path starting with ./)
    if data[:2] == b'./':
        return True
    
    # Check for valid TAR header
    try:
        # Try to parse as TAR
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as tf:
            # Just try to get the first member
            members = tf.getmembers()
            return len(members) > 0
    except Exception:
        return False


def extract_tar_to_folder(data: bytes, outdir: Path, log_cb: Callable[[str], None],
                          decrypt_content: bool = True, max_depth: int = 5,
                          current_depth: int = 0) -> None:
    """
    Extract TAR archive contents with recursive processing.
    
    Args:
        data: TAR archive content
        outdir: Output directory
        log_cb: Logging callback
        decrypt_content: Whether to auto-decrypt content
        max_depth: Maximum recursion depth
        current_depth: Current recursion depth
    """
    if current_depth >= max_depth:
        log_cb(f"  [WARN] Max recursion depth ({max_depth}) reached in TAR extraction")
        return
    
    outdir.mkdir(parents=True, exist_ok=True)
    
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:*') as tf:
            for member in tf.getmembers():
                if member.isdir():
                    continue
                
                try:
                    file_data = tf.extractfile(member)
                    if file_data is None:
                        continue
                    file_content = file_data.read()
                except Exception as e:
                    log_cb(f"  [ERROR] Failed to read {member.name} from TAR: {e}")
                    continue
                
                # Smart decrypt if enabled
                if decrypt_content:
                    file_content, layers = recursive_smart_decrypt(file_content)
                    if layers:
                        for key, desc in layers:
                            log_cb(f"  [DECRYPT] TAR content: {desc}")
                
                # Get safe output name
                safe_name = _safe_output_name(member.name)
                
                # Detect file type
                file_type, proper_ext, type_desc = detect_file_type(file_content)
                if proper_ext != ".bin":
                    safe_name = Path(safe_name).stem + proper_ext
                
                out_path = outdir / safe_name
                
                # Handle conflicts
                if out_path.exists():
                    k = 1
                    while True:
                        candidate = outdir / f"{out_path.stem}_{k}{out_path.suffix}"
                        if not candidate.exists():
                            out_path = candidate
                            break
                        k += 1
                
                out_path.write_bytes(file_content)
                log_cb(f"  [TAR] {member.name} -> {out_path.name} ({len(file_content):,} bytes) [{type_desc}]")
                
                # Recursively process extracted content
                if _is_mbdf_archive_bytes(file_content):
                    subfolder = outdir / (_safe_folder_name(out_path.name) + "_extracted")
                    log_cb(f"  Detected nested Yamaha archive in TAR: {out_path.name}")
                    try:
                        extract_archive_bytes_to_folder(
                            file_content, subfolder, log_cb,
                            decrypt_content=decrypt_content,
                            max_depth=max_depth,
                            current_depth=current_depth + 1
                        )
                    except Exception as e:
                        log_cb(f"  [ERROR] Nested extraction from TAR failed: {e}")
                
                elif file_type in ("zip", "zip_empty"):
                    subfolder = outdir / (_safe_folder_name(out_path.name) + "_unzipped")
                    log_cb(f"  Detected nested ZIP in TAR: {out_path.name}")
                    try:
                        extract_zip_to_folder(
                            file_content, subfolder, log_cb,
                            decrypt_content=decrypt_content,
                            max_depth=max_depth,
                            current_depth=current_depth + 1
                        )
                    except Exception as e:
                        log_cb(f"  [ERROR] Nested ZIP extraction failed: {e}")
                
                elif file_type == "xz":
                    subfolder = outdir / (_safe_folder_name(out_path.name) + "_xz_extracted")
                    log_cb(f"  Detected nested XZ in TAR: {out_path.name}")
                    try:
                        extract_xz_to_folder(
                            file_content, subfolder, log_cb,
                            decrypt_content=decrypt_content,
                            max_depth=max_depth,
                            current_depth=current_depth + 1
                        )
                    except Exception as e:
                        log_cb(f"  [ERROR] Nested XZ extraction failed: {e}")
                        
    except tarfile.TarError as e:
        log_cb(f"  [ERROR] Invalid TAR file: {e}")
    except Exception as e:
        log_cb(f"  [ERROR] TAR extraction error: {e}")


# =============================================================================
# DNT (AUDINATE DANTE) FIRMWARE EXTRACTION
# =============================================================================

@dataclass
class DntSection:
    """Represents a section in a DNT firmware file."""
    section_type: int
    flags: int
    offset: int
    size: int
    name: str = ""


def is_dnt_file(data: bytes) -> bool:
    """Check if data is an Audinate Dante firmware file (.dnt)."""
    return len(data) >= 4 and data[:4] == MAGIC_DNT


def parse_dnt_header(data: bytes) -> Tuple[Dict[str, Any], List[DntSection]]:
    """
    Parse the header of a DNT (Audinate Dante) firmware file.
    
    DNT files contain:
    - AUDI magic header
    - Header size at offset 0x04 (big-endian)
    - Manufacturer string (e.g., "Yamaha")
    - Section table with offset/size entries
    - U-Boot bootloader sections
    - Application firmware sections (compressed)
    - File system sections
    
    Args:
        data: Raw DNT file data
    
    Returns:
        Tuple of (header_info dict, list of DntSection objects)
    """
    if not is_dnt_file(data):
        raise ValueError("Not a valid DNT file (missing AUDI magic)")
    
    header_info = {
        "magic": data[:4].decode('ascii'),
        "header_size": struct.unpack('>I', data[4:8])[0],
        "file_size": len(data),
    }
    
    header_size = header_info["header_size"]
    
    # Extract manufacturer string (at offset ~0x1c, after some header fields)
    # Looking for "Yamaha" or other manufacturer
    mfg_pos = data.find(b'Yamaha', 0, header_size)
    if mfg_pos != -1:
        header_info["manufacturer"] = "Yamaha"
    else:
        # Try to find any manufacturer string
        mfg_pos = data.find(b'Audinate', 0, header_size)
        if mfg_pos != -1:
            header_info["manufacturer"] = "Audinate"
        else:
            header_info["manufacturer"] = "Unknown"
    
    # Find product code/model (usually right before U-boot identifier at 0xd0)
    # At offset 0xa0-0xa8 there's often a product identifier
    if len(data) >= 0xa8:
        product_bytes = data[0xa0:0xa8].rstrip(b'\x00')
        if product_bytes and all(32 <= b < 127 for b in product_bytes):
            header_info["product_code"] = product_bytes.decode('ascii', errors='ignore')
    
    # Look for U-Boot string as description
    uboot_pos = data.find(b'Audinate U-boot', 0, 256)
    if uboot_pos != -1:
        uboot_end = data.find(b'\x00', uboot_pos)
        if uboot_end != -1:
            header_info["bootloader"] = data[uboot_pos:uboot_end].decode('ascii', errors='ignore')
    
    # Parse section table (starting at 0x40 with 16-byte entries)
    sections = []
    
    # The section table format (big-endian):
    # - bytes 0-3: section type/ID
    # - bytes 4-7: flags/version  
    # - bytes 8-11: offset in file
    # - bytes 12-15: size
    
    pos = 0x40
    section_num = 0
    while pos < header_size - 16:
        entry = struct.unpack('>IIII', data[pos:pos+16])
        section_type, flags, offset, size = entry
        
        # Check for valid section (non-zero type, valid offset/size within file)
        if section_type != 0 and offset < len(data) and size > 0 and offset + size <= len(data):
            section_num += 1
            
            # Determine section name based on type and content
            section_name = f"section_{section_num}"
            
            # Check content at offset for better naming
            if offset < len(data):
                sample = data[offset:offset+64]
                if b'U-Boot' in sample or b'uboot' in sample.lower():
                    section_name = f"uboot_{section_num}"
                elif sample[:2] == b'\x7fE':  # ELF
                    section_name = f"elf_{section_num}"
                elif sample[:2] in ZLIB_HEADS:
                    section_name = f"compressed_{section_num}"
                elif sample == b'\xff' * 64:
                    section_name = f"blank_{section_num}"
                elif sample == b'\x00' * 64:
                    section_name = f"padding_{section_num}"
            
            sections.append(DntSection(
                section_type=section_type,
                flags=flags,
                offset=offset,
                size=size,
                name=section_name
            ))
        
        pos += 16
        
        # Stop after finding reasonable number of sections
        if section_num >= 10:
            break
    
    header_info["section_count"] = len(sections)
    
    return header_info, sections


def extract_dnt_to_folder(data: bytes, outdir: Path, log_cb: Callable[[str], None],
                          decrypt_content: bool = True, max_depth: int = 5,
                          current_depth: int = 0) -> None:
    """
    Extract Audinate Dante firmware (.dnt) file contents.
    
    DNT files contain multiple sections including:
    - U-Boot bootloader
    - Compressed application firmware
    - File system data
    - Configuration data
    
    Args:
        data: DNT file content
        outdir: Output directory
        log_cb: Logging callback
        decrypt_content: Whether to auto-decrypt content
        max_depth: Maximum recursion depth
        current_depth: Current recursion depth
    """
    if current_depth >= max_depth:
        log_cb(f"  [WARN] Max recursion depth ({max_depth}) reached in DNT extraction")
        return
    
    outdir.mkdir(parents=True, exist_ok=True)
    
    try:
        header_info, sections = parse_dnt_header(data)
        
        log_cb(f"  [DNT] Audinate Dante firmware file")
        log_cb(f"  [DNT] Manufacturer: {header_info.get('manufacturer', 'Unknown')}")
        log_cb(f"  [DNT] Header size: {header_info['header_size']} bytes")
        log_cb(f"  [DNT] Sections found: {len(sections)}")
        
        if header_info.get('bootloader'):
            log_cb(f"  [DNT] Bootloader: {header_info['bootloader']}")
        if header_info.get('product_code'):
            log_cb(f"  [DNT] Product: {header_info['product_code']}")
        
        # Save header info
        header_path = outdir / "dnt_header_info.json"
        with open(header_path, 'w') as f:
            json.dump({
                **header_info,
                "sections": [{"type": s.section_type, "flags": s.flags, 
                             "offset": s.offset, "size": s.size, "name": s.name}
                            for s in sections]
            }, f, indent=2)
        log_cb(f"  [OK] Header info -> dnt_header_info.json")
        
        # Extract each section
        for section in sections:
            if section.size == 0:
                continue
            
            section_data = data[section.offset:section.offset + section.size]
            
            # Skip blank/padding sections
            if section_data == b'\xff' * len(section_data) or section_data == b'\x00' * len(section_data):
                log_cb(f"  [SKIP] {section.name}: blank/padding section ({section.size:,} bytes)")
                continue
            
            # Detect file type
            file_type, proper_ext, type_desc = detect_file_type(section_data)
            
            # Generate output filename
            out_name = f"{section.name}{proper_ext}"
            out_path = outdir / out_name
            
            # Handle conflicts
            if out_path.exists():
                k = 1
                while True:
                    candidate = outdir / f"{section.name}_{k}{proper_ext}"
                    if not candidate.exists():
                        out_path = candidate
                        break
                    k += 1
            
            # Save section
            out_path.write_bytes(section_data)
            log_cb(f"  [OK] {section.name} @ 0x{section.offset:x} -> {out_path.name} ({section.size:,} bytes) [{type_desc}]")
            
            # Try to further extract compressed sections
            if section_data[:2] in ZLIB_HEADS:
                try:
                    decompressed = zlib.decompress(section_data)
                    decomp_path = outdir / f"{section.name}_decompressed.bin"
                    
                    # Detect type of decompressed content
                    decomp_type, decomp_ext, decomp_desc = detect_file_type(decompressed)
                    if decomp_ext != ".bin":
                        decomp_path = outdir / f"{section.name}_decompressed{decomp_ext}"
                    
                    decomp_path.write_bytes(decompressed)
                    log_cb(f"  [DECOMPRESS] {section.name} -> {decomp_path.name} ({len(decompressed):,} bytes) [{decomp_desc}]")
                    
                    # Recursively process decompressed content
                    if _is_mbdf_archive_bytes(decompressed):
                        subfolder = outdir / f"{section.name}_extracted"
                        log_cb(f"  [DNT] Found Yamaha archive in decompressed section")
                        try:
                            extract_archive_bytes_to_folder(
                                decompressed, subfolder, log_cb,
                                decrypt_content=decrypt_content,
                                max_depth=max_depth,
                                current_depth=current_depth + 1
                            )
                        except Exception as e:
                            log_cb(f"  [ERROR] Nested extraction failed: {e}")
                except zlib.error:
                    pass  # Not valid zlib or decompression failed
            
            # Check for ELF binaries and extract symbols/sections
            elif section_data[:4] == b'\x7fELF':
                log_cb(f"  [DNT] ELF binary detected: {out_path.name}")
                # Could add ELF section extraction here
            
            # Check for nested Yamaha archives
            elif _is_mbdf_archive_bytes(section_data):
                subfolder = outdir / f"{section.name}_extracted"
                log_cb(f"  [DNT] Found nested Yamaha archive in section")
                try:
                    extract_archive_bytes_to_folder(
                        section_data, subfolder, log_cb,
                        decrypt_content=decrypt_content,
                        max_depth=max_depth,
                        current_depth=current_depth + 1
                    )
                except Exception as e:
                    log_cb(f"  [ERROR] Nested extraction failed: {e}")
        
        # Also scan for embedded content not in section table
        log_cb(f"  [DNT] Scanning for additional embedded content...")
        
        # Find zlib streams not in section table
        additional_found = _scan_dnt_for_embedded(data, sections, outdir, log_cb, 
                                                  decrypt_content, max_depth, current_depth)
        
        if additional_found > 0:
            log_cb(f"  [DNT] Found {additional_found} additional embedded items")
        
    except Exception as e:
        log_cb(f"  [ERROR] DNT extraction failed: {e}")
        import traceback
        traceback.print_exc()


def _scan_dnt_for_embedded(data: bytes, known_sections: List[DntSection], 
                           outdir: Path, log_cb: Callable[[str], None],
                           decrypt_content: bool, max_depth: int, 
                           current_depth: int) -> int:
    """
    Scan DNT file for embedded content not in the section table.
    
    This finds things like U-Boot strings, additional compressed sections,
    ELF binaries, and other embedded content.
    """
    found_count = 0
    
    # Get already known regions
    known_regions = set()
    for section in known_sections:
        for offset in range(section.offset, section.offset + section.size):
            known_regions.add(offset)
    
    # Look for U-Boot version strings
    uboot_pattern = re.compile(rb'U-Boot \d+\.\d+\.\d+[^\x00]{0,50}')
    for match in uboot_pattern.finditer(data):
        if match.start() not in known_regions:
            version_str = match.group().decode('ascii', errors='ignore')
            log_cb(f"  [DNT] U-Boot version at 0x{match.start():x}: {version_str}")
    
    # Look for standalone ELF binaries
    elf_positions = []
    pos = 0
    while True:
        pos = data.find(b'\x7fELF', pos)
        if pos == -1:
            break
        if pos not in known_regions:
            elf_positions.append(pos)
        pos += 4
        if len(elf_positions) >= 10:
            break
    
    for idx, elf_pos in enumerate(elf_positions[:5]):
        # Try to extract ELF
        elf_data = _extract_elf_at_offset(data, elf_pos)
        if elf_data and len(elf_data) > 64:
            out_path = outdir / f"embedded_elf_{idx+1}.elf"
            out_path.write_bytes(elf_data)
            log_cb(f"  [DNT] Embedded ELF at 0x{elf_pos:x} -> {out_path.name} ({len(elf_data):,} bytes)")
            found_count += 1
    
    return found_count


def deep_scan_and_extract(data: bytes, outdir: Path, log_cb: Callable[[str], None],
                          decrypt_content: bool = True, max_depth: int = 10,
                          current_depth: int = 0, parent_name: str = "") -> int:
    """
    Deep scan binary data for any extractable content.
    
    This function scans raw binary data looking for embedded files,
    archives, and other extractable content at any offset.
    
    Args:
        data: Binary data to scan
        outdir: Output directory
        log_cb: Logging callback
        decrypt_content: Whether to auto-decrypt content
        max_depth: Maximum recursion depth
        current_depth: Current recursion depth
        parent_name: Name of parent file for logging
    
    Returns:
        Number of items extracted
    """
    if current_depth >= max_depth:
        return 0
    
    outdir.mkdir(parents=True, exist_ok=True)
    extracted_count = 0
    
    # First try XOR decryption
    if decrypt_content:
        data, layers = recursive_smart_decrypt(data)
        if layers:
            for key, desc in layers:
                log_cb(f"  [DECRYPT] {parent_name}: {desc}")
    
    # 1. Check if it's a Yamaha archive
    if _is_mbdf_archive_bytes(data):
        log_cb(f"  [SCAN] Found Yamaha archive in {parent_name or 'data'}")
        try:
            extract_archive_bytes_to_folder(
                data, outdir, log_cb,
                decrypt_content=decrypt_content,
                max_depth=max_depth,
                current_depth=current_depth
            )
            return 1
        except Exception as e:
            log_cb(f"  [ERROR] Yamaha archive extraction failed: {e}")
    
    # 2. Check if it's a ZIP
    if data[:4] == b'PK\x03\x04':
        log_cb(f"  [SCAN] Found ZIP archive in {parent_name or 'data'}")
        try:
            extract_zip_to_folder(
                data, outdir, log_cb,
                decrypt_content=decrypt_content,
                max_depth=max_depth,
                current_depth=current_depth
            )
            return 1
        except Exception as e:
            log_cb(f"  [ERROR] ZIP extraction failed: {e}")
    
    # 3. Check if it's XZ compressed
    if data[:6] == b'\xfd7zXZ\x00':
        log_cb(f"  [SCAN] Found XZ compressed data in {parent_name or 'data'}")
        try:
            extract_xz_to_folder(
                data, outdir, log_cb,
                decrypt_content=decrypt_content,
                max_depth=max_depth,
                current_depth=current_depth
            )
            return 1
        except Exception as e:
            log_cb(f"  [ERROR] XZ extraction failed: {e}")
    
    # 4. Check if it's a TAR archive
    if _is_tar_archive(data):
        log_cb(f"  [SCAN] Found TAR archive in {parent_name or 'data'}")
        try:
            extract_tar_to_folder(
                data, outdir, log_cb,
                decrypt_content=decrypt_content,
                max_depth=max_depth,
                current_depth=current_depth
            )
            return 1
        except Exception as e:
            log_cb(f"  [ERROR] TAR extraction failed: {e}")
    
    # 5. Check if it's an Audinate Dante firmware (.dnt)
    if is_dnt_file(data):
        log_cb(f"  [SCAN] Found Audinate Dante firmware in {parent_name or 'data'}")
        try:
            extract_dnt_to_folder(
                data, outdir, log_cb,
                decrypt_content=decrypt_content,
                max_depth=max_depth,
                current_depth=current_depth
            )
            return 1
        except Exception as e:
            log_cb(f"  [ERROR] DNT extraction failed: {e}")
    
    # 6. Scan for embedded signatures
    signatures_to_find = [
        (MAGIC_ARCHIVE, "Yamaha Archive"),
        (MAGIC_FILE, "Yamaha File Block"),
        (MAGIC_FIRMWARE, "Yamaha Firmware Block"),
        (MAGIC_DNT, "Audinate Dante firmware"),
        (b'PK\x03\x04', "ZIP"),
        (b'MZ', "PE Executable"),
        (b'\x7fELF', "ELF Binary"),
        (b'<?xml', "XML"),
    ]
    
    for sig, sig_name in signatures_to_find:
        offset = 0
        found_count = 0
        while offset < len(data) - len(sig) and found_count < 100:
            pos = data.find(sig, offset)
            if pos == -1:
                break
            
            # Skip if at start (already handled)
            if pos == 0:
                offset = pos + len(sig)
                continue
            
            log_cb(f"  [SCAN] Found {sig_name} at offset 0x{pos:x} in {parent_name or 'data'}")
            
            # Extract based on type
            if sig == MAGIC_ARCHIVE:
                # Try to extract Yamaha archive from this offset
                chunk = data[pos:]
                subfolder = outdir / f"embedded_yamaha_{pos:08x}"
                try:
                    extract_archive_bytes_to_folder(
                        chunk, subfolder, log_cb,
                        decrypt_content=decrypt_content,
                        max_depth=max_depth,
                        current_depth=current_depth + 1
                    )
                    extracted_count += 1
                except Exception:
                    pass
            
            elif sig == b'PK\x03\x04':
                # Try to extract ZIP from this offset
                chunk = data[pos:]
                subfolder = outdir / f"embedded_zip_{pos:08x}"
                try:
                    extract_zip_to_folder(
                        chunk, subfolder, log_cb,
                        decrypt_content=decrypt_content,
                        max_depth=max_depth,
                        current_depth=current_depth + 1
                    )
                    extracted_count += 1
                except Exception:
                    pass
            
            elif sig == b'MZ':
                # Extract PE file
                pe_data = _extract_pe_at_offset(data, pos)
                if pe_data:
                    pe_path = outdir / f"embedded_pe_{pos:08x}.exe"
                    pe_path.write_bytes(pe_data)
                    log_cb(f"  [EXTRACT] PE executable at 0x{pos:x} -> {pe_path.name} ({len(pe_data):,} bytes)")
                    extracted_count += 1
            
            elif sig == b'\x7fELF':
                # Extract ELF file
                elf_data = _extract_elf_at_offset(data, pos)
                if elf_data:
                    elf_path = outdir / f"embedded_elf_{pos:08x}.elf"
                    elf_path.write_bytes(elf_data)
                    log_cb(f"  [EXTRACT] ELF binary at 0x{pos:x} -> {elf_path.name} ({len(elf_data):,} bytes)")
                    extracted_count += 1
            
            elif sig == b'<?xml':
                # Extract XML
                xml_data = _extract_xml_at_offset(data, pos)
                if xml_data:
                    xml_path = outdir / f"embedded_xml_{pos:08x}.xml"
                    xml_path.write_bytes(xml_data)
                    log_cb(f"  [EXTRACT] XML at 0x{pos:x} -> {xml_path.name} ({len(xml_data):,} bytes)")
                    extracted_count += 1
            
            offset = pos + len(sig)
            found_count += 1
    
    return extracted_count


def _extract_pe_at_offset(data: bytes, offset: int) -> Optional[bytes]:
    """Try to extract a PE file from the given offset."""
    if offset + 64 > len(data):
        return None
    
    try:
        # Check MZ header
        if data[offset:offset+2] != b'MZ':
            return None
        
        # Get PE header offset
        pe_offset = struct.unpack('<I', data[offset+0x3c:offset+0x40])[0]
        
        if pe_offset < 0x40 or pe_offset > 0x400:
            return None
        
        abs_pe_offset = offset + pe_offset
        if abs_pe_offset + 24 > len(data):
            return None
        
        # Verify PE signature
        if data[abs_pe_offset:abs_pe_offset+4] != b'PE\x00\x00':
            return None
        
        # Get size info from optional header
        # This is simplified - real PE parsing is more complex
        num_sections = struct.unpack('<H', data[abs_pe_offset+6:abs_pe_offset+8])[0]
        optional_header_size = struct.unpack('<H', data[abs_pe_offset+20:abs_pe_offset+22])[0]
        
        # Estimate file size (simplified)
        section_table_offset = abs_pe_offset + 24 + optional_header_size
        
        if num_sections > 0 and section_table_offset + (num_sections * 40) <= len(data):
            max_end = 0
            for i in range(num_sections):
                sec_offset = section_table_offset + (i * 40)
                raw_size = struct.unpack('<I', data[sec_offset+16:sec_offset+20])[0]
                raw_ptr = struct.unpack('<I', data[sec_offset+20:sec_offset+24])[0]
                section_end = offset + raw_ptr + raw_size
                max_end = max(max_end, section_end)
            
            if max_end > offset and max_end <= len(data):
                return data[offset:max_end]
        
        # Fallback: return a reasonable chunk
        chunk_size = min(len(data) - offset, 1024 * 1024)  # Max 1MB
        return data[offset:offset + chunk_size]
        
    except Exception:
        return None


def _extract_elf_at_offset(data: bytes, offset: int) -> Optional[bytes]:
    """Try to extract an ELF file from the given offset."""
    if offset + 64 > len(data):
        return None
    
    try:
        # Check ELF magic
        if data[offset:offset+4] != b'\x7fELF':
            return None
        
        # Get ELF class (32 or 64 bit)
        elf_class = data[offset + 4]
        endian = data[offset + 5]
        
        if elf_class == 1:  # 32-bit
            header_size = 52
            if endian == 1:  # Little endian
                shoff = struct.unpack('<I', data[offset+32:offset+36])[0]
                shentsize = struct.unpack('<H', data[offset+46:offset+48])[0]
                shnum = struct.unpack('<H', data[offset+48:offset+50])[0]
            else:
                shoff = struct.unpack('>I', data[offset+32:offset+36])[0]
                shentsize = struct.unpack('>H', data[offset+46:offset+48])[0]
                shnum = struct.unpack('>H', data[offset+48:offset+50])[0]
        elif elf_class == 2:  # 64-bit
            header_size = 64
            if endian == 1:
                shoff = struct.unpack('<Q', data[offset+40:offset+48])[0]
                shentsize = struct.unpack('<H', data[offset+58:offset+60])[0]
                shnum = struct.unpack('<H', data[offset+60:offset+62])[0]
            else:
                shoff = struct.unpack('>Q', data[offset+40:offset+48])[0]
                shentsize = struct.unpack('>H', data[offset+58:offset+60])[0]
                shnum = struct.unpack('>H', data[offset+60:offset+62])[0]
        else:
            return None
        
        # Calculate file size
        if shoff > 0 and shnum > 0:
            file_size = shoff + (shentsize * shnum)
            if offset + file_size <= len(data):
                return data[offset:offset + file_size]
        
        # Fallback
        chunk_size = min(len(data) - offset, 1024 * 1024)
        return data[offset:offset + chunk_size]
        
    except Exception:
        return None


def _extract_xml_at_offset(data: bytes, offset: int) -> Optional[bytes]:
    """Try to extract XML from the given offset."""
    try:
        # Find the end of XML (look for closing tag or null bytes)
        chunk = data[offset:offset + 1024 * 1024]  # Max 1MB
        
        # Look for XML end patterns
        end_markers = [b'</function>', b'</module>', b'</document>', b'</xml>', b'</root>',
                       b'</console>', b'</backup>', b'</project>', b'</scene>']
        
        best_end = len(chunk)
        for marker in end_markers:
            pos = chunk.find(marker)
            if pos != -1:
                end_pos = pos + len(marker)
                # Find next newline or end
                newline = chunk.find(b'\n', end_pos)
                if newline != -1 and newline < best_end:
                    best_end = newline + 1
                elif end_pos < best_end:
                    best_end = end_pos
        
        # Also look for consecutive nulls as end marker
        null_seq = chunk.find(b'\x00\x00\x00\x00')
        if null_seq != -1 and null_seq < best_end:
            best_end = null_seq
        
        if best_end > 10:  # Minimum valid XML size
            return chunk[:best_end]
        
        return None
    except Exception:
        return None


# =============================================================================
# FIRMWARE ANALYSIS FUNCTIONS
# =============================================================================

# OS/Architecture signatures for firmware analysis
FW_OS_SIGNATURES = {
    b'QNX': 'QNX RTOS',
    b'VxWorks': 'VxWorks RTOS',
    b'FreeRTOS': 'FreeRTOS',
    b'Linux': 'Linux',
    b'kernel': 'Linux kernel',
    b'vmlinux': 'Linux kernel image',
    b'initrd': 'Linux initrd',
    b'busybox': 'BusyBox (Linux)',
    b'NTFS': 'Windows NTFS',
    b'Windows': 'Windows OS',
    b'kernel32': 'Windows kernel32',
    b'ntdll': 'Windows ntdll',
    b'.exe': 'Windows executable',
    b'.dll': 'Windows DLL',
    b'uboot': 'U-Boot bootloader',
    b'U-Boot': 'U-Boot bootloader',
    b'grub': 'GRUB bootloader',
}

FW_ARCH_SIGNATURES = {
    b'\x7fELF': 'ELF binary',
    b'ARM': 'ARM architecture',
    b'THUMB': 'ARM Thumb mode',
    b'SH4': 'SuperH 4 (SH4)',
    b'PowerPC': 'PowerPC',
    b'i386': 'x86 32-bit',
    b'x86_64': 'x86 64-bit',
    b'AMD64': 'x86-64',
    b'MIPS': 'MIPS',
    b'Audinate': 'Dante (Audinate)',
}


@dataclass
class FirmwareFileInfo:
    """Information about an analyzed firmware file."""
    filename: str
    output_path: str
    size_bytes: int
    file_type: str
    file_description: str
    md5_hash: str = ""
    sha256_hash: str = ""
    xor_key_used: Optional[int] = None
    nested_archive: bool = False
    nested_contents: List[str] = field(default_factory=list)
    strings_extracted: int = 0
    os_signatures: List[str] = field(default_factory=list)
    architecture_hints: List[str] = field(default_factory=list)
    pe_files_found: int = 0


@dataclass
class FirmwareReport:
    """Complete firmware extraction and analysis report."""
    source_file: str
    source_size: int
    extraction_time: str
    output_directory: str
    total_files_extracted: int
    total_bytes_extracted: int
    xor_decryption_applied: bool
    xor_keys_found: List[int]
    archive_type: str
    files: List[FirmwareFileInfo]
    nested_archives_found: int
    firmware_sections_found: int
    summary: Dict[str, Any] = field(default_factory=dict)


def calculate_file_hashes(data: bytes) -> Tuple[str, str]:
    """Calculate MD5 and SHA256 hashes of data."""
    md5 = hashlib.md5(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    return md5, sha256


def extract_firmware_strings(data: bytes, min_length: int = 8, max_strings: int = 100) -> List[str]:
    """Extract printable ASCII strings from binary data."""
    strings = []
    current = ""
    
    for b in data:
        if 32 <= b < 127:
            current += chr(b)
        else:
            if len(current) >= min_length:
                strings.append(current)
                if len(strings) >= max_strings:
                    break
            current = ""
    
    # Don't forget the last string
    if len(current) >= min_length and len(strings) < max_strings:
        strings.append(current)
    
    return strings


def detect_firmware_os(data: bytes) -> List[str]:
    """Detect operating system signatures in firmware data."""
    found = []
    sample = data[:65536]  # Check first 64KB
    
    for sig, name in FW_OS_SIGNATURES.items():
        if sig in sample:
            found.append(name)
    
    # Also check with XOR decryption
    for xor_key in KNOWN_XOR_KEYS:
        if xor_key == 0:
            continue
        for sig, name in FW_OS_SIGNATURES.items():
            if len(sig) < 10:  # Only short signatures
                xored = bytes([b ^ xor_key for b in sig])
                if xored in sample:
                    found.append(f"{name} (XOR 0x{xor_key:02x})")
    
    return list(set(found))


def detect_firmware_architecture(data: bytes) -> List[str]:
    """Detect CPU architecture hints in firmware data."""
    found = []
    sample = data[:4096]
    
    for sig, name in FW_ARCH_SIGNATURES.items():
        if sig in sample:
            found.append(name)
    
    # Check for ARM exception vectors
    if len(data) >= 4:
        if data[:4] in [b'\xea\x00\x00\x00', b'\x00\x00\x00\xea']:
            found.append("ARM exception vector (possible)")
    
    return list(set(found))


def count_firmware_pe_files(data: bytes) -> int:
    """Count potential PE (Windows executable) files in data."""
    count = 0
    pos = 0
    
    # Check for MZ headers (both plain and XOR-encrypted)
    while pos < len(data) - 0x40:
        for xor_key in [0x00] + list(KNOWN_XOR_KEYS):
            if xor_key == 0x00:
                mz_bytes = b'MZ'
            else:
                mz_bytes = bytes([ord('M') ^ xor_key, ord('Z') ^ xor_key])
            if data[pos:pos+2] == mz_bytes:
                # Quick validation - check for valid PE offset
                try:
                    dos_header = bytes([b ^ xor_key for b in data[pos:pos+64]])
                    if dos_header[:2] == b'MZ':
                        pe_offset = struct.unpack('<I', dos_header[0x3c:0x40])[0]
                        if 0x40 <= pe_offset <= 0x200:
                            if pos + pe_offset + 4 < len(data):
                                pe_sig = bytes([b ^ xor_key for b in data[pos+pe_offset:pos+pe_offset+4]])
                                if pe_sig == b'PE\x00\x00':
                                    count += 1
                                    break
                except Exception:
                    pass
        pos += 1
        if count >= 100:  # Limit search
            break
    
    return count


def analyze_firmware_content(data: bytes, filename: str) -> FirmwareFileInfo:
    """Analyze firmware file content and return detailed information."""
    file_type, ext, description = detect_file_type(data)
    md5, sha256 = calculate_file_hashes(data)
    
    info = FirmwareFileInfo(
        filename=filename,
        output_path="",
        size_bytes=len(data),
        file_type=file_type,
        file_description=description,
        md5_hash=md5,
        sha256_hash=sha256,
    )
    
    # For binary files, extract more info
    if file_type in ("binary", "elf", "pe_executable", "arm_firmware", "qnx_rtos", 
                     "vxworks_rtos", "freertos", "rtos_generic"):
        info.os_signatures = detect_firmware_os(data)
        info.architecture_hints = detect_firmware_architecture(data)
        info.pe_files_found = count_firmware_pe_files(data)
        strings = extract_firmware_strings(data)
        info.strings_extracted = len(strings)
    
    # Check if it's a nested archive
    if _is_mbdf_archive_bytes(data):
        info.nested_archive = True
        try:
            nested = parse_mbdf_archive(data)
            info.nested_contents = [ef.name for ef in nested[:20]]
        except Exception:
            pass
    
    return info


def generate_firmware_report(
    input_path: Path,
    output_dir: Path,
    log_cb: Callable[[str], None] = print,
    max_depth: int = 10,
) -> FirmwareReport:
    """
    Extract firmware and generate comprehensive analysis report.
    
    Args:
        input_path: Path to input file
        output_dir: Output directory for extraction
        log_cb: Logging callback function
        max_depth: Maximum recursion depth for nested archives
    
    Returns:
        FirmwareReport with all extraction details
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    
    log_cb(f"Reading: {input_path}")
    data = input_path.read_bytes()
    
    # Initialize report
    report = FirmwareReport(
        source_file=str(input_path),
        source_size=len(data),
        extraction_time=datetime.now().isoformat(),
        output_directory=str(output_dir),
        total_files_extracted=0,
        total_bytes_extracted=0,
        xor_decryption_applied=False,
        xor_keys_found=[],
        archive_type="unknown",
        files=[],
        nested_archives_found=0,
        firmware_sections_found=0,
    )
    
    # Try XOR decryption
    decrypted_data, layers = recursive_smart_decrypt(data)
    if layers:
        report.xor_decryption_applied = True
        report.xor_keys_found = [key for key, _ in layers]
        for key, desc in layers:
            log_cb(f"[DECRYPT] {desc}")
        data = decrypted_data
    
    # Determine archive type
    file_type, _, type_desc = detect_file_type(data)
    report.archive_type = type_desc
    log_cb(f"Archive type: {type_desc}")
    
    # Extract based on file type
    if _is_mbdf_archive_bytes(data):
        log_cb("Detected Yamaha MBDFArchive")
        embedded = parse_mbdf_archive(data)
        report.firmware_sections_found = len(embedded)
        log_cb(f"Found {len(embedded)} embedded sections")
        
        for ef in embedded:
            try:
                payload = extract_one(data, ef)
                
                # Decrypt payload
                payload, content_layers = recursive_smart_decrypt(payload)
                if content_layers:
                    for key, desc in content_layers:
                        log_cb(f"  [DECRYPT] Content: {desc}")
                
                # Get file type
                payload_type, proper_ext, payload_desc = detect_file_type(payload)
                
                # Determine output filename
                safe_name = _safe_output_name(ef.name)
                if proper_ext != ".bin" and not safe_name.lower().endswith(proper_ext.lower()):
                    safe_name = Path(safe_name).stem + proper_ext
                
                out_path = output_dir / safe_name
                
                # Handle conflicts
                if out_path.exists():
                    k = 1
                    while True:
                        candidate = output_dir / f"{out_path.stem}_{k}{out_path.suffix}"
                        if not candidate.exists():
                            out_path = candidate
                            break
                        k += 1
                
                # Write file
                out_path.write_bytes(payload)
                log_cb(f"  [OK] {ef.name} -> {out_path.name} ({len(payload):,} bytes) [{payload_desc}]")
                
                # Analyze extracted file
                file_info = analyze_firmware_content(payload, out_path.name)
                file_info.output_path = str(out_path.relative_to(output_dir))
                report.files.append(file_info)
                report.total_files_extracted += 1
                report.total_bytes_extracted += len(payload)
                
                if file_info.nested_archive:
                    report.nested_archives_found += 1
                
                # Handle nested archives recursively
                if _is_mbdf_archive_bytes(payload):
                    subfolder = output_dir / (_safe_folder_name(out_path.name) + "_extracted")
                    log_cb(f"  Extracting nested archive -> {subfolder.name}/")
                    try:
                        extract_archive_bytes_to_folder(
                            payload, subfolder, log_cb,
                            decrypt_content=True,
                            max_depth=max_depth,
                            current_depth=1
                        )
                    except Exception as e:
                        log_cb(f"  [ERROR] Nested extraction failed: {e}")
                
                elif payload_type in ("zip", "zip_empty"):
                    subfolder = output_dir / (_safe_folder_name(out_path.name) + "_unzipped")
                    log_cb(f"  Extracting ZIP -> {subfolder.name}/")
                    try:
                        extract_zip_to_folder(
                            payload, subfolder, log_cb,
                            decrypt_content=True,
                            max_depth=max_depth,
                            current_depth=1
                        )
                    except Exception as e:
                        log_cb(f"  [ERROR] ZIP extraction failed: {e}")
                
            except Exception as e:
                log_cb(f"  [ERROR] Failed to extract {ef.name}: {e}")
    
    elif file_type in ("zip", "zip_empty"):
        log_cb("Detected ZIP archive")
        try:
            extract_zip_to_folder(
                data, output_dir, log_cb,
                decrypt_content=True,
                max_depth=max_depth,
                current_depth=0
            )
            report.total_files_extracted += 1
        except Exception as e:
            log_cb(f"[ERROR] ZIP extraction failed: {e}")
    
    else:
        # Not a recognized archive - save as-is and analyze
        log_cb(f"Unknown format - saving raw file and analyzing")
        out_path = output_dir / input_path.name
        out_path.write_bytes(data)
        file_info = analyze_firmware_content(data, input_path.name)
        file_info.output_path = str(out_path.relative_to(output_dir))
        report.files.append(file_info)
        report.total_files_extracted = 1
        report.total_bytes_extracted = len(data)
    
    # Scan output directory for all files and update report
    all_files = []
    for fpath in output_dir.rglob("*"):
        if fpath.is_file() and not fpath.name.endswith('.json') and not fpath.name.endswith('.txt'):
            try:
                file_data = fpath.read_bytes()
                info = analyze_firmware_content(file_data, fpath.name)
                info.output_path = str(fpath.relative_to(output_dir))
                all_files.append(info)
            except Exception:
                pass
    
    if all_files:
        report.files = all_files
        report.total_files_extracted = len(all_files)
        report.total_bytes_extracted = sum(f.size_bytes for f in all_files)
    
    # Generate summary
    report.summary = {
        "file_types": {},
        "largest_files": [],
        "binary_files_with_strings": [],
        "files_with_os_signatures": [],
    }
    
    for f in report.files:
        ft = f.file_type
        report.summary["file_types"][ft] = report.summary["file_types"].get(ft, 0) + 1
        
        if f.os_signatures:
            report.summary["files_with_os_signatures"].append({
                "file": f.output_path,
                "signatures": f.os_signatures
            })
        
        if f.strings_extracted > 10:
            report.summary["binary_files_with_strings"].append({
                "file": f.output_path,
                "strings_count": f.strings_extracted
            })
    
    # Top 10 largest files
    sorted_by_size = sorted(report.files, key=lambda x: x.size_bytes, reverse=True)
    report.summary["largest_files"] = [
        {"file": f.output_path, "size": f.size_bytes}
        for f in sorted_by_size[:10]
    ]
    
    return report


def save_firmware_report(report: FirmwareReport, output_dir: Path, log_cb: Callable[[str], None] = print):
    """Save firmware report to JSON and human-readable text files."""
    # Save JSON report
    report_path = output_dir / "extraction_report.json"
    with open(report_path, 'w') as f:
        json.dump(asdict(report), f, indent=2, default=str)
    log_cb(f"[REPORT] Saved JSON report to: {report_path}")
    
    # Save human-readable summary
    summary_path = output_dir / "extraction_summary.txt"
    with open(summary_path, 'w') as f:
        f.write(f"{'='*70}\n")
        f.write(f"YAMAHA FIRMWARE EXTRACTION REPORT\n")
        f.write(f"{'='*70}\n\n")
        f.write(f"Source File: {report.source_file}\n")
        f.write(f"Source Size: {report.source_size:,} bytes ({report.source_size/1024/1024:.2f} MB)\n")
        f.write(f"Archive Type: {report.archive_type}\n")
        f.write(f"Extraction Time: {report.extraction_time}\n")
        f.write(f"Output Directory: {report.output_directory}\n\n")
        
        if report.xor_decryption_applied:
            f.write(f"XOR Decryption: Applied (keys: {', '.join(f'0x{k:02x}' for k in report.xor_keys_found)})\n")
        else:
            f.write(f"XOR Decryption: Not required\n")
        
        f.write(f"\n{'='*70}\n")
        f.write(f"EXTRACTION SUMMARY\n")
        f.write(f"{'='*70}\n\n")
        f.write(f"Total Files Extracted: {report.total_files_extracted}\n")
        f.write(f"Total Bytes Extracted: {report.total_bytes_extracted:,} ({report.total_bytes_extracted/1024/1024:.2f} MB)\n")
        f.write(f"Firmware Sections Found: {report.firmware_sections_found}\n")
        f.write(f"Nested Archives Found: {report.nested_archives_found}\n\n")
        
        f.write(f"File Types:\n")
        for ftype, count in sorted(report.summary.get("file_types", {}).items()):
            f.write(f"  {ftype}: {count}\n")
        
        f.write(f"\n{'='*70}\n")
        f.write(f"EXTRACTED FILES\n")
        f.write(f"{'='*70}\n\n")
        
        for file_info in sorted(report.files, key=lambda x: x.output_path):
            f.write(f"File: {file_info.output_path}\n")
            f.write(f"  Size: {file_info.size_bytes:,} bytes\n")
            f.write(f"  Type: {file_info.file_description}\n")
            f.write(f"  MD5: {file_info.md5_hash}\n")
            if file_info.os_signatures:
                f.write(f"  OS Signatures: {', '.join(file_info.os_signatures)}\n")
            if file_info.architecture_hints:
                f.write(f"  Architecture: {', '.join(file_info.architecture_hints)}\n")
            if file_info.pe_files_found:
                f.write(f"  PE Files Found: {file_info.pe_files_found}\n")
            if file_info.strings_extracted:
                f.write(f"  Strings Found: {file_info.strings_extracted}\n")
            if file_info.nested_archive:
                f.write(f"  Nested Archive: Yes ({len(file_info.nested_contents)} items)\n")
            f.write("\n")
        
        f.write(f"\n{'='*70}\n")
        f.write(f"LARGEST FILES\n")
        f.write(f"{'='*70}\n\n")
        for item in report.summary.get("largest_files", []):
            f.write(f"  {item['file']}: {item['size']:,} bytes\n")
        
        if report.summary.get("files_with_os_signatures"):
            f.write(f"\n{'='*70}\n")
            f.write(f"FILES WITH OS SIGNATURES\n")
            f.write(f"{'='*70}\n\n")
            for item in report.summary["files_with_os_signatures"]:
                f.write(f"  {item['file']}: {', '.join(item['signatures'])}\n")
    
    log_cb(f"[REPORT] Saved summary to: {summary_path}")


def analyze_firmware_file(filepath: Path, log_cb: Callable[[str], None] = print) -> Dict[str, Any]:
    """
    Analyze a single firmware file without extraction.
    
    Returns dict with analysis results including:
    - File info (size, type, hashes)
    - OS signatures detected
    - Architecture hints
    - PE file count
    - String count
    """
    data = filepath.read_bytes()
    
    # Try decryption
    decrypted_data, layers = recursive_smart_decrypt(data)
    if layers:
        for key, desc in layers:
            log_cb(f"[DECRYPT] {desc}")
        data = decrypted_data
    
    file_type, _, description = detect_file_type(data)
    md5, sha256 = calculate_file_hashes(data)
    
    result = {
        "filename": filepath.name,
        "size_bytes": len(data),
        "file_type": file_type,
        "description": description,
        "md5_hash": md5,
        "sha256_hash": sha256,
        "xor_keys": [k for k, _ in layers] if layers else [],
        "os_signatures": detect_firmware_os(data),
        "architecture_hints": detect_firmware_architecture(data),
        "pe_files_found": count_firmware_pe_files(data),
        "strings_found": len(extract_firmware_strings(data)),
        "is_yamaha_archive": _is_mbdf_archive_bytes(data),
    }
    
    # If it's a Yamaha archive, count embedded files
    if result["is_yamaha_archive"]:
        try:
            embedded = parse_mbdf_archive(data)
            result["embedded_files"] = len(embedded)
            result["embedded_names"] = [ef.name for ef in embedded[:20]]
        except Exception:
            pass
    
    return result


# GUI class - only defined if tkinter is available
if HAS_TKINTER:
    class App(ttk.Frame):
        def __init__(self, master: tk.Tk):
            super().__init__(master)
            self.master = master
            self.master.title("Yamaha MBDFArchive Extractor (Smart XOR)")
            self.master.geometry("1180x700")

            self.input_files: List[Path] = []
            self.output_dir: Optional[Path] = None

            # Preview cache: map from displayed list index -> (source_file_path, EmbeddedFile)
            self._preview_entries: List[Tuple[Path, EmbeddedFile]] = []
            # Nested preview cache: map from list index -> list of nested EmbeddedFile
            self._nested_preview: Dict[int, List[EmbeddedFile]] = {}
            
            # XOR decryption options
            self.smart_decrypt = tk.BooleanVar(value=True)
            self.recursive_extract = tk.BooleanVar(value=True)
            self.max_depth = tk.IntVar(value=5)
            
            # Firmware report options
            self.generate_report = tk.BooleanVar(value=True)
            self.analyze_firmware = tk.BooleanVar(value=True)

            self._build_ui()

        def _build_ui(self):
            pad = {"padx": 8, "pady": 6}

            top = ttk.Frame(self)
            top.pack(fill="x", **pad)

            ttk.Button(top, text="Add file(s)…", command=self.add_files).pack(side="left")
            ttk.Button(top, text="Clear list", command=self.clear_files).pack(side="left", padx=(8, 0))

            out = ttk.Frame(self)
            out.pack(fill="x", **pad)

            ttk.Button(out, text="Choose output folder…", command=self.choose_output).pack(side="left")
            self.out_label = ttk.Label(out, text="(no output folder chosen)")
            self.out_label.pack(side="left", padx=(10, 0), fill="x", expand=True)
            
            # Smart Decryption options frame
            xor_frame = ttk.LabelFrame(self, text="Smart XOR Decryption & Extraction")
            xor_frame.pack(fill="x", **pad)
            
            ttk.Checkbutton(
                xor_frame, 
                text="Smart auto-decrypt (detects keys automatically)", 
                variable=self.smart_decrypt
            ).pack(side="left", padx=5)
            
            ttk.Checkbutton(
                xor_frame, 
                text="Recursive extraction", 
                variable=self.recursive_extract
            ).pack(side="left", padx=5)
            
            ttk.Label(xor_frame, text="Max depth:").pack(side="left", padx=(10, 2))
            depth_spin = ttk.Spinbox(xor_frame, from_=1, to=10, width=3, textvariable=self.max_depth)
            depth_spin.pack(side="left")
            
            ttk.Label(
                xor_frame,
                text="(Known keys: 0xa9, 0xf1, 0x87, 0xf7, 0x78)"
            ).pack(side="left", padx=10)
            
            # Firmware Analysis options frame
            fw_frame = ttk.LabelFrame(self, text="Firmware Analysis & Reporting")
            fw_frame.pack(fill="x", **pad)
            
            ttk.Checkbutton(
                fw_frame, 
                text="Generate extraction report (JSON + TXT)", 
                variable=self.generate_report
            ).pack(side="left", padx=5)
            
            ttk.Checkbutton(
                fw_frame, 
                text="Analyze firmware (OS, architecture, PE files)", 
                variable=self.analyze_firmware
            ).pack(side="left", padx=5)
            
            ttk.Button(fw_frame, text="Analyze Only (no extract)", command=self.analyze_only).pack(side="left", padx=(10, 0))

            mid = ttk.Frame(self)
            mid.pack(fill="both", expand=True, **pad)

            # LEFT: input files
            left = ttk.Frame(mid)
            left.pack(side="left", fill="both", expand=True)

            ttk.Label(left, text="Input files").pack(anchor="w")
            self.files_list = tk.Listbox(left, height=10)
            self.files_list.pack(fill="both", expand=True)

            # CENTER: embedded contents
            center = ttk.Frame(mid)
            center.pack(side="left", fill="both", expand=True, padx=(10, 0))

            ttk.Label(center, text="Embedded contents (preview)").pack(anchor="w")
            self.contents = tk.Listbox(center, height=10)
            self.contents.pack(fill="both", expand=True)
            self.contents.bind("<<ListboxSelect>>", self.on_select_embedded)

            # RIGHT: nested embedded contents
            right = ttk.Frame(mid)
            right.pack(side="left", fill="both", expand=True, padx=(10, 0))

            ttk.Label(right, text="Nested contents (1 level) of selected item").pack(anchor="w")
            self.nested = tk.Listbox(right, height=10)
            self.nested.pack(fill="both", expand=True)

            actions = ttk.Frame(self)
            actions.pack(fill="x", **pad)

            ttk.Button(actions, text="Preview contents", command=self.preview).pack(side="left")
            ttk.Button(actions, text="Extract (1 level deep)", command=self.extract).pack(side="left", padx=(8, 0))
            ttk.Button(actions, text="Open output folder", command=self.open_output).pack(side="left", padx=(8, 0))

            ttk.Separator(self).pack(fill="x", padx=8, pady=(6, 0))

            logf = ttk.Frame(self)
            logf.pack(fill="both", expand=True, padx=8, pady=8)

            ttk.Label(logf, text="Log").pack(anchor="w")
            self.log = tk.Text(logf, height=12, wrap="word")
            self.log.pack(fill="both", expand=True)

            self.pack(fill="both", expand=True)

        def log_line(self, s: str):
            self.log.insert("end", s + "\n")
            self.log.see("end")
            self.master.update_idletasks()

        def add_files(self):
            paths = filedialog.askopenfilenames(
                title="Select Yamaha firmware files",
                filetypes=[
                    ("All supported", "*.bin *.dnt"),
                    ("BIN files", "*.bin"),
                    ("DNT files (Dante)", "*.dnt"),
                    ("All files", "*.*"),
                ],
            )
            if not paths:
                return

            for p in paths:
                pp = Path(p)
                if pp not in self.input_files:
                    self.input_files.append(pp)
                    self.files_list.insert("end", str(pp))

            self.log_line(f"Added {len(paths)} file(s).")

        def clear_files(self):
            self.input_files.clear()
            self.files_list.delete(0, "end")
            self.contents.delete(0, "end")
            self.nested.delete(0, "end")
            self._preview_entries.clear()
            self._nested_preview.clear()
            self.log_line("Cleared input file list.")

        def choose_output(self):
            p = filedialog.askdirectory(title="Choose output folder")
            if not p:
                return
            self.output_dir = Path(p)
            self.out_label.configure(text=str(self.output_dir))
            self.log_line(f"Output folder: {self.output_dir}")

        def preview(self):
            self.contents.delete(0, "end")
            self.nested.delete(0, "end")
            self._preview_entries.clear()
            self._nested_preview.clear()

            if not self.input_files:
                messagebox.showinfo("Nothing to preview", "Add one or more files first.")
                return

            total = 0
            for f in self.input_files:
                try:
                    data = f.read_bytes()
                except Exception as e:
                    self.log_line(f"[ERROR] Reading {f}: {e}")
                    continue
                
                # Smart decrypt if enabled
                decrypt_info = ""
                if self.smart_decrypt.get():
                    data, layers = recursive_smart_decrypt(data)
                    if layers:
                        keys_str = ", ".join(f"0x{k:02x}" for k, _ in layers)
                        decrypt_info = f" [XOR: {keys_str}]"
                        self.log_line(f"[DECRYPT] {f.name}: Decrypted with keys {keys_str}")

                # Check if this is a DNT file first
                if is_dnt_file(data):
                    self.log_line(f"{f.name}: Audinate Dante firmware file detected.")
                    dnt_fallback = f"{f.name}  ->  (DNT firmware - use Extract to process){decrypt_info}"
                    try:
                        header_info, sections = parse_dnt_header(data)
                        self.log_line(f"  [DNT] Manufacturer: {header_info.get('manufacturer', 'Unknown')}")
                        self.log_line(f"  [DNT] Header size: {header_info['header_size']} bytes")
                        self.log_line(f"  [DNT] Sections: {len(sections)}")
                        
                        # Show DNT sections as preview items
                        for section in sections:
                            total += 1
                            shown = f"{f.name}  ->  {section.name}   [DNT section @ 0x{section.offset:x}]{decrypt_info}"
                            self.contents.insert("end", shown)
                        
                        if not sections:
                            total += 1
                            self.contents.insert("end", dnt_fallback)
                    except Exception as e:
                        self.log_line(f"  [DNT] Preview failed: {e}")
                        total += 1
                        self.contents.insert("end", dnt_fallback)
                    continue

                if MAGIC_ARCHIVE not in data[:2048]:
                    self.log_line(f"[WARN] {f.name}: MBDF header not found (still attempting parse).")

                embedded = parse_mbdf_archive(data)
                self.log_line(f"{f.name}: found {len(embedded)} embedded block(s).")

                for ef in embedded:
                    idx = len(self._preview_entries)
                    self._preview_entries.append((f, ef))

                    total += 1
                    mtag = ef.marker.decode("ascii", errors="replace")
                    shown = f"{f.name}  ->  {ef.name}   [{mtag}]{decrypt_info}"
                    self.contents.insert("end", shown)

                    # Precompute nested preview
                    try:
                        payload = extract_one(data, ef)
                        # Smart decrypt payload too
                        if self.smart_decrypt.get():
                            payload, _ = recursive_smart_decrypt(payload)
                        if _is_mbdf_archive_bytes(payload):
                            nested_list = parse_mbdf_archive(payload)
                            self._nested_preview[idx] = nested_list
                    except Exception:
                        pass

            if total == 0:
                self.log_line("No embedded blocks found. Try different decryption settings.")

        def on_select_embedded(self, _evt):
            self.nested.delete(0, "end")
            sel = self.contents.curselection()
            if not sel:
                return
            i = int(sel[0])

            nested = self._nested_preview.get(i)
            if not nested:
                self.nested.insert("end", "(no nested MBDF archive detected)")
                return

            self.nested.insert("end", f"(nested MBDF archive: {len(nested)} item(s))")
            for ef in nested:
                mtag = ef.marker.decode("ascii", errors="replace")
                self.nested.insert("end", f"{ef.name}   [{mtag}]")

        def extract(self):
            if not self.input_files:
                messagebox.showinfo("Nothing to extract", "Add one or more files first.")
                return
            if not self.output_dir:
                messagebox.showinfo("No output folder", "Choose an output folder first.")
                return

            outdir = self.output_dir
            outdir.mkdir(parents=True, exist_ok=True)
            
            do_smart_decrypt = self.smart_decrypt.get()
            do_recursive = self.recursive_extract.get()
            max_depth = self.max_depth.get()

            extracted = 0
            
            # First, check for split ZIP files and combine them
            split_zips = self._find_split_zips()
            for base_name, parts in split_zips.items():
                self.log_line(f"--- Combining split ZIP: {base_name} ({len(parts)} parts) ---")
                try:
                    combined_data = b''
                    for part_path in sorted(parts):
                        combined_data += part_path.read_bytes()
                    
                    # Extract the combined ZIP
                    if combined_data[:4] == b'PK\x03\x04':
                        subfolder = outdir / (base_name + "_unzipped")
                        self.log_line(f"  Extracting combined ZIP -> {subfolder.name}/")
                        try:
                            extract_zip_to_folder(
                                combined_data, subfolder, self.log_line,
                                decrypt_content=do_smart_decrypt,
                                max_depth=max_depth,
                                current_depth=0
                            )
                            extracted += 1
                        except Exception as e:
                            self.log_line(f"  [ERROR] Combined ZIP extraction failed: {e}")
                            # Save the combined file for manual inspection
                            combined_path = outdir / (base_name + ".zip")
                            combined_path.write_bytes(combined_data)
                            self.log_line(f"  [SAVE] Saved combined ZIP to {combined_path.name}")
                except Exception as e:
                    self.log_line(f"[ERROR] Failed to combine split ZIP {base_name}: {e}")
        
            for f in self.input_files:
                # Skip files that were part of split ZIPs
                is_split_part = False
                for parts in split_zips.values():
                    if f in parts:
                        is_split_part = True
                        break
                if is_split_part:
                    continue
                
                self.log_line(f"--- Extracting from: {f} ---")
                try:
                    data = f.read_bytes()
                except Exception as e:
                    self.log_line(f"[ERROR] Reading {f}: {e}")
                    continue
                
                # Smart decrypt archive
                layers = []
                if do_smart_decrypt:
                    data, layers = recursive_smart_decrypt(data)
                    if layers:
                        for key, desc in layers:
                            self.log_line(f"[DECRYPT] Archive: {desc}")
                
                # Re-detect type after decryption (or first time)
                file_type, _, type_desc = detect_file_type(data)
                if layers:
                    self.log_line(f"  Decrypted file type: {type_desc}")
                
                # Handle different file types
                if file_type in ("zip", "zip_empty"):
                    # Direct ZIP extraction
                    subfolder = outdir / (_safe_folder_name(f.name) + "_unzipped")
                    self.log_line(f"  ZIP archive detected -> {subfolder.name}/")
                    try:
                        extract_zip_to_folder(
                            data, subfolder, self.log_line,
                            decrypt_content=do_smart_decrypt,
                            max_depth=max_depth,
                            current_depth=0
                        )
                        extracted += 1
                    except Exception as e:
                        self.log_line(f"  [ERROR] ZIP extraction failed: {e}")
                    continue
                
                # Handle Audinate Dante firmware (.dnt) files
                if is_dnt_file(data):
                    subfolder = outdir / (_safe_folder_name(f.name) + "_dnt_extracted")
                    self.log_line(f"  Audinate Dante firmware detected -> {subfolder.name}/")
                    try:
                        extract_dnt_to_folder(
                            data, subfolder, self.log_line,
                            decrypt_content=do_smart_decrypt,
                            max_depth=max_depth,
                            current_depth=0
                        )
                        extracted += 1
                    except Exception as e:
                        self.log_line(f"  [ERROR] DNT extraction failed: {e}")
                    continue
                
                # Try Yamaha archive extraction
                embedded = parse_mbdf_archive(data)
                if not embedded:
                    # No embedded blocks - try deep scan
                    if do_recursive:
                        subfolder = outdir / (_safe_folder_name(f.name) + "_scanned")
                        self.log_line(f"  No Yamaha blocks found, performing deep scan...")
                        count = deep_scan_and_extract(
                            data, subfolder, self.log_line,
                            decrypt_content=do_smart_decrypt,
                            max_depth=max_depth,
                            current_depth=0,
                            parent_name=f.name
                        )
                        if count > 0:
                            extracted += count
                        else:
                            self.log_line("[WARN] No extractable content found in this input.")
                    else:
                        self.log_line("[WARN] No embedded blocks found in this input.")
                    continue

                for ef in embedded:
                    safe = _safe_output_name(ef.name)
                    out_path = outdir / safe

                    if out_path.exists():
                        stem = out_path.stem
                        suf = out_path.suffix
                        k = 1
                        while True:
                            candidate = outdir / f"{stem}_{k}{suf}"
                            if not candidate.exists():
                                out_path = candidate
                                break
                            k += 1

                    try:
                        payload = extract_one(data, ef)
                    except zlib.error as e:
                        raw_path = outdir / (out_path.name + ".raw")
                        try:
                            raw_path.write_bytes(data[ef.start_offset:ef.end_offset])
                            self.log_line(f"[ERROR] zlib failed for {ef.name}: {e} (wrote raw: {raw_path.name})")
                        except Exception as we:
                            self.log_line(f"[ERROR] zlib failed: {e} (write error: {we})")
                        continue
                    except Exception as e:
                        self.log_line(f"[ERROR] Extract failed for {ef.name}: {e}")
                        continue
                    
                    # Smart decrypt content
                    if do_smart_decrypt:
                        payload, content_layers = recursive_smart_decrypt(payload)
                        if content_layers:
                            for key, desc in content_layers:
                                self.log_line(f"  [DECRYPT] Content: {desc}")

                    # Detect file type and assign proper extension
                    payload_type, proper_ext, payload_desc = detect_file_type(payload)
                    if proper_ext != ".bin" and not out_path.suffix.lower() == proper_ext.lower():
                        new_name = out_path.stem + proper_ext
                        out_path = outdir / new_name
                        if out_path.exists():
                            k = 1
                            while True:
                                candidate = outdir / f"{out_path.stem}_{k}{proper_ext}"
                                if not candidate.exists():
                                    out_path = candidate
                                    break
                                k += 1

                    out_path.write_bytes(payload)
                    extracted += 1
                    self.log_line(f"[OK] {ef.name}  ->  {out_path.name}  ({len(payload):,} bytes) [{payload_desc}]")

                    # Recursive extraction of nested archives
                    if do_recursive:
                        if _is_mbdf_archive_bytes(payload):
                            subfolder = outdir / (_safe_folder_name(out_path.name) + "_extracted")
                            self.log_line(f"  Nested Yamaha archive detected -> {subfolder.name}/")
                            try:
                                extract_archive_bytes_to_folder(
                                    payload, subfolder, self.log_line,
                                    decrypt_content=do_smart_decrypt,
                                    max_depth=max_depth,
                                    current_depth=1
                                )
                            except Exception as e:
                                self.log_line(f"  [ERROR] Nested extraction failed: {e}")
                        
                        elif payload_type in ("zip", "zip_empty"):
                            subfolder = outdir / (_safe_folder_name(out_path.name) + "_unzipped")
                            self.log_line(f"  ZIP archive detected -> {subfolder.name}/")
                            try:
                                extract_zip_to_folder(
                                    payload, subfolder, self.log_line,
                                    decrypt_content=do_smart_decrypt,
                                    max_depth=max_depth,
                                    current_depth=1
                                )
                            except Exception as e:
                                self.log_line(f"  [ERROR] ZIP extraction failed: {e}")

            self.log_line(f"Done. Extracted {extracted} file(s) into: {outdir}")
            
            # Generate firmware report if requested
            if extracted and self.generate_report.get():
                self.log_line("Generating firmware extraction report...")
                try:
                    # Build report from extracted files
                    report = FirmwareReport(
                        source_file=", ".join(str(f) for f in self.input_files),
                        source_size=sum(f.stat().st_size for f in self.input_files),
                        extraction_time=datetime.now().isoformat(),
                        output_directory=str(outdir),
                        total_files_extracted=0,
                        total_bytes_extracted=0,
                        xor_decryption_applied=do_smart_decrypt,
                        xor_keys_found=[],
                        archive_type="Yamaha MBDFArchive",
                        files=[],
                        nested_archives_found=0,
                        firmware_sections_found=extracted,
                    )
                    
                    # Scan output directory for all files
                    for fpath in outdir.rglob("*"):
                        if fpath.is_file() and not fpath.name.endswith('.json') and not fpath.name.endswith('.txt'):
                            try:
                                file_data = fpath.read_bytes()
                                info = analyze_firmware_content(file_data, fpath.name)
                                info.output_path = str(fpath.relative_to(outdir))
                                report.files.append(info)
                                
                                if info.nested_archive:
                                    report.nested_archives_found += 1
                            except Exception:
                                pass
                    
                    report.total_files_extracted = len(report.files)
                    report.total_bytes_extracted = sum(f.size_bytes for f in report.files)
                    
                    # Build summary
                    report.summary = {
                        "file_types": {},
                        "largest_files": [],
                        "binary_files_with_strings": [],
                        "files_with_os_signatures": [],
                    }
                    
                    for f in report.files:
                        ft = f.file_type
                        report.summary["file_types"][ft] = report.summary["file_types"].get(ft, 0) + 1
                        
                        if f.os_signatures:
                            report.summary["files_with_os_signatures"].append({
                                "file": f.output_path,
                                "signatures": f.os_signatures
                            })
                    
                    sorted_by_size = sorted(report.files, key=lambda x: x.size_bytes, reverse=True)
                    report.summary["largest_files"] = [
                        {"file": f.output_path, "size": f.size_bytes}
                        for f in sorted_by_size[:10]
                    ]
                    
                    save_firmware_report(report, outdir, self.log_line)
                except Exception as e:
                    self.log_line(f"[ERROR] Failed to generate report: {e}")
            
            if extracted:
                messagebox.showinfo("Extraction complete", f"Extracted {extracted} file(s) into:\n{outdir}")
    
        def analyze_only(self):
            """Analyze firmware files without extraction - just report on contents."""
            if not self.input_files:
                messagebox.showinfo("Nothing to analyze", "Add one or more files first.")
                return
            
            self.log_line("\n" + "="*60)
            self.log_line("FIRMWARE ANALYSIS (No Extraction)")
            self.log_line("="*60)
            
            for f in self.input_files:
                self.log_line(f"\n--- Analyzing: {f.name} ---")
                try:
                    result = analyze_firmware_file(f, self.log_line)
                    
                    self.log_line(f"  File size: {result['size_bytes']:,} bytes ({result['size_bytes']/1024/1024:.2f} MB)")
                    self.log_line(f"  File type: {result['description']}")
                    self.log_line(f"  MD5: {result['md5_hash']}")
                    self.log_line(f"  SHA256: {result['sha256_hash'][:32]}...")
                    
                    if result['xor_keys']:
                        self.log_line(f"  XOR keys detected: {', '.join(f'0x{k:02x}' for k in result['xor_keys'])}")
                    
                    if result['os_signatures']:
                        self.log_line(f"  OS signatures: {', '.join(result['os_signatures'])}")
                    
                    if result['architecture_hints']:
                        self.log_line(f"  Architecture: {', '.join(result['architecture_hints'])}")
                    
                    if result['pe_files_found']:
                        self.log_line(f"  PE files found: {result['pe_files_found']}")
                    
                    if result['strings_found']:
                        self.log_line(f"  Strings found: {result['strings_found']}")
                    
                    if result['is_yamaha_archive']:
                        self.log_line(f"  Yamaha archive: Yes")
                        if 'embedded_files' in result:
                            self.log_line(f"  Embedded files: {result['embedded_files']}")
                            if result.get('embedded_names'):
                                self.log_line(f"  Sample contents:")
                                for name in result['embedded_names'][:10]:
                                    self.log_line(f"    - {name}")
                    
                except Exception as e:
                    self.log_line(f"  [ERROR] Analysis failed: {e}")
            
            self.log_line("\n" + "="*60)
            self.log_line("Analysis complete.")

        def _find_split_zips(self) -> Dict[str, List[Path]]:
            """Find split ZIP archives (e.g., file.zip.001, file.zip.002)."""
            split_zips: Dict[str, List[Path]] = {}
        
            for f in self.input_files:
                name = f.name
                # Check for .zip.NNN pattern
                match = re.match(r'^(.+\.zip)\.(\d{3})$', name, re.IGNORECASE)
                if match:
                    base_name = match.group(1)
                    if base_name not in split_zips:
                        split_zips[base_name] = []
                    split_zips[base_name].append(f)
        
            return split_zips

        def open_output(self):
            if not self.output_dir:
                messagebox.showinfo("No output folder", "Choose an output folder first.")
                return
            p = str(self.output_dir)
            try:
                if sys.platform.startswith("win"):
                    os.startfile(p)  # type: ignore[attr-defined]
                elif sys.platform == "darwin":
                    os.system(f'open "{p}"')
                else:
                    os.system(f'xdg-open "{p}"')
            except Exception as e:
                messagebox.showerror("Open folder failed", str(e))


def extract_from_files(input_files: List[Path], output_dir: Path, 
                       decrypt: bool = True, max_depth: int = 10) -> int:
    """
    Command-line extraction function for use without GUI.
    
    Args:
        input_files: List of input file paths
        output_dir: Output directory path
        decrypt: Whether to auto-decrypt content
        max_depth: Maximum recursion depth
    
    Returns:
        Number of items extracted
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    total_extracted = 0
    
    def log(msg):
        print(msg)
    
    # Check for split ZIP files
    split_zips: Dict[str, List[Path]] = {}
    for f in input_files:
        name = f.name
        match = re.match(r'^(.+\.zip)\.(\d{3})$', name, re.IGNORECASE)
        if match:
            base_name = match.group(1)
            if base_name not in split_zips:
                split_zips[base_name] = []
            split_zips[base_name].append(f)
    
    # Process split ZIPs
    for base_name, parts in split_zips.items():
        log(f"--- Combining split ZIP: {base_name} ({len(parts)} parts) ---")
        try:
            combined_data = b''
            for part_path in sorted(parts):
                combined_data += part_path.read_bytes()
            
            if combined_data[:4] == b'PK\x03\x04':
                subfolder = output_dir / (base_name + "_unzipped")
                log(f"  Extracting combined ZIP -> {subfolder.name}/")
                extract_zip_to_folder(
                    combined_data, subfolder, log,
                    decrypt_content=decrypt,
                    max_depth=max_depth,
                    current_depth=0
                )
                total_extracted += 1
        except Exception as e:
            log(f"[ERROR] Failed to process split ZIP {base_name}: {e}")
    
    # Process other files
    for f in input_files:
        # Skip files that were part of split ZIPs
        is_split_part = False
        for parts in split_zips.values():
            if f in parts:
                is_split_part = True
                break
        if is_split_part:
            continue
        
        log(f"--- Extracting from: {f} ---")
        try:
            data = f.read_bytes()
        except Exception as e:
            log(f"[ERROR] Reading {f}: {e}")
            continue
        
        # Smart decrypt
        if decrypt:
            data, layers = recursive_smart_decrypt(data)
            if layers:
                for key, desc in layers:
                    log(f"[DECRYPT] {desc}")
        
        # Detect file type
        file_type, _, type_desc = detect_file_type(data)
        log(f"  File type: {type_desc}")
        
        # Handle ZIP
        if file_type in ("zip", "zip_empty"):
            subfolder = output_dir / (_safe_folder_name(f.name) + "_unzipped")
            try:
                extract_zip_to_folder(
                    data, subfolder, log,
                    decrypt_content=decrypt,
                    max_depth=max_depth,
                    current_depth=0
                )
                total_extracted += 1
            except Exception as e:
                log(f"[ERROR] ZIP extraction failed: {e}")
            continue
        
        # Try Yamaha archive
        if _is_mbdf_archive_bytes(data):
            subfolder = output_dir / (_safe_folder_name(f.name) + "_extracted")
            try:
                extract_archive_bytes_to_folder(
                    data, subfolder, log,
                    decrypt_content=decrypt,
                    max_depth=max_depth,
                    current_depth=0
                )
                total_extracted += 1
            except Exception as e:
                log(f"[ERROR] Yamaha archive extraction failed: {e}")
            continue
        
        # Handle Audinate Dante firmware (.dnt)
        if is_dnt_file(data):
            subfolder = output_dir / (_safe_folder_name(f.name) + "_dnt_extracted")
            try:
                extract_dnt_to_folder(
                    data, subfolder, log,
                    decrypt_content=decrypt,
                    max_depth=max_depth,
                    current_depth=0
                )
                total_extracted += 1
            except Exception as e:
                log(f"[ERROR] DNT extraction failed: {e}")
            continue
        
        # Handle raw firmware files (give informative message)
        if file_type in ("raw_firmware_versioned", "arm_cortex_m_firmware", 
                        "yamaha_dsp_firmware", "sh4_firmware", "arm_firmware",
                        "arm_thumb_firmware"):
            log(f"  [INFO] This is a raw firmware image, not a container archive.")
            log(f"  [INFO] Raw firmware files don't contain extractable embedded blocks.")
            log(f"  [INFO] Consider using firmware_analyzer.py for analysis instead.")
            # Save the file as-is with analysis
            out_path = output_dir / f.name
            out_path.write_bytes(data)
            log(f"  [OK] Copied to: {out_path}")
            total_extracted += 1
            continue
        
        # Deep scan
        subfolder = output_dir / (_safe_folder_name(f.name) + "_scanned")
        count = deep_scan_and_extract(
            data, subfolder, log,
            decrypt_content=decrypt,
            max_depth=max_depth,
            current_depth=0,
            parent_name=f.name
        )
        total_extracted += count
    
    log(f"\nDone. Extracted {total_extracted} items.")
    return total_extracted


def main():
    """Main entry point - runs GUI if available, otherwise shows usage."""
    if not HAS_TKINTER:
        print("Yamaha MBDFArchive Extractor")
        print("=" * 40)
        print("\nGUI not available (tkinter not installed).")
        print("\nCommand-line usage:")
        print("  python yamaha_extractor.py <input_file> <output_dir>")
        print("  python yamaha_extractor.py <input_file1> <input_file2> ... <output_dir>")
        print("\nExample:")
        print("  python yamaha_extractor.py firmware.bin ./extracted")
        print("  python yamaha_extractor.py archive.zip.001 archive.zip.002 ./extracted")
        
        if len(sys.argv) >= 3:
            # Command line mode
            output_dir = Path(sys.argv[-1])
            input_files = [Path(f) for f in sys.argv[1:-1]]
            
            # Verify inputs exist
            for f in input_files:
                if not f.exists():
                    print(f"Error: Input file not found: {f}")
                    sys.exit(1)
            
            count = extract_from_files(input_files, output_dir, decrypt=True, max_depth=10)
            print(f"\nExtracted {count} items to {output_dir}")
        return
    
    # GUI mode
    root = tk.Tk()
    try:
        style = ttk.Style()
        if "clam" in style.theme_names():
            style.theme_use("clam")
    except Exception:
        pass

    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
