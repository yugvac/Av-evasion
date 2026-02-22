"""
SentinelLab – Deep File Analyzer

Performs advanced static analysis that goes beyond standard analysis:
- String extraction & categorization
- PE binary analysis (headers, sections, imports)
- Network IOC extraction
- Entropy heatmap generation
- MITRE ATT&CK technique mapping
- Composite risk scoring
"""
import re
import struct
import math
import hashlib
from datetime import datetime, timezone


# ──────────────────────────────────────────────
# 1. STRING EXTRACTION & CATEGORIZATION
# ──────────────────────────────────────────────

# Regex patterns for categorizing strings
PATTERNS = {
    "urls": re.compile(
        r'https?://[^\s\x00-\x1f\x7f"\'<>]{4,200}', re.IGNORECASE
    ),
    "ips": re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b'
    ),
    "domains": re.compile(
        r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|tk|xyz|top|info|biz|cc|pw|ws|online|site|live|me|co|uk|de|fr|jp)\b',
        re.IGNORECASE,
    ),
    "emails": re.compile(
        r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
    ),
    "registry_keys": re.compile(
        r'HKEY_[A-Z_]+(?:\\[^\s\x00"]{2,})+', re.IGNORECASE
    ),
    "file_paths_win": re.compile(
        r'[A-Z]:\\(?:[^\s\x00"\\/:*?<>|]{1,}\\)*[^\s\x00"\\/:*?<>|]{1,}',
    ),
    "file_paths_unix": re.compile(
        r'(?:/(?:usr|etc|tmp|var|opt|home|bin|sbin|dev|proc|sys|mnt|root|boot)[/\w.-]+)',
    ),
    "crypto_wallets": re.compile(
        r'\b(?:1|3|bc1)[a-zA-HJ-NP-Z0-9]{25,39}\b'  # Bitcoin
    ),
    "base64_blobs": re.compile(
        r'(?:[A-Za-z0-9+/]{40,}={0,2})'
    ),
}

# Suspicious command/function strings
SUSPICIOUS_STRINGS = {
    "shell_commands": [
        "cmd.exe", "powershell", "cmd /c", "/bin/sh", "/bin/bash",
        "wget ", "curl ", "chmod +x", "exec(", "eval(", "system(",
        "ShellExecute", "WScript.Shell", "Invoke-Expression",
        "Invoke-WebRequest", "Start-Process", "Net.WebClient",
        "DownloadFile", "DownloadString", "IEX(",
    ],
    "crypto_api": [
        "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptAcquireContext",
        "BCryptEncrypt", "BCryptDecrypt", "AES", "RSA", "FromBase64String",
        "ToBase64String", "atob(", "btoa(",
    ],
    "process_injection": [
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect",
        "WriteProcessMemory", "CreateRemoteThread", "NtWriteVirtualMemory",
        "RtlCreateUserThread", "QueueUserAPC", "NtQueueApcThread",
        "OpenProcess", "NtUnmapViewOfSection",
    ],
    "persistence": [
        "RegSetValue", "RegCreateKey", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "CurrentVersion\\RunOnce", "Wow6432Node", "schtasks",
        "at.exe", "crontab", "systemctl enable", "autostart",
        "HKLM\\SOFTWARE", "HKCU\\SOFTWARE",
    ],
    "evasion": [
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "OutputDebugString", "GetTickCount", "QueryPerformanceCounter",
        "Sleep(", "SleepEx", "NtDelayExecution", "VirtualBox", "VMware",
        "VBOX", "sandbox", "Wine", "QEMU",
    ],
    "network": [
        "WSAStartup", "socket(", "connect(", "send(", "recv(",
        "InternetOpen", "HttpOpenRequest", "HttpSendRequest",
        "URLDownloadToFile", "WinHttpOpen", "WinHttpConnect",
        "getaddrinfo", "gethostbyname",
    ],
    "file_operations": [
        "CreateFile", "WriteFile", "ReadFile", "DeleteFile",
        "MoveFile", "CopyFile", "FindFirstFile", "GetTempPath",
        "SetFileAttributes", "NtCreateFile",
    ],
    "credential_access": [
        "CredEnumerate", "lsass", "mimikatz", "sekurlsa",
        "SAM", "NTDS.dit", "shadow", "passwd", "credential",
        "keychain", "LoginKeychain",
    ],
}

# Suspicious DLL imports
SUSPICIOUS_DLLS = {
    "kernel32.dll": "Core Windows API - process, memory, file operations",
    "ntdll.dll": "Native API - direct system calls (common in malware)",
    "advapi32.dll": "Security, registry, service management",
    "ws2_32.dll": "Winsock networking",
    "wininet.dll": "HTTP/FTP networking",
    "winhttp.dll": "HTTP client API",
    "crypt32.dll": "Cryptography functions",
    "bcrypt.dll": "Next-gen cryptography",
    "user32.dll": "User interface (keylogging potential)",
    "shell32.dll": "Shell operations, execution",
    "urlmon.dll": "URL monikers (file download)",
    "ole32.dll": "COM/OLE (shellcode, exploits)",
    "psapi.dll": "Process status API (process enumeration)",
    "dbghelp.dll": "Debug helper (memory dumping)",
    "amsi.dll": "Anti-Malware Scan Interface (AMSI bypass target)",
    "vaultcli.dll": "Credential vault (credential theft)",
}


def extract_strings(data: bytes, min_length: int = 4) -> dict:
    """Extract and categorize all printable strings from binary data."""
    # ASCII strings
    ascii_pattern = re.compile(rb'[\x20-\x7e]{%d,}' % min_length)
    # UTF-16LE strings (Windows wide strings)
    utf16_pattern = re.compile(rb'(?:[\x20-\x7e]\x00){%d,}' % min_length)

    raw_strings = set()
    for m in ascii_pattern.finditer(data):
        try:
            raw_strings.add(m.group().decode("ascii", errors="ignore"))
        except Exception:
            pass
    for m in utf16_pattern.finditer(data):
        try:
            raw_strings.add(m.group().decode("utf-16-le", errors="ignore"))
        except Exception:
            pass

    text = "\n".join(raw_strings)

    # Categorize
    categorized = {}
    for cat, pattern in PATTERNS.items():
        matches = list(set(pattern.findall(text)))[:50]  # cap at 50
        if matches:
            categorized[cat] = matches

    # Find suspicious strings
    suspicious = {}
    for cat, keywords in SUSPICIOUS_STRINGS.items():
        found = []
        for kw in keywords:
            if kw.lower() in text.lower():
                found.append(kw)
        if found:
            suspicious[cat] = found

    return {
        "total_strings": len(raw_strings),
        "categorized": categorized,
        "suspicious": suspicious,
        "interesting_strings": sorted(
            [s for s in raw_strings if len(s) > 8 and any(c in s for c in ":/\\@.=")],
            key=len, reverse=True
        )[:100],
    }


# ──────────────────────────────────────────────
# 2. PE BINARY ANALYSIS
# ──────────────────────────────────────────────

# Known packer signatures (first bytes after MZ header entry point)
PACKER_SIGNATURES = {
    "UPX": [b"UPX0", b"UPX1", b"UPX2", b"UPX!"],
    "ASPack": [b".aspack", b".adata"],
    "Themida": [b".themida"],
    "MPRESS": [b".MPRESS1", b".MPRESS2"],
    "PECompact": [b".pec", b"PEC2"],
    "NSPack": [b".nsp0", b".nsp1"],
    "PEtite": [b".petite"],
    "MEW": [b"MEW"],
    "FSG": [b".FSG"],
}


def analyze_pe(data: bytes) -> dict | None:
    """Parse PE file structure. Returns None if not a PE file."""
    if len(data) < 64 or data[:2] != b"MZ":
        return None

    try:
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
            return None

        # COFF Header
        machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
        num_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
        timestamp = struct.unpack_from("<I", data, pe_offset + 8)[0]
        characteristics = struct.unpack_from("<H", data, pe_offset + 22)[0]

        # Architecture
        arch_map = {0x14c: "x86 (32-bit)", 0x8664: "x64 (64-bit)", 0xAA64: "ARM64"}
        architecture = arch_map.get(machine, f"Unknown (0x{machine:04x})")

        # Compile time
        try:
            compile_time = datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
        except (OSError, ValueError):
            compile_time = f"Invalid (0x{timestamp:08x})"

        # Check if timestamp is suspicious
        compile_suspicious = False
        try:
            ct = datetime.fromtimestamp(timestamp, tz=timezone.utc)
            if ct.year < 2000 or ct > datetime.now(timezone.utc):
                compile_suspicious = True
        except Exception:
            compile_suspicious = True

        # Optional header
        opt_offset = pe_offset + 24
        opt_magic = struct.unpack_from("<H", data, opt_offset)[0]
        is_pe32_plus = opt_magic == 0x20B  # PE32+

        # Entry point
        entry_point = struct.unpack_from("<I", data, opt_offset + 16)[0]

        # Image base
        if is_pe32_plus:
            image_base = struct.unpack_from("<Q", data, opt_offset + 24)[0]
            opt_header_size = 112
        else:
            image_base = struct.unpack_from("<I", data, opt_offset + 28)[0]
            opt_header_size = 96

        # Subsystem
        subsystem_offset = opt_offset + 68 if not is_pe32_plus else opt_offset + 68
        subsystem = struct.unpack_from("<H", data, subsystem_offset)[0]
        subsystem_map = {1: "Native", 2: "GUI", 3: "Console", 7: "POSIX"}
        subsystem_name = subsystem_map.get(subsystem, f"Unknown ({subsystem})")

        # Sections
        section_offset = opt_offset + struct.unpack_from("<H", data, pe_offset + 20)[0]
        sections = []
        for i in range(min(num_sections, 96)):
            off = section_offset + i * 40
            if off + 40 > len(data):
                break
            name_bytes = data[off:off + 8].rstrip(b'\x00')
            name = name_bytes.decode("ascii", errors="replace")
            vsize = struct.unpack_from("<I", data, off + 8)[0]
            rva = struct.unpack_from("<I", data, off + 12)[0]
            raw_size = struct.unpack_from("<I", data, off + 16)[0]
            raw_ptr = struct.unpack_from("<I", data, off + 20)[0]
            chars = struct.unpack_from("<I", data, off + 36)[0]

            # Section entropy
            section_data = data[raw_ptr:raw_ptr + raw_size] if raw_ptr + raw_size <= len(data) else b""
            section_entropy = _compute_entropy_block(section_data) if section_data else 0.0

            # Section flags
            flags = []
            if chars & 0x20: flags.append("CODE")
            if chars & 0x40: flags.append("INITIALIZED_DATA")
            if chars & 0x80: flags.append("UNINITIALIZED_DATA")
            if chars & 0x20000000: flags.append("EXECUTE")
            if chars & 0x40000000: flags.append("READ")
            if chars & 0x80000000: flags.append("WRITE")

            # Suspicious section characteristics
            suspicious = False
            if section_entropy > 7.0:
                suspicious = True  # Likely packed/encrypted
            if (chars & 0x20000000) and (chars & 0x80000000):
                suspicious = True  # RWX (read-write-execute)
            if name.startswith(".") and name not in (".text", ".data", ".rdata", ".bss", ".rsrc", ".reloc", ".idata", ".edata", ".pdata", ".tls"):
                suspicious = True  # Unusual section name

            sections.append({
                "name": name,
                "virtual_size": vsize,
                "virtual_address": f"0x{rva:08x}",
                "raw_size": raw_size,
                "raw_address": f"0x{raw_ptr:08x}",
                "entropy": round(section_entropy, 4),
                "flags": flags,
                "suspicious": suspicious,
            })

        # Import table parsing
        imports = _parse_imports(data, pe_offset, opt_offset, is_pe32_plus)

        # Packer detection
        detected_packers = _detect_packers(data, sections)

        # DLL characteristics (ASLR, DEP, etc.)
        dll_chars_offset = opt_offset + (70 if not is_pe32_plus else 70)
        dll_chars = struct.unpack_from("<H", data, dll_chars_offset)[0]
        security_features = {
            "ASLR": bool(dll_chars & 0x40),
            "DEP/NX": bool(dll_chars & 0x100),
            "SEH": not bool(dll_chars & 0x400),
            "CFG": bool(dll_chars & 0x4000),
            "High Entropy ASLR": bool(dll_chars & 0x20),
        }

        return {
            "architecture": architecture,
            "compile_time": compile_time,
            "compile_suspicious": compile_suspicious,
            "entry_point": f"0x{entry_point:08x}",
            "image_base": f"0x{image_base:016x}" if is_pe32_plus else f"0x{image_base:08x}",
            "subsystem": subsystem_name,
            "pe_type": "PE32+" if is_pe32_plus else "PE32",
            "num_sections": num_sections,
            "sections": sections,
            "imports": imports,
            "packers_detected": detected_packers,
            "security_features": security_features,
            "is_dll": bool(characteristics & 0x2000),
            "is_executable": bool(characteristics & 0x2),
        }
    except Exception as e:
        return {"error": str(e), "partial": True}


def _parse_imports(data: bytes, pe_offset: int, opt_offset: int, is_pe32_plus: bool) -> dict:
    """Parse PE import table to extract imported DLLs and functions."""
    imports = {}
    try:
        # Data directories start after the fixed optional header fields
        if is_pe32_plus:
            dd_offset = opt_offset + 112
        else:
            dd_offset = opt_offset + 96

        # Import directory (index 1)
        import_rva = struct.unpack_from("<I", data, dd_offset + 8)[0]
        import_size = struct.unpack_from("<I", data, dd_offset + 12)[0]

        if import_rva == 0:
            return imports

        # Find import RVA in sections
        section_offset = opt_offset + struct.unpack_from("<H", data, pe_offset + 20)[0]
        num_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]

        import_file_offset = _rva_to_offset(data, import_rva, section_offset, num_sections)
        if import_file_offset is None:
            return imports

        # Parse import descriptors
        pos = import_file_offset
        for _ in range(200):  # safety limit
            if pos + 20 > len(data):
                break
            name_rva = struct.unpack_from("<I", data, pos + 12)[0]
            if name_rva == 0:
                break

            dll_name_offset = _rva_to_offset(data, name_rva, section_offset, num_sections)
            if dll_name_offset and dll_name_offset < len(data):
                end = data.index(b'\x00', dll_name_offset) if b'\x00' in data[dll_name_offset:dll_name_offset + 256] else dll_name_offset + 256
                dll_name = data[dll_name_offset:end].decode("ascii", errors="replace")

                # Parse function names from ILT/INT
                ilt_rva = struct.unpack_from("<I", data, pos)[0]
                if ilt_rva == 0:
                    ilt_rva = struct.unpack_from("<I", data, pos + 16)[0]  # Use IAT

                functions = []
                if ilt_rva:
                    ilt_offset = _rva_to_offset(data, ilt_rva, section_offset, num_sections)
                    if ilt_offset:
                        entry_size = 8 if is_pe32_plus else 4
                        for j in range(500):
                            entry_off = ilt_offset + j * entry_size
                            if entry_off + entry_size > len(data):
                                break
                            if is_pe32_plus:
                                entry = struct.unpack_from("<Q", data, entry_off)[0]
                                ordinal_flag = entry & 0x8000000000000000
                            else:
                                entry = struct.unpack_from("<I", data, entry_off)[0]
                                ordinal_flag = entry & 0x80000000
                            if entry == 0:
                                break
                            if ordinal_flag:
                                functions.append(f"Ordinal #{entry & 0xFFFF}")
                            else:
                                hint_rva = entry & 0x7FFFFFFF
                                hint_off = _rva_to_offset(data, hint_rva, section_offset, num_sections)
                                if hint_off and hint_off + 2 < len(data):
                                    fname_start = hint_off + 2
                                    fname_end = data.index(b'\x00', fname_start) if b'\x00' in data[fname_start:fname_start + 256] else fname_start + 256
                                    func_name = data[fname_start:fname_end].decode("ascii", errors="replace")
                                    functions.append(func_name)

                is_suspicious = dll_name.lower() in SUSPICIOUS_DLLS
                imports[dll_name] = {
                    "functions": functions[:100],
                    "count": len(functions),
                    "suspicious": is_suspicious,
                    "description": SUSPICIOUS_DLLS.get(dll_name.lower(), ""),
                }
            pos += 20

    except Exception:
        pass

    return imports


def _rva_to_offset(data: bytes, rva: int, section_offset: int, num_sections: int) -> int | None:
    """Convert RVA to file offset using section table."""
    for i in range(min(num_sections, 96)):
        off = section_offset + i * 40
        if off + 40 > len(data):
            break
        vaddr = struct.unpack_from("<I", data, off + 12)[0]
        vsize = struct.unpack_from("<I", data, off + 8)[0]
        raw_ptr = struct.unpack_from("<I", data, off + 20)[0]
        raw_size = struct.unpack_from("<I", data, off + 16)[0]
        if vaddr <= rva < vaddr + max(vsize, raw_size):
            return raw_ptr + (rva - vaddr)
    return None


def _detect_packers(data: bytes, sections: list) -> list:
    """Detect known packers by section names and signatures."""
    detected = []
    text = data[:min(len(data), 50000)]  # Search first 50KB

    for packer, sigs in PACKER_SIGNATURES.items():
        for sig in sigs:
            if sig in text:
                detected.append(packer)
                break

    # Check section names
    section_names = [s["name"] for s in sections]
    for name in section_names:
        name_lower = name.lower().strip(".")
        if name_lower in ("upx0", "upx1", "upx2"):
            if "UPX" not in detected:
                detected.append("UPX")
        elif name_lower in ("aspack", "adata"):
            if "ASPack" not in detected:
                detected.append("ASPack")
        elif name_lower == "themida":
            if "Themida" not in detected:
                detected.append("Themida")
        elif name_lower in ("mpress1", "mpress2"):
            if "MPRESS" not in detected:
                detected.append("MPRESS")

    # High entropy heuristic (all sections > 7.0 suggests packing)
    if len(sections) > 0:
        high_entropy_count = sum(1 for s in sections if s["entropy"] > 7.0 and s["raw_size"] > 512)
        if high_entropy_count >= len(sections) * 0.6 and not detected:
            detected.append("Unknown Packer (high entropy)")

    return detected


# ──────────────────────────────────────────────
# 3. NETWORK IOC EXTRACTION
# ──────────────────────────────────────────────

def extract_network_iocs(data: bytes) -> dict:
    """Extract network indicators of compromise."""
    text = data.decode("ascii", errors="ignore") + data.decode("utf-16-le", errors="ignore")

    urls = list(set(PATTERNS["urls"].findall(text)))[:50]
    ips = list(set(PATTERNS["ips"].findall(text)))
    domains = list(set(PATTERNS["domains"].findall(text)))[:50]
    emails = list(set(PATTERNS["emails"].findall(text)))[:20]

    # Filter out common/benign IPs
    ips = [ip for ip in ips if not ip.startswith(("0.", "127.", "255.", "224."))][:30]
    # Filter common benign domains
    benign = {"microsoft.com", "google.com", "apple.com", "w3.org", "xml.org", "xmlsoap.org", "schemas.microsoft.com"}
    domains = [d for d in domains if d.lower() not in benign]

    # Classify each IOC
    ioc_list = []
    for url in urls:
        severity = "medium"
        if any(s in url.lower() for s in ["pastebin", "raw.githubusercontent", "discord.gg", "bit.ly", ".tk", ".xyz"]):
            severity = "high"
        ioc_list.append({"type": "url", "value": url, "severity": severity})

    for ip in ips:
        ioc_list.append({"type": "ip", "value": ip, "severity": "medium"})

    for domain in domains:
        severity = "low"
        if any(tld in domain for tld in [".tk", ".xyz", ".top", ".pw", ".ws", ".cc"]):
            severity = "high"
        ioc_list.append({"type": "domain", "value": domain, "severity": severity})

    for email in emails:
        ioc_list.append({"type": "email", "value": email, "severity": "low"})

    return {
        "total_iocs": len(ioc_list),
        "urls": urls,
        "ips": ips,
        "domains": domains,
        "emails": emails,
        "ioc_list": ioc_list,
    }


# ──────────────────────────────────────────────
# 4. ENTROPY HEATMAP
# ──────────────────────────────────────────────

def _compute_entropy_block(block: bytes) -> float:
    """Compute Shannon entropy of a byte block."""
    if not block:
        return 0.0
    freq = [0] * 256
    for b in block:
        freq[b] += 1
    length = len(block)
    entropy = 0.0
    for f in freq:
        if f > 0:
            p = f / length
            entropy -= p * math.log2(p)
    return entropy


def compute_entropy_map(data: bytes, num_blocks: int = 256) -> dict:
    """Compute entropy across file in blocks for heatmap visualization."""
    if not data:
        return {"blocks": [], "overall": 0.0, "max": 0.0, "min": 0.0}

    block_size = max(1, len(data) // num_blocks)
    blocks = []
    for i in range(0, len(data), block_size):
        chunk = data[i:i + block_size]
        ent = round(_compute_entropy_block(chunk), 4)
        blocks.append({
            "offset": i,
            "size": len(chunk),
            "entropy": ent,
        })

    overall = _compute_entropy_block(data)
    entropies = [b["entropy"] for b in blocks]

    return {
        "blocks": blocks[:512],  # cap
        "overall": round(overall, 4),
        "max": round(max(entropies), 4) if entropies else 0.0,
        "min": round(min(entropies), 4) if entropies else 0.0,
        "block_size": block_size,
        "file_size": len(data),
    }


# ──────────────────────────────────────────────
# 5. MITRE ATT&CK MAPPING
# ──────────────────────────────────────────────

MITRE_MAP = {
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "keywords": ["cmd.exe", "powershell", "/bin/sh", "/bin/bash", "WScript.Shell", "cscript", "wscript"],
        "description": "Adversaries may abuse command interpreters to execute commands, scripts, or binaries.",
    },
    "T1059.001": {
        "name": "PowerShell",
        "tactic": "Execution",
        "keywords": ["powershell", "Invoke-Expression", "IEX(", "Invoke-WebRequest", "DownloadString", "-EncodedCommand", "-exec bypass"],
        "description": "Adversaries may abuse PowerShell for execution and automation.",
    },
    "T1547.001": {
        "name": "Registry Run Keys / Startup Folder",
        "tactic": "Persistence",
        "keywords": ["CurrentVersion\\Run", "RunOnce", "RegSetValue", "RegCreateKey", "HKLM\\SOFTWARE", "HKCU\\SOFTWARE"],
        "description": "Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Run key.",
    },
    "T1053": {
        "name": "Scheduled Task/Job",
        "tactic": "Persistence",
        "keywords": ["schtasks", "at.exe", "crontab", "systemctl enable"],
        "description": "Adversaries may abuse task scheduling to execute malicious code at a predefined time.",
    },
    "T1055": {
        "name": "Process Injection",
        "tactic": "Defense Evasion",
        "keywords": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtWriteVirtualMemory", "QueueUserAPC", "NtUnmapViewOfSection"],
        "description": "Adversaries may inject code into processes to evade defenses and elevate privileges.",
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "keywords": ["FromBase64String", "ToBase64String", "atob(", "btoa(", "-EncodedCommand", "CryptEncrypt"],
        "description": "Adversaries may obfuscate payloads to make them difficult to discover or analyze.",
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "keywords": ["HttpOpenRequest", "HttpSendRequest", "InternetOpen", "WinHttpOpen", "URLDownloadToFile", "wget ", "curl "],
        "description": "Adversaries may communicate using application layer protocols (HTTP, HTTPS, DNS).",
    },
    "T1082": {
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "keywords": ["GetComputerName", "GetVersionEx", "systeminfo", "uname", "GetSystemInfo"],
        "description": "Adversaries may attempt to get detailed information about the operating system and hardware.",
    },
    "T1083": {
        "name": "File and Directory Discovery",
        "tactic": "Discovery",
        "keywords": ["FindFirstFile", "FindNextFile", "dir /s", "ls -la", "GetFileAttributes"],
        "description": "Adversaries may enumerate files and directories or search for specific file types.",
    },
    "T1497": {
        "name": "Virtualization/Sandbox Evasion",
        "tactic": "Defense Evasion",
        "keywords": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "VirtualBox", "VMware", "VBOX", "sandbox", "Wine", "QEMU", "GetTickCount"],
        "description": "Adversaries may check for virtualization or sandbox environments to avoid analysis.",
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "keywords": ["lsass", "mimikatz", "sekurlsa", "SAM", "NTDS.dit", "shadow", "passwd"],
        "description": "Adversaries may dump credentials from the OS to gain access to other systems.",
    },
    "T1562": {
        "name": "Impair Defenses",
        "tactic": "Defense Evasion",
        "keywords": ["amsi.dll", "AmsiScanBuffer", "EtwEventWrite", "NtTraceEvent", "DisableAntiSpyware"],
        "description": "Adversaries may maliciously modify components of a victim environment to hinder defenses.",
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "keywords": ["DownloadFile", "URLDownloadToFile", "wget ", "curl ", "Invoke-WebRequest", "Net.WebClient"],
        "description": "Adversaries may transfer tools from an external system into a compromised environment.",
    },
    "T1140": {
        "name": "Deobfuscate/Decode Files or Information",
        "tactic": "Defense Evasion",
        "keywords": ["CryptDecrypt", "BCryptDecrypt", "FromBase64String", "atob(", "certutil -decode"],
        "description": "Adversaries may deobfuscate or decode files or information to reveal their true payload.",
    },
    "T1569.002": {
        "name": "Service Execution",
        "tactic": "Execution",
        "keywords": ["CreateService", "StartService", "sc.exe", "net start"],
        "description": "Adversaries may abuse the Windows service control manager to execute malicious commands.",
    },
}


def map_mitre_attacks(strings_result: dict, pe_result: dict | None) -> list:
    """Map discovered strings and imports to MITRE ATT&CK techniques."""
    # Combine all searchable text
    all_strings = set()
    for cat_items in strings_result.get("suspicious", {}).values():
        all_strings.update(cat_items)
    for cat_items in strings_result.get("categorized", {}).values():
        all_strings.update(cat_items)
    for s in strings_result.get("interesting_strings", []):
        all_strings.add(s)

    # Add import function names
    if pe_result and isinstance(pe_result, dict) and "imports" in pe_result:
        for dll, info in pe_result["imports"].items():
            all_strings.add(dll)
            for func in info.get("functions", []):
                all_strings.add(func)

    search_text = " ".join(all_strings).lower()

    matched = []
    for technique_id, info in MITRE_MAP.items():
        matches = [kw for kw in info["keywords"] if kw.lower() in search_text]
        if matches:
            matched.append({
                "id": technique_id,
                "name": info["name"],
                "tactic": info["tactic"],
                "description": info["description"],
                "matched_indicators": matches,
                "confidence": min(100, len(matches) * 25),
            })

    # Sort by confidence desc
    matched.sort(key=lambda x: x["confidence"], reverse=True)
    return matched


# ──────────────────────────────────────────────
# 6. RISK SCORE
# ──────────────────────────────────────────────

def compute_risk_score(vt_detections: int, vt_total: int, strings_result: dict,
                       pe_result: dict | None, ioc_result: dict, mitre_result: list,
                       entropy: float) -> dict:
    """Compute a composite risk score (0-100) with breakdown."""
    factors = {}

    # Factor 1: VT Detection Ratio (0-35 points)
    if vt_total > 0:
        detection_pct = vt_detections / vt_total
        vt_score = min(35, int(detection_pct * 35))
    else:
        vt_score = 0
    factors["vt_detections"] = {
        "score": vt_score,
        "max": 35,
        "label": "AV Engine Detections",
        "detail": f"{vt_detections}/{vt_total} security vendors flagged",
    }

    # Factor 2: Suspicious Strings (0-20 points)
    suspicious_count = sum(len(v) for v in strings_result.get("suspicious", {}).values())
    strings_score = min(20, suspicious_count * 2)
    factors["suspicious_strings"] = {
        "score": strings_score,
        "max": 20,
        "label": "Suspicious Strings",
        "detail": f"{suspicious_count} suspicious indicators found",
    }

    # Factor 3: Network IOCs (0-15 points)
    ioc_count = ioc_result.get("total_iocs", 0)
    high_sev = sum(1 for i in ioc_result.get("ioc_list", []) if i.get("severity") == "high")
    ioc_score = min(15, ioc_count + high_sev * 3)
    factors["network_iocs"] = {
        "score": ioc_score,
        "max": 15,
        "label": "Network Indicators",
        "detail": f"{ioc_count} IOCs ({high_sev} high severity)",
    }

    # Factor 4: PE Anomalies (0-15 points)
    pe_score = 0
    pe_detail = "Not a PE file"
    if pe_result and isinstance(pe_result, dict) and "error" not in pe_result:
        if pe_result.get("packers_detected"):
            pe_score += 5
        if pe_result.get("compile_suspicious"):
            pe_score += 3
        suspicious_sections = sum(1 for s in pe_result.get("sections", []) if s.get("suspicious"))
        pe_score += min(4, suspicious_sections * 2)
        suspicious_imports = sum(1 for d in pe_result.get("imports", {}).values() if d.get("suspicious"))
        pe_score += min(3, suspicious_imports)
        pe_score = min(15, pe_score)
        pe_detail = f"{len(pe_result.get('packers_detected', []))} packers, {suspicious_sections} suspicious sections"
    factors["pe_anomalies"] = {
        "score": pe_score,
        "max": 15,
        "label": "PE Anomalies",
        "detail": pe_detail,
    }

    # Factor 5: MITRE ATT&CK (0-10 points)
    mitre_score = min(10, len(mitre_result) * 2)
    factors["mitre_techniques"] = {
        "score": mitre_score,
        "max": 10,
        "label": "MITRE ATT&CK Techniques",
        "detail": f"{len(mitre_result)} techniques mapped",
    }

    # Factor 6: Entropy (0-5 points)
    entropy_score = 0
    if entropy > 7.5:
        entropy_score = 5
    elif entropy > 7.0:
        entropy_score = 3
    elif entropy > 6.5:
        entropy_score = 1
    factors["entropy"] = {
        "score": entropy_score,
        "max": 5,
        "label": "File Entropy",
        "detail": f"{entropy:.2f} bits/byte" + (" (packed/encrypted)" if entropy > 7.0 else ""),
    }

    total = sum(f["score"] for f in factors.values())
    max_total = sum(f["max"] for f in factors.values())

    # Risk level
    if total >= 75:
        level = "Critical"
    elif total >= 50:
        level = "High"
    elif total >= 25:
        level = "Medium"
    elif total >= 10:
        level = "Low"
    else:
        level = "Clean"

    return {
        "total_score": total,
        "max_score": max_total,
        "level": level,
        "factors": factors,
    }


# ──────────────────────────────────────────────
# MAIN ANALYSIS ENTRY POINT
# ──────────────────────────────────────────────

def run_deep_analysis(data: bytes, filename: str, vt_detections: int = 0, vt_total: int = 0) -> dict:
    """Run all deep analysis modules on a file."""
    from backend.scanner.engine import compute_entropy

    entropy = compute_entropy(data)

    # 1. Strings
    strings_result = extract_strings(data)

    # 2. PE Analysis
    pe_result = analyze_pe(data)

    # 3. Network IOCs
    ioc_result = extract_network_iocs(data)

    # 4. Entropy heatmap
    entropy_map = compute_entropy_map(data)

    # 5. MITRE ATT&CK
    mitre_result = map_mitre_attacks(strings_result, pe_result)

    # 6. Risk score
    risk_score = compute_risk_score(
        vt_detections, vt_total,
        strings_result, pe_result, ioc_result, mitre_result,
        entropy,
    )

    return {
        "strings": strings_result,
        "pe_info": pe_result,
        "network_iocs": ioc_result,
        "entropy_map": entropy_map,
        "mitre_attacks": mitre_result,
        "risk_score": risk_score,
    }
