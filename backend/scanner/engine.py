"""
SentinelLab – Real Multi-Engine API Scanner

Uploads files to external analysis service, polls for analysis results,
and returns real detection data from 70+ AV engines.
"""
import hashlib
import math
import os
import time
import requests
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent.parent / ".env")

VT_API_KEY = os.getenv("VT_API_KEY", "")
VT_BASE = "https://www.virustotal.com/api/v3"
HEADERS = {"x-apikey": VT_API_KEY}

# Max poll time for VT analysis (seconds)
MAX_POLL_TIME = 120
POLL_INTERVAL = 10


def compute_file_hashes(data: bytes) -> dict:
    """Compute SHA-256, SHA-1, MD5."""
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
    }


def compute_entropy(data: bytes) -> float:
    """Shannon entropy (0-8 bits/byte)."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    entropy = 0.0
    for f in freq:
        if f > 0:
            p = f / length
            entropy -= p * math.log2(p)
    return entropy


def detect_file_type(filename: str, data: bytes) -> tuple[str, str, str]:
    """Basic file type detection from extension & magic bytes."""
    ext = Path(filename).suffix.lower()
    magic = data[:4].hex() if data else ""

    type_map = {
        ".exe": ("PE Executable", "application/x-dosexec"),
        ".dll": ("Dynamic Link Library", "application/x-dosexec"),
        ".pdf": ("PDF Document", "application/pdf"),
        ".doc": ("Word Document", "application/msword"),
        ".docx": ("Word Document (OOXML)", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
        ".zip": ("ZIP Archive", "application/zip"),
        ".rar": ("RAR Archive", "application/x-rar-compressed"),
        ".py": ("Python Script", "text/x-python"),
        ".js": ("JavaScript File", "application/javascript"),
        ".sh": ("Shell Script", "application/x-sh"),
        ".bat": ("Batch Script", "application/x-msdos-program"),
        ".ps1": ("PowerShell Script", "application/x-powershell"),
        ".jpg": ("JPEG Image", "image/jpeg"),
        ".png": ("PNG Image", "image/png"),
        ".txt": ("Text File", "text/plain"),
        ".html": ("HTML File", "text/html"),
        ".apk": ("Android Package", "application/vnd.android.package-archive"),
        ".jar": ("Java Archive", "application/java-archive"),
        ".iso": ("Disk Image", "application/x-iso9660-image"),
    }

    if ext in type_map:
        ft, mt = type_map[ext]
    else:
        ft, mt = "Unknown", "application/octet-stream"

    return ft, mt, magic


def _upload_to_vt(file_data: bytes, filename: str) -> str:
    """Upload file to VirusTotal. Returns analysis ID."""
    resp = requests.post(
        f"{VT_BASE}/files",
        headers=HEADERS,
        files={"file": (filename, file_data)},
        timeout=60,
    )
    resp.raise_for_status()
    data = resp.json()
    return data["data"]["id"]


def check_hash_on_vt(sha256: str) -> dict | None:
    """Check if VT already has a report for this hash."""
    resp = requests.get(
        f"{VT_BASE}/files/{sha256}",
        headers=HEADERS,
        timeout=30,
    )
    if resp.status_code == 200:
        return resp.json()
    return None


def _poll_analysis(analysis_id: str) -> dict:
    """Poll VT until analysis is complete."""
    start = time.time()
    while time.time() - start < MAX_POLL_TIME:
        resp = requests.get(
            f"{VT_BASE}/analyses/{analysis_id}",
            headers=HEADERS,
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        status = data["data"]["attributes"]["status"]
        return data
        time.sleep(POLL_INTERVAL)
    raise TimeoutError("Analysis timed out")


def parse_vt_results(vt_data: dict, filename: str, file_data: bytes) -> dict:
    """Parse VT API response into our standard format."""
    attrs = vt_data.get("data", {}).get("attributes", {})

    # If this is from /files/{hash}, structure is different than /analyses/{id}
    last_analysis = attrs.get("last_analysis_results", {})
    stats = attrs.get("last_analysis_stats", {})

    hashes = compute_file_hashes(file_data)
    entropy = compute_entropy(file_data)
    file_type, mime_type, magic = detect_file_type(filename, file_data)

    # Override with VT data if available
    vt_file_type = attrs.get("type_description", file_type)
    vt_magic = attrs.get("magic", "")

    engine_results = []
    total_engines = 0
    total_detections = 0

    for engine_name, result in sorted(last_analysis.items()):
        detected = result.get("category") in ("malicious", "suspicious")
        threat = result.get("result")
        category = result.get("category", "undetected")
        version = result.get("engine_version", "N/A")

        total_engines += 1
        if detected:
            total_detections += 1

        engine_results.append({
            "engine_name": engine_name,
            "engine_version": version or "N/A",
            "detected": detected,
            "threat_name": threat if detected else None,
            "category": category,
            "confidence": 100.0 if detected else 0.0,
            "scan_time_ms": 0,
        })

    return {
        **hashes,
        "filename": filename,
        "file_size": len(file_data),
        "file_type": vt_file_type or file_type,
        "mime_type": mime_type,
        "magic_bytes": magic,
        "entropy": round(entropy, 4),
        "total_engines": total_engines,
        "detections": total_detections,
        "detection_ratio": f"{total_detections}/{total_engines}",
        "engine_results": engine_results,
        "vt_link": f"https://www.virustotal.com/gui/file/{hashes['sha256']}",
    }


def _parse_analysis_results(analysis_data: dict, filename: str, file_data: bytes) -> dict:
    """Parse analysis poll response."""
    attrs = analysis_data.get("data", {}).get("attributes", {})
    results = attrs.get("results", {})
    stats = attrs.get("stats", {})

    hashes = compute_file_hashes(file_data)
    entropy = compute_entropy(file_data)
    file_type, mime_type, magic = detect_file_type(filename, file_data)

    engine_results = []
    total_engines = 0
    total_detections = 0

    for engine_name, result in sorted(results.items()):
        detected = result.get("category") in ("malicious", "suspicious")
        threat = result.get("result")
        category = result.get("category", "undetected")
        version = result.get("engine_version", "N/A")

        total_engines += 1
        if detected:
            total_detections += 1

        engine_results.append({
            "engine_name": engine_name,
            "engine_version": version or "N/A",
            "detected": detected,
            "threat_name": threat if detected else None,
            "category": category,
            "confidence": 100.0 if detected else 0.0,
            "scan_time_ms": 0,
        })

    return {
        **hashes,
        "filename": filename,
        "file_size": len(file_data),
        "file_type": file_type,
        "mime_type": mime_type,
        "magic_bytes": magic,
        "entropy": round(entropy, 4),
        "total_engines": total_engines,
        "detections": total_detections,
        "detection_ratio": f"{total_detections}/{total_engines}",
        "engine_results": engine_results,
        "vt_link": f"https://www.virustotal.com/gui/file/{hashes['sha256']}",
    }


def start_vt_scan(file_data: bytes, filename: str) -> str:
    """
    Start a file scan on VirusTotal.
    Returns: analysis_id (str)
    """
    # 1. Upload the file to get an analysis ID
    try:
        return _upload_to_vt(file_data, filename)
    except requests.exceptions.RequestException as e:
        # If upload fails, try to check if hash exists (maybe we missed it)
        hashes = compute_file_hashes(file_data)
        existing = check_hash_on_vt(hashes["sha256"])
        if existing:
            # If it exists, we can't get a new analysis ID easily without re-rescan
            # But we can return the object ID (sha256) and handle it
            return existing.get("data", {}).get("id") or hashes["sha256"]
        raise e


def poll_vt_results(analysis_id: str, file_data: bytes, filename: str) -> dict:
    """
    Check status of a running Analysis.
    Returns: dict with "status" (queued, completed, scanning) and "data" (parsed results)
    Now also returns partial results during scanning so engines appear live.
    """
    try:
        data = _poll_analysis_once(analysis_id)
        status = data["data"]["attributes"]["status"]
        
        # Always parse whatever results are available
        parsed = _parse_analysis_results(data, filename, file_data)
        
        if status == "completed":
            return {"status": "completed", "data": parsed}
        
        # Return partial results during scanning
        return {"status": "scanning", "data": parsed}
    except Exception as e:
        return {"status": "failed", "error": str(e)}


def _poll_analysis_once(analysis_id: str) -> dict:
    """Single poll check."""
    resp = requests.get(
        f"{VT_BASE}/analyses/{analysis_id}",
        headers=HEADERS,
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


def scan_file_sync(file_data: bytes, filename: str) -> dict:
    """Legacy synchronous scan (blocking)."""
    # ... logic from before if needed, or just wrap the above ...
    # For now, we are moving to async, so we'll leave this or remove it.
    # Let's keep a simplified version for 'rescan' if needed
    analysis_id = start_vt_scan(file_data, filename)
    
    start = time.time()
    while time.time() - start < MAX_POLL_TIME:
        res = poll_vt_results(analysis_id, file_data, filename)
        if res["status"] == "completed":
            return res["data"]
        time.sleep(POLL_INTERVAL)
    raise TimeoutError("Analysis timed out")
