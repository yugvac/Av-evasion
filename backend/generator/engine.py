"""
SentinelLab — Test File Generator Engine

Generates harmless test files with varying characteristics for AV detection research.
All generated files contain ONLY random/structured benign data — zero malicious content.
"""
import os
import math
import random
import hashlib
import base64
import struct
import string
from pathlib import Path
from typing import Optional
from backend.config import SAMPLES_DIR
from backend.utils.logger import get_logger

logger = get_logger("Generator")

# ── Entropy Level Profiles ──────────────────────────────────────────
ENTROPY_PROFILES = {
    "very_low":  (0.5, 1.5),
    "low":       (1.5, 3.0),
    "medium":    (3.0, 5.0),
    "high":      (5.5, 6.5),
    "very_high": (6.5, 7.5),
    "maximum":   (7.5, 7.99),
}

# ── Encoding Formats ────────────────────────────────────────────────
ENCODINGS = ["plaintext", "base64", "xor", "hex", "rot13"]

# ── Structural Patterns ─────────────────────────────────────────────
STRUCTURAL_PATTERNS = ["sequential", "random", "repeating", "mixed", "layered"]

# ── Metadata Profiles (simulated file headers) ──────────────────────
METADATA_PROFILES = {
    "generic":   b"\x00" * 16,
    "pe_like":   b"MZ" + b"\x90" * 14,      # PE-style (harmless stub)
    "elf_like":  b"\x7fELF" + b"\x00" * 12,  # ELF-style header
    "pdf_like":  b"%PDF-1.7\n" + b"\x00" * 7, # PDF header
    "office_like": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 8,  # OLE header
    "zip_like":  b"PK\x03\x04" + b"\x00" * 12,  # ZIP header
}

# ── File Size Distributions ──────────────────────────────────────────
SIZE_PROFILES = {
    "tiny":   (512, 2048),
    "small":  (2048, 10240),
    "medium": (10240, 102400),
    "large":  (102400, 524288),
    "xlarge": (524288, 1048576),
}


def _generate_low_entropy_block(size: int) -> bytes:
    """Generate data with low entropy (lots of repetition)."""
    char = random.choice(string.ascii_letters).encode()
    pattern = char * random.randint(4, 16)
    repeats = (size // len(pattern)) + 1
    return (pattern * repeats)[:size]


def _generate_medium_entropy_block(size: int) -> bytes:
    """Generate data with medium entropy (somewhat varied)."""
    charset = string.ascii_letters + string.digits
    block_size = random.randint(8, 32)
    blocks = []
    while sum(len(b) for b in blocks) < size:
        block = ''.join(random.choices(charset, k=block_size)).encode()
        repeat = random.randint(1, 4)
        blocks.append(block * repeat)
    return b''.join(blocks)[:size]


def _generate_high_entropy_block(size: int) -> bytes:
    """Generate data with high entropy (nearly random)."""
    return os.urandom(size)


def _generate_data_for_entropy(target_entropy: float, size: int) -> bytes:
    """Generate data approximating a target entropy value (0-8 bits/byte)."""
    if target_entropy < 2.0:
        return _generate_low_entropy_block(size)
    elif target_entropy < 5.0:
        # Mix repetitive and random data
        random_ratio = (target_entropy - 1.0) / 6.0
        random_bytes = int(size * random_ratio)
        repetitive_bytes = size - random_bytes
        data = _generate_low_entropy_block(repetitive_bytes) + os.urandom(random_bytes)
        data_list = list(data)
        random.shuffle(data_list)
        return bytes(data_list)[:size]
    else:
        # High entropy: mostly random
        random_ratio = min((target_entropy - 3.0) / 5.0, 1.0)
        random_bytes = int(size * random_ratio)
        pattern_bytes = size - random_bytes
        data = os.urandom(random_bytes)
        if pattern_bytes > 0:
            data += _generate_medium_entropy_block(pattern_bytes)
        data_list = list(data)
        random.shuffle(data_list)
        return bytes(data_list)[:size]


def _apply_encoding(data: bytes, encoding: str) -> bytes:
    """Apply an encoding transformation to the data."""
    if encoding == "base64":
        return base64.b64encode(data)
    elif encoding == "xor":
        key = random.randint(1, 255)
        return bytes(b ^ key for b in data)
    elif encoding == "hex":
        return data.hex().encode()
    elif encoding == "rot13":
        result = []
        for b in data:
            if 65 <= b <= 90:
                result.append(((b - 65 + 13) % 26) + 65)
            elif 97 <= b <= 122:
                result.append(((b - 97 + 13) % 26) + 97)
            else:
                result.append(b)
        return bytes(result)
    return data  # plaintext


def _apply_structure(data: bytes, pattern: str) -> bytes:
    """Apply structural pattern to data layout."""
    size = len(data)
    if pattern == "sequential":
        return data
    elif pattern == "repeating":
        chunk = data[:size // 4] if size > 4 else data
        return (chunk * 5)[:size]
    elif pattern == "mixed":
        quarter = size // 4
        return (
            data[:quarter]
            + bytes(reversed(data[quarter:quarter*2]))
            + data[quarter*2:quarter*3]
            + os.urandom(size - quarter*3)
        )
    elif pattern == "layered":
        # Interleave the data with a pattern
        layer = b"\x00\xff" * (size // 2)
        return bytes(a ^ b for a, b in zip(data, layer[:size]))
    else:  # random
        data_list = list(data)
        random.shuffle(data_list)
        return bytes(data_list)


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data (bits per byte, 0-8)."""
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def generate_test_file(
    experiment_id: int,
    index: int,
    entropy_level: Optional[str] = None,
    encoding: Optional[str] = None,
    size_profile: Optional[str] = None,
    structural_pattern: Optional[str] = None,
    metadata_profile: Optional[str] = None,
) -> dict:
    """
    Generate a single harmless test file with specified characteristics.

    Returns dict with file metadata for database storage.
    """
    # Randomize any unspecified parameters
    if entropy_level is None:
        entropy_level = random.choice(list(ENTROPY_PROFILES.keys()))
    if encoding is None:
        encoding = random.choice(ENCODINGS)
    if size_profile is None:
        size_profile = random.choice(list(SIZE_PROFILES.keys()))
    if structural_pattern is None:
        structural_pattern = random.choice(STRUCTURAL_PATTERNS)
    if metadata_profile is None:
        metadata_profile = random.choice(list(METADATA_PROFILES.keys()))

    # Determine target entropy and file size
    ent_min, ent_max = ENTROPY_PROFILES[entropy_level]
    target_entropy = random.uniform(ent_min, ent_max)
    size_min, size_max = SIZE_PROFILES[size_profile]
    file_size = random.randint(size_min, size_max)

    # Generate data
    header = METADATA_PROFILES[metadata_profile]
    body_size = max(file_size - len(header), 64)
    body = _generate_data_for_entropy(target_entropy, body_size)
    body = _apply_encoding(body, encoding)
    body = _apply_structure(body, structural_pattern)

    # Ensure we don't exceed target size too much
    file_data = header + body[:body_size]

    # Calculate actual entropy
    actual_entropy = calculate_entropy(file_data)

    # Generate filename and save
    filename = f"exp{experiment_id:04d}_sample{index:04d}_{entropy_level}_{encoding}.bin"
    exp_dir = SAMPLES_DIR / f"experiment_{experiment_id}"
    exp_dir.mkdir(parents=True, exist_ok=True)
    filepath = exp_dir / filename

    with open(filepath, "wb") as f:
        f.write(file_data)

    file_hash = hashlib.sha256(file_data).hexdigest()

    logger.info(
        f"Generated: {filename} | Size: {len(file_data)} | "
        f"Entropy: {actual_entropy:.2f} | Encoding: {encoding} | Pattern: {structural_pattern}"
    )

    return {
        "filename": filename,
        "file_size": len(file_data),
        "entropy": actual_entropy,
        "encoding": encoding,
        "structural_pattern": structural_pattern,
        "metadata_profile": metadata_profile,
        "file_hash": file_hash,
    }


def generate_batch(
    experiment_id: int,
    count: int = 20,
    entropy_levels: Optional[list] = None,
    encodings: Optional[list] = None,
) -> list[dict]:
    """Generate a batch of test files for an experiment."""
    logger.info(f"Generating batch of {count} samples for experiment {experiment_id}")
    samples = []

    for i in range(count):
        ent = random.choice(entropy_levels) if entropy_levels else None
        enc = random.choice(encodings) if encodings else None
        sample = generate_test_file(experiment_id, i, entropy_level=ent, encoding=enc)
        samples.append(sample)

    logger.info(f"Batch complete: {len(samples)} samples generated")
    return samples
