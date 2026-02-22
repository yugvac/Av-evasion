"""
SentinelLab — Seed Script

Generates initial demo data so the dashboard isn't empty on first launch.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.database import init_db
from backend.scheduler.scheduler import run_single_experiment_now
from backend.utils.logger import get_logger

logger = get_logger("Seed")


def seed():
    """Generate demo experiments."""
    init_db()
    logger.info("🌱 Seeding database with demo experiments...")

    demo_experiments = [
        ("Baseline Entropy Study", "Analyzing detection rates across entropy levels", 25),
        ("Encoding Impact Analysis", "Testing how encoding formats affect classification", 20),
        ("PE Header Detection Test", "Measuring false positives with PE-like headers", 15),
        ("High Entropy Stress Test", "Maximum entropy samples vs scanner engines", 30),
        ("Mixed Profile Benchmark", "Comprehensive test across all parameter combinations", 35),
        ("Small File Anomaly Study", "How file size affects detection heuristics", 20),
        ("XOR Encoding Deep Dive", "XOR-encoded samples and scanner sensitivity", 25),
        ("Metadata Profile Sweep", "Testing all metadata profiles systematically", 20),
    ]

    for name, desc, count in demo_experiments:
        logger.info(f"  → {name} ({count} samples)")
        run_single_experiment_now(name, desc, count)

    logger.info("✅ Seeding complete!")


if __name__ == "__main__":
    seed()
