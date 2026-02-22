"""
SentinelLab — AV Research Platform Configuration
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
BACKEND_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
SAMPLES_DIR = DATA_DIR / "samples"
REPORTS_DIR = DATA_DIR / "reports"
LOGS_DIR = DATA_DIR / "logs"
DATABASE_URL = f"sqlite:///{DATA_DIR / 'sentinellab.db'}"

# Ensure directories exist
for d in [DATA_DIR, SAMPLES_DIR, REPORTS_DIR, LOGS_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# App settings
APP_NAME = "SentinelLab"
APP_VERSION = "1.0.0"
APP_DESCRIPTION = "Cybersecurity Research Platform — AV Detection Analysis"
DEBUG = os.getenv("SENTINELLAB_DEBUG", "true").lower() == "true"

# Scheduler settings
SCHEDULER_INTERVAL_MINUTES = int(os.getenv("SCHEDULER_INTERVAL", "30"))
AUTO_EXPERIMENT_SAMPLE_COUNT = 25

# Scanner simulation settings
SCANNER_NAMES = [
    "SentinelCore",
    "HeuristicEngine",
    "EntropyAnalyzer",
    "PatternMatcher",
    "BehaviorSim",
]
