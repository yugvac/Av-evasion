"""
SentinelLab — Experiment Scheduler

Automated experiment scheduling using APScheduler.
"""
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from backend.config import SCHEDULER_INTERVAL_MINUTES, AUTO_EXPERIMENT_SAMPLE_COUNT
from backend.utils.logger import get_logger
from backend.database import SessionLocal
from backend.models import Experiment, TestSample, ScanResult, ExperimentStatus
from backend.generator.engine import generate_batch
from backend.scanner.engine import scan_sample_all_scanners
import datetime
import random

logger = get_logger("Scheduler")

_scheduler: BackgroundScheduler | None = None
_is_running = False
_run_count = 0


def _run_automated_experiment():
    """Execute a single automated experiment."""
    global _run_count
    _run_count += 1
    db = SessionLocal()

    try:
        experiment = Experiment(
            name=f"Auto-Experiment #{_run_count:04d}",
            description=f"Automated scheduled experiment — {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M')}",
            status=ExperimentStatus.RUNNING.value,
            sample_count=AUTO_EXPERIMENT_SAMPLE_COUNT,
        )
        db.add(experiment)
        db.commit()
        db.refresh(experiment)

        logger.info(f"[Scheduler] Starting auto-experiment {experiment.id}")

        # Generate samples
        sample_configs = generate_batch(experiment.id, AUTO_EXPERIMENT_SAMPLE_COUNT)

        total_detections = 0
        total_fps = 0
        total_confidence = 0
        total_entropy = 0
        scan_count = 0

        for config in sample_configs:
            sample = TestSample(
                experiment_id=experiment.id,
                **config,
            )
            db.add(sample)
            db.commit()
            db.refresh(sample)

            total_entropy += config["entropy"]

            # Scan with all engines
            results = scan_sample_all_scanners(config)
            for r in results:
                scan_result = ScanResult(
                    sample_id=sample.id,
                    experiment_id=experiment.id,
                    **r,
                )
                db.add(scan_result)
                scan_count += 1
                total_confidence += r["confidence"]
                if r["classification"] != "clean":
                    total_detections += 1
                if r["is_false_positive"]:
                    total_fps += 1

        db.commit()

        # Update experiment stats
        experiment.status = ExperimentStatus.COMPLETED.value
        experiment.completed_at = datetime.datetime.utcnow()
        experiment.total_detections = total_detections
        experiment.false_positives = total_fps
        experiment.detection_rate = round((total_detections / scan_count * 100) if scan_count > 0 else 0, 2)
        experiment.avg_confidence = round(total_confidence / scan_count if scan_count > 0 else 0, 2)
        experiment.avg_entropy = round(total_entropy / len(sample_configs) if sample_configs else 0, 2)
        experiment.duration_seconds = (experiment.completed_at - experiment.created_at).total_seconds()
        db.commit()

        logger.info(
            f"[Scheduler] Experiment {experiment.id} complete — "
            f"Detections: {total_detections}/{scan_count} ({experiment.detection_rate}%) | "
            f"FPs: {total_fps}"
        )

    except Exception as e:
        logger.error(f"[Scheduler] Experiment failed: {e}")
        db.rollback()
    finally:
        db.close()


def start_scheduler(interval_minutes: int | None = None):
    """Start the background scheduler."""
    global _scheduler, _is_running
    if _is_running:
        logger.warning("Scheduler already running")
        return

    interval = interval_minutes or SCHEDULER_INTERVAL_MINUTES
    _scheduler = BackgroundScheduler()
    _scheduler.add_job(
        _run_automated_experiment,
        trigger=IntervalTrigger(minutes=interval),
        id="auto_experiment",
        name="Automated Experiment Runner",
        replace_existing=True,
    )
    _scheduler.start()
    _is_running = True
    logger.info(f"Scheduler started — interval: {interval} minutes")


def stop_scheduler():
    """Stop the background scheduler."""
    global _scheduler, _is_running
    if _scheduler and _is_running:
        _scheduler.shutdown(wait=False)
        _is_running = False
        logger.info("Scheduler stopped")


def get_scheduler_status() -> dict:
    """Get current scheduler status."""
    return {
        "is_running": _is_running,
        "run_count": _run_count,
        "interval_minutes": SCHEDULER_INTERVAL_MINUTES,
    }


def run_single_experiment_now(name: str, description: str, sample_count: int) -> int:
    """Run a single experiment immediately (synchronous). Returns experiment ID."""
    global _run_count
    _run_count += 1
    db = SessionLocal()

    try:
        experiment = Experiment(
            name=name,
            description=description,
            status=ExperimentStatus.RUNNING.value,
            sample_count=sample_count,
        )
        db.add(experiment)
        db.commit()
        db.refresh(experiment)

        logger.info(f"Running experiment {experiment.id}: {name}")

        sample_configs = generate_batch(experiment.id, sample_count)

        total_detections = 0
        total_fps = 0
        total_confidence = 0
        total_entropy = 0
        scan_count = 0

        for config in sample_configs:
            sample = TestSample(experiment_id=experiment.id, **config)
            db.add(sample)
            db.commit()
            db.refresh(sample)

            total_entropy += config["entropy"]

            results = scan_sample_all_scanners(config)
            for r in results:
                scan_result = ScanResult(
                    sample_id=sample.id,
                    experiment_id=experiment.id,
                    **r,
                )
                db.add(scan_result)
                scan_count += 1
                total_confidence += r["confidence"]
                if r["classification"] != "clean":
                    total_detections += 1
                if r["is_false_positive"]:
                    total_fps += 1

        db.commit()

        experiment.status = ExperimentStatus.COMPLETED.value
        experiment.completed_at = datetime.datetime.utcnow()
        experiment.total_detections = total_detections
        experiment.false_positives = total_fps
        experiment.detection_rate = round((total_detections / scan_count * 100) if scan_count > 0 else 0, 2)
        experiment.avg_confidence = round(total_confidence / scan_count if scan_count > 0 else 0, 2)
        experiment.avg_entropy = round(total_entropy / len(sample_configs) if sample_configs else 0, 2)
        experiment.duration_seconds = (experiment.completed_at - experiment.created_at).total_seconds()
        db.commit()

        logger.info(f"Experiment {experiment.id} complete — Detection rate: {experiment.detection_rate}%")
        return experiment.id

    except Exception as e:
        logger.error(f"Experiment failed: {e}")
        db.rollback()
        raise
    finally:
        db.close()
