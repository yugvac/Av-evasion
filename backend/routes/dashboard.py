"""
SentinelLab — Dashboard Analytics Routes
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from backend.database import get_db
from backend.models import Experiment, TestSample, ScanResult

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


@router.get("/overview")
def get_overview(db: Session = Depends(get_db)):
    """Get dashboard overview statistics."""
    total_experiments = db.query(func.count(Experiment.id)).scalar() or 0
    total_samples = db.query(func.count(TestSample.id)).scalar() or 0
    total_scans = db.query(func.count(ScanResult.id)).scalar() or 0
    total_detections = db.query(func.count(ScanResult.id)).filter(
        ScanResult.classification != "clean"
    ).scalar() or 0
    total_false_positives = db.query(func.count(ScanResult.id)).filter(
        ScanResult.is_false_positive == True
    ).scalar() or 0

    avg_detection_rate = db.query(func.avg(Experiment.detection_rate)).scalar() or 0
    avg_confidence = db.query(func.avg(Experiment.avg_confidence)).scalar() or 0
    avg_entropy = db.query(func.avg(Experiment.avg_entropy)).scalar() or 0

    # Classification distribution
    clean_count = db.query(func.count(ScanResult.id)).filter(
        ScanResult.classification == "clean"
    ).scalar() or 0
    suspicious_count = db.query(func.count(ScanResult.id)).filter(
        ScanResult.classification == "suspicious"
    ).scalar() or 0
    malicious_count = db.query(func.count(ScanResult.id)).filter(
        ScanResult.classification == "malicious"
    ).scalar() or 0

    # Recent experiments
    recent = db.query(Experiment).order_by(Experiment.created_at.desc()).limit(5).all()

    return {
        "total_experiments": total_experiments,
        "total_samples": total_samples,
        "total_scans": total_scans,
        "total_detections": total_detections,
        "total_false_positives": total_false_positives,
        "avg_detection_rate": round(float(avg_detection_rate), 2),
        "avg_confidence": round(float(avg_confidence), 2),
        "avg_entropy": round(float(avg_entropy), 2),
        "classification_distribution": {
            "clean": clean_count,
            "suspicious": suspicious_count,
            "malicious": malicious_count,
        },
        "recent_experiments": [
            {
                "id": e.id,
                "name": e.name,
                "status": e.status,
                "detection_rate": e.detection_rate,
                "sample_count": e.sample_count,
                "created_at": str(e.created_at),
            }
            for e in recent
        ],
    }


@router.get("/detection-trends")
def get_detection_trends(db: Session = Depends(get_db)):
    """Get detection rate trends over time (per experiment)."""
    experiments = (
        db.query(Experiment)
        .filter(Experiment.status == "completed")
        .order_by(Experiment.created_at.asc())
        .all()
    )

    return {
        "labels": [str(e.created_at)[:16] for e in experiments],
        "detection_rates": [e.detection_rate for e in experiments],
        "false_positive_counts": [e.false_positives for e in experiments],
        "avg_confidences": [e.avg_confidence for e in experiments],
        "experiment_names": [e.name for e in experiments],
        "experiment_ids": [e.id for e in experiments],
    }


@router.get("/false-positives")
def get_false_positives(db: Session = Depends(get_db)):
    """Get false positive analysis data."""
    # FP by scanner
    scanner_fps = (
        db.query(
            ScanResult.scanner_name,
            func.count(ScanResult.id).label("total"),
            func.sum(func.cast(ScanResult.is_false_positive, db.bind.dialect.name == 'sqlite' and type_coerce(ScanResult.is_false_positive, Integer) or ScanResult.is_false_positive)).label("fps"),
        )
        .group_by(ScanResult.scanner_name)
        .all()
    ) if False else []

    # Simplified FP by scanner query
    scanners = db.query(ScanResult.scanner_name).distinct().all()
    scanner_data = []
    for (scanner_name,) in scanners:
        total = db.query(func.count(ScanResult.id)).filter(
            ScanResult.scanner_name == scanner_name
        ).scalar() or 0
        fps = db.query(func.count(ScanResult.id)).filter(
            ScanResult.scanner_name == scanner_name,
            ScanResult.is_false_positive == True,
        ).scalar() or 0
        detections = db.query(func.count(ScanResult.id)).filter(
            ScanResult.scanner_name == scanner_name,
            ScanResult.classification != "clean",
        ).scalar() or 0
        scanner_data.append({
            "scanner": scanner_name,
            "total_scans": total,
            "false_positives": fps,
            "detections": detections,
            "fp_rate": round((fps / total * 100) if total > 0 else 0, 2),
        })

    # FP by encoding
    encodings = db.query(TestSample.encoding).distinct().all()
    encoding_data = []
    for (enc,) in encodings:
        sample_ids = [s.id for s in db.query(TestSample.id).filter(TestSample.encoding == enc).all()]
        if sample_ids:
            fps = db.query(func.count(ScanResult.id)).filter(
                ScanResult.sample_id.in_(sample_ids),
                ScanResult.is_false_positive == True,
            ).scalar() or 0
            total = db.query(func.count(ScanResult.id)).filter(
                ScanResult.sample_id.in_(sample_ids),
            ).scalar() or 0
            encoding_data.append({
                "encoding": enc,
                "false_positives": fps,
                "total_scans": total,
                "fp_rate": round((fps / total * 100) if total > 0 else 0, 2),
            })

    return {
        "by_scanner": scanner_data,
        "by_encoding": encoding_data,
    }


@router.get("/entropy-detection")
def get_entropy_detection(db: Session = Depends(get_db)):
    """Get entropy vs detection data for scatter plots."""
    # Get all samples with their scan results
    samples = db.query(TestSample).all()
    data_points = []

    for sample in samples:
        results = db.query(ScanResult).filter(ScanResult.sample_id == sample.id).all()
        if results:
            avg_confidence = sum(r.confidence for r in results) / len(results)
            detection_count = sum(1 for r in results if r.classification != "clean")
            detection_ratio = detection_count / len(results)
            data_points.append({
                "entropy": sample.entropy,
                "avg_confidence": round(avg_confidence, 2),
                "detection_ratio": round(detection_ratio, 2),
                "encoding": sample.encoding,
                "file_size": sample.file_size,
                "metadata_profile": sample.metadata_profile,
                "filename": sample.filename,
            })

    return {"data_points": data_points}


@router.get("/timeline")
def get_timeline(db: Session = Depends(get_db)):
    """Get experiment timeline data."""
    experiments = (
        db.query(Experiment)
        .order_by(Experiment.created_at.desc())
        .limit(50)
        .all()
    )

    return {
        "events": [
            {
                "id": e.id,
                "name": e.name,
                "description": e.description,
                "status": e.status,
                "sample_count": e.sample_count,
                "detection_rate": e.detection_rate,
                "false_positives": e.false_positives,
                "avg_entropy": e.avg_entropy,
                "duration_seconds": e.duration_seconds,
                "created_at": str(e.created_at),
                "completed_at": str(e.completed_at) if e.completed_at else None,
            }
            for e in experiments
        ],
    }


@router.get("/scanner-comparison")
def get_scanner_comparison(db: Session = Depends(get_db)):
    """Get scanner performance comparison."""
    scanners = db.query(ScanResult.scanner_name).distinct().all()
    comparison = []

    for (scanner_name,) in scanners:
        results = db.query(ScanResult).filter(ScanResult.scanner_name == scanner_name).all()
        if results:
            total = len(results)
            detections = sum(1 for r in results if r.classification != "clean")
            malicious = sum(1 for r in results if r.classification == "malicious")
            suspicious = sum(1 for r in results if r.classification == "suspicious")
            fps = sum(1 for r in results if r.is_false_positive)
            avg_conf = sum(r.confidence for r in results) / total
            avg_dur = sum(r.scan_duration_ms for r in results) / total

            comparison.append({
                "scanner": scanner_name,
                "total_scans": total,
                "detections": detections,
                "malicious": malicious,
                "suspicious": suspicious,
                "clean": total - detections,
                "false_positives": fps,
                "detection_rate": round(detections / total * 100, 2),
                "fp_rate": round(fps / total * 100, 2),
                "avg_confidence": round(avg_conf, 2),
                "avg_scan_time_ms": round(avg_dur, 2),
            })

    return {"scanners": comparison}
