"""
SentinelLab — Report Routes
"""
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from sqlalchemy import func
from backend.database import get_db
from backend.models import Experiment, TestSample, ScanResult
from backend.reports.pdf_generator import generate_summary_report, generate_experiment_report
from backend.utils.logger import get_logger

logger = get_logger("API.Reports")
router = APIRouter(prefix="/api/reports", tags=["Reports"])


@router.get("/summary/pdf")
def download_summary_report(db: Session = Depends(get_db)):
    """Generate and download a full research summary PDF."""
    total_experiments = db.query(func.count(Experiment.id)).scalar() or 0
    total_samples = db.query(func.count(TestSample.id)).scalar() or 0
    total_fps = db.query(func.count(ScanResult.id)).filter(
        ScanResult.is_false_positive == True
    ).scalar() or 0
    avg_detection_rate = db.query(func.avg(Experiment.detection_rate)).scalar() or 0

    stats = {
        "total_experiments": total_experiments,
        "total_samples": total_samples,
        "total_false_positives": total_fps,
        "avg_detection_rate": float(avg_detection_rate),
    }

    experiments = db.query(Experiment).order_by(Experiment.created_at.desc()).all()
    exp_list = [
        {
            "id": e.id,
            "name": e.name,
            "sample_count": e.sample_count,
            "total_detections": e.total_detections,
            "false_positives": e.false_positives,
            "detection_rate": e.detection_rate,
            "avg_entropy": e.avg_entropy,
            "created_at": str(e.created_at),
        }
        for e in experiments
    ]

    filepath = generate_summary_report(stats, exp_list)
    return FileResponse(
        filepath,
        media_type="application/pdf",
        filename=filepath.split("/")[-1],
    )


@router.get("/{experiment_id}/pdf")
def download_experiment_report(experiment_id: int, db: Session = Depends(get_db)):
    """Generate and download a PDF report for a single experiment."""
    exp = db.query(Experiment).filter(Experiment.id == experiment_id).first()
    if not exp:
        raise HTTPException(status_code=404, detail="Experiment not found")

    experiment = {
        "id": exp.id,
        "name": exp.name,
        "description": exp.description,
        "status": exp.status,
        "sample_count": exp.sample_count,
        "total_detections": exp.total_detections,
        "false_positives": exp.false_positives,
        "detection_rate": exp.detection_rate,
        "avg_confidence": exp.avg_confidence,
        "avg_entropy": exp.avg_entropy,
        "duration_seconds": exp.duration_seconds,
        "created_at": str(exp.created_at),
    }

    samples = [
        {
            "id": s.id,
            "filename": s.filename,
            "file_size": s.file_size,
            "entropy": s.entropy,
            "encoding": s.encoding,
            "structural_pattern": s.structural_pattern,
        }
        for s in db.query(TestSample).filter(TestSample.experiment_id == experiment_id).all()
    ]

    scan_results = [
        {
            "id": r.id,
            "scanner_name": r.scanner_name,
            "classification": r.classification,
            "confidence": r.confidence,
            "is_false_positive": r.is_false_positive,
            "threat_label": r.threat_label,
        }
        for r in db.query(ScanResult).filter(ScanResult.experiment_id == experiment_id).all()
    ]

    filepath = generate_experiment_report(experiment, samples, scan_results)
    return FileResponse(
        filepath,
        media_type="application/pdf",
        filename=filepath.split("/")[-1],
    )
