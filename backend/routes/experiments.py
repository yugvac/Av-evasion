"""
SentinelLab — Experiment Routes
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from typing import Optional
from backend.database import get_db
from backend.models import Experiment, TestSample, ScanResult
from backend.scheduler.scheduler import run_single_experiment_now
from backend.utils.logger import get_logger

logger = get_logger("API.Experiments")
router = APIRouter(prefix="/api/experiments", tags=["Experiments"])


class ExperimentCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: str = ""
    sample_count: int = Field(default=20, ge=1, le=200)


class ExperimentResponse(BaseModel):
    id: int
    name: str
    description: str
    status: str
    sample_count: int
    total_detections: int
    false_positives: int
    detection_rate: float
    avg_confidence: float
    avg_entropy: float
    created_at: str
    completed_at: Optional[str]
    duration_seconds: float

    class Config:
        from_attributes = True


@router.post("", response_model=dict)
def create_experiment(payload: ExperimentCreate, db: Session = Depends(get_db)):
    """Create and run a new experiment."""
    logger.info(f"Creating experiment: {payload.name} ({payload.sample_count} samples)")
    try:
        exp_id = run_single_experiment_now(
            name=payload.name,
            description=payload.description,
            sample_count=payload.sample_count,
        )
        exp = db.query(Experiment).filter(Experiment.id == exp_id).first()
        return {
            "id": exp.id,
            "name": exp.name,
            "status": exp.status,
            "sample_count": exp.sample_count,
            "detection_rate": exp.detection_rate,
            "total_detections": exp.total_detections,
            "false_positives": exp.false_positives,
            "avg_entropy": exp.avg_entropy,
            "duration_seconds": exp.duration_seconds,
            "message": "Experiment completed successfully",
        }
    except Exception as e:
        logger.error(f"Experiment creation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("", response_model=list[dict])
def list_experiments(
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
):
    """List all experiments."""
    experiments = (
        db.query(Experiment)
        .order_by(Experiment.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return [
        {
            "id": e.id,
            "name": e.name,
            "description": e.description,
            "status": e.status,
            "sample_count": e.sample_count,
            "total_detections": e.total_detections,
            "false_positives": e.false_positives,
            "detection_rate": e.detection_rate,
            "avg_confidence": e.avg_confidence,
            "avg_entropy": e.avg_entropy,
            "created_at": str(e.created_at),
            "completed_at": str(e.completed_at) if e.completed_at else None,
            "duration_seconds": e.duration_seconds,
        }
        for e in experiments
    ]


@router.get("/{experiment_id}")
def get_experiment(experiment_id: int, db: Session = Depends(get_db)):
    """Get experiment details with samples and scan results."""
    exp = db.query(Experiment).filter(Experiment.id == experiment_id).first()
    if not exp:
        raise HTTPException(status_code=404, detail="Experiment not found")

    samples = db.query(TestSample).filter(TestSample.experiment_id == experiment_id).all()
    scan_results = db.query(ScanResult).filter(ScanResult.experiment_id == experiment_id).all()

    return {
        "experiment": {
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
            "created_at": str(exp.created_at),
            "completed_at": str(exp.completed_at) if exp.completed_at else None,
            "duration_seconds": exp.duration_seconds,
        },
        "samples": [
            {
                "id": s.id,
                "filename": s.filename,
                "file_size": s.file_size,
                "entropy": s.entropy,
                "encoding": s.encoding,
                "structural_pattern": s.structural_pattern,
                "metadata_profile": s.metadata_profile,
                "file_hash": s.file_hash,
            }
            for s in samples
        ],
        "scan_results": [
            {
                "id": r.id,
                "sample_id": r.sample_id,
                "scanner_name": r.scanner_name,
                "classification": r.classification,
                "confidence": r.confidence,
                "is_false_positive": r.is_false_positive,
                "threat_label": r.threat_label,
                "scan_duration_ms": r.scan_duration_ms,
                "scanned_at": str(r.scanned_at),
            }
            for r in scan_results
        ],
    }


@router.delete("/{experiment_id}")
def delete_experiment(experiment_id: int, db: Session = Depends(get_db)):
    """Delete an experiment and all related data."""
    exp = db.query(Experiment).filter(Experiment.id == experiment_id).first()
    if not exp:
        raise HTTPException(status_code=404, detail="Experiment not found")

    db.delete(exp)
    db.commit()
    logger.info(f"Deleted experiment {experiment_id}")
    return {"message": f"Experiment {experiment_id} deleted"}
