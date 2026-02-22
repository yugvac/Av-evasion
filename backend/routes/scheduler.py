"""
SentinelLab — Scheduler Routes
"""
from fastapi import APIRouter
from pydantic import BaseModel, Field
from typing import Optional
from backend.scheduler.scheduler import start_scheduler, stop_scheduler, get_scheduler_status
from backend.utils.logger import get_logger

logger = get_logger("API.Scheduler")
router = APIRouter(prefix="/api/scheduler", tags=["Scheduler"])


class SchedulerConfig(BaseModel):
    interval_minutes: Optional[int] = Field(default=30, ge=1, le=1440)


@router.post("/start")
def start_auto_scheduler(config: SchedulerConfig = SchedulerConfig()):
    """Start the automated experiment scheduler."""
    start_scheduler(config.interval_minutes)
    return {"message": "Scheduler started", "interval_minutes": config.interval_minutes}


@router.post("/stop")
def stop_auto_scheduler():
    """Stop the automated experiment scheduler."""
    stop_scheduler()
    return {"message": "Scheduler stopped"}


@router.get("/status")
def scheduler_status():
    """Get scheduler status."""
    return get_scheduler_status()
