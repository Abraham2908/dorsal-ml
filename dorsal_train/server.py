"""dorsal-train service: minimal FastAPI server for triggering and monitoring training runs."""

from __future__ import annotations

import logging
import threading
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

from dorsal_train import config
from dorsal_train.worker import execute_training_run, get_run_state

logger = logging.getLogger(__name__)
app = FastAPI(title="dorsal-train", version="0.1.0")


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


async def verify_api_key(x_api_key: str = Header(default="")) -> None:
    if config.DORSAL_ML_API_KEY and x_api_key != config.DORSAL_ML_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class TriggerRequest(BaseModel):
    run_id: int
    mode: str = "all"
    source_ids: list[int] = []
    hyperparams: dict[str, Any] = {}
    validation_gates: dict[str, Any] = {}


class TriggerResponse(BaseModel):
    run_id: int
    accepted: bool
    message: str


class StatusResponse(BaseModel):
    run_id: int
    current_step: str
    mode: str
    started_at: str | None = None
    error: str | None = None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/runs/trigger", response_model=TriggerResponse, status_code=202, dependencies=[Depends(verify_api_key)])
def trigger_run(req: TriggerRequest) -> TriggerResponse:
    """Receive a training job from the Control Plane and run it in the background."""
    existing = get_run_state(req.run_id)
    if existing is not None:
        return TriggerResponse(
            run_id=req.run_id,
            accepted=False,
            message=f"run_id={req.run_id} is already in progress (step={existing.get('current_step')})",
        )

    thread = threading.Thread(
        target=execute_training_run,
        kwargs={
            "run_id": req.run_id,
            "mode": req.mode,
            "source_ids": req.source_ids,
            "hyperparams": req.hyperparams,
            "validation_gates": req.validation_gates,
        },
        daemon=True,
    )
    thread.start()
    logger.info("training_run_dispatched run_id=%d mode=%s", req.run_id, req.mode)

    return TriggerResponse(run_id=req.run_id, accepted=True, message="run_queued")


@app.get("/runs/{run_id}/status", response_model=StatusResponse)
def run_status(run_id: int) -> StatusResponse:
    """Return the current progress of an in-flight training run."""
    state = get_run_state(run_id)
    if state is None:
        raise HTTPException(status_code=404, detail="run_not_found_or_completed")
    return StatusResponse(
        run_id=run_id,
        current_step=state.get("current_step", "unknown"),
        mode=state.get("mode", "unknown"),
        started_at=state.get("started_at"),
        error=state.get("error"),
    )
