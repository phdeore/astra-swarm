"""FastAPI service exposing Astra-Swarm graph as HTTP endpoints."""

from __future__ import annotations

import os
import uuid
from typing import Optional

from fastapi import FastAPI, HTTPException
from langchain_core.runnables import RunnableConfig
from langgraph.types import Command
from pydantic import BaseModel, Field

from astra_swarm.graph import new_incident_state, triage_graph

app = FastAPI(
    title="Astra-Swarm SOC + ITDR Triage",
    description="Multi-agent security alert triage with human-in-the-loop approval",
    version="1.0.0",
)


class TriageRequest(BaseModel):
    alert: str = Field(..., description="Raw alert text (CEF, JSON, plain, etc.)")
    thread_id: Optional[str] = Field(
        None,
        description="Thread ID for checkpoint continuity. Auto-generated if omitted.",
    )


class TriageResponse(BaseModel):
    thread_id: str
    status: str  # "completed" | "awaiting_approval" | "guardrail_quarantined"
    incident_id: Optional[str] = None
    routing: Optional[dict] = None
    investigation: Optional[dict] = None
    workers_run: list[str] = []
    escalated: bool = False
    guardrail_flagged: bool = False
    approval_prompt: Optional[dict] = None  # populated when paused for approval


class ApprovalRequest(BaseModel):
    thread_id: str
    approved: bool
    note: str = ""


@app.get("/")
def root():
    return {"service": "astra-swarm", "version": "1.0.0", "status": "ok"}


@app.post("/triage", response_model=TriageResponse)
def triage(req: TriageRequest) -> TriageResponse:
    """Submit an alert for triage. Returns final result OR an approval prompt."""
    thread_id = req.thread_id or f"api-{uuid.uuid4().hex[:12]}"
    config: RunnableConfig = {"configurable": {"thread_id": thread_id}}

    initial_state = new_incident_state(req.alert)

    try:
        result = triage_graph.invoke(initial_state, config=config)
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Graph execution failed: {type(e).__name__}: {e}"
        )

    # Check for interrupt (approval needed)
    if "__interrupt__" in result:
        interrupt_data = result["__interrupt__"][0].value
        return TriageResponse(
            thread_id=thread_id,
            status="awaiting_approval",
            incident_id=interrupt_data.get("incident_id"),
            approval_prompt=interrupt_data,
        )

    # Normal completion — flatten Pydantic models to dicts for JSON serialization
    routing = result.get("routing")
    investigation = result.get("investigation")
    return TriageResponse(
        thread_id=thread_id,
        status="completed",
        incident_id=result.get("incident_id"),
        routing=routing.model_dump() if routing else None,
        investigation=investigation.model_dump() if investigation else None,
        workers_run=result.get("workers_run", []),
        escalated=result.get("escalated", False),
        guardrail_flagged=result.get("guardrail_flagged", False),
    )


@app.post("/approve", response_model=TriageResponse)
def approve(req: ApprovalRequest) -> TriageResponse:
    """Resume a paused triage with an approval decision."""
    config: RunnableConfig = {"configurable": {"thread_id": req.thread_id}}
    resume_command = Command(resume={"approved": req.approved, "note": req.note})

    try:
        result = triage_graph.invoke(resume_command, config=config)
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Resume failed: {type(e).__name__}: {e}"
        )

    if "__interrupt__" in result:
        # Shouldn't happen — approval should terminate the graph — but handle defensively
        interrupt_data = result["__interrupt__"][0].value
        return TriageResponse(
            thread_id=req.thread_id,
            status="awaiting_approval",
            incident_id=interrupt_data.get("incident_id"),
            approval_prompt=interrupt_data,
        )

    routing = result.get("routing")
    investigation = result.get("investigation")
    return TriageResponse(
        thread_id=req.thread_id,
        status="completed",
        incident_id=result.get("incident_id"),
        routing=routing.model_dump() if routing else None,
        investigation=investigation.model_dump() if investigation else None,
        workers_run=result.get("workers_run", []),
        escalated=result.get("escalated", False),
        guardrail_flagged=result.get("guardrail_flagged", False),
    )


@app.get("/health")
def health():
    """Liveness probe for orchestrators (K8s, Docker Compose, etc.)."""
    return {"status": "healthy", "graph_version": 4}
