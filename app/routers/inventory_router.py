"""Server inventory (projects, owners, criticality) and absolute capacity forecasts."""
from __future__ import annotations
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel

from app.auth import get_current_user, require_admin
from app.services import capacity_forecast, inventory_service

router = APIRouter(prefix="/api/inventory", tags=["inventory"])
forecast_router = APIRouter(prefix="/api/forecast", tags=["forecast"])


class ServerUpdate(BaseModel):
    project: Optional[str] = None
    environment: Optional[str] = None
    application: Optional[str] = None
    owner: Optional[str] = None
    criticality: Optional[str] = None
    notes: Optional[str] = None


@router.get("/servers")
async def servers(_: dict = Depends(get_current_user)):
    return {"servers": await inventory_service.list_servers()}


@router.get("/projects")
async def projects(_: dict = Depends(get_current_user)):
    return {"projects": await inventory_service.projects()}


@router.get("/export.csv")
async def export_csv(_: dict = Depends(get_current_user)):
    return Response(await inventory_service.export_csv(), media_type="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="cloudpulse-server-inventory.csv"'})


@router.post("/import")
async def import_csv(file: UploadFile = File(...), apply: bool = Query(False), user: dict = Depends(require_admin)):
    """Preview (apply=false) or apply a CSV of project / environment / owner … assignments."""
    raw = await file.read()
    if len(raw) > 5_000_000:
        raise HTTPException(413, "CSV too large")
    return await inventory_service.import_csv(raw, apply, user["username"])


@router.put("/servers/{server_key}")
async def update(server_key: str, body: ServerUpdate, user: dict = Depends(require_admin)):
    fields = {k: v for k, v in body.model_dump().items() if v is not None}
    if fields.get("criticality") and fields["criticality"].capitalize() not in inventory_service.CRITICALITY + [""]:
        raise HTTPException(400, f"criticality must be one of {inventory_service.CRITICALITY}")
    if not await inventory_service.update_server(server_key, fields, user["username"]):
        raise HTTPException(404, "Server not found or nothing to update")
    return {"ok": True}


@router.post("/refresh")
async def refresh(_: dict = Depends(require_admin)):
    return {"ok": True, "servers": await inventory_service.refresh()}


@forecast_router.get("/units")
async def units(scope: str = Query("fleet", pattern="^(fleet|project|server)$"), name: Optional[str] = None,
                lookback: int = Query(90, ge=7, le=365), horizon: int = Query(180),
                _: dict = Depends(get_current_user)):
    """Current vs forecast in vCPU / GB with deltas and direction, for fleet, a project or a server."""
    if scope != "fleet" and not name:
        raise HTTPException(400, "name is required for project / server scope")
    return await capacity_forecast.forecast(scope, name, lookback, horizon)


@forecast_router.get("/projects")
async def project_forecasts(lookback: int = Query(90, ge=7, le=365), horizon: int = Query(180),
                            _: dict = Depends(get_current_user)):
    return await capacity_forecast.projects_summary(lookback, horizon)
