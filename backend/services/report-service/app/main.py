"""report-service entrypoint: reportes ejecutivos/de cumplimiento generados
100% a partir de datos ya existentes en otros servicios (nunca datos
inventados). Exportables como JSON o CSV plano; ver app/export.py."""
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import Counter, make_asgi_app
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared.database import get_db, engine, Base
from backend.shared.logging import configure_logging
from app.schemas import ReportRequest, GeneratedReportOut
from app.dependencies import get_current_claims, require_role
from app import services
from app.export import export_to_csv

logger = configure_logging("report-service")
reports_generated_total = Counter("report_generated_total", "Reportes generados", ["report_type"])


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("report-service iniciado")
    yield


app = FastAPI(title="SentinelOps Report Service", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
app.mount("/metrics", make_asgi_app())


@app.get("/health")
async def health():
    return {"status": "ok", "service": "report-service"}


@app.post("/reports/generate", response_model=GeneratedReportOut, status_code=status.HTTP_201_CREATED)
async def generate_report(
    payload: ReportRequest,
    request: Request,
    claims: dict = Depends(require_role("admin", "soc_manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    auth_header = request.headers.get("authorization")
    report = await services.generate_report(db, payload.report_type, auth_header, claims.get("sub", ""))
    await db.commit()
    reports_generated_total.labels(report_type=payload.report_type).inc()
    return report


@app.get("/reports", response_model=list[GeneratedReportOut])
async def list_reports(
    report_type: str | None = None,
    claims: dict = Depends(get_current_claims),
    db: AsyncSession = Depends(get_db),
):
    return await services.list_reports(db, report_type)


@app.get("/reports/{report_id}", response_model=GeneratedReportOut)
async def get_report(report_id: str, claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    report = await services.get_report(db, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Reporte no encontrado")
    return report


@app.get("/reports/{report_id}/export")
async def export_report(
    report_id: str,
    format: str = "json",
    claims: dict = Depends(get_current_claims),
    db: AsyncSession = Depends(get_db),
):
    report = await services.get_report(db, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Reporte no encontrado")
    if format == "csv":
        csv_text = export_to_csv(report.report_type, report.data)
        return Response(content=csv_text, media_type="text/csv")
    return GeneratedReportOut.model_validate(report).model_dump(mode="json")
