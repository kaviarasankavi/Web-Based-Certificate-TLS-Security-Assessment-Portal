"""
Report Router — API endpoints for generating and downloading reports.
"""
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
import io

from database import get_pg_db as get_db
from models.scan import Scan
from report.generator import ReportGenerator

router = APIRouter(prefix="/api/v1", tags=["reports"])

report_gen = ReportGenerator()


@router.get("/report/{scan_id}")
async def get_report_data(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Get report data as JSON."""
    scan = await _load_scan(scan_id, db)
    return report_gen.build_report_data(scan)


@router.get("/report/{scan_id}/html")
async def download_html_report(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Download HTML report."""
    scan = await _load_scan(scan_id, db)
    html_content = report_gen.generate_html(scan)
    return HTMLResponse(
        content=html_content,
        headers={
            "Content-Disposition": f"attachment; filename=tls-report-{scan.target_url}.html"
        }
    )


@router.get("/report/{scan_id}/pdf")
async def download_pdf_report(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Download PDF report."""
    scan = await _load_scan(scan_id, db)
    pdf_bytes = report_gen.generate_pdf(scan)

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=tls-report-{scan.target_url}.pdf"
        }
    )


async def _load_scan(scan_id: str, db: AsyncSession) -> Scan:
    """Load a scan with all relationships."""
    stmt = (
        select(Scan)
        .options(
            selectinload(Scan.certificate),
            selectinload(Scan.tls_config),
            selectinload(Scan.cipher_suites),
            selectinload(Scan.revocation),
            selectinload(Scan.chain),
            selectinload(Scan.recommendations),
        )
        .where(Scan.id == scan_id)
    )
    result = await db.execute(stmt)
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != "completed":
        raise HTTPException(status_code=400, detail="Scan not yet completed")

    return scan
