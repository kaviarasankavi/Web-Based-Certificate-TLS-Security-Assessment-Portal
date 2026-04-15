"""
Scan Router — API endpoints for initiating scans and retrieving results.
All endpoints require a valid JWT token. Scans are scoped per-user.
"""
import re
import asyncio
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy import select, func
from sqlalchemy.orm import selectinload
from sqlalchemy.pool import NullPool

from config import settings
from database import get_pg_db
from models.scan import Scan
from models.certificate import CertificateResult
from models.tls_config import TLSConfigResult
from models.cipher_suite import CipherSuiteResult
from models.revocation import RevocationResult
from models.chain import ChainResult
from models.recommendation import Recommendation
from schemas import (
    ScanRequest, ScanResponse, ScanDetailResponse, ScanListResponse,
    ScanStatusResponse, CertificateResponse, TLSConfigResponse,
    CipherSuiteResponse, RevocationResponse, ChainResponse,
    RecommendationResponse, ChainCertificate,
)
from scanner.orchestrator import ScanOrchestrator

router = APIRouter(prefix="/api/v1", tags=["scans"])
bearer_scheme = HTTPBearer(auto_error=True)


# ── Auth helper ────────────────────────────────────────────────────────────────

def _get_user_id_from_token(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> int:
    """Decode JWT and return the user_id (int). Raises 401 on failure."""
    try:
        payload = jwt.decode(
            credentials.credentials,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
        )
        return int(payload["sub"])
    except (JWTError, KeyError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid or expired token")


# ── Helpers ────────────────────────────────────────────────────────────────────

def _normalize_hostname(url: str) -> str:
    """Strip protocol, path, trailing slashes from URL to get hostname."""
    url = url.strip()
    url = re.sub(r"^https?://", "", url)
    url = url.split("/")[0]
    url = url.split(":")[0]
    return url


async def _run_scan_task(scan_id: str, hostname: str, port: int, pg_url: str):
    """Background task: run the scan and persist results to PostgreSQL."""
    engine = create_async_engine(pg_url, echo=False, poolclass=NullPool)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with session_factory() as session:
        try:
            scan = await session.get(Scan, scan_id)
            if not scan:
                return
            scan.status = "scanning"
            await session.commit()

            orchestrator = ScanOrchestrator()
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, orchestrator.run_scan, hostname, port)

            if result.error:
                scan.status = "failed"
                scan.error_message = result.error
                await session.commit()
                return

            if result.certificate:
                session.add(CertificateResult(
                    scan_id=scan_id,
                    subject_cn=result.certificate.subject_cn,
                    issuer_cn=result.certificate.issuer_cn,
                    issuer_org=result.certificate.issuer_org,
                    valid_from=result.certificate.valid_from.replace(tzinfo=None) if result.certificate.valid_from else None,
                    valid_to=result.certificate.valid_to.replace(tzinfo=None) if result.certificate.valid_to else None,
                    days_until_expiry=result.certificate.days_until_expiry,
                    is_expired=result.certificate.is_expired,
                    is_self_signed=result.certificate.is_self_signed,
                    serial_number=result.certificate.serial_number,
                    signature_algo=result.certificate.signature_algo,
                    public_key_type=result.certificate.public_key_type,
                    public_key_size=result.certificate.public_key_size,
                    san_list=result.certificate.san_list,
                    raw_pem=result.certificate.raw_pem,
                ))

            if result.tls_config:
                session.add(TLSConfigResult(
                    scan_id=scan_id,
                    tls_1_0=result.tls_config.tls_1_0,
                    tls_1_1=result.tls_config.tls_1_1,
                    tls_1_2=result.tls_config.tls_1_2,
                    tls_1_3=result.tls_config.tls_1_3,
                    insecure_reneg=result.tls_config.insecure_reneg,
                    preferred_proto=result.tls_config.preferred_proto,
                ))

            for cs in result.cipher_suites:
                session.add(CipherSuiteResult(
                    scan_id=scan_id,
                    cipher_name=cs.cipher_name,
                    protocol=cs.protocol,
                    key_exchange=cs.key_exchange,
                    strength=cs.strength,
                    is_dangerous=cs.is_dangerous,
                    bits=cs.bits,
                ))

            if result.revocation:
                session.add(RevocationResult(
                    scan_id=scan_id,
                    ocsp_status=result.revocation.ocsp_status,
                    ocsp_url=result.revocation.ocsp_url,
                    crl_present=result.revocation.crl_present,
                    crl_url=result.revocation.crl_url,
                    stapling_support=result.revocation.stapling_support,
                ))

            if result.chain:
                chain_data_json = [
                    {
                        "subject": c.subject,
                        "issuer": c.issuer,
                        "is_root": c.is_root,
                        "is_expired": c.is_expired,
                        "valid_from": c.valid_from,
                        "valid_to": c.valid_to,
                    }
                    for c in result.chain.chain_certs
                ]
                session.add(ChainResult(
                    scan_id=scan_id,
                    chain_depth=result.chain.chain_depth,
                    chain_valid=result.chain.chain_valid,
                    chain_data=chain_data_json,
                    has_broken_chain=result.chain.has_broken_chain,
                    has_expired_intermediate=result.chain.has_expired_intermediate,
                ))

            for rec in result.recommendations:
                session.add(Recommendation(
                    scan_id=scan_id,
                    severity=rec["severity"],
                    title=rec["title"],
                    description=rec["description"],
                    fix_suggestion=rec["fix_suggestion"],
                ))

            scan.grade = result.score.grade
            scan.score = result.score.score
            scan.status = "completed"
            scan.completed_at = datetime.utcnow()
            await session.commit()

        except Exception as e:
            try:
                scan.status = "failed"
                scan.error_message = str(e)
                await session.commit()
            except Exception:
                pass

    await engine.dispose()


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/scan", response_model=ScanStatusResponse)
async def initiate_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_pg_db),
    user_id: int = Depends(_get_user_id_from_token),
):
    """Start a new TLS security scan for the given URL (authenticated)."""
    hostname = _normalize_hostname(request.url)
    if not hostname:
        raise HTTPException(status_code=400, detail="Invalid URL provided")

    scan = Scan(target_url=hostname, port=request.port, user_id=user_id)
    db.add(scan)
    await db.flush()

    background_tasks.add_task(
        _run_scan_task, scan.id, hostname, request.port, settings.POSTGRES_URL
    )

    return ScanStatusResponse(scan_id=scan.id, status="pending", step="queued", progress=0)


@router.get("/scan/{scan_id}/status", response_model=ScanStatusResponse)
async def get_scan_status(
    scan_id: str,
    db: AsyncSession = Depends(get_pg_db),
    user_id: int = Depends(_get_user_id_from_token),
):
    """Poll the status of an ongoing scan."""
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.user_id != user_id:
        raise HTTPException(status_code=403, detail="Access denied")

    progress_map = {"pending": 0, "scanning": 50, "completed": 100, "failed": 100}
    return ScanStatusResponse(
        scan_id=scan.id,
        status=scan.status,
        step=scan.status,
        progress=progress_map.get(scan.status, 0),
    )


@router.get("/scan/{scan_id}", response_model=ScanDetailResponse)
async def get_scan_result(
    scan_id: str,
    db: AsyncSession = Depends(get_pg_db),
    user_id: int = Depends(_get_user_id_from_token),
):
    """Get the full scan results for the authenticated user."""
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
    if scan.user_id != user_id:
        raise HTTPException(status_code=403, detail="Access denied")

    cert_resp = CertificateResponse.model_validate(scan.certificate) if scan.certificate else None
    tls_resp = TLSConfigResponse.model_validate(scan.tls_config) if scan.tls_config else None
    cipher_resp = [CipherSuiteResponse.model_validate(c) for c in scan.cipher_suites]
    rev_resp = RevocationResponse.model_validate(scan.revocation) if scan.revocation else None

    chain_resp = None
    if scan.chain:
        chain_data = [ChainCertificate(**cd) for cd in (scan.chain.chain_data or [])]
        chain_resp = ChainResponse(
            chain_depth=scan.chain.chain_depth,
            chain_valid=scan.chain.chain_valid,
            chain_data=chain_data,
            has_broken_chain=scan.chain.has_broken_chain,
            has_expired_intermediate=scan.chain.has_expired_intermediate,
        )

    rec_resp = [RecommendationResponse.model_validate(r) for r in scan.recommendations]

    return ScanDetailResponse(
        id=scan.id,
        target_url=scan.target_url,
        port=scan.port,
        grade=scan.grade,
        score=scan.score,
        status=scan.status,
        created_at=scan.created_at,
        completed_at=scan.completed_at,
        error_message=scan.error_message,
        certificate=cert_resp,
        tls_config=tls_resp,
        cipher_suites=cipher_resp,
        revocation=rev_resp,
        chain=chain_resp,
        recommendations=rec_resp,
    )


@router.get("/scans", response_model=ScanListResponse)
async def list_scans(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    grade: str = Query(None),
    search: str = Query(None),
    db: AsyncSession = Depends(get_pg_db),
    user_id: int = Depends(_get_user_id_from_token),
):
    """List scan history for the currently authenticated user only."""
    stmt = (
        select(Scan)
        .where(Scan.user_id == user_id)   # ← scoped to this user
        .order_by(Scan.created_at.desc())
    )

    if grade:
        stmt = stmt.where(Scan.grade == grade)
    if search:
        stmt = stmt.where(Scan.target_url.ilike(f"%{search}%"))

    count_stmt = select(func.count()).select_from(stmt.subquery())
    total_result = await db.execute(count_stmt)
    total = total_result.scalar()

    stmt = stmt.offset((page - 1) * limit).limit(limit)
    result = await db.execute(stmt)
    scans = result.scalars().all()

    return ScanListResponse(
        total=total,
        page=page,
        limit=limit,
        scans=[ScanResponse.model_validate(s) for s in scans],
    )
