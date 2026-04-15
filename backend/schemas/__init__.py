from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


# ---------- Request Schemas ----------

class ScanRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=500, description="Target hostname or URL to scan")
    port: int = Field(default=443, ge=1, le=65535)


# ---------- Response Schemas ----------

class CertificateResponse(BaseModel):
    subject_cn: Optional[str] = None
    issuer_cn: Optional[str] = None
    issuer_org: Optional[str] = None
    valid_from: Optional[datetime] = None
    valid_to: Optional[datetime] = None
    days_until_expiry: Optional[int] = None
    is_expired: bool = False
    is_self_signed: bool = False
    serial_number: Optional[str] = None
    signature_algo: Optional[str] = None
    public_key_type: Optional[str] = None
    public_key_size: Optional[int] = None
    san_list: list[str] = []

    class Config:
        from_attributes = True


class TLSConfigResponse(BaseModel):
    tls_1_0: bool = False
    tls_1_1: bool = False
    tls_1_2: bool = False
    tls_1_3: bool = False
    insecure_reneg: bool = False
    preferred_proto: Optional[str] = None

    class Config:
        from_attributes = True


class CipherSuiteResponse(BaseModel):
    cipher_name: Optional[str] = None
    protocol: Optional[str] = None
    key_exchange: Optional[str] = None
    strength: Optional[str] = None
    is_dangerous: bool = False
    bits: Optional[int] = None

    class Config:
        from_attributes = True


class RevocationResponse(BaseModel):
    ocsp_status: Optional[str] = None
    ocsp_url: Optional[str] = None
    crl_present: bool = False
    crl_url: Optional[str] = None
    stapling_support: bool = False

    class Config:
        from_attributes = True


class ChainCertificate(BaseModel):
    subject: Optional[str] = None
    issuer: Optional[str] = None
    is_root: bool = False
    is_expired: bool = False
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None


class ChainResponse(BaseModel):
    chain_depth: Optional[int] = None
    chain_valid: bool = True
    chain_data: list[ChainCertificate] = []
    has_broken_chain: bool = False
    has_expired_intermediate: bool = False

    class Config:
        from_attributes = True


class RecommendationResponse(BaseModel):
    severity: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    fix_suggestion: Optional[str] = None

    class Config:
        from_attributes = True


class ScanStatusResponse(BaseModel):
    scan_id: str
    status: str
    step: Optional[str] = None
    progress: int = 0


class ScanResponse(BaseModel):
    id: str
    target_url: str
    port: int = 443
    grade: Optional[str] = None
    score: Optional[int] = None
    status: str = "pending"
    created_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None

    class Config:
        from_attributes = True


class ScanDetailResponse(ScanResponse):
    certificate: Optional[CertificateResponse] = None
    tls_config: Optional[TLSConfigResponse] = None
    cipher_suites: list[CipherSuiteResponse] = []
    revocation: Optional[RevocationResponse] = None
    chain: Optional[ChainResponse] = None
    recommendations: list[RecommendationResponse] = []


class ScanListResponse(BaseModel):
    total: int
    page: int
    limit: int
    scans: list[ScanResponse]
