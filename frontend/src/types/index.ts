/* ============ Types for TLS Inspector ============ */

export interface ScanRequest {
  url: string;
  port: number;
}

export interface ScanStatusResponse {
  scan_id: string;
  status: string;
  step: string | null;
  progress: number;
}

export interface CertificateResponse {
  subject_cn: string | null;
  issuer_cn: string | null;
  issuer_org: string | null;
  valid_from: string | null;
  valid_to: string | null;
  days_until_expiry: number | null;
  is_expired: boolean;
  is_self_signed: boolean;
  serial_number: string | null;
  signature_algo: string | null;
  public_key_type: string | null;
  public_key_size: number | null;
  san_list: string[];
}

export interface TLSConfigResponse {
  tls_1_0: boolean;
  tls_1_1: boolean;
  tls_1_2: boolean;
  tls_1_3: boolean;
  insecure_reneg: boolean;
  preferred_proto: string | null;
}

export interface CipherSuiteResponse {
  cipher_name: string | null;
  protocol: string | null;
  key_exchange: string | null;
  strength: string | null;
  is_dangerous: boolean;
  bits: number | null;
}

export interface RevocationResponse {
  ocsp_status: string | null;
  ocsp_url: string | null;
  crl_present: boolean;
  crl_url: string | null;
  stapling_support: boolean;
}

export interface ChainCertificate {
  subject: string | null;
  issuer: string | null;
  is_root: boolean;
  is_expired: boolean;
  valid_from: string | null;
  valid_to: string | null;
}

export interface ChainResponse {
  chain_depth: number | null;
  chain_valid: boolean;
  chain_data: ChainCertificate[];
  has_broken_chain: boolean;
  has_expired_intermediate: boolean;
}

export interface RecommendationResponse {
  severity: string | null;
  title: string | null;
  description: string | null;
  fix_suggestion: string | null;
}

export interface ScanResponse {
  id: string;
  target_url: string;
  port: number;
  grade: string | null;
  score: number | null;
  status: string;
  created_at: string | null;
  completed_at: string | null;
  error_message: string | null;
}

export interface ScanDetailResponse extends ScanResponse {
  certificate: CertificateResponse | null;
  tls_config: TLSConfigResponse | null;
  cipher_suites: CipherSuiteResponse[];
  revocation: RevocationResponse | null;
  chain: ChainResponse | null;
  recommendations: RecommendationResponse[];
}

export interface ScanListResponse {
  total: number;
  page: number;
  limit: number;
  scans: ScanResponse[];
}
