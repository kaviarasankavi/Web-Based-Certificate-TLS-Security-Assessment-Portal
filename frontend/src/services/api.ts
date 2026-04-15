/**
 * API Service — Handles all communication with the FastAPI backend.
 * Automatically attaches the JWT Bearer token from localStorage.
 */
import type {
  ScanRequest,
  ScanStatusResponse,
  ScanDetailResponse,
  ScanListResponse,
} from '../types';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1';

/** Get the stored JWT token */
function getToken(): string | null {
  return localStorage.getItem('tls_token');
}

/** Build auth headers — throws if token is missing */
function authHeaders(extra: Record<string, string> = {}): Record<string, string> {
  const token = getToken();
  if (!token) throw new Error('Not authenticated. Please sign in.');
  return {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${token}`,
    ...extra,
  };
}

async function request<T>(url: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${url}`, {
    headers: authHeaders(),
    ...options,
  });
  if (!res.ok) {
    if (res.status === 401) {
      localStorage.removeItem('tls_token');
      localStorage.removeItem('tls_user');
      window.location.href = '/';
      throw new Error('Session expired. Please sign in again.');
    }
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || 'API request failed');
  }
  return res.json();
}

/** Initiate a new scan */
export async function startScan(data: ScanRequest): Promise<ScanStatusResponse> {
  return request<ScanStatusResponse>('/scan', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

/** Poll scan status */
export async function getScanStatus(scanId: string): Promise<ScanStatusResponse> {
  return request<ScanStatusResponse>(`/scan/${scanId}/status`);
}

/** Get full scan results */
export async function getScanDetail(scanId: string): Promise<ScanDetailResponse> {
  return request<ScanDetailResponse>(`/scan/${scanId}`);
}

/** List scans with pagination & filters (only returns the current user's scans) */
export async function listScans(params?: {
  page?: number;
  limit?: number;
  grade?: string;
  search?: string;
}): Promise<ScanListResponse> {
  const query = new URLSearchParams();
  if (params?.page) query.set('page', String(params.page));
  if (params?.limit) query.set('limit', String(params.limit));
  if (params?.grade) query.set('grade', params.grade);
  if (params?.search) query.set('search', params.search);
  const qs = query.toString();
  return request<ScanListResponse>(`/scans${qs ? `?${qs}` : ''}`);
}

/** Get report data */
export async function getReportData(scanId: string) {
  return request<Record<string, unknown>>(`/report/${scanId}`);
}

/** Download PDF report — returns a blob URL */
export async function downloadPDF(scanId: string): Promise<string> {
  const token = getToken();
  if (!token) throw new Error('Not authenticated');
  const res = await fetch(`${API_BASE}/report/${scanId}/pdf`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (res.status === 401) {
    localStorage.removeItem('tls_token');
    localStorage.removeItem('tls_user');
    window.location.href = '/';
    throw new Error('Session expired. Please sign in again.');
  }
  if (!res.ok) throw new Error('Failed to download PDF');
  const blob = await res.blob();
  return URL.createObjectURL(blob);
}

/** Download HTML report — returns a blob URL */
export async function downloadHTML(scanId: string): Promise<string> {
  const token = getToken();
  if (!token) throw new Error('Not authenticated');
  const res = await fetch(`${API_BASE}/report/${scanId}/html`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (res.status === 401) {
    localStorage.removeItem('tls_token');
    localStorage.removeItem('tls_user');
    window.location.href = '/';
    throw new Error('Session expired. Please sign in again.');
  }
  if (!res.ok) throw new Error('Failed to download HTML');
  const blob = await res.blob();
  return URL.createObjectURL(blob);
}
