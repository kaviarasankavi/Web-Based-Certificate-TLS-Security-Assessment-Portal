import { useState, useEffect, useCallback } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import './ScannerPage.css';
import GradeBadge from '../components/GradeBadge';
import ScoreGauge from '../components/ScoreGauge';
import ScoreBreakdown from '../components/ScoreBreakdown';
import { startScan, getScanStatus, getScanDetail, downloadPDF, downloadHTML, getSecurityHeaders, getVulnerabilities, getDNSSecurity } from '../services/api';
import type { ScanDetailResponse } from '../types';

const TABS = ['Overview', 'Certificate', 'TLS Config', 'Cipher Suites', 'Revocation', 'Chain', 'Recommendations', 'HTTP Headers', 'Vulnerabilities', 'DNS Security'];

export default function ScannerPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const [url, setUrl] = useState(searchParams.get('url') || '');
  const [port] = useState(443);
  const [scanning, setScanning] = useState(false);
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [progress, setProgress] = useState(0);
  const [statusText, setStatusText] = useState('');
  const [result, setResult] = useState<ScanDetailResponse | null>(null);
  const [activeTab, setActiveTab] = useState(0);
  const [error, setError] = useState('');
  const [stepLog, setStepLog] = useState<string[]>([]);
  // Lazy-loaded extra tab data
  const [headersData, setHeadersData] = useState<Record<string, unknown> | null>(null);
  const [headersLoading, setHeadersLoading] = useState(false);
  const [vulnsData, setVulnsData] = useState<Record<string, unknown> | null>(null);
  const [vulnsLoading, setVulnsLoading] = useState(false);
  const [dnsData, setDnsData] = useState<Record<string, unknown> | null>(null);
  const [dnsLoading, setDnsLoading] = useState(false);

  const pollStatus = useCallback(async (scanId: string) => {
    const maxAttempts = 60;
    for (let i = 0; i < maxAttempts; i++) {
      await new Promise(r => setTimeout(r, 2000));
      try {
        const status = await getScanStatus(scanId);
        setProgress(status.progress);
        const stepText = status.step || status.status;
        setStatusText(stepText);
        // Append new step to log (avoid consecutive duplicates)
        if (stepText) {
          setStepLog(prev =>
            prev.length > 0 && prev[prev.length - 1] === stepText
              ? prev
              : [...prev, stepText]
          );
        }

        if (status.status === 'completed') {
          const detail = await getScanDetail(scanId);
          setResult(detail);
          setScanning(false);
          return;
        }
        if (status.status === 'failed') {
          setError('Scan failed. Please check the URL and try again.');
          setScanning(false);
          return;
        }
      } catch {
        // retry
      }
    }
    setError('Scan timed out.');
    setScanning(false);
  }, []);

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;
    setScanning(true);
    setResult(null);
    setError('');
    setProgress(0);
    setStatusText('Initiating scan...');
    setStepLog(['Initiating scan...']);

    try {
      const res = await startScan({ url: url.trim(), port });
      pollStatus(res.scan_id);
    } catch (err: any) {
      setError(err.message || 'Failed to start scan');
      setScanning(false);
    }
  };

  useEffect(() => {
    // ── Load existing scan by ?id= (History "View" button) ──
    const scanId = searchParams.get('id');
    if (scanId) {
      setLoadingHistory(true);
      setError('');
      getScanDetail(scanId)
        .then((detail) => {
          setResult(detail);
          setUrl(detail.target_url);
          setActiveTab(0);
        })
        .catch((err) => {
          setError(err.message || 'Failed to load scan results.');
        })
        .finally(() => {
          setLoadingHistory(false);
        });
      return; // skip auto-scan by URL
    }

    // ── Auto-scan if ?url= provided ──
    const urlParam = searchParams.get('url');
    if (urlParam && !result && !scanning) {
      setUrl(urlParam);
      setTimeout(() => {
        setScanning(true);
        setResult(null);
        setError('');
        setProgress(0);
        setStatusText('Initiating scan...');
        startScan({ url: urlParam, port: 443 })
          .then((res) => pollStatus(res.scan_id))
          .catch((err) => {
            setError(err.message || 'Failed to start scan');
            setScanning(false);
          });
      }, 300);
    }
  // Run only once on mount
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleDownloadPDF = async () => {
    if (!result) return;
    try {
      const blobUrl = await downloadPDF(result.id);
      const a = document.createElement('a');
      a.href = blobUrl;
      a.download = `tls-report-${result.target_url}.pdf`;
      a.click();
    } catch { alert('Failed to download PDF'); }
  };

  const handleDownloadHTML = async () => {
    if (!result) return;
    try {
      const blobUrl = await downloadHTML(result.id);
      const a = document.createElement('a');
      a.href = blobUrl;
      a.download = `tls-report-${result.target_url}.html`;
      a.click();
    } catch { alert('Failed to download HTML'); }
  };

  return (
    <div className="scanner-page container">
      {/* Search bar */}
      <form className="scanner-search" onSubmit={handleScan} id="scanner-form">
        <div className="scanner-input-wrap">
          <span className="search-icon">🌐</span>
          <input
            id="scanner-url-input"
            type="text"
            placeholder="Enter domain (e.g., google.com)"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            disabled={scanning || loadingHistory}
          />
        </div>
        <button type="submit" className="btn btn-primary" disabled={scanning || loadingHistory} id="scanner-scan-btn">
          {scanning ? 'Scanning...' : 'Scan'}
        </button>
      </form>

      {/* Error */}
      {error && <div className="scan-error glass-card" id="scan-error">{error}</div>}

      {/* History loading spinner */}
      {loadingHistory && (
        <div className="scan-progress" id="scan-loading-history">
          <div className="loading-state"><div className="spinner"></div></div>
          <p className="progress-text">Loading scan results...</p>
        </div>
      )}

      {/* Animated Step Log during scan */}
      {scanning && !loadingHistory && (
        <div className="scan-step-log glass-card" id="scan-step-log">
          <div className="step-log-header">
            <div className="spinner-sm" />
            <span>Scanning in progress...</span>
            <span className="step-progress-pct">{progress}%</span>
          </div>
          <div className="step-log-entries">
            {stepLog.map((step, i) => {
              const isActive = i === stepLog.length - 1;
              return (
                <div
                  key={i}
                  className={`step-entry ${ isActive ? 'step-entry-active' : 'step-entry-done'}`}
                >
                  <span className="step-entry-icon">{isActive ? '⏳' : '✅'}</span>
                  <span className="step-entry-text">{step}</span>
                </div>
              );
            })}
          </div>
          <div className="step-log-footer">
            <div className="progress-bar-track">
              <div
                className="progress-bar-fill"
                style={{ width: `${Math.max(progress, 5)}%` }}
              />
            </div>
          </div>
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="scan-results animate-in" id="scan-results">
          {/* Score header with animated gauge */}
          <div className="result-header glass-card">
            <ScoreGauge score={result.score ?? 0} grade={result.grade || 'F'} />
            <div className="result-header-info">
              <h2 className="result-domain">{result.target_url}</h2>
              <p className="result-date">
                🕐 Scanned: {result.completed_at
                  ? new Date(result.completed_at).toLocaleString()
                  : 'N/A'}
              </p>
              <div className="result-actions">
                <button
                  className="btn btn-ghost btn-rescan-main"
                  title="Start a fresh scan of this domain"
                  onClick={() => navigate(`/scan?url=${encodeURIComponent(result.target_url)}`)}
                >
                  ↻ Rescan
                </button>
                <button className="btn btn-secondary" onClick={handleDownloadPDF} id="download-pdf-btn">
                  📄 PDF Report
                </button>
                <button className="btn btn-secondary" onClick={handleDownloadHTML} id="download-html-btn">
                  🌐 HTML Report
                </button>
              </div>
            </div>
          </div>

          {/* Summary cards */}
          <div className="summary-cards">
            <div className="summary-card glass-card">
              <span className="summary-icon">{result.certificate?.is_expired ? '❌' : '✅'}</span>
              <div>
                <p className="summary-label">Certificate</p>
                <p className="summary-value">{result.certificate?.is_expired ? 'Expired' : 'Valid'}</p>
              </div>
            </div>
            <div className="summary-card glass-card">
              <span className="summary-icon">✅</span>
              <div>
                <p className="summary-label">TLS Version</p>
                <p className="summary-value">{result.tls_config?.preferred_proto || 'N/A'}</p>
              </div>
            </div>
            <div className="summary-card glass-card">
              <span className="summary-icon">🛡️</span>
              <div>
                <p className="summary-label">Cipher Suites</p>
                <p className="summary-value">{result.cipher_suites.length} found</p>
              </div>
            </div>
            <div className="summary-card glass-card">
              <span className="summary-icon">{result.revocation?.ocsp_status === 'Good' ? '✅' : '⚠️'}</span>
              <div>
                <p className="summary-label">OCSP</p>
                <p className="summary-value">{result.revocation?.ocsp_status || 'N/A'}</p>
              </div>
            </div>
          </div>

          {/* Score Breakdown Card */}
          <ScoreBreakdown result={result} />

          {/* Tabs */}
          <div className="result-tabs" id="result-tabs">
            {TABS.map((tab, i) => (
              <button
                key={tab}
                className={`tab-btn ${activeTab === i ? 'active' : ''}`}
                onClick={() => setActiveTab(i)}
              >
                {tab}
              </button>
            ))}
          </div>

          {/* Tab content */}
          <div className="tab-content glass-card" id="tab-content">
            {activeTab === 0 && <OverviewTab result={result} />}
            {activeTab === 1 && <CertificateTab result={result} />}
            {activeTab === 2 && <TLSConfigTab result={result} />}
            {activeTab === 3 && <CipherSuiteTab result={result} />}
            {activeTab === 4 && <RevocationTab result={result} />}
            {activeTab === 5 && <ChainTab result={result} />}
            {activeTab === 6 && <RecommendationsTab result={result} />}
            {activeTab === 7 && (
              <SecurityHeadersTab
                scanId={result.id}
                data={headersData}
                loading={headersLoading}
                onLoad={async () => {
                  if (headersData || headersLoading) return;
                  setHeadersLoading(true);
                  try { setHeadersData(await getSecurityHeaders(result.id)); }
                  catch { setHeadersData({ error: 'Failed to fetch headers' }); }
                  setHeadersLoading(false);
                }}
              />
            )}
            {activeTab === 8 && (
              <VulnerabilitiesTab
                scanId={result.id}
                data={vulnsData}
                loading={vulnsLoading}
                onLoad={async () => {
                  if (vulnsData || vulnsLoading) return;
                  setVulnsLoading(true);
                  try { setVulnsData(await getVulnerabilities(result.id)); }
                  catch { setVulnsData({ error: 'Failed to run vulnerability scan' }); }
                  setVulnsLoading(false);
                }}
              />
            )}
            {activeTab === 9 && (
              <DNSSecurityTab
                scanId={result.id}
                data={dnsData}
                loading={dnsLoading}
                onLoad={async () => {
                  if (dnsData || dnsLoading) return;
                  setDnsLoading(true);
                  try { setDnsData(await getDNSSecurity(result.id)); }
                  catch { setDnsData({ error: 'Failed to run DNS security audit' }); }
                  setDnsLoading(false);
                }}
              />
            )}
          </div>
        </div>
      )}
    </div>
  );
}

/* ===== Tab Components ===== */

function OverviewTab({ result }: { result: ScanDetailResponse }) {
  return (
    <div className="overview-tab">
      <h3>Security Overview</h3>
      <div className="overview-grid">
        <div className="overview-item">
          <span className="ov-label">Domain</span>
          <span className="ov-value">{result.target_url}</span>
        </div>
        <div className="overview-item">
          <span className="ov-label">Grade</span>
          <span className="ov-value"><GradeBadge grade={result.grade || 'F'} size="sm" /></span>
        </div>
        <div className="overview-item">
          <span className="ov-label">Score</span>
          <span className="ov-value">{result.score}/100</span>
        </div>
        <div className="overview-item">
          <span className="ov-label">Scanned At</span>
          <span className="ov-value">{result.completed_at ? new Date(result.completed_at).toLocaleString() : 'N/A'}</span>
        </div>
        <div className="overview-item">
          <span className="ov-label">Certificate</span>
          <span className="ov-value">{result.certificate?.is_expired ? '❌ Expired' : '✅ Valid'}</span>
        </div>
        <div className="overview-item">
          <span className="ov-label">TLS 1.3</span>
          <span className="ov-value">{result.tls_config?.tls_1_3 ? '✅ Supported' : '❌ Not supported'}</span>
        </div>
        <div className="overview-item">
          <span className="ov-label">Weak Ciphers</span>
          <span className="ov-value">{result.cipher_suites.filter(c => c.strength === 'Weak').length} found</span>
        </div>
        <div className="overview-item">
          <span className="ov-label">Chain Valid</span>
          <span className="ov-value">{result.chain?.chain_valid ? '✅ Yes' : '❌ No'}</span>
        </div>
      </div>
    </div>
  );
}

function CertificateTab({ result }: { result: ScanDetailResponse }) {
  const cert = result.certificate;
  if (!cert) return <p>No certificate data available.</p>;
  return (
    <div className="cert-tab">
      <h3>Certificate Details</h3>
      <div className="kv-table">
        <KV label="Subject CN" value={cert.subject_cn} />
        <KV label="Issuer CN" value={cert.issuer_cn} />
        <KV label="Issuer Org" value={cert.issuer_org} />
        <KV label="Valid From" value={cert.valid_from ? new Date(cert.valid_from).toLocaleDateString() : null} />
        <KV label="Valid To" value={cert.valid_to ? new Date(cert.valid_to).toLocaleDateString() : null} />
        <KV label="Days Until Expiry" value={cert.days_until_expiry?.toString()} badge={cert.days_until_expiry && cert.days_until_expiry > 30 ? 'good' : 'critical'} />
        <KV label="Expired" value={cert.is_expired ? '✗ Yes' : '✓ No'} badge={cert.is_expired ? 'critical' : 'good'} />
        <KV label="Self-Signed" value={cert.is_self_signed ? '✗ Yes' : '✓ No'} badge={cert.is_self_signed ? 'warning' : 'good'} />
        <KV label="Public Key" value={`${cert.public_key_type || 'N/A'} ${cert.public_key_size || ''} bits`} />
        <KV label="Signature Algorithm" value={cert.signature_algo} />
        <KV label="Serial Number" value={cert.serial_number} mono />
      </div>
      {cert.san_list.length > 0 && (
        <div className="san-section">
          <h4>Subject Alternative Names ({cert.san_list.length})</h4>
          <div className="san-list">
            {cert.san_list.map((san, i) => <span key={i} className="san-chip">{san}</span>)}
          </div>
        </div>
      )}
    </div>
  );
}

function TLSConfigTab({ result }: { result: ScanDetailResponse }) {
  const tls = result.tls_config;
  if (!tls) return <p>No TLS configuration data available.</p>;
  return (
    <div className="tls-tab">
      <h3>TLS Configuration</h3>
      <table className="data-table">
        <thead><tr><th>Protocol</th><th>Supported</th><th>Status</th></tr></thead>
        <tbody>
          <tr>
            <td>TLS 1.0</td>
            <td>{tls.tls_1_0 ? 'Yes' : 'No'}</td>
            <td>{tls.tls_1_0 ? <span className="badge badge-critical">Insecure</span> : <span className="badge badge-good">Safe</span>}</td>
          </tr>
          <tr>
            <td>TLS 1.1</td>
            <td>{tls.tls_1_1 ? 'Yes' : 'No'}</td>
            <td>{tls.tls_1_1 ? <span className="badge badge-warning">Deprecated</span> : <span className="badge badge-good">Safe</span>}</td>
          </tr>
          <tr>
            <td>TLS 1.2</td>
            <td>{tls.tls_1_2 ? 'Yes' : 'No'}</td>
            <td>{tls.tls_1_2 ? <span className="badge badge-good">Secure</span> : <span className="badge badge-warning">Missing</span>}</td>
          </tr>
          <tr>
            <td>TLS 1.3</td>
            <td>{tls.tls_1_3 ? 'Yes' : 'No'}</td>
            <td>{tls.tls_1_3 ? <span className="badge badge-strong">Best</span> : <span className="badge badge-info">Recommended</span>}</td>
          </tr>
        </tbody>
      </table>
      <div className="kv-table" style={{ marginTop: '20px' }}>
        <KV label="Preferred Protocol" value={tls.preferred_proto} />
        <KV label="Insecure Renegotiation" value={tls.insecure_reneg ? '✗ Yes' : '✓ No'} badge={tls.insecure_reneg ? 'critical' : 'good'} />
      </div>
    </div>
  );
}

function CipherSuiteTab({ result }: { result: ScanDetailResponse }) {
  const ciphers = result.cipher_suites;
  if (!ciphers.length) return <p>No cipher suite data available.</p>;

  const strong = ciphers.filter(c => c.strength === 'Strong').length;
  const acceptable = ciphers.filter(c => c.strength === 'Acceptable').length;
  const weak = ciphers.filter(c => c.strength === 'Weak').length;

  return (
    <div className="cipher-tab">
      <h3>Cipher Suites ({ciphers.length})</h3>
      <div className="cipher-summary">
        <span className="badge badge-strong">Strong: {strong}</span>
        <span className="badge badge-acceptable">Acceptable: {acceptable}</span>
        <span className="badge badge-weak">Weak: {weak}</span>
      </div>
      <table className="data-table">
        <thead><tr><th>Cipher Name</th><th>Protocol</th><th>Key Exchange</th><th>Bits</th><th>Strength</th></tr></thead>
        <tbody>
          {ciphers.map((cs, i) => (
            <tr key={i} className={cs.is_dangerous ? 'row-danger' : ''}>
              <td className="mono">{cs.cipher_name}</td>
              <td>{cs.protocol}</td>
              <td>{cs.key_exchange}</td>
              <td>{cs.bits}</td>
              <td><span className={`badge badge-${cs.strength?.toLowerCase()}`}>{cs.strength}</span></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function RevocationTab({ result }: { result: ScanDetailResponse }) {
  const rev = result.revocation;
  if (!rev) return <p>No revocation data available.</p>;
  return (
    <div className="rev-tab">
      <h3>Revocation Status</h3>
      <div className="kv-table">
        <KV label="OCSP Status" value={rev.ocsp_status} badge={rev.ocsp_status === 'Good' ? 'good' : rev.ocsp_status === 'Revoked' ? 'critical' : 'warning'} />
        <KV label="OCSP URL" value={rev.ocsp_url} mono />
        <KV label="CRL Present" value={rev.crl_present ? '✓ Yes' : '✗ No'} badge={rev.crl_present ? 'good' : 'info'} />
        <KV label="CRL URL" value={rev.crl_url} mono />
        <KV label="OCSP Stapling" value={rev.stapling_support ? '✓ Supported' : '✗ Not supported'} />
      </div>
    </div>
  );
}

function ChainTab({ result }: { result: ScanDetailResponse }) {
  const chain = result.chain;
  if (!chain) return <p>No chain data available.</p>;
  return (
    <div className="chain-tab">
      <h3>Certificate Chain</h3>
      <div className="kv-table">
        <KV label="Chain Depth" value={chain.chain_depth?.toString()} />
        <KV label="Chain Valid" value={chain.chain_valid ? '✓ Yes' : '✗ No'} badge={chain.chain_valid ? 'good' : 'critical'} />
        <KV label="Broken Chain" value={chain.has_broken_chain ? '✗ Yes' : '✓ No'} badge={chain.has_broken_chain ? 'critical' : 'good'} />
        <KV label="Expired Intermediate" value={chain.has_expired_intermediate ? '✗ Yes' : '✓ No'} badge={chain.has_expired_intermediate ? 'critical' : 'good'} />
      </div>
      {chain.chain_data.length > 0 && (
        <div className="chain-visual">
          {chain.chain_data.map((cert, i) => (
            <div key={i} className={`chain-cert-card glass-card ${cert.is_expired ? 'chain-cert-expired' : ''}`}>
              <div className="chain-connector">{i === 0 ? '🔐' : '↓'}</div>
              <div className="chain-cert-info">
                <p className="chain-subject"><strong>{cert.subject}</strong></p>
                <p className="chain-issuer">Issued by: {cert.issuer}</p>
                <div className="chain-badges">
                  {cert.is_root && <span className="badge badge-info">Root CA</span>}
                  {cert.is_expired && <span className="badge badge-critical">Expired</span>}
                  {!cert.is_root && !cert.is_expired && <span className="badge badge-good">Valid</span>}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function RecommendationsTab({ result }: { result: ScanDetailResponse }) {
  const recs = result.recommendations;
  if (!recs.length) return <p>No recommendations.</p>;
  return (
    <div className="rec-tab">
      <h3>Security Recommendations</h3>
      {recs.map((rec, i) => (
        <div key={i} className={`rec-item rec-${rec.severity?.toLowerCase()}`}>
          <span className={`badge badge-${rec.severity?.toLowerCase()}`}>{rec.severity}</span>
          <h4>{rec.title}</h4>
          <p className="rec-desc">{rec.description}</p>
          <p className="rec-fix">💡 {rec.fix_suggestion}</p>
        </div>
      ))}
    </div>
  );
}

/* Key-Value row helper */
function KV({ label, value, badge, mono }: { label: string; value?: string | null; badge?: string; mono?: boolean }) {
  return (
    <div className="kv-row">
      <span className="kv-label">{label}</span>
      <span className={`kv-value ${mono ? 'mono' : ''}`}>
        {badge ? <span className={`badge badge-${badge}`}>{value || 'N/A'}</span> : (value || 'N/A')}
      </span>
    </div>
  );
}

/* ===== Security Headers Tab ===== */
interface LazyTabProps {
  scanId: string;
  data: Record<string, unknown> | null;
  loading: boolean;
  onLoad: () => void;
}

function SecurityHeadersTab({ data, loading, onLoad }: LazyTabProps) {
  useEffect(() => { onLoad(); }, []);

  if (loading) return (
    <div className="lazy-tab-loading">
      <div className="spinner" />
      <p>Fetching HTTP headers from server...</p>
    </div>
  );

  if (!data) return null;
  if (data.error) return <p className="tab-error">⚠️ {data.error as string}</p>;

  const checks = (data.checks as any[]) || [];
  const score = data.overall_score as number;
  const grade = data.grade as string;

  return (
    <div className="headers-tab">
      <div className="headers-summary">
        <h3>🛡️ HTTP Security Headers</h3>
        <div className="headers-meta">
          <span className="headers-score" style={{ color: score >= 80 ? 'var(--accent)' : score >= 60 ? 'var(--warning)' : 'var(--danger)' }}>
            Score: {score}/100
          </span>
          <span className={`badge badge-${grade === 'A' || grade === 'B' ? 'good' : grade === 'C' ? 'warning' : 'critical'}`}>
            Grade {grade}
          </span>
        </div>
      </div>
      <div className="headers-grid">
        {checks.map((check: any, i: number) => (
          <div key={i} className={`header-card glass-card header-${check.present ? 'present' : 'missing'}`}>
            <div className="header-card-top">
              <span className="header-icon">{check.present ? '✅' : '❌'}</span>
              <span className="header-name">{check.header}</span>
              <span className={`badge badge-${check.severity === 'High' ? 'critical' : check.severity === 'Medium' ? 'warning' : 'info'}`}>
                {check.severity}
              </span>
            </div>
            {check.value && (
              <code className="header-value">{check.value}</code>
            )}
            {check.recommendation && (
              <p className="header-rec">💡 {check.recommendation}</p>
            )}
            {check.details && !check.recommendation && (
              <p className="header-details">{check.details}</p>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

/* ===== Vulnerabilities Tab ===== */
function VulnerabilitiesTab({ data, loading, onLoad }: LazyTabProps) {
  useEffect(() => { onLoad(); }, []);

  if (loading) return (
    <div className="lazy-tab-loading">
      <div className="spinner" />
      <p>Running vulnerability checks (Heartbleed, POODLE, BEAST, ROBOT, SWEET32, CRIME)...</p>
      <p className="lazy-tab-sub">This may take 15–30 seconds.</p>
    </div>
  );

  if (!data) return null;
  if (data.error) return <p className="tab-error">⚠️ {data.error as string}</p>;

  const vulns = (data.vulnerabilities as any[]) || [];
  const summary = data.summary as any;
  const vscore = data.vulnerability_score as number;

  const severityIcon: Record<string, string> = {
    Critical: '🔴', High: '🟠', Medium: '🟡', Low: '🔵', Info: '⚪', Unknown: '⚫',
  };

  return (
    <div className="vulns-tab">
      <div className="vulns-summary">
        <h3>🔍 Vulnerability Scan Results</h3>
        <div className="vulns-counts">
          <div className={`vuln-count ${summary?.critical > 0 ? 'vuln-critical' : ''}`}>
            <span>🔴</span><strong>{summary?.critical ?? 0}</strong><span>Critical</span>
          </div>
          <div className={`vuln-count ${summary?.high > 0 ? 'vuln-high' : ''}`}>
            <span>🟠</span><strong>{summary?.high ?? 0}</strong><span>High</span>
          </div>
          <div className={`vuln-count ${summary?.medium > 0 ? 'vuln-medium' : ''}`}>
            <span>🟡</span><strong>{summary?.medium ?? 0}</strong><span>Medium</span>
          </div>
          <div className="vuln-count">
            <span>🔵</span><strong>{summary?.low ?? 0}</strong><span>Low</span>
          </div>
          <div className="vuln-score">
            Safety Score: <strong style={{ color: vscore >= 80 ? 'var(--accent)' : vscore >= 50 ? 'var(--warning)' : 'var(--danger)' }}>
              {vscore}/100
            </strong>
          </div>
        </div>
      </div>
      <div className="vulns-list">
        {vulns.map((v: any, i: number) => (
          <div key={i} className={`vuln-item glass-card ${v.vulnerable ? `vuln-item-${v.severity?.toLowerCase()}` : 'vuln-item-safe'}`}>
            <div className="vuln-item-header">
              <span className="vuln-sev-icon">{severityIcon[v.severity] || '⚫'}</span>
              <span className="vuln-name">{v.name}</span>
              <code className="vuln-cve">{v.cve}</code>
              <span className={`badge badge-${v.vulnerable ? (v.severity === 'Critical' ? 'critical' : v.severity === 'High' ? 'warning' : 'info') : 'good'}`}>
                {v.vulnerable ? '⚠ VULNERABLE' : '✓ SAFE'}
              </span>
            </div>
            {v.details && <p className="vuln-details">{v.details}</p>}
            {v.mitigation && v.vulnerable && <p className="vuln-mitigation">🛠 {v.mitigation}</p>}
            {v.error && <p className="vuln-error">Error: {v.error}</p>}
          </div>
        ))}
      </div>
    </div>
  );
}
/* ===== DNS Security Tab ===== */
function DNSSecurityTab({ data, loading, onLoad }: LazyTabProps) {
  useEffect(() => { onLoad(); }, []);

  if (loading) return (
    <div className="lazy-tab-loading">
      <div className="spinner" />
      <p>Running DNS security audit (DNSSEC, CAA, SPF, DMARC)...</p>
      <p className="lazy-tab-sub">Querying DNS records for all four checks...</p>
    </div>
  );

  if (!data) return null;
  if (data.error) return <p className="tab-error">⚠️ {data.error as string}</p>;

  const caa    = data.caa    as any;
  const dnssec = data.dnssec as any;
  const spf    = data.spf    as any;
  const dmarc  = data.dmarc  as any;
  const score  = data.overall_score as number;
  const grade  = data.grade as string;

  const gradeColor = grade === 'A' ? 'var(--accent)' : grade === 'B' ? '#74B9FF' : grade === 'C' ? 'var(--warning)' : 'var(--danger)';

  return (
    <div className="dns-tab">
      {/* Header */}
      <div className="dns-header">
        <h3>🌐 DNS Security Audit</h3>
        <div className="dns-header-meta">
          <span className="dns-score" style={{ color: gradeColor }}>Score: {score}/100</span>
          <span className={`badge badge-${grade === 'A' || grade === 'B' ? 'good' : grade === 'C' ? 'warning' : 'critical'}`}>Grade {grade}</span>
        </div>
      </div>

      <div className="dns-grid">
        {/* CAA Records */}
        <div className={`dns-card glass-card dns-check-${caa?.present ? 'pass' : 'fail'}`}>
          <div className="dns-card-header">
            <span className="dns-card-icon">{caa?.present ? '✅' : '❌'}</span>
            <div>
              <h4 className="dns-card-title">CAA Records</h4>
              <p className="dns-card-sub">Certification Authority Authorization</p>
            </div>
          </div>
          {caa?.present ? (
            <>
              <div className="caa-records">
                {(caa.records || []).map((r: any, i: number) => (
                  <div key={i} className="caa-record-row">
                    <span className="caa-tag">{r.tag}</span>
                    <code className="caa-value">{r.value || '(any)'}</code>
                    <span className="caa-flag">flag:{r.flag}</span>
                  </div>
                ))}
              </div>
              {caa.issuers_allowed?.length > 0 && (
                <p className="dns-info-line">✅ Authorized CAs: <strong>{caa.issuers_allowed.join(', ')}</strong></p>
              )}
              <p className="dns-info-line">
                Wildcard: <strong>{caa.wildcard_allowed ? '⚠️ Allowed' : '✅ Restricted'}</strong>
              </p>
            </>
          ) : (
            <p className="dns-missing">⚠️ No CAA records found. Any CA can issue certificates for this domain.</p>
          )}
        </div>

        {/* DNSSEC */}
        <div className={`dns-card glass-card dns-check-${dnssec?.enabled ? 'pass' : 'fail'}`}>
          <div className="dns-card-header">
            <span className="dns-card-icon">{dnssec?.enabled ? '✅' : '❌'}</span>
            <div>
              <h4 className="dns-card-title">DNSSEC</h4>
              <p className="dns-card-sub">DNS Security Extensions</p>
            </div>
          </div>
          {dnssec?.enabled ? (
            <>
              <p className="dns-info-line">✅ DNSKEY records present</p>
              <p className="dns-info-line">
                Validation: <strong style={{ color: dnssec.valid ? 'var(--accent)' : 'var(--warning)' }}>
                  {dnssec.valid ? '✅ Valid (RRSIG present)' : '⚠️ Not fully validated'}
                </strong>
              </p>
              {dnssec.details && <p className="dns-detail-text">{dnssec.details}</p>}
            </>
          ) : (
            <p className="dns-missing">⚠️ DNSSEC not enabled. DNS responses cannot be authenticated.</p>
          )}
        </div>

        {/* SPF */}
        <div className={`dns-card glass-card dns-check-${spf?.present ? 'pass' : 'fail'}`}>
          <div className="dns-card-header">
            <span className="dns-card-icon">{spf?.present ? '✅' : '❌'}</span>
            <div>
              <h4 className="dns-card-title">SPF Record</h4>
              <p className="dns-card-sub">Sender Policy Framework</p>
            </div>
          </div>
          {spf?.present ? (
            <>
              <code className="dns-record-value">{spf.record}</code>
              {spf.all_mechanism && (
                <p className="dns-info-line">
                  Policy: <strong style={{
                    color: spf.all_mechanism === '-all' ? 'var(--accent)'
                         : spf.all_mechanism === '~all' ? 'var(--warning)' : 'var(--danger)'
                  }}>{spf.all_mechanism}</strong>
                  &nbsp;
                  <span className="dns-detail-text">
                    {spf.all_mechanism === '-all' ? '(Strict reject)' :
                     spf.all_mechanism === '~all' ? '(Soft fail)' : '(Permissive — update recommended)'}
                  </span>
                </p>
              )}
            </>
          ) : (
            <p className="dns-missing">⚠️ No SPF record. Domain is vulnerable to email spoofing.</p>
          )}
          {spf?.error && <p className="dns-detail-text">{spf.error}</p>}
        </div>

        {/* DMARC */}
        <div className={`dns-card glass-card dns-check-${dmarc?.present ? 'pass' : 'fail'}`}>
          <div className="dns-card-header">
            <span className="dns-card-icon">{dmarc?.present ? '✅' : '❌'}</span>
            <div>
              <h4 className="dns-card-title">DMARC Policy</h4>
              <p className="dns-card-sub">Domain-based Message Authentication</p>
            </div>
          </div>
          {dmarc?.present ? (
            <>
              <code className="dns-record-value">{dmarc.record}</code>
              {dmarc.policy && (
                <p className="dns-info-line">
                  Policy: <strong style={{
                    color: dmarc.policy === 'reject' ? 'var(--accent)'
                         : dmarc.policy === 'quarantine' ? 'var(--warning)' : 'var(--danger)'
                  }}>{dmarc.policy.toUpperCase()}</strong>
                </p>
              )}
              {dmarc.subdomain_policy && (
                <p className="dns-info-line">Subdomain policy: <strong>{dmarc.subdomain_policy}</strong></p>
              )}
              {dmarc.percentage < 100 && (
                <p className="dns-info-line" style={{ color: 'var(--warning)' }}>
                  ⚠️ Applied to {dmarc.percentage}% of messages only
                </p>
              )}
            </>
          ) : (
            <p className="dns-missing">⚠️ No DMARC policy. Email phishing protection is missing.</p>
          )}
          {dmarc?.error && <p className="dns-detail-text">{dmarc.error}</p>}
        </div>
      </div>
    </div>
  );
}
