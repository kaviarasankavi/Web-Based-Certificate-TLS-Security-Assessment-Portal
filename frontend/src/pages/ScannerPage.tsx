import { useState, useEffect, useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import './ScannerPage.css';
import GradeBadge from '../components/GradeBadge';
import { startScan, getScanStatus, getScanDetail, downloadPDF, downloadHTML } from '../services/api';
import type { ScanDetailResponse } from '../types';

const TABS = ['Overview', 'Certificate', 'TLS Config', 'Cipher Suites', 'Revocation', 'Chain', 'Recommendations'];

export default function ScannerPage() {
  const [searchParams] = useSearchParams();
  const [url, setUrl] = useState(searchParams.get('url') || '');
  const [port] = useState(443);
  const [scanning, setScanning] = useState(false);
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [progress, setProgress] = useState(0);
  const [statusText, setStatusText] = useState('');
  const [result, setResult] = useState<ScanDetailResponse | null>(null);
  const [activeTab, setActiveTab] = useState(0);
  const [error, setError] = useState('');

  const pollStatus = useCallback(async (scanId: string) => {
    const maxAttempts = 60;
    for (let i = 0; i < maxAttempts; i++) {
      await new Promise(r => setTimeout(r, 2000));
      try {
        const status = await getScanStatus(scanId);
        setProgress(status.progress);
        setStatusText(status.step || status.status);

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

      {/* Progress */}
      {scanning && !loadingHistory && (
        <div className="scan-progress" id="scan-progress">
          <div className="progress-bar-track">
            <div className="progress-bar-fill" style={{ width: `${Math.max(progress, 10)}%` }}></div>
          </div>
          <p className="progress-text">{statusText || 'Scanning...'} — {progress}%</p>
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="scan-results animate-in" id="scan-results">
          {/* Score header */}
          <div className="result-header glass-card">
            <div className="result-score-section">
              <GradeBadge grade={result.grade || 'F'} size="lg" />
              <div className="score-details">
                <h2>{result.target_url}</h2>
                <p className="score-num">Security Score: <strong>{result.score ?? 0}/100</strong></p>
              </div>
            </div>
            <div className="result-actions">
              <button className="btn btn-secondary" onClick={handleDownloadPDF} id="download-pdf-btn">📄 PDF Report</button>
              <button className="btn btn-secondary" onClick={handleDownloadHTML} id="download-html-btn">🌐 HTML Report</button>
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
