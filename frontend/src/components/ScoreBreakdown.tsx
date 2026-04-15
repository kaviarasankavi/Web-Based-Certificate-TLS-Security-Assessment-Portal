/**
 * ScoreBreakdown — Shows a detailed breakdown of how the security score was computed.
 * Mirrors the exact scoring logic from backend/scanner/scorer.py.
 * All calculations are done client-side from the existing ScanDetailResponse data.
 */
import './ScoreBreakdown.css';
import type { ScanDetailResponse } from '../types';

interface Props {
  result: ScanDetailResponse;
}

interface BreakdownItem {
  key: string;
  label: string;
  icon: string;
  points: number;
  maxPoints: number;
  weight: number;       // weight percentage (e.g. 25)
  earned: number;       // weighted points earned (e.g. 23.5)
  maxEarned: number;    // max weighted points (e.g. 25)
  notes: string[];
  status: 'good' | 'warning' | 'critical';
}

function getBarColor(pct: number): string {
  if (pct >= 85) return 'var(--accent)';
  if (pct >= 60) return 'var(--warning)';
  return 'var(--danger)';
}

function computeBreakdown(result: ScanDetailResponse): BreakdownItem[] {
  const items: BreakdownItem[] = [];

  /* ── 1. Certificate (25%) ── */
  {
    let score = 100;
    const notes: string[] = [];
    const cert = result.certificate;
    if (cert) {
      if (cert.is_expired) {
        score = 0;
        notes.push('❌ Certificate is expired');
      } else {
        notes.push('✅ Certificate is valid');
      }
      if (cert.is_self_signed) {
        score = Math.max(0, score - 40);
        notes.push('⚠️ Self-signed certificate (-40)');
      }
      if (cert.days_until_expiry !== null && cert.days_until_expiry < 30) {
        score = Math.max(0, score - 20);
        notes.push(`⚠️ Expires in ${cert.days_until_expiry} days (-20)`);
      } else if (cert.days_until_expiry !== null) {
        notes.push(`✅ ${cert.days_until_expiry} days until expiry`);
      }
      if (cert.public_key_type === 'RSA' && cert.public_key_size && cert.public_key_size < 2048) {
        score = Math.max(0, score - 30);
        notes.push(`⚠️ Weak key size: ${cert.public_key_size} bits (-30)`);
      } else if (cert.public_key_size) {
        notes.push(`✅ Key size: ${cert.public_key_type} ${cert.public_key_size} bits`);
      }
    } else {
      score = 0;
      notes.push('❌ No certificate data');
    }
    const weight = 25;
    items.push({
      key: 'certificate',
      label: 'Certificate',
      icon: '📜',
      points: score,
      maxPoints: 100,
      weight,
      earned: (score * weight) / 100,
      maxEarned: weight,
      notes,
      status: score >= 85 ? 'good' : score >= 50 ? 'warning' : 'critical',
    });
  }

  /* ── 2. TLS Version (25%) ── */
  {
    let score = 100;
    const notes: string[] = [];
    const tls = result.tls_config;
    if (tls) {
      if (tls.tls_1_0) {
        score = Math.max(0, score - 30);
        notes.push('❌ TLS 1.0 enabled (insecure) (-30)');
      }
      if (tls.tls_1_1) {
        score = Math.max(0, score - 20);
        notes.push('⚠️ TLS 1.1 enabled (deprecated) (-20)');
      }
      if (!tls.tls_1_2 && !tls.tls_1_3) {
        score = 0;
        notes.push('❌ No modern TLS version supported');
      }
      if (tls.insecure_reneg) {
        score = Math.max(0, score - 20);
        notes.push('⚠️ Insecure renegotiation enabled (-20)');
      }
      if (tls.tls_1_3) {
        score = Math.min(100, score + 10);
        notes.push('✅ TLS 1.3 supported (+10 bonus)');
      }
      if (tls.tls_1_2 && !tls.tls_1_0 && !tls.tls_1_1) {
        notes.push('✅ TLS 1.2 enabled');
      }
    } else {
      score = 0;
      notes.push('❌ No TLS config data');
    }
    const weight = 25;
    items.push({
      key: 'tls_version',
      label: 'TLS Version',
      icon: '🔄',
      points: score,
      maxPoints: 100,
      weight,
      earned: (score * weight) / 100,
      maxEarned: weight,
      notes,
      status: score >= 85 ? 'good' : score >= 50 ? 'warning' : 'critical',
    });
  }

  /* ── 3. Cipher Strength (20%) ── */
  {
    let score = 100;
    const notes: string[] = [];
    const ciphers = result.cipher_suites;
    if (ciphers && ciphers.length > 0) {
      const total = ciphers.length;
      const weak = ciphers.filter(c => c.strength === 'Weak').length;
      const dangerous = ciphers.filter(c => c.is_dangerous).length;
      const strong = ciphers.filter(c => c.strength === 'Strong').length;
      if (dangerous > 0) {
        score = Math.max(0, score - 40);
        notes.push(`❌ ${dangerous} dangerous cipher(s) detected (-40)`);
      }
      if (total > 0) {
        const weakPct = weak / total;
        const penalty = Math.floor(weakPct * 40);
        if (penalty > 0) {
          score = Math.max(0, score - penalty);
          notes.push(`⚠️ ${weak}/${total} weak ciphers (${Math.round(weakPct * 100)}%) (-${penalty})`);
        }
      }
      notes.push(`✅ ${strong} strong cipher suite(s)`);
      notes.push(`📊 ${total} total cipher suites`);
    } else {
      score = 50;
      notes.push('⚠️ No cipher data available (partial score)');
    }
    const weight = 20;
    items.push({
      key: 'cipher_strength',
      label: 'Cipher Suites',
      icon: '🔒',
      points: score,
      maxPoints: 100,
      weight,
      earned: (score * weight) / 100,
      maxEarned: weight,
      notes,
      status: score >= 85 ? 'good' : score >= 50 ? 'warning' : 'critical',
    });
  }

  /* ── 4. Revocation (15%) ── */
  {
    let score = 100;
    const notes: string[] = [];
    const rev = result.revocation;
    if (rev) {
      if (rev.ocsp_status === 'Good') {
        score = 100;
        notes.push('✅ OCSP status: Good');
      } else if (rev.ocsp_status === 'Revoked') {
        score = 0;
        notes.push('❌ Certificate is revoked!');
      } else if (rev.ocsp_status === 'Unknown') {
        score = 60;
        notes.push('⚠️ OCSP status unknown');
      } else if (rev.ocsp_status === 'Error') {
        score = 50;
        notes.push('⚠️ OCSP check error');
      } else {
        score = 40;
        notes.push('⚠️ No OCSP URL available');
      }
      if (!rev.crl_present) {
        score = Math.max(0, score - 10);
        notes.push('⚠️ No CRL present (-10)');
      } else {
        notes.push('✅ CRL present');
      }
      if (rev.stapling_support) {
        notes.push('✅ OCSP stapling supported');
      }
    } else {
      score = 0;
      notes.push('❌ No revocation data');
    }
    const weight = 15;
    items.push({
      key: 'revocation',
      label: 'Revocation',
      icon: '✅',
      points: score,
      maxPoints: 100,
      weight,
      earned: (score * weight) / 100,
      maxEarned: weight,
      notes,
      status: score >= 85 ? 'good' : score >= 50 ? 'warning' : 'critical',
    });
  }

  /* ── 5. Chain (15%) ── */
  {
    let score = 100;
    const notes: string[] = [];
    const chain = result.chain;
    if (chain) {
      if (chain.has_broken_chain) {
        score = 0;
        notes.push('❌ Broken certificate chain');
      } else if (chain.has_expired_intermediate) {
        score = 20;
        notes.push('❌ Expired intermediate certificate (-80)');
      } else if (!chain.chain_valid) {
        score = 30;
        notes.push('⚠️ Chain not fully valid');
      } else {
        notes.push('✅ Certificate chain is valid');
      }
      notes.push(`📊 Chain depth: ${chain.chain_depth ?? 'N/A'}`);
    } else {
      score = 0;
      notes.push('❌ No chain data');
    }
    const weight = 15;
    items.push({
      key: 'chain',
      label: 'Chain',
      icon: '🔗',
      points: score,
      maxPoints: 100,
      weight,
      earned: (score * weight) / 100,
      maxEarned: weight,
      notes,
      status: score >= 85 ? 'good' : score >= 50 ? 'warning' : 'critical',
    });
  }

  return items;
}

export default function ScoreBreakdown({ result }: Props) {
  const items = computeBreakdown(result);
  const totalEarned = items.reduce((sum, i) => sum + i.earned, 0);
  const totalMax = items.reduce((sum, i) => sum + i.maxEarned, 0);

  return (
    <div className="score-breakdown" id="score-breakdown">
      <div className="breakdown-header">
        <h3>📊 Score Breakdown</h3>
        <p className="breakdown-subtitle">
          How your <strong>{Math.round(totalEarned)}/{totalMax}</strong> security score was calculated
        </p>
      </div>

      <div className="breakdown-rows">
        {items.map(item => {
          const pct = item.points; // raw 0-100 score for this category
          const barColor = getBarColor(pct);
          return (
            <div key={item.key} className={`breakdown-row breakdown-${item.status}`}>
              {/* Left: icon + label + weight */}
              <div className="breakdown-label-col">
                <span className="breakdown-icon">{item.icon}</span>
                <div>
                  <span className="breakdown-label">{item.label}</span>
                  <span className="breakdown-weight">weight: {item.weight}%</span>
                </div>
              </div>

              {/* Middle: progress bar */}
              <div className="breakdown-bar-col">
                <div className="breakdown-bar-track">
                  <div
                    className="breakdown-bar-fill"
                    style={{
                      width: `${pct}%`,
                      background: barColor,
                      boxShadow: `0 0 8px ${barColor}60`,
                    }}
                  />
                </div>
                <div className="breakdown-notes">
                  {item.notes.map((note, i) => (
                    <span key={i} className="breakdown-note">{note}</span>
                  ))}
                </div>
              </div>

              {/* Right: points */}
              <div className="breakdown-score-col">
                <span className="breakdown-pts" style={{ color: barColor }}>
                  {item.earned.toFixed(1)}
                </span>
                <span className="breakdown-pts-max">/ {item.maxEarned}</span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Total row */}
      <div className="breakdown-total">
        <span className="breakdown-total-label">Total Score</span>
        <span className="breakdown-total-score">
          {Math.round(totalEarned)} <span className="breakdown-total-max">/ 100</span>
        </span>
      </div>
    </div>
  );
}
