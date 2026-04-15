import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import './LandingPage.css';
import { useAuth } from '../context/AuthContext';
import AuthModal from '../components/AuthModal';

const features = [
  {
    icon: '🔐',
    title: 'Certificate Analysis',
    desc: 'Deep X.509 certificate inspection — subject, issuer, validity, SAN, key type & size.',
  },
  {
    icon: '🔄',
    title: 'TLS Version Check',
    desc: 'Test TLS 1.0 through 1.3 support and detect insecure protocol versions.',
  },
  {
    icon: '🔒',
    title: 'Cipher Suite Audit',
    desc: 'Enumerate all cipher suites and classify them as Strong, Acceptable, or Weak.',
  },
  {
    icon: '✅',
    title: 'Revocation Check',
    desc: 'OCSP and CRL verification to detect revoked or compromised certificates.',
  },
  {
    icon: '🔗',
    title: 'Chain Validation',
    desc: 'Verify the full certificate chain — detect broken chains and expired intermediates.',
  },
  {
    icon: '📄',
    title: 'Report Generator',
    desc: 'Generate downloadable PDF & HTML security reports with actionable fixes.',
  },
];

const steps = [
  { num: 1, title: 'Create Account', desc: 'Sign up free in under 30 seconds' },
  { num: 2, title: 'Enter URL', desc: 'Type any domain you want to assess' },
  { num: 3, title: 'Get Report', desc: 'View results and download a detailed security report' },
];

const trustBadges = [
  { label: 'TLS 1.3 Analysis', icon: '🛡️' },
  { label: 'OCSP Verified', icon: '✔️' },
  { label: 'Cipher Grading', icon: '🏅' },
  { label: 'PDF Reports', icon: '📋' },
  { label: 'Free to Use', icon: '🎁' },
];

export default function LandingPage() {
  const [url, setUrl] = useState('');
  const [modalOpen, setModalOpen] = useState(false);
  const [modalTab, setModalTab] = useState<'login' | 'signup'>('signup');
  const navigate = useNavigate();
  const { user } = useAuth();

  const handleScan = (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;
    if (user) {
      navigate(`/scan?url=${encodeURIComponent(url.trim())}`);
    } else {
      setModalTab('signup');
      setModalOpen(true);
    }
  };

  const openSignup = () => { setModalTab('signup'); setModalOpen(true); };
  const openLogin = () => { setModalTab('login'); setModalOpen(true); };

  return (
    <div className="landing-page">
      {/* Hero */}
      <section className="hero-section" id="hero">
        <div className="hero-bg-effects">
          <div className="hero-orb hero-orb-1" />
          <div className="hero-orb hero-orb-2" />
          <div className="hero-grid" />
        </div>

        <div className="container hero-content">
          <div className="hero-badge animate-in">
            <span className="hero-badge-dot" />
            Free TLS Security Assessment Tool
          </div>

          <h1 className="hero-title animate-in" style={{ animationDelay: '0.05s' }}>
            Instantly Assess Any Website's<br />
            <span className="gradient-text">TLS Security</span>
          </h1>

          <p className="hero-subtitle animate-in" style={{ animationDelay: '0.12s' }}>
            Analyze SSL/TLS certificates, cipher suites, protocol versions, and revocation
            status. Get actionable security recommendations in seconds.
          </p>

          <form className="hero-search animate-in" onSubmit={handleScan} style={{ animationDelay: '0.2s' }}>
            <div className="search-input-wrapper">
              <span className="search-icon">🔍</span>
              <input
                id="hero-url-input"
                type="text"
                placeholder="Enter domain (e.g., google.com)"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                className="search-input"
              />
            </div>
            <button type="submit" className="btn btn-primary scan-btn" id="hero-scan-btn">
              <span>Scan Now</span>
              <span>→</span>
            </button>
          </form>

          {/* CTA buttons */}
          <div className="hero-cta-group animate-in" style={{ animationDelay: '0.28s' }}>
            {user ? (
              <button className="cta-primary" onClick={() => navigate('/scan')} id="hero-goto-scan-btn">
                🔍 Go to Scanner
              </button>
            ) : (
              <>
                <button className="cta-primary" onClick={openSignup} id="hero-getstarted-btn">
                  Get Started — It's Free
                </button>
                <button className="cta-ghost" onClick={openLogin} id="hero-signin-btn">
                  Sign In
                </button>
              </>
            )}
          </div>

          {/* Trust badges */}
          <div className="trust-badges animate-in" style={{ animationDelay: '0.35s' }}>
            {trustBadges.map((b, i) => (
              <span className="trust-badge" key={i}>
                {b.icon} {b.label}
              </span>
            ))}
          </div>
        </div>
      </section>

      {/* Features */}
      <section className="features-section section" id="features">
        <div className="container">
          <h2 className="section-title" style={{ textAlign: 'center' }}>
            Comprehensive <span className="gradient-text">Security Analysis</span>
          </h2>
          <p className="section-subtitle" style={{ textAlign: 'center', margin: '0 auto var(--space-2xl)' }}>
            Everything you need to evaluate and strengthen your website's HTTPS configuration.
          </p>
          <div className="features-grid">
            {features.map((f, i) => (
              <div className="feature-card glass-card" key={i} style={{ animationDelay: `${i * 0.08}s` }}>
                <div className="feature-icon">{f.icon}</div>
                <h3>{f.title}</h3>
                <p>{f.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* How It Works */}
      <section className="steps-section section" id="how-it-works">
        <div className="container">
          <h2 className="section-title" style={{ textAlign: 'center' }}>
            How It <span className="gradient-text">Works</span>
          </h2>
          <div className="steps-row">
            {steps.map((s, i) => (
              <div className="step-item" key={i}>
                <div className="step-number">{s.num}</div>
                <h3>{s.title}</h3>
                <p>{s.desc}</p>
                {i < steps.length - 1 && <div className="step-connector">→</div>}
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="cta-section" id="cta">
        <div className="container">
          <div className="cta-card glass-card">
            <div className="cta-orb" />
            <h2>Ready to secure your website?</h2>
            <p>Join thousands of developers checking their TLS configurations daily.</p>
            {!user && (
              <button className="cta-primary large" onClick={openSignup} id="cta-signup-btn">
                Create Free Account →
              </button>
            )}
            {user && (
              <button className="cta-primary large" onClick={() => navigate('/scan')} id="cta-scan-btn">
                Start Scanning →
              </button>
            )}
          </div>
        </div>
      </section>

      {/* Stats bar */}
      <section className="stats-section" id="stats">
        <div className="container">
          <div className="stats-row">
            <div className="stat-item">
              <span className="stat-label">Certificate &amp; TLS Analysis</span>
            </div>
            <div className="stat-item">
              <span className="stat-label">Cipher Suite Auditing</span>
            </div>
            <div className="stat-item">
              <span className="stat-label">Security Score &amp; Grade</span>
            </div>
          </div>
        </div>
      </section>

      <AuthModal
        isOpen={modalOpen}
        onClose={() => setModalOpen(false)}
        defaultTab={modalTab}
      />
    </div>
  );
}
