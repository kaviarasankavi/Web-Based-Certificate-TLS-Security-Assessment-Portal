import './AboutPage.css';

export default function AboutPage() {
  return (
    <div className="about-page container" id="about-page">
      <div className="about-hero">
        <h1>About <span className="gradient-text">TLS Inspector</span></h1>
        <p className="about-subtitle">
          A Web-Based Certificate & TLS Security Assessment Portal
        </p>
      </div>

      <div className="about-sections">
        <div className="about-card glass-card">
          <h2>🎯 Project Overview</h2>
          <p>
            TLS Inspector is a comprehensive web-based security tool that enables users to analyze
            any website's SSL/TLS configuration. It performs deep analysis of X.509 certificates,
            tests TLS protocol versions, audits cipher suites, checks certificate revocation status,
            and validates the entire certificate chain.
          </p>
        </div>

        <div className="about-card glass-card">
          <h2>🔍 What We Analyze</h2>
          <div className="about-grid">
            <div>
              <h3>📜 Certificate Details</h3>
              <p>Subject, Issuer, Validity, SAN entries, Public key type & size, Signature algorithm</p>
            </div>
            <div>
              <h3>🔐 TLS Versions</h3>
              <p>TLS 1.0 through 1.3 support testing, insecure renegotiation detection</p>
            </div>
            <div>
              <h3>🛡️ Cipher Suites</h3>
              <p>Enumeration and classification as Strong, Acceptable, or Weak. Flags RC4, 3DES, NULL</p>
            </div>
            <div>
              <h3>🔄 Revocation</h3>
              <p>OCSP status checking, CRL distribution point verification, stapling support</p>
            </div>
            <div>
              <h3>🔗 Chain Validation</h3>
              <p>Full certificate chain analysis, broken chain detection, expired intermediate alerts</p>
            </div>
            <div>
              <h3>📊 Security Scoring</h3>
              <p>Weighted security score (0–100) with A+ to F grading, actionable recommendations</p>
            </div>
          </div>
        </div>

        <div className="about-card glass-card">
          <h2>🏗️ Technology Stack</h2>
          <div className="tech-tags">
            <span className="tech-tag">React</span>
            <span className="tech-tag">TypeScript</span>
            <span className="tech-tag">Vite</span>
            <span className="tech-tag">Python</span>
            <span className="tech-tag">FastAPI</span>
            <span className="tech-tag">PostgreSQL</span>
            <span className="tech-tag">OpenSSL</span>
            <span className="tech-tag">cryptography</span>
          </div>
        </div>

        <div className="about-card glass-card">
          <h2>📚 Areas of Interest</h2>
          <p>
            Cryptography & PKI • Network Security & HTTPS/TLS • Web Security & Secure Deployment •
            Security Automation & DevSecOps • Certificate Lifecycle Management • Compliance & Governance
            (OWASP, NIST, Mozilla TLS guidelines)
          </p>
        </div>
      </div>
    </div>
  );
}
