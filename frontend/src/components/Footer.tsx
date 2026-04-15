import './Footer.css';

export default function Footer() {
  return (
    <footer className="footer" id="site-footer">
      <div className="footer-inner container">
        <div className="footer-brand">
          <span className="brand-icon">🔒</span>
          <span>TLS Inspector</span>
        </div>
        <p className="footer-copy">
          Web-Based Certificate &amp; TLS Security Assessment Portal
        </p>
        <p className="footer-credits">
          Built for Cyber Security &bull; M.Tech Project &bull; {new Date().getFullYear()}
        </p>
      </div>
    </footer>
  );
}
