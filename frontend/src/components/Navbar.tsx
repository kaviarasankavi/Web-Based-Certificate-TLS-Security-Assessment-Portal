import { useState } from 'react';
import './Navbar.css';
import { Link, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import AuthModal from './AuthModal';

export default function Navbar() {
  const location = useLocation();
  const isActive = (path: string) => location.pathname === path;
  const { user, logout } = useAuth();

  const [modalOpen, setModalOpen] = useState(false);
  const [modalTab, setModalTab] = useState<'login' | 'signup'>('login');

  const openLogin = () => { setModalTab('login'); setModalOpen(true); };
  const openSignup = () => { setModalTab('signup'); setModalOpen(true); };

  return (
    <>
      <nav className="navbar" id="main-navbar">
        <div className="navbar-inner container">
          <Link to="/" className="navbar-brand">
            <span className="brand-icon">🔒</span>
            <span className="brand-text">TLS Inspector</span>
          </Link>

          <div className="navbar-links">
            <Link to="/" className={`nav-link ${isActive('/') ? 'active' : ''}`}>Home</Link>
            <Link to="/scan" className={`nav-link ${isActive('/scan') ? 'active' : ''}`}>Scan</Link>
            <Link to="/history" className={`nav-link ${isActive('/history') ? 'active' : ''}`}>History</Link>
            <Link to="/about" className={`nav-link ${isActive('/about') ? 'active' : ''}`}>About</Link>
          </div>

          <div className="navbar-auth">
            {user ? (
              <div className="navbar-user">
                <div className="user-avatar" title={user.email}>
                  {user.username.charAt(0).toUpperCase()}
                </div>
                <span className="user-name">{user.username}</span>
                <button
                  className="btn-logout"
                  onClick={logout}
                  id="logout-btn"
                  title="Sign out"
                >
                  Sign Out
                </button>
              </div>
            ) : (
              <div className="navbar-guest">
                <button className="nav-btn-ghost" onClick={openLogin} id="navbar-login-btn">
                  Sign In
                </button>
                <button className="nav-btn-primary" onClick={openSignup} id="navbar-signup-btn">
                  Get Started
                </button>
              </div>
            )}
          </div>
        </div>
      </nav>

      <AuthModal
        isOpen={modalOpen}
        onClose={() => setModalOpen(false)}
        defaultTab={modalTab}
      />
    </>
  );
}
