/**
 * AuthModal — Login / Sign Up modal with glassmorphism design
 */
import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import './AuthModal.css';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  defaultTab?: 'login' | 'signup';
}

export default function AuthModal({ isOpen, onClose, defaultTab = 'login' }: Props) {
  const [tab, setTab] = useState<'login' | 'signup'>(defaultTab);
  const [isVisible, setIsVisible] = useState(false);

  // Login fields
  const [loginEmail, setLoginEmail] = useState('');
  const [loginPassword, setLoginPassword] = useState('');

  // Signup fields
  const [signupUsername, setSignupUsername] = useState('');
  const [signupEmail, setSignupEmail] = useState('');
  const [signupPassword, setSignupPassword] = useState('');
  const [signupConfirm, setSignupConfirm] = useState('');

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [showLoginPw, setShowLoginPw] = useState(false);
  const [showSignupPw, setShowSignupPw] = useState(false);

  const { login, register } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (isOpen) {
      setIsVisible(true);
      setError('');
    } else {
      const t = setTimeout(() => setIsVisible(false), 300);
      return () => clearTimeout(t);
    }
  }, [isOpen]);

  useEffect(() => {
    setTab(defaultTab);
    setError('');
  }, [defaultTab, isOpen]);

  if (!isVisible) return null;

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (!loginEmail || !loginPassword) { setError('Please fill in all fields'); return; }
    setLoading(true);
    try {
      await login(loginEmail, loginPassword);
      onClose();
      navigate('/scan');
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  const handleSignup = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (!signupUsername || !signupEmail || !signupPassword || !signupConfirm) {
      setError('Please fill in all fields'); return;
    }
    if (signupPassword !== signupConfirm) {
      setError('Passwords do not match'); return;
    }
    if (signupPassword.length < 6) {
      setError('Password must be at least 6 characters'); return;
    }
    setLoading(true);
    try {
      await register(signupUsername, signupEmail, signupPassword);
      onClose();
      navigate('/scan');
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className={`auth-overlay ${isOpen ? 'open' : 'closing'}`} onClick={onClose}>
      <div className="auth-modal" onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div className="auth-modal-header">
          <div className="auth-logo">
            <span className="auth-logo-icon">🔒</span>
            <span className="auth-logo-text">TLS Inspector</span>
          </div>
          <button className="auth-close-btn" onClick={onClose} id="auth-close-btn" aria-label="Close">✕</button>
        </div>

        {/* Tabs */}
        <div className="auth-tabs">
          <button
            className={`auth-tab ${tab === 'login' ? 'active' : ''}`}
            onClick={() => { setTab('login'); setError(''); }}
            id="auth-tab-login"
          >
            Sign In
          </button>
          <button
            className={`auth-tab ${tab === 'signup' ? 'active' : ''}`}
            onClick={() => { setTab('signup'); setError(''); }}
            id="auth-tab-signup"
          >
            Create Account
          </button>
          <div className={`auth-tab-indicator ${tab === 'signup' ? 'right' : ''}`} />
        </div>

        {/* Error banner */}
        {error && (
          <div className="auth-error" role="alert">
            <span>⚠️</span> {error}
          </div>
        )}

        {/* Login Form */}
        {tab === 'login' && (
          <form className="auth-form" onSubmit={handleLogin} id="login-form">
            <div className="auth-welcome">
              <h2>Welcome back</h2>
              <p>Sign in to access your security dashboard</p>
            </div>

            <div className="auth-field">
              <label htmlFor="login-email">Email Address</label>
              <div className="auth-input-wrapper">
                <span className="auth-input-icon">✉️</span>
                <input
                  id="login-email"
                  type="email"
                  placeholder="you@example.com"
                  value={loginEmail}
                  onChange={(e) => setLoginEmail(e.target.value)}
                  autoComplete="email"
                  required
                />
              </div>
            </div>

            <div className="auth-field">
              <label htmlFor="login-password">Password</label>
              <div className="auth-input-wrapper">
                <span className="auth-input-icon">🔑</span>
                <input
                  id="login-password"
                  type={showLoginPw ? 'text' : 'password'}
                  placeholder="Your password"
                  value={loginPassword}
                  onChange={(e) => setLoginPassword(e.target.value)}
                  autoComplete="current-password"
                  required
                />
                <button
                  type="button"
                  className="auth-pw-toggle"
                  onClick={() => setShowLoginPw(!showLoginPw)}
                  tabIndex={-1}
                >
                  {showLoginPw ? '🙈' : '👁️'}
                </button>
              </div>
            </div>

            <button
              type="submit"
              className="auth-submit-btn"
              id="login-submit-btn"
              disabled={loading}
            >
              {loading ? <span className="auth-spinner" /> : 'Sign In →'}
            </button>

            <p className="auth-switch">
              Don't have an account?{' '}
              <button type="button" onClick={() => { setTab('signup'); setError(''); }}>
                Create one
              </button>
            </p>
          </form>
        )}

        {/* Signup Form */}
        {tab === 'signup' && (
          <form className="auth-form" onSubmit={handleSignup} id="signup-form">
            <div className="auth-welcome">
              <h2>Create your account</h2>
              <p>Start assessing TLS security in seconds</p>
            </div>

            <div className="auth-field">
              <label htmlFor="signup-username">Username</label>
              <div className="auth-input-wrapper">
                <span className="auth-input-icon">👤</span>
                <input
                  id="signup-username"
                  type="text"
                  placeholder="Choose a username"
                  value={signupUsername}
                  onChange={(e) => setSignupUsername(e.target.value)}
                  autoComplete="username"
                  required
                />
              </div>
            </div>

            <div className="auth-field">
              <label htmlFor="signup-email">Email Address</label>
              <div className="auth-input-wrapper">
                <span className="auth-input-icon">✉️</span>
                <input
                  id="signup-email"
                  type="email"
                  placeholder="you@example.com"
                  value={signupEmail}
                  onChange={(e) => setSignupEmail(e.target.value)}
                  autoComplete="email"
                  required
                />
              </div>
            </div>

            <div className="auth-field">
              <label htmlFor="signup-password">Password</label>
              <div className="auth-input-wrapper">
                <span className="auth-input-icon">🔑</span>
                <input
                  id="signup-password"
                  type={showSignupPw ? 'text' : 'password'}
                  placeholder="Min. 6 characters"
                  value={signupPassword}
                  onChange={(e) => setSignupPassword(e.target.value)}
                  autoComplete="new-password"
                  required
                />
                <button
                  type="button"
                  className="auth-pw-toggle"
                  onClick={() => setShowSignupPw(!showSignupPw)}
                  tabIndex={-1}
                >
                  {showSignupPw ? '🙈' : '👁️'}
                </button>
              </div>
            </div>

            <div className="auth-field">
              <label htmlFor="signup-confirm">Confirm Password</label>
              <div className="auth-input-wrapper">
                <span className="auth-input-icon">🔐</span>
                <input
                  id="signup-confirm"
                  type={showSignupPw ? 'text' : 'password'}
                  placeholder="Repeat password"
                  value={signupConfirm}
                  onChange={(e) => setSignupConfirm(e.target.value)}
                  autoComplete="new-password"
                  required
                />
              </div>
            </div>

            <button
              type="submit"
              className="auth-submit-btn"
              id="signup-submit-btn"
              disabled={loading}
            >
              {loading ? <span className="auth-spinner" /> : 'Create Account →'}
            </button>

            <p className="auth-switch">
              Already have an account?{' '}
              <button type="button" onClick={() => { setTab('login'); setError(''); }}>
                Sign in
              </button>
            </p>
          </form>
        )}
      </div>
    </div>
  );
}
