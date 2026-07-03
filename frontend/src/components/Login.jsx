import { useState } from 'react';
import { API_BASE } from '../api.js';

// eslint-disable-next-line react/prop-types
export default function Login({ onLoginSuccess }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [guestLoading, setGuestLoading] = useState(false);

  const handleGuestLogin = async () => {
    setGuestLoading(true);
    setError('');
    try {
      const res = await fetch(`${API_BASE}/api/guest-login`, { method: 'POST' });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Guest login failed');
      onLoginSuccess(data.user);
    } catch (err) {
      setError(err.message);
    } finally {
      setGuestLoading(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const response = await fetch(`${API_BASE}/api/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Login failed');
      }

      // Pass the full user object (which already contains .token)
      onLoginSuccess(data.user);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="w-full max-w-md bg-white p-10 border-t-8 rounded-lg shadow-2xl mx-auto" style={{ borderColor: '#A00000' }}>
      {/* IIITA CAS Header */}
      <div className="text-center mb-8">
        <div className="flex items-center justify-center gap-3 mb-3">
          <div className="w-10 h-10 rounded-full flex items-center justify-center text-white font-bold text-lg" style={{ backgroundColor: '#A00000' }}>
            II
          </div>
          <div className="text-left">
            <div className="font-extrabold text-xl leading-tight" style={{ color: '#A00000' }}>IIITA-Crypt</div>
            <div className="text-xs text-gray-400 font-medium tracking-wider">IIIT ALLAHABAD</div>
          </div>
        </div>
        <div className="h-px bg-gray-100 my-4" />
        <p className="text-gray-500 text-sm font-medium tracking-wide">Central Authentication Service (CAS)</p>
        {/* <p className="text-gray-400 text-xs mt-1">Zero-Trust Secure Portal — CP-ABE Protected</p> */}
      </div>

      <form className="flex flex-col gap-4" onSubmit={handleSubmit}>
        {error && (
          <div className="text-sm font-semibold text-center border rounded p-3" style={{ color: '#A00000', backgroundColor: '#fff5f5', borderColor: '#fecaca' }}>
            ⚠️ {error}
          </div>
        )}

        <div className="flex flex-col gap-1">
          <label className="text-xs font-semibold text-gray-500 uppercase tracking-wider">Institutional Email</label>
          <input
            id="login-email"
            type="email"
            className="w-full p-3 border border-gray-200 rounded-lg bg-gray-50 focus:outline-none focus:ring-2 focus:bg-white transition-all text-sm"
            style={{ '--tw-ring-color': '#23495C', 'border-color': 'gray' }}
            placeholder=""
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
        </div>

        <div className="flex flex-col gap-1">
          <label className="text-xs font-semibold text-gray-500 uppercase tracking-wider">Password</label>
          <input
            id="login-password"
            type="password"
            className="w-full p-3 border border-gray-200 rounded-lg bg-gray-50 focus:outline-none focus:ring-2 focus:bg-white transition-all text-sm"
            style={{ '--tw-ring-color': '#23495C', 'border-color': 'gray' }}
            placeholder=""
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </div>

        <button
          id="login-submit"
          type="submit"
          className="mt-2 w-full text-white font-bold py-3 px-6 rounded-lg transition-all uppercase tracking-widest text-sm disabled:opacity-60 disabled:cursor-not-allowed hover:opacity-90 active:scale-95"
          style={{ backgroundColor: '#A00000' }}
          disabled={loading}
        >
          {loading ? (
            <span className="flex items-center justify-center gap-2">
              <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24" fill="none">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              Authenticating...
            </span>
          ) : '🔐 Secure Login'}
        </button>
      </form>

      <div className="mt-6 pt-4 border-t border-gray-100 text-center">
        <p className="text-xs text-gray-400">
          Restricted to <span className="font-semibold text-gray-500">@iiita.ac.in</span> addresses only.
        </p>
        <p className="text-xs text-gray-400 mt-1">
          Your identity attributes are cryptographically signed into your session.
        </p>
      </div>

      {/* Guest Login */}
      <div className="mt-4 pt-4 border-t border-dashed border-gray-200 text-center">
        <p className="text-xs text-gray-400 mb-2">No credentials? Explore with limited access.</p>
        <button
          id="guest-login-btn"
          type="button"
          onClick={handleGuestLogin}
          disabled={guestLoading || loading}
          className="w-full py-2.5 px-4 rounded-lg border border-gray-300 text-sm font-medium text-gray-500 hover:bg-gray-50 hover:border-gray-400 hover:text-gray-700 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {guestLoading ? '⏳ Entering...' : '👤 Continue as Guest'}
        </button>
      </div>
    </div>
  );
}