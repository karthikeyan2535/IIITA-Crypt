import { useState } from 'react';
import Login from './components/Login';
import Chat from './components/Chat';

function App() {
  const [user, setUser] = useState(null);

  // Login.jsx calls onLoginSuccess(data.user, data.token)
  // data.user already contains { email, role, attributes, token }
  const handleLogin = (userData) => {
    setUser(userData);
  };

  const handleLogout = () => {
    setUser(null);
  };

  const handleTokenRefresh = (newToken) => {
    setUser((prev) => ({ ...prev, token: newToken }));
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4 bg-penrose">
      {!user ? (
        <Login onLoginSuccess={handleLogin} />
      ) : (
        <Chat user={user} onLogout={handleLogout} onTokenRefresh={handleTokenRefresh} />
      )}
    </div>
  );
}

export default App;
