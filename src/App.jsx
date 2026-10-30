import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { useState, useEffect } from 'react';

// Layouts
import Layout from './components/Layout';

// Pages
import Landing from './pages/Landing';
import Login from './pages/Login';
import StudentDashboard from './pages/StudentDashboard';
import FacultyDashboard from './pages/FacultyDashboard';
import AdminDashboard from './pages/AdminDashboard';
import Profile from './pages/Profile';
import Security from './pages/Security';
import AccessDenied from './pages/AccessDenied';
import { apiUrl } from './config/api';

function App() {
  const [user, setUser] = useState(null);
  const [initializing, setInitializing] = useState(true);

  // Recover active session on page mount
  useEffect(() => {
    async function checkSession() {
      try {
        const response = await fetch(apiUrl('/api/me'), {
          method: 'GET',
          credentials: 'include'
        });
        if (response.ok) {
          const userData = await response.json();
          setUser(userData);
        }
      } catch (err) {
        // Backend not reachable or unauthenticated
      } finally {
        setInitializing(false);
      }
    }

    checkSession();
  }, []);

  const login = (userData) => {
    setUser(userData);
  };

  const logout = async () => {
    try {
      await fetch(apiUrl('/api/logout'), {
        method: 'POST',
        credentials: 'include'
      });
    } catch (err) {
      console.error('Logout error:', err);
    } finally {
      setUser(null);
    }
  };

  if (initializing) {
    return (
      <div className="min-h-screen bg-cf-dark flex items-center justify-center text-slate-400">
        <div className="flex flex-col items-center space-y-3">
          <div className="w-8 h-8 border-2 border-cf-orange border-t-transparent rounded-full animate-spin"></div>
          <span className="text-sm font-medium">Verifying Zero Trust session...</span>
        </div>
      </div>
    );
  }

  return (
    <Router>
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route
          path="/login"
          element={
            user ? (
              <Navigate
                to={user.role === 'Administrator' ? '/admin' : user.role === 'Faculty' ? '/faculty' : '/student'}
                replace
              />
            ) : (
              <Login onLogin={login} />
            )
          }
        />
        
        {/* Protected Routes */}
        <Route element={<Layout user={user} onLogout={logout} />}>
          <Route path="/student" element={user?.role === 'Student' ? <StudentDashboard user={user} /> : <Navigate to="/access-denied" state={{ reqApp: 'Student Portal', role: user?.role }} />} />
          <Route path="/faculty" element={user?.role === 'Faculty' ? <FacultyDashboard user={user} /> : <Navigate to="/access-denied" state={{ reqApp: 'Faculty Portal', role: user?.role }} />} />
          <Route path="/admin" element={user?.role === 'Administrator' ? <AdminDashboard user={user} /> : <Navigate to="/access-denied" state={{ reqApp: 'Admin Portal', role: user?.role }} />} />
          <Route path="/profile" element={user ? <Profile user={user} /> : <Navigate to="/login" />} />
          <Route path="/security" element={user ? <Security user={user} /> : <Navigate to="/login" />} />
          <Route path="/access-denied" element={<AccessDenied user={user} />} />
        </Route>
      </Routes>
    </Router>
  );
}

export default App;
