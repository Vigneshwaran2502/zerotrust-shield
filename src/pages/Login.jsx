import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Lock, Mail, User, ChevronRight, AlertCircle } from 'lucide-react';
import { apiUrl } from '../config/api';

export default function Login({ onLogin }) {
  const navigate = useNavigate();
  const [isLogin, setIsLogin] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const [formData, setFormData] = useState({
    name: '',
    email: '',
    password: ''
  });

  const handleInputChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const demoCredentials = {
    student: { email: 'student@zerotrustcampus.edu', password: 'StudentPass123!' },
    faculty: { email: 'faculty@zerotrustcampus.edu', password: 'FacultyPass123!' },
    admin: { email: 'admin@zerotrustcampus.edu', password: 'AdminPass123!' }
  };

  const handleDemoLogin = async (roleKey) => {
    setLoading(true);
    setError(null);
    try {
      const creds = demoCredentials[roleKey];
      if (!creds) {
        throw new Error('Invalid demo role requested');
      }

      const response = await fetch(apiUrl('/api/login'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(creds)
      });

      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(data.error || `Authentication failed (HTTP ${response.status})`);
      }

      onLogin(data);
      if (data.role === 'Student') navigate('/student');
      else if (data.role === 'Faculty') navigate('/faculty');
      else if (data.role === 'Administrator') navigate('/admin');
      else navigate('/');
    } catch (err) {
      setError(err.message || 'Authentication failed');
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    const url = isLogin ? apiUrl('/api/login') : apiUrl('/api/register');
    const payload = isLogin 
      ? { email: formData.email, password: formData.password }
      : { name: formData.name, email: formData.email, password: formData.password };

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(payload)
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Something went wrong');
      }

      // Success
      onLogin(data);
      if (data.role === 'Student') navigate('/student');
      else if (data.role === 'Faculty') navigate('/faculty');
      else if (data.role === 'Administrator') navigate('/admin');
      else navigate('/'); // Fallback
      
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-cf-dark flex flex-col justify-center py-12 sm:px-6 lg:px-8 relative overflow-hidden">
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-full max-w-4xl h-64 bg-cf-orange/20 blur-[100px] rounded-full pointer-events-none"></div>
      
      <div className="sm:mx-auto sm:w-full sm:max-w-md relative z-10 slide-up">
        <div className="flex justify-center">
          <Shield className="w-12 h-12 text-cf-orange" />
        </div>
        <h2 className="mt-6 text-center text-3xl font-extrabold text-white">
          {isLogin ? 'Sign in to ZeroTrust Campus' : 'Create an Account'}
        </h2>
        <p className="mt-2 text-center text-sm text-slate-400">
          Your identity and access permissions are verified before accessing protected campus applications.
        </p>
      </div>

      <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md relative z-10 fade-in" style={{ animationDelay: '0.1s' }}>
        <div className="glass-panel py-8 px-4 sm:px-10">
          
          {error && (
            <div className="mb-4 bg-red-500/10 border border-red-500/20 rounded-md p-3 flex items-center text-red-400 text-sm">
              <AlertCircle className="w-4 h-4 mr-2" />
              {error}
            </div>
          )}

          <form className="space-y-6" onSubmit={handleSubmit}>
            {!isLogin && (
              <div>
                <label className="block text-sm font-medium text-slate-300">
                  Full Name
                </label>
                <div className="mt-1 relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                    <User className="h-5 w-5 text-slate-500" />
                  </div>
                  <input
                    type="text"
                    name="name"
                    required
                    value={formData.name}
                    onChange={handleInputChange}
                    className="appearance-none block w-full pl-10 px-3 py-2 border border-cf-border bg-slate-900 rounded-md shadow-sm placeholder-slate-500 text-white focus:outline-none focus:ring-cf-orange focus:border-cf-orange sm:text-sm"
                    placeholder="John Doe"
                  />
                </div>
              </div>
            )}

            <div>
              <label className="block text-sm font-medium text-slate-300">
                Email address
              </label>
              <div className="mt-1 relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Mail className="h-5 w-5 text-slate-500" />
                </div>
                <input
                  type="email"
                  name="email"
                  required
                  value={formData.email}
                  onChange={handleInputChange}
                  className="appearance-none block w-full pl-10 px-3 py-2 border border-cf-border bg-slate-900 rounded-md shadow-sm placeholder-slate-500 text-white focus:outline-none focus:ring-cf-orange focus:border-cf-orange sm:text-sm"
                  placeholder="name@zerotrustcampus.edu"
                />
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-300">
                Password
              </label>
              <div className="mt-1 relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Lock className="h-5 w-5 text-slate-500" />
                </div>
                <input
                  type="password"
                  name="password"
                  required
                  minLength={8}
                  value={formData.password}
                  onChange={handleInputChange}
                  className="appearance-none block w-full pl-10 px-3 py-2 border border-cf-border bg-slate-900 rounded-md shadow-sm placeholder-slate-500 text-white focus:outline-none focus:ring-cf-orange focus:border-cf-orange sm:text-sm"
                  placeholder="••••••••"
                />
              </div>
            </div>

            {!isLogin && (
              <div className="bg-slate-800/60 border border-cf-border/60 rounded-md p-3 text-xs text-slate-400">
                <span className="font-semibold text-slate-300">Role Policy:</span> New accounts are registered with the standard <span className="text-cf-orange font-medium">Student</span> role. Faculty and Administrator access are granted by campus security policies.
              </div>
            )}

            <div>
              <button
                type="submit"
                disabled={loading}
                className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-cf-orange hover:bg-cf-accent focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-cf-orange disabled:opacity-50"
              >
                {loading ? 'Processing...' : (isLogin ? 'Sign In' : 'Create Account')}
              </button>
            </div>
          </form>

          <div className="mt-6 text-center">
            <button
              type="button"
              onClick={() => {
                setIsLogin(!isLogin);
                setError(null);
              }}
              className="text-sm font-medium text-cf-orange hover:text-cf-accent"
            >
              {isLogin ? "Don't have an account? Sign Up" : 'Already have an account? Sign In'}
            </button>
          </div>

          <div className="mt-8">
            <div className="relative">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-cf-border" />
              </div>
              <div className="relative flex justify-center text-sm">
                <span className="px-2 bg-cf-card text-slate-400">
                  Or use Demo Login
                </span>
              </div>
            </div>

            <div className="mt-6 space-y-3">
              <button
                onClick={() => handleDemoLogin('student')}
                className="w-full flex items-center justify-between px-4 py-3 border border-cf-border rounded-md shadow-sm bg-slate-800 text-sm font-medium text-white hover:bg-slate-700 transition-colors"
                disabled={loading}
              >
                <div className="flex items-center">
                  <span className="w-2 h-2 rounded-full bg-green-400 mr-3"></span>
                  Continue as Student
                </div>
                <ChevronRight className="w-4 h-4 text-slate-400" />
              </button>
              <button
                onClick={() => handleDemoLogin('faculty')}
                className="w-full flex items-center justify-between px-4 py-3 border border-cf-border rounded-md shadow-sm bg-slate-800 text-sm font-medium text-white hover:bg-slate-700 transition-colors"
                disabled={loading}
              >
                <div className="flex items-center">
                  <span className="w-2 h-2 rounded-full bg-blue-400 mr-3"></span>
                  Continue as Faculty
                </div>
                <ChevronRight className="w-4 h-4 text-slate-400" />
              </button>
              <button
                onClick={() => handleDemoLogin('admin')}
                className="w-full flex items-center justify-between px-4 py-3 border border-cf-border rounded-md shadow-sm bg-slate-800 text-sm font-medium text-white hover:bg-slate-700 transition-colors"
                disabled={loading}
              >
                <div className="flex items-center">
                  <span className="w-2 h-2 rounded-full bg-purple-400 mr-3"></span>
                  Continue as Admin
                </div>
                <ChevronRight className="w-4 h-4 text-slate-400" />
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
