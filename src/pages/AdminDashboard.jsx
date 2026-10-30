import { useState, useEffect } from 'react';
import { Users, Server, ShieldAlert, Activity, CheckCircle, AlertCircle, RefreshCw, KeyRound, Shield, UserPlus, Copy, Check, Lock, UserCheck, X } from 'lucide-react';
import DashboardCard from '../components/DashboardCard';
import ApplicationCard from '../components/ApplicationCard';
import { applications } from '../data/mockData';
import { apiUrl } from '../config/api';

function formatLogTimestamp(isoStr) {
  if (!isoStr) return '—';
  try {
    const d = new Date(isoStr);
    return d.toLocaleString([], {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  } catch {
    return isoStr;
  }
}

export default function AdminDashboard({ user }) {
  // Overview metrics state from /api/admin/dashboard
  const [dashboardData, setDashboardData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Dedicated real-time audit logs state from /api/admin/audit-logs
  const [auditLogs, setAuditLogs] = useState([]);
  const [auditLoading, setAuditLoading] = useState(true);
  const [auditError, setAuditError] = useState(null);

  // Demo student account management state from /api/admin/students
  const [demoStudents, setDemoStudents] = useState([]);
  const [demoStats, setDemoStats] = useState({ total: 0, maxLimit: 5, remaining: 5 });
  const [studentsLoading, setStudentsLoading] = useState(true);
  const [studentsError, setStudentsError] = useState(null);

  // Student creation form state
  const [formName, setFormName] = useState('');
  const [formEmail, setFormEmail] = useState('');
  const [formStudentId, setFormStudentId] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [createError, setCreateError] = useState(null);
  const [createSuccess, setCreateSuccess] = useState(null);
  const [createdCredentials, setCreatedCredentials] = useState(null);
  const [copied, setCopied] = useState(false);

  const fetchDashboardMetrics = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(apiUrl('/api/admin/dashboard'), {
        method: 'GET',
        credentials: 'include'
      });
      if (!res.ok) {
        throw new Error(`Metrics API returned HTTP ${res.status}: ${res.statusText}`);
      }
      const data = await res.json();
      setDashboardData(data);
    } catch (err) {
      setError(err.message || 'Failed to load administrative console');
    } finally {
      setLoading(false);
    }
  };

  const fetchAuditLogs = async () => {
    setAuditLoading(true);
    setAuditError(null);
    try {
      const res = await fetch(apiUrl('/api/admin/audit-logs?limit=50&offset=0'), {
        method: 'GET',
        credentials: 'include'
      });
      if (!res.ok) {
        throw new Error(`Audit Logs API returned HTTP ${res.status}: ${res.statusText}`);
      }
      const data = await res.json();
      // Ensure we only set real array from backend; never fall back to mock data
      setAuditLogs(Array.isArray(data.auditLogs) ? data.auditLogs : []);
    } catch (err) {
      setAuditError(err.message || 'Failed to retrieve security audit records');
      setAuditLogs([]); // Honest error: do not display mock events on failure
    } finally {
      setAuditLoading(false);
    }
  };

  const fetchDemoStudents = async () => {
    setStudentsLoading(true);
    setStudentsError(null);
    try {
      const res = await fetch(apiUrl('/api/admin/students'), {
        method: 'GET',
        credentials: 'include'
      });
      if (!res.ok) {
        throw new Error(`Student API returned HTTP ${res.status}: ${res.statusText}`);
      }
      const data = await res.json();
      setDemoStudents(Array.isArray(data.students) ? data.students : []);
      setDemoStats({
        total: data.total || 0,
        maxLimit: data.maxLimit || 5,
        remaining: typeof data.remaining === 'number' ? data.remaining : 5
      });
    } catch (err) {
      setStudentsError(err.message || 'Failed to load demo student accounts');
      setDemoStudents([]);
    } finally {
      setStudentsLoading(false);
    }
  };

  const handleCreateStudent = async (e) => {
    e.preventDefault();
    setCreateError(null);
    setCreateSuccess(null);
    setCreatedCredentials(null);
    setCopied(false);

    if (!formName.trim() || !formEmail.trim()) {
      setCreateError('Name and Email are required.');
      return;
    }

    setSubmitting(true);
    try {
      const res = await fetch(apiUrl('/api/admin/students'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        credentials: 'include',
        body: JSON.stringify({
          name: formName.trim(),
          email: formEmail.trim(),
          studentId: formStudentId.trim() ? formStudentId.trim() : undefined
        })
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to create student account');
      }

      setCreatedCredentials(data.student);
      setCreateSuccess(`Demo Student account created successfully! Temporary credentials generated.`);
      setFormName('');
      setFormEmail('');
      setFormStudentId('');
      fetchDemoStudents();
      fetchDashboardMetrics();
    } catch (err) {
      setCreateError(err.message);
    } finally {
      setSubmitting(false);
    }
  };

  const handleCopyCredentials = () => {
    if (!createdCredentials) return;
    const credText = `Student Credentials:
Name: ${createdCredentials.name}
Student ID: ${createdCredentials.id}
Email: ${createdCredentials.email}
Role: ${createdCredentials.role}
Temporary Password: ${createdCredentials.temporaryPassword}

Note: Share this privately with the student. Change password upon first login.`;

    navigator.clipboard.writeText(credText).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 3000);
    }).catch(() => {
      // Fallback
      setCopied(true);
    });
  };

  const handleRefreshAll = () => {
    fetchDashboardMetrics();
    fetchAuditLogs();
    fetchDemoStudents();
  };

  useEffect(() => {
    fetchDashboardMetrics();
    fetchAuditLogs();
    fetchDemoStudents();
  }, []);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[50vh] space-y-4">
        <div className="w-8 h-8 border-2 border-cf-orange border-t-transparent rounded-full animate-spin"></div>
        <p className="text-sm text-slate-400">Loading live security audit records & metrics...</p>
      </div>
    );
  }

  if (error) {
    const isNetworkError = error.includes('Failed to fetch') || error.includes('NetworkError');
    return (
      <div className="glass-panel p-6 border-red-500/30 max-w-xl mx-auto my-12 text-center">
        <AlertCircle className="w-10 h-10 text-red-500 mx-auto mb-3" />
        <h3 className="text-lg font-bold text-white mb-2">Access Error</h3>
        <p className="text-sm text-slate-400 mb-4">{error}</p>

        {isNetworkError && (
          <div className="mb-5 p-3.5 bg-slate-900/80 rounded-lg border border-slate-700 text-xs text-slate-300 text-left space-y-2">
            <p className="font-semibold text-cf-orange flex items-center">
              Why is "Failed to fetch" showing on this page?
            </p>
            <p className="text-slate-300 leading-relaxed">
              This frontend is loaded over HTTPS (<span className="text-white font-mono">workers.dev</span>), while the API base URL is currently set to <code className="text-white font-mono">http://localhost:3001</code>. Modern web browsers strictly block requests from HTTPS sites to local HTTP addresses (<span className="text-amber-300 font-medium">Mixed Content Security Policy</span>).
            </p>
            <div className="pt-1 border-t border-slate-800 text-slate-400">
              💡 <strong className="text-slate-200">To view live SQLite audit records:</strong> Open your local portal at{' '}
              <a href="http://localhost:5173/admin" className="text-cf-orange underline hover:text-white font-mono font-medium" target="_blank" rel="noreferrer">
                http://localhost:5173/admin
              </a>{' '}
              (where your local backend on port 3001 is directly accessible).
            </div>
          </div>
        )}

        <div className="flex items-center justify-center space-x-3">
          <button onClick={handleRefreshAll} className="btn-primary inline-flex items-center text-sm">
            <RefreshCw className="w-4 h-4 mr-2" /> Retry Connection
          </button>
          <a href="/login" className="px-4 py-2 rounded text-sm font-medium bg-slate-800 text-slate-300 hover:text-white border border-slate-700 hover:border-cf-orange/50 transition-colors">
            Sign In
          </a>
        </div>
      </div>
    );
  }

  const metrics = dashboardData?.metrics || {
    totalUsers: 0,
    activeSessions: 0,
    activeApplications: 8,
    protectedEndpoints: 4
  };

  return (
    <div className="space-y-6 slide-up">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Admin Security Console</h1>
          <p className="text-xs text-slate-400 mt-1">Administrator: {dashboardData?.user?.name || user?.name} • ID: {dashboardData?.user?.id || user?.id}</p>
        </div>
        <button 
          onClick={handleRefreshAll} 
          className="text-xs font-medium px-3 py-1.5 rounded bg-slate-800 text-slate-300 hover:text-white border border-cf-border hover:border-cf-orange/50 flex items-center transition-colors"
        >
          <RefreshCw className="w-3 h-3 mr-1.5" /> Refresh Console
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <DashboardCard title="Registered Users" value={metrics.totalUsers} subtitle="Verified database accounts" icon={Users} colorClass="text-blue-400" />
        <DashboardCard title="Active Sessions" value={metrics.activeSessions} subtitle="Valid unexpired tokens" icon={KeyRound} colorClass="text-green-400" />
        <DashboardCard title="Active Applications" value={metrics.activeApplications} subtitle="Policy-gated campus apps" icon={Server} colorClass="text-purple-400" />
        <DashboardCard title="Protected APIs" value={metrics.protectedEndpoints} subtitle="Server-side RBAC enforced" icon={ShieldAlert} colorClass="text-cf-orange" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-6">
          {/* Manage Demo Student Accounts Panel */}
          <div className="glass-panel p-6">
            <div className="flex items-center justify-between mb-4 flex-wrap gap-2">
              <div>
                <div className="flex items-center space-x-2">
                  <h2 className="text-lg font-bold text-white flex items-center">
                    <UserPlus className="w-5 h-5 text-cf-orange mr-2" />
                    Manage Demo Student Accounts
                  </h2>
                  <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                    Admin Only
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-1">
                  Create up to 5 demo student accounts with secure, one-time temporary credentials. Public registration remains strictly disabled.
                </p>
              </div>

              <div className="flex items-center space-x-2">
                <span className={`text-xs font-semibold px-2.5 py-1 rounded-full border flex items-center ${
                  demoStats.total >= demoStats.maxLimit 
                    ? 'bg-amber-500/10 text-amber-400 border-amber-500/30' 
                    : 'bg-blue-500/10 text-blue-400 border-blue-500/30'
                }`}>
                  <Users className="w-3.5 h-3.5 mr-1.5" />
                  {demoStats.total} / {demoStats.maxLimit} Created ({demoStats.remaining} Remaining)
                </span>
              </div>
            </div>

            {/* Quota Progress Bar */}
            <div className="w-full bg-slate-800/80 rounded-full h-2 mb-6 border border-slate-700 overflow-hidden">
              <div 
                className={`h-full transition-all duration-500 ${
                  demoStats.total >= demoStats.maxLimit ? 'bg-amber-500' : 'bg-cf-orange'
                }`}
                style={{ width: `${Math.min(100, (demoStats.total / demoStats.maxLimit) * 100)}%` }}
              />
            </div>

            {/* One-Time Credentials Display Banner / Box */}
            {createdCredentials && (
              <div className="mb-6 p-4 rounded-lg bg-emerald-950/30 border border-emerald-500/40 text-emerald-300 space-y-3 slide-up">
                <div className="flex items-start justify-between">
                  <div className="flex items-center space-x-2">
                    <CheckCircle className="w-5 h-5 text-emerald-400 shrink-0" />
                    <h4 className="text-sm font-bold text-white">Student Account Created & Credentials Generated</h4>
                  </div>
                  <button 
                    onClick={() => setCreatedCredentials(null)}
                    className="text-slate-400 hover:text-white p-1 rounded hover:bg-slate-800 transition-colors"
                    title="Dismiss credential banner"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>

                <div className="p-3 bg-slate-900/90 rounded border border-slate-700/80 space-y-2 font-mono text-xs text-slate-200">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    <div>
                      <span className="text-slate-400">Student Name: </span>
                      <span className="text-white font-semibold">{createdCredentials.name}</span>
                    </div>
                    <div>
                      <span className="text-slate-400">Student ID: </span>
                      <span className="text-cf-orange font-semibold">{createdCredentials.id}</span>
                    </div>
                    <div>
                      <span className="text-slate-400">Login Email: </span>
                      <span className="text-white font-semibold">{createdCredentials.email}</span>
                    </div>
                    <div>
                      <span className="text-slate-400">Role: </span>
                      <span className="text-emerald-400 font-semibold">{createdCredentials.role}</span>
                    </div>
                  </div>
                  <div className="pt-2 border-t border-slate-800 flex items-center justify-between flex-wrap gap-2">
                    <div className="flex items-center space-x-2">
                      <Lock className="w-3.5 h-3.5 text-amber-400" />
                      <span className="text-slate-400">Temporary Password: </span>
                      <span className="bg-slate-800 px-2 py-0.5 rounded text-amber-300 font-bold tracking-wider select-all">
                        {createdCredentials.temporaryPassword}
                      </span>
                    </div>
                    <button
                      onClick={handleCopyCredentials}
                      className="px-2.5 py-1 rounded text-xs font-sans font-medium bg-cf-orange text-white hover:bg-orange-600 flex items-center transition-colors shadow-sm"
                    >
                      {copied ? (
                        <>
                          <Check className="w-3 h-3 mr-1" /> Copied!
                        </>
                      ) : (
                        <>
                          <Copy className="w-3 h-3 mr-1" /> Copy Credentials
                        </>
                      )}
                    </button>
                  </div>
                </div>

                <p className="text-[11px] text-amber-300/90 flex items-center">
                  <ShieldAlert className="w-3.5 h-3.5 mr-1 shrink-0 text-amber-400" />
                  <span>
                    <strong>Security Notice:</strong> This temporary password is only displayed once. It is securely hashed with bcrypt and never stored in plaintext. Provide these credentials securely to the student and advise them to change their password upon first login.
                  </span>
                </p>
              </div>
            )}

            {/* Error / Success Feedback */}
            {createError && (
              <div className="mb-4 p-3 bg-red-950/30 border border-red-500/40 rounded-lg text-xs text-red-300 flex items-center">
                <AlertCircle className="w-4 h-4 mr-2 text-red-400 shrink-0" />
                <span>{createError}</span>
              </div>
            )}
            {createSuccess && !createdCredentials && (
              <div className="mb-4 p-3 bg-emerald-950/30 border border-emerald-500/40 rounded-lg text-xs text-emerald-300 flex items-center">
                <CheckCircle className="w-4 h-4 mr-2 text-emerald-400 shrink-0" />
                <span>{createSuccess}</span>
              </div>
            )}

            {/* Account Creation Form */}
            {demoStats.remaining > 0 ? (
              <form onSubmit={handleCreateStudent} className="mb-6 p-4 bg-slate-900/60 rounded-lg border border-slate-800 space-y-4">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300 flex items-center">
                  <UserPlus className="w-3.5 h-3.5 mr-1.5 text-cf-orange" />
                  Provision New Demo Student ({demoStats.remaining} of 5 available)
                </h3>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div>
                    <label className="block text-[11px] font-medium text-slate-400 mb-1">
                      Full Name <span className="text-red-400">*</span>
                    </label>
                    <input
                      type="text"
                      value={formName}
                      onChange={(e) => setFormName(e.target.value)}
                      placeholder="e.g. Maya Lin"
                      required
                      disabled={submitting}
                      className="w-full bg-slate-800 border border-slate-700 rounded px-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cf-orange"
                    />
                  </div>
                  <div>
                    <label className="block text-[11px] font-medium text-slate-400 mb-1">
                      Student Email <span className="text-red-400">*</span>
                    </label>
                    <input
                      type="email"
                      value={formEmail}
                      onChange={(e) => setFormEmail(e.target.value)}
                      placeholder="e.g. maya.lin@campus.edu"
                      required
                      disabled={submitting}
                      className="w-full bg-slate-800 border border-slate-700 rounded px-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cf-orange"
                    />
                  </div>
                  <div>
                    <label className="block text-[11px] font-medium text-slate-400 mb-1">
                      Student ID <span className="text-slate-500">(Optional)</span>
                    </label>
                    <input
                      type="text"
                      value={formStudentId}
                      onChange={(e) => setFormStudentId(e.target.value)}
                      placeholder="e.g. STU-2026-901"
                      disabled={submitting}
                      className="w-full bg-slate-800 border border-slate-700 rounded px-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cf-orange"
                    />
                  </div>
                </div>

                <div className="flex items-center justify-between pt-1">
                  <span className="text-[11px] text-slate-500">
                    Role is automatically locked to <strong className="text-slate-300">Student</strong> on the server.
                  </span>
                  <button
                    type="submit"
                    disabled={submitting || demoStats.remaining <= 0}
                    className="btn-primary text-xs px-4 py-1.5 inline-flex items-center disabled:opacity-50"
                  >
                    {submitting ? (
                      <>
                        <RefreshCw className="w-3 h-3 mr-1.5 animate-spin" /> Creating...
                      </>
                    ) : (
                      <>
                        <UserPlus className="w-3.5 h-3.5 mr-1.5" /> Create Student Account
                      </>
                    )}
                  </button>
                </div>
              </form>
            ) : (
              <div className="mb-6 p-3.5 bg-slate-900/60 rounded-lg border border-amber-500/30 text-xs text-amber-300 flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <ShieldAlert className="w-4 h-4 text-amber-400 shrink-0" />
                  <span>Demo student account quota reached (5 of 5 accounts created). Public registration remains disabled.</span>
                </div>
                <span className="px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 text-[10px] font-mono font-bold">
                  Quota Maxed
                </span>
              </div>
            )}

            {/* List of Created Demo Student Accounts */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300 flex items-center">
                  <UserCheck className="w-3.5 h-3.5 mr-1.5 text-blue-400" />
                  Provisioned Demo Accounts ({demoStudents.length})
                </h3>
                <button
                  onClick={fetchDemoStudents}
                  disabled={studentsLoading}
                  className="text-slate-400 hover:text-white text-xs flex items-center p-1 rounded hover:bg-slate-800 disabled:opacity-50"
                  title="Refresh student list"
                >
                  <RefreshCw className={`w-3 h-3 mr-1 ${studentsLoading ? 'animate-spin' : ''}`} />
                  Refresh
                </button>
              </div>

              {studentsLoading ? (
                <div className="py-6 text-center text-xs text-slate-400">
                  <div className="w-5 h-5 border-2 border-cf-orange border-t-transparent rounded-full animate-spin mx-auto mb-2"></div>
                  Loading student accounts...
                </div>
              ) : demoStudents.length === 0 ? (
                <div className="p-4 bg-slate-900/40 rounded border border-slate-800 text-center text-xs text-slate-500">
                  No demo student accounts have been created yet. Use the form above to provision your demo students.
                </div>
              ) : (
                <div className="overflow-x-auto rounded border border-slate-800">
                  <table className="w-full text-xs text-left">
                    <thead className="text-[11px] text-slate-400 uppercase bg-slate-800/60">
                      <tr>
                        <th className="px-3 py-2">Student ID</th>
                        <th className="px-3 py-2">Name</th>
                        <th className="px-3 py-2">Email</th>
                        <th className="px-3 py-2">Role</th>
                        <th className="px-3 py-2">Created</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800 bg-slate-900/40">
                      {demoStudents.map((stu) => (
                        <tr key={stu.id} className="hover:bg-slate-800/40 transition-colors">
                          <td className="px-3 py-2 font-mono font-medium text-cf-orange">{stu.id}</td>
                          <td className="px-3 py-2 text-white font-medium">{stu.name}</td>
                          <td className="px-3 py-2 text-slate-300 font-mono">{stu.email}</td>
                          <td className="px-3 py-2">
                            <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-blue-500/10 text-blue-400 border border-blue-500/30">
                              {stu.role}
                            </span>
                          </td>
                          <td className="px-3 py-2 text-slate-400 font-mono">
                            {stu.createdAt ? new Date(stu.createdAt).toLocaleDateString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : '—'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>

          <div className="glass-panel p-6">
            <div className="flex items-center justify-between mb-4 flex-wrap gap-2">
              <div>
                <div className="flex items-center space-x-2">
                  <h2 className="text-lg font-bold text-white">Recent Security Events</h2>
                  <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                    GET /api/admin/audit-logs
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-0.5">
                  Streamed directly from SQLite <code className="font-mono text-slate-300">audit_logs</code> table (Real Database Records)
                </p>
              </div>
              <div className="flex items-center space-x-2">
                <button
                  onClick={fetchAuditLogs}
                  disabled={auditLoading}
                  className="text-xs font-medium px-2.5 py-1 rounded bg-slate-800 text-slate-300 hover:text-white border border-cf-border hover:border-cf-orange/50 flex items-center transition-colors disabled:opacity-50"
                  aria-label="Refresh security audit logs"
                >
                  <RefreshCw className={`w-3 h-3 mr-1.5 ${auditLoading ? 'animate-spin' : ''}`} />
                  Refresh
                </button>
                <span className="text-xs font-medium px-2.5 py-1 rounded-full bg-cf-orange/10 text-cf-orange border border-cf-orange/20 flex items-center">
                  <span className="w-1.5 h-1.5 rounded-full bg-cf-orange animate-pulse mr-1.5"></span> Live Telemetry
                </span>
              </div>
            </div>

            {auditError ? (
              <div className="p-6 bg-red-950/20 border border-red-500/30 rounded-lg text-center my-4">
                <AlertCircle className="w-8 h-8 text-red-400 mx-auto mb-2" />
                <h4 className="text-sm font-semibold text-white mb-1">Failed to Load Live Audit Logs</h4>
                <p className="text-xs text-red-300 mb-3 font-mono">{auditError}</p>
                <button
                  onClick={fetchAuditLogs}
                  className="btn-primary inline-flex items-center text-xs"
                >
                  <RefreshCw className="w-3.5 h-3.5 mr-1.5" /> Retry Audit Query
                </button>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm text-left">
                  <thead className="text-xs text-slate-400 uppercase bg-slate-800/50">
                    <tr>
                      <th scope="col" className="px-3 py-3 rounded-tl-lg">Decision</th>
                      <th scope="col" className="px-3 py-3">Event Type</th>
                      <th scope="col" className="px-3 py-3">HTTP / Endpoint</th>
                      <th scope="col" className="px-3 py-3">User Identity</th>
                      <th scope="col" className="px-3 py-3">Reason / Details</th>
                      <th scope="col" className="px-3 py-3 rounded-tr-lg">Timestamp</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-cf-border/40">
                    {auditLoading ? (
                      <tr>
                        <td colSpan="6" className="px-4 py-8 text-center">
                          <div className="flex flex-col items-center justify-center space-y-2">
                            <div className="w-6 h-6 border-2 border-cf-orange border-t-transparent rounded-full animate-spin"></div>
                            <p className="text-xs text-slate-400">Querying real-time SQLite audit records...</p>
                          </div>
                        </td>
                      </tr>
                    ) : auditLogs.length === 0 ? (
                      <tr>
                        <td colSpan="6" className="px-4 py-8 text-center text-slate-500">
                          <ShieldAlert className="w-6 h-6 mx-auto mb-2 text-slate-600" />
                          <p className="text-sm text-slate-400">No security events recorded in audit log yet.</p>
                          <p className="text-xs text-slate-500 mt-1">Actions on protected endpoints will stream here in real time.</p>
                        </td>
                      </tr>
                    ) : (
                      auditLogs.map((evt) => (
                        <tr key={evt.id || `${evt.timestamp}-${evt.endpoint}`} className="hover:bg-slate-800/30 transition-colors">
                          <td className="px-3 py-3 whitespace-nowrap">
                            {evt.outcome === 'ALLOW' ? (
                              <span
                                className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
                                role="status"
                                aria-label="Outcome: ALLOW (Permitted)"
                              >
                                <CheckCircle className="w-3.5 h-3.5 mr-1 text-emerald-400 shrink-0" aria-hidden="true" />
                                <span>ALLOW</span>
                                <span className="sr-only"> - Permitted</span>
                              </span>
                            ) : (
                              <span
                                className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/30"
                                role="status"
                                aria-label="Outcome: DENY (Blocked)"
                              >
                                <ShieldAlert className="w-3.5 h-3.5 mr-1 text-rose-400 shrink-0" aria-hidden="true" />
                                <span>DENY</span>
                                <span className="sr-only"> - Denied</span>
                              </span>
                            )}
                          </td>
                          <td className="px-3 py-3 whitespace-nowrap">
                            <span className="font-semibold text-white text-xs block">{evt.event_type}</span>
                          </td>
                          <td className="px-3 py-3">
                            <div className="flex items-center space-x-1.5 font-mono text-xs">
                              <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-300 border border-slate-700 shrink-0">
                                {evt.method || 'GET'}
                              </span>
                              <span className="text-slate-200 truncate max-w-[170px]" title={evt.endpoint}>
                                {evt.endpoint || '—'}
                              </span>
                            </div>
                          </td>
                          <td className="px-3 py-3 text-xs font-mono">
                            <span className="text-slate-300 font-medium truncate max-w-[130px] block" title={evt.user_id || 'Anonymous'}>
                              {evt.user_id || <span className="text-slate-500 italic">Anonymous</span>}
                            </span>
                          </td>
                          <td className="px-3 py-3 text-xs">
                            <span className="text-slate-300 block min-w-[260px] break-words whitespace-normal leading-relaxed" title={evt.reason || 'None'}>
                              {evt.reason || <span className="text-slate-500 italic">None</span>}
                            </span>
                          </td>
                          <td className="px-3 py-3 text-slate-400 text-xs whitespace-nowrap font-mono">
                            <time dateTime={evt.timestamp} title={evt.timestamp}>
                              {formatLogTimestamp(evt.timestamp)}
                            </time>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>

        <div className="space-y-6">
          <div className="glass-panel p-6">
            <h2 className="text-lg font-bold text-white mb-4">Campus Applications</h2>
            <div className="space-y-4">
              {applications.map(app => (
                <ApplicationCard key={app.id} app={app} userRole={user.role} />
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
