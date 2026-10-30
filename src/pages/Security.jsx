import { useState, useEffect } from 'react';
import { ShieldCheck, Server, User, Activity, CheckCircle, ShieldAlert, RefreshCw, AlertCircle } from 'lucide-react';
import { apiUrl } from '../config/api';

export default function Security({ user }) {
  const isAdmin = user?.role === 'Administrator';
  const [auditLogs, setAuditLogs] = useState([]);
  const [loading, setLoading] = useState(isAdmin);
  const [error, setError] = useState(null);

  const fetchAuditLogs = async () => {
    if (!isAdmin) return;
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(apiUrl('/api/admin/audit-logs?limit=10&offset=0'), {
        method: 'GET',
        credentials: 'include'
      });
      if (!res.ok) {
        throw new Error(`Audit log API returned HTTP ${res.status}: ${res.statusText}`);
      }
      const data = await res.json();
      setAuditLogs(Array.isArray(data.auditLogs) ? data.auditLogs : []);
    } catch (err) {
      setError(err.message || 'Failed to retrieve security audit records');
      setAuditLogs([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isAdmin) {
      fetchAuditLogs();
    }
  }, [isAdmin]);

  return (
    <div className="space-y-6 slide-up">
      <h1 className="text-2xl font-bold text-white">Security & Access Status</h1>
      <p className="text-slate-400 mb-6 max-w-3xl">
        This page demonstrates the Zero Trust principles applied to your current session. Every access request is evaluated against your identity, role, and device context.
      </p>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="glass-panel p-6">
          <h2 className="text-lg font-bold text-white mb-6 flex items-center">
            <ShieldCheck className="w-5 h-5 mr-2 text-cf-orange" />
            Current Access Context
          </h2>
          
          <div className="space-y-6">
            {/* Visual Flow */}
            <div className="flex flex-col items-center space-y-2">
              <div className="flex items-center space-x-4 w-full">
                <div className="flex-1 bg-slate-800 p-3 rounded-lg border border-cf-border text-center">
                  <User className="w-5 h-5 mx-auto text-blue-400 mb-1" />
                  <p className="text-xs text-slate-400 uppercase">Identity</p>
                  <p className="text-sm font-bold text-white">{user?.name}</p>
                  <p className="text-xs text-green-400 flex items-center justify-center mt-1"><CheckCircle className="w-3 h-3 mr-1"/>Verified</p>
                </div>
                <div className="text-slate-500">→</div>
                <div className="flex-1 bg-slate-800 p-3 rounded-lg border border-cf-border text-center">
                  <ShieldCheck className="w-5 h-5 mx-auto text-cf-orange mb-1" />
                  <p className="text-xs text-slate-400 uppercase">Role</p>
                  <p className="text-sm font-bold text-white">{user?.role}</p>
                  <p className="text-xs text-green-400 flex items-center justify-center mt-1"><CheckCircle className="w-3 h-3 mr-1"/>Valid</p>
                </div>
              </div>
              
              <div className="w-px h-6 bg-slate-600"></div>
              
              <div className="bg-cf-orange/10 border border-cf-orange/30 p-4 rounded-lg w-full text-center">
                <p className="text-xs text-cf-orange font-bold uppercase tracking-wider mb-2">Zero Trust Policy Engine</p>
                <div className="flex justify-center space-x-6 text-sm text-slate-300">
                  <span className="flex items-center"><CheckCircle className="w-4 h-4 text-green-400 mr-1"/> MFA Checked</span>
                  <span className="flex items-center"><CheckCircle className="w-4 h-4 text-green-400 mr-1"/> Device Trusted</span>
                </div>
              </div>

              <div className="w-px h-6 bg-slate-600"></div>

              <div className="w-full bg-slate-800 p-3 rounded-lg border border-cf-border text-center flex flex-col items-center">
                <Server className="w-5 h-5 text-purple-400 mb-1" />
                <p className="text-xs text-slate-400 uppercase">Requested App</p>
                <p className="text-sm font-bold text-white">Campus Applications</p>
              </div>
            </div>
          </div>
        </div>

        <div className="glass-panel p-6">
          <div className="flex items-center justify-between mb-4 flex-wrap gap-2">
            <h2 className="text-lg font-bold text-white flex items-center">
              <Activity className="w-5 h-5 mr-2 text-cf-orange" />
              Recent Security Events
            </h2>
            {isAdmin && (
              <button
                onClick={fetchAuditLogs}
                disabled={loading}
                className="text-xs font-medium px-2 py-1 rounded bg-slate-800 text-slate-300 hover:text-white border border-cf-border hover:border-cf-orange/50 flex items-center transition-colors disabled:opacity-50"
                aria-label="Refresh security audit logs"
              >
                <RefreshCw className={`w-3 h-3 mr-1 ${loading ? 'animate-spin' : ''}`} />
                Refresh
              </button>
            )}
          </div>
          <p className="text-sm text-slate-400 mb-4">
            {isAdmin
              ? 'Real-time telemetry streamed directly from SQLite audit_logs table.'
              : 'Zero Trust policy evaluations for your active session.'}
          </p>
          
          {error ? (
            <div className="p-4 bg-red-950/20 border border-red-500/30 rounded-lg text-center my-2">
              <AlertCircle className="w-6 h-6 text-red-400 mx-auto mb-1" />
              <p className="text-xs text-red-300 font-mono mb-2">{error}</p>
              <button onClick={fetchAuditLogs} className="btn-primary text-xs px-2.5 py-1">
                Retry
              </button>
            </div>
          ) : !isAdmin ? (
            <div className="p-6 bg-slate-800/40 rounded-lg border border-cf-border text-center space-y-2">
              <ShieldCheck className="w-8 h-8 text-emerald-400 mx-auto mb-1" />
              <p className="text-sm font-semibold text-white">Active Session Evaluated</p>
              <p className="text-xs text-slate-400">
                Identity verified as <span className="text-white font-mono">{user?.name}</span> ({user?.role}). Full organization-wide audit records are restricted to Administrator consoles.
              </p>
            </div>
          ) : loading ? (
            <div className="py-8 text-center space-y-2">
              <div className="w-5 h-5 border-2 border-cf-orange border-t-transparent rounded-full animate-spin mx-auto"></div>
              <p className="text-xs text-slate-400">Loading audit records...</p>
            </div>
          ) : auditLogs.length === 0 ? (
            <div className="py-8 text-center text-slate-500">
              <p className="text-xs">No audit logs recorded yet.</p>
            </div>
          ) : (
            <div className="overflow-x-auto rounded-lg border border-cf-border">
              <table className="w-full text-sm text-left">
                <thead className="text-xs text-slate-400 uppercase bg-slate-800">
                  <tr>
                    <th className="px-3 py-3">Outcome</th>
                    <th className="px-3 py-3">Event</th>
                    <th className="px-3 py-3">Endpoint</th>
                    <th className="px-3 py-3">User</th>
                    <th className="px-3 py-3">Timestamp</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-cf-border/50 bg-cf-card/50">
                  {auditLogs.map((log) => (
                    <tr key={log.id || `${log.timestamp}-${log.endpoint}`} className="hover:bg-slate-800/50">
                      <td className="px-3 py-3 whitespace-nowrap">
                        {log.outcome === 'ALLOW' ? (
                          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                            <CheckCircle className="w-3 h-3 mr-1" /> ALLOW
                          </span>
                        ) : (
                          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-rose-500/10 text-rose-400 border border-rose-500/20">
                            <ShieldAlert className="w-3 h-3 mr-1" /> DENY
                          </span>
                        )}
                      </td>
                      <td className="px-3 py-3 text-xs font-medium text-white">{log.event_type}</td>
                      <td className="px-3 py-3 text-xs font-mono text-slate-300 truncate max-w-[120px]" title={log.endpoint}>
                        {log.endpoint}
                      </td>
                      <td className="px-3 py-3 text-xs font-mono text-slate-400 truncate max-w-[100px]" title={log.user_id || 'Anonymous'}>
                        {log.user_id || 'Anonymous'}
                      </td>
                      <td className="px-3 py-3 text-slate-400 text-xs whitespace-nowrap font-mono">
                        {log.timestamp ? new Date(log.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
