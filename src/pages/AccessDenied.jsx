import { useLocation, useNavigate } from 'react-router-dom';
import { ShieldAlert, ArrowLeft, Shield } from 'lucide-react';

export default function AccessDenied({ user }) {
  const location = useLocation();
  const navigate = useNavigate();
  
  const reqApp = location.state?.reqApp || 'Unknown Application';
  const role = location.state?.role || user?.role || 'Unknown Role';

  return (
    <div className="flex flex-col items-center justify-center min-h-[70vh] slide-up">
      <div className="glass-panel p-10 max-w-lg w-full text-center relative overflow-hidden border-red-500/30">
        <div className="absolute top-0 left-0 w-full h-1 bg-red-500"></div>
        
        <div className="w-20 h-20 bg-red-500/10 rounded-full flex items-center justify-center mx-auto mb-6">
          <ShieldAlert className="w-10 h-10 text-red-500" />
        </div>
        
        <h1 className="text-3xl font-bold text-white mb-2">Access Denied</h1>
        <p className="text-slate-400 mb-8">
          You do not have permission to access this application.
        </p>

        <div className="bg-slate-900/50 rounded-lg p-5 text-left mb-8 border border-cf-border">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <p className="text-xs text-slate-500 font-medium uppercase tracking-wider mb-1">Requested App</p>
              <p className="text-white font-medium">{reqApp}</p>
            </div>
            <div>
              <p className="text-xs text-slate-500 font-medium uppercase tracking-wider mb-1">Current Role</p>
              <p className="text-white font-medium">{role}</p>
            </div>
            <div>
              <p className="text-xs text-slate-500 font-medium uppercase tracking-wider mb-1">Decision</p>
              <p className="text-red-400 font-bold">DENIED</p>
            </div>
            <div>
              <p className="text-xs text-slate-500 font-medium uppercase tracking-wider mb-1">Reason</p>
              <p className="text-slate-300 text-sm">Insufficient privileges</p>
            </div>
          </div>
        </div>

        <button 
          onClick={() => navigate(-1)}
          className="btn-primary w-full flex justify-center items-center"
        >
          <ArrowLeft className="w-4 h-4 mr-2" />
          Return to Previous Page
        </button>
      </div>

      <div className="mt-8 text-center max-w-md">
        <div className="flex items-center justify-center text-cf-orange mb-2">
          <Shield className="w-5 h-5 mr-2" />
          <span className="font-semibold">Zero Trust Policy</span>
        </div>
        <p className="text-sm text-slate-500">
          Access is granted based on identity, role, and application-specific permissions. All access attempts are logged and monitored.
        </p>
      </div>
    </div>
  );
}
