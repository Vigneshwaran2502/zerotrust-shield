import { useNavigate } from 'react-router-dom';
import { Lock, Unlock, ShieldAlert } from 'lucide-react';
import { accessPolicies } from '../data/mockData';

export default function ApplicationCard({ app, userRole }) {
  const navigate = useNavigate();
  
  const hasAccess = accessPolicies[userRole]?.includes(app.id);

  const handleClick = () => {
    if (!hasAccess) {
      navigate('/access-denied', { state: { reqApp: app.name, role: userRole } });
    } else {
      if (app.id === 'app_student') navigate('/student');
      else if (app.id === 'app_faculty') navigate('/faculty');
      else if (app.id === 'app_admin') navigate('/admin');
    }
  };

  return (
    <div 
      onClick={handleClick}
      className={`glass-panel p-6 cursor-pointer transition-all duration-200 border-2 ${
        hasAccess 
          ? 'border-transparent hover:border-cf-orange/50' 
          : 'border-transparent hover:border-red-500/50 opacity-75'
      }`}
    >
      <div className="flex justify-between items-start mb-4">
        <div className="w-12 h-12 bg-slate-800 rounded-lg flex items-center justify-center text-white">
          <ShieldAlert className="w-6 h-6" /> {/* Generic icon for now, ideally pass dynamic icon */}
        </div>
        <div>
          {hasAccess ? (
            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-500/10 text-green-400 border border-green-500/20">
              <Unlock className="w-3 h-3 mr-1" />
              Accessible
            </span>
          ) : (
            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-500/10 text-red-400 border border-red-500/20">
              <Lock className="w-3 h-3 mr-1" />
              Restricted
            </span>
          )}
        </div>
      </div>
      
      <h4 className="text-lg font-bold text-white mb-2">{app.name}</h4>
      <p className="text-sm text-slate-400">{app.description}</p>
    </div>
  );
}
