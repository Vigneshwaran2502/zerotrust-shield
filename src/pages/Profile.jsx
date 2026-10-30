import { User, Mail, Building, Fingerprint, Smartphone, CheckCircle, ShieldCheck } from 'lucide-react';

export default function Profile({ user }) {
  return (
    <div className="max-w-4xl mx-auto space-y-6 slide-up">
      <h1 className="text-2xl font-bold text-white mb-6">User Profile</h1>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="md:col-span-1">
          <div className="glass-panel p-6 text-center">
            <div className="w-32 h-32 mx-auto rounded-full bg-slate-800 border-4 border-cf-card overflow-hidden mb-4 shadow-lg">
              {user?.avatar ? (
                <img src={user.avatar} alt={user.name} className="w-full h-full object-cover" />
              ) : (
                <User className="w-full h-full p-6 text-slate-500" />
              )}
            </div>
            <h2 className="text-xl font-bold text-white">{user?.name}</h2>
            <p className="text-cf-orange font-medium">{user?.role}</p>
            <div className="mt-4 inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-green-500/10 text-green-400 border border-green-500/20">
              <CheckCircle className="w-3 h-3 mr-1" />
              Account Active
            </div>
          </div>
        </div>

        <div className="md:col-span-2 space-y-6">
          <div className="glass-panel p-6">
            <h3 className="text-lg font-bold text-white mb-4 border-b border-cf-border pb-2">Personal Information</h3>
            <div className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <p className="text-xs text-slate-500 font-medium uppercase tracking-wider mb-1 flex items-center"><User className="w-3 h-3 mr-1"/> Full Name</p>
                  <p className="text-white font-medium">{user?.name}</p>
                </div>
                <div>
                  <p className="text-xs text-slate-500 font-medium uppercase tracking-wider mb-1 flex items-center"><Fingerprint className="w-3 h-3 mr-1"/> User ID</p>
                  <p className="text-white font-medium">{user?.id}</p>
                </div>
                <div>
                  <p className="text-xs text-slate-500 font-medium uppercase tracking-wider mb-1 flex items-center"><Mail className="w-3 h-3 mr-1"/> Email Address</p>
                  <p className="text-white font-medium">{user?.email}</p>
                </div>
                <div>
                  <p className="text-xs text-slate-500 font-medium uppercase tracking-wider mb-1 flex items-center"><Building className="w-3 h-3 mr-1"/> Department</p>
                  <p className="text-white font-medium">{user?.department}</p>
                </div>
              </div>
            </div>
          </div>

          <div className="glass-panel p-6 border-l-4 border-cf-orange">
            <h3 className="text-lg font-bold text-white mb-4 border-b border-cf-border pb-2 flex items-center">
              <ShieldCheck className="w-5 h-5 mr-2 text-cf-orange" />
              Security Information
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <p className="text-xs text-slate-500 font-medium uppercase tracking-wider mb-1">Identity Status</p>
                <p className="text-green-400 font-medium flex items-center"><CheckCircle className="w-4 h-4 mr-1" /> Verified</p>
              </div>
              <div>
                <p className="text-xs text-slate-500 font-medium uppercase tracking-wider mb-1 flex items-center">MFA Status</p>
                <p className="text-green-400 font-medium flex items-center"><Smartphone className="w-4 h-4 mr-1" /> Enabled (Demo)</p>
              </div>
              <div>
                <p className="text-xs text-slate-500 font-medium uppercase tracking-wider mb-1">Device State</p>
                <p className="text-green-400 font-medium flex items-center"><CheckCircle className="w-4 h-4 mr-1" /> Trusted (Demo)</p>
              </div>
              <div>
                <p className="text-xs text-slate-500 font-medium uppercase tracking-wider mb-1">Current Session</p>
                <p className="text-green-400 font-medium flex items-center"><Activity className="w-4 h-4 mr-1" /> Active</p>
              </div>
            </div>
            <p className="mt-4 text-xs text-slate-500 bg-slate-900/50 p-3 rounded">
              * Note: This is a frontend demonstration. Real authentication and MFA will be enforced by Cloudflare Access.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

// Quick helper
function Activity(props) {
  return <svg {...props} xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg>;
}
