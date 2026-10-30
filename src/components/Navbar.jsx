import { Menu, Bell, User as UserIcon } from 'lucide-react';

export default function Navbar({ user, onMenuClick }) {
  return (
    <header className="h-16 bg-cf-card/80 backdrop-blur-md border-b border-cf-border flex items-center justify-between px-6 z-10 sticky top-0">
      <div className="flex items-center md:hidden">
        <button onClick={onMenuClick} className="text-slate-400 hover:text-white">
          <Menu className="w-6 h-6" />
        </button>
      </div>
      
      <div className="hidden md:flex items-center text-sm font-medium text-slate-400">
        <span className="bg-cf-orange/20 text-cf-orange px-2 py-1 rounded text-xs mr-2">BETA</span>
        Campus Identity Network
      </div>

      <div className="flex items-center space-x-4">
        <button className="relative p-2 text-slate-400 hover:text-white transition-colors rounded-full hover:bg-slate-800">
          <Bell className="w-5 h-5" />
          <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-cf-orange rounded-full border-2 border-cf-card"></span>
        </button>
        
        <div className="flex items-center space-x-3 pl-4 border-l border-cf-border">
          <div className="text-right hidden sm:block">
            <div className="text-sm font-medium text-white">{user?.name}</div>
            <div className="text-xs text-slate-400">{user?.role}</div>
          </div>
          <div className="w-8 h-8 rounded-full bg-slate-800 flex items-center justify-center overflow-hidden border border-cf-border">
            {user?.avatar ? (
              <img src={user.avatar} alt="Avatar" className="w-full h-full object-cover" />
            ) : (
              <UserIcon className="w-4 h-4 text-slate-400" />
            )}
          </div>
        </div>
      </div>
    </header>
  );
}
