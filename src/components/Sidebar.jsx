import { Link, useLocation } from 'react-router-dom';
import { 
  LayoutDashboard, 
  BookOpen, 
  Users, 
  ShieldCheck, 
  User, 
  LogOut,
  AppWindow,
  FileKey
} from 'lucide-react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs) {
  return twMerge(clsx(inputs));
}

export default function Sidebar({ user, onLogout, isOpen, setIsOpen }) {
  const location = useLocation();

  const getNavItems = () => {
    const baseItems = [
      { name: 'Profile', path: '/profile', icon: User },
      { name: 'Security & Access', path: '/security', icon: ShieldCheck },
    ];

    if (user?.role === 'Student') {
      return [
        { name: 'Dashboard', path: '/student', icon: LayoutDashboard },
        { name: 'My Courses', path: '#', icon: BookOpen },
        ...baseItems
      ];
    }
    if (user?.role === 'Faculty') {
      return [
        { name: 'Dashboard', path: '/faculty', icon: LayoutDashboard },
        { name: 'My Courses', path: '#', icon: BookOpen },
        { name: 'Students', path: '#', icon: Users },
        ...baseItems
      ];
    }
    if (user?.role === 'Administrator') {
      return [
        { name: 'Dashboard', path: '/admin', icon: LayoutDashboard },
        { name: 'Users', path: '#', icon: Users },
        { name: 'Applications', path: '#', icon: AppWindow },
        { name: 'Security Events', path: '/admin', icon: FileKey },
        ...baseItems
      ];
    }
    return baseItems;
  };

  const navItems = getNavItems();

  return (
    <>
      {/* Mobile overlay */}
      {isOpen && (
        <div 
          className="fixed inset-0 bg-black/50 z-40 md:hidden transition-opacity"
          onClick={() => setIsOpen(false)}
        />
      )}

      <aside className={cn(
        "fixed md:static inset-y-0 left-0 z-50 w-64 bg-cf-card border-r border-cf-border flex flex-col transition-transform duration-300 ease-in-out md:translate-x-0",
        isOpen ? "translate-x-0" : "-translate-x-full"
      )}>
        <div className="p-6 border-b border-cf-border flex items-center space-x-3">
          <ShieldCheck className="w-8 h-8 text-cf-orange" />
          <span className="font-bold text-xl tracking-tight text-white">ZeroTrust</span>
        </div>
        
        <nav className="flex-1 p-4 space-y-2 overflow-y-auto">
          {navItems.map((item) => {
            const isActive = location.pathname === item.path;
            return (
              <Link
                key={item.name}
                to={item.path}
                onClick={() => setIsOpen(false)}
                className={cn(
                  "flex items-center space-x-3 px-4 py-3 rounded-lg transition-all duration-200",
                  isActive 
                    ? "bg-cf-orange/10 text-cf-orange font-medium" 
                    : "text-slate-400 hover:bg-slate-800 hover:text-white"
                )}
              >
                <item.icon className="w-5 h-5" />
                <span>{item.name}</span>
              </Link>
            );
          })}
        </nav>

        <div className="p-4 border-t border-cf-border">
          <button 
            onClick={onLogout}
            className="flex items-center space-x-3 px-4 py-3 w-full rounded-lg text-slate-400 hover:bg-red-500/10 hover:text-red-400 transition-all duration-200"
          >
            <LogOut className="w-5 h-5" />
            <span>Logout</span>
          </button>
        </div>
      </aside>
    </>
  );
}
