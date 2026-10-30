export default function DashboardCard({ title, value, subtitle, icon: Icon, colorClass = "text-cf-orange" }) {
  return (
    <div className="glass-panel p-6 flex items-start justify-between">
      <div>
        <p className="text-sm font-medium text-slate-400 mb-1">{title}</p>
        <h3 className="text-3xl font-bold text-white mb-2">{value}</h3>
        {subtitle && <p className="text-sm text-slate-500">{subtitle}</p>}
      </div>
      <div className={`p-3 rounded-lg bg-slate-800 ${colorClass}`}>
        <Icon className="w-6 h-6" />
      </div>
    </div>
  );
}
