import { useState, useEffect } from 'react';
import { Users, BookOpen, ClipboardCheck, Bell, AlertCircle, RefreshCw } from 'lucide-react';
import DashboardCard from '../components/DashboardCard';
import ApplicationCard from '../components/ApplicationCard';
import { applications } from '../data/mockData';
import { apiUrl } from '../config/api';

export default function FacultyDashboard({ user }) {
  const [dashboardData, setDashboardData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchDashboard = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(apiUrl('/api/faculty/dashboard'), {
        method: 'GET',
        credentials: 'include'
      });
      if (!res.ok) {
        throw new Error(`Server returned HTTP ${res.status}: ${res.statusText}`);
      }
      const data = await res.json();
      setDashboardData(data);
    } catch (err) {
      setError(err.message || 'Failed to load faculty portal data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboard();
  }, []);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[50vh] space-y-4">
        <div className="w-8 h-8 border-2 border-cf-orange border-t-transparent rounded-full animate-spin"></div>
        <p className="text-sm text-slate-400">Loading verified faculty portal data...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="glass-panel p-6 border-red-500/30 max-w-xl mx-auto my-12 text-center">
        <AlertCircle className="w-10 h-10 text-red-500 mx-auto mb-3" />
        <h3 className="text-lg font-bold text-white mb-2">Unable to Load Portal</h3>
        <p className="text-sm text-slate-400 mb-4">{error}</p>
        <button onClick={fetchDashboard} className="btn-primary inline-flex items-center text-sm">
          <RefreshCw className="w-4 h-4 mr-2" /> Retry Connection
        </button>
      </div>
    );
  }

  const metrics = dashboardData?.metrics || {
    coursesTeaching: 2,
    totalStudents: 75,
    pendingEvaluations: 12,
    notifications: 2
  };

  const courses = dashboardData?.courses || [];

  return (
    <div className="space-y-6 slide-up">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Faculty Portal</h1>
          <p className="text-xs text-slate-400 mt-1">Instructor: {dashboardData?.user?.name || user?.name} • Role: {dashboardData?.user?.role || user?.role}</p>
        </div>
        <span className="text-xs font-medium px-2.5 py-1 rounded bg-green-500/10 text-green-400 border border-green-500/20">
          ✓ Session Active
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <DashboardCard title="Courses Teaching" value={metrics.coursesTeaching} subtitle="Active this term" icon={BookOpen} colorClass="text-blue-400" />
        <DashboardCard title="Total Students" value={metrics.totalStudents} subtitle="Across assigned sections" icon={Users} colorClass="text-green-400" />
        <DashboardCard title="Pending Evaluations" value={metrics.pendingEvaluations} subtitle="Require grading" icon={ClipboardCheck} colorClass="text-cf-orange" />
        <DashboardCard title="Notifications" value={metrics.notifications} subtitle="Campus announcements" icon={Bell} colorClass="text-amber-400" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-6">
          <div className="glass-panel p-6">
            <h2 className="text-lg font-bold text-white mb-4">Assigned Courses</h2>
            {courses.length === 0 ? (
              <p className="text-sm text-slate-400">No active teaching assignments found.</p>
            ) : (
              <div className="space-y-4">
                {courses.map(course => (
                  <div key={course.id} className="flex flex-col sm:flex-row sm:items-center justify-between p-4 bg-slate-800/50 rounded-lg border border-cf-border">
                    <div className="mb-2 sm:mb-0">
                      <h4 className="font-medium text-white">{course.name}</h4>
                      <p className="text-xs text-slate-400">{course.id} • {course.students} Students</p>
                    </div>
                    <div className="text-sm bg-slate-800 px-3 py-1.5 rounded text-slate-300 border border-cf-border/50">
                      Next: {course.nextClass}
                    </div>
                  </div>
                ))}
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
