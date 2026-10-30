import { useState, useEffect } from 'react';
import { GraduationCap, BookOpen, Clock, Bell, AlertCircle, RefreshCw } from 'lucide-react';
import DashboardCard from '../components/DashboardCard';
import ApplicationCard from '../components/ApplicationCard';
import { applications } from '../data/mockData';
import { apiUrl } from '../config/api';

export default function StudentDashboard({ user }) {
  const [dashboardData, setDashboardData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchDashboard = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(apiUrl('/api/student/dashboard'), {
        method: 'GET',
        credentials: 'include'
      });
      if (!res.ok) {
        throw new Error(`Server returned HTTP ${res.status}: ${res.statusText}`);
      }
      const data = await res.json();
      setDashboardData(data);
    } catch (err) {
      setError(err.message || 'Failed to load student dashboard');
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
        <p className="text-sm text-slate-400">Loading verified student portal data...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="glass-panel p-6 border-red-500/30 max-w-xl mx-auto my-12 text-center">
        <AlertCircle className="w-10 h-10 text-red-500 mx-auto mb-3" />
        <h3 className="text-lg font-bold text-white mb-2">Unable to Load Dashboard</h3>
        <p className="text-sm text-slate-400 mb-4">{error}</p>
        <button onClick={fetchDashboard} className="btn-primary inline-flex items-center text-sm">
          <RefreshCw className="w-4 h-4 mr-2" /> Retry Connection
        </button>
      </div>
    );
  }

  const metrics = dashboardData?.metrics || {
    attendance: '87%',
    currentCourses: 5,
    assignmentsPending: 3,
    notifications: 4
  };

  const courses = dashboardData?.courses || [];

  return (
    <div className="space-y-6 slide-up">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Student Portal</h1>
          <p className="text-xs text-slate-400 mt-1">Identity: {dashboardData?.user?.name || user?.name} • ID: {dashboardData?.user?.id || user?.id}</p>
        </div>
        <span className="text-xs font-medium px-2.5 py-1 rounded bg-green-500/10 text-green-400 border border-green-500/20">
          ✓ Session Active
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <DashboardCard title="Attendance" value={metrics.attendance} subtitle="Current semester" icon={Clock} colorClass="text-green-400" />
        <DashboardCard title="Current Courses" value={metrics.currentCourses} subtitle="Enrolled subjects" icon={BookOpen} colorClass="text-blue-400" />
        <DashboardCard title="Assignments" value={metrics.assignmentsPending} subtitle="Pending evaluation" icon={GraduationCap} colorClass="text-purple-400" />
        <DashboardCard title="Notifications" value={metrics.notifications} subtitle="Unread security alerts" icon={Bell} colorClass="text-amber-400" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-6">
          <div className="glass-panel p-6">
            <h2 className="text-lg font-bold text-white mb-4">My Courses</h2>
            {courses.length === 0 ? (
              <p className="text-sm text-slate-400">No courses registered for this semester.</p>
            ) : (
              <div className="space-y-4">
                {courses.map(course => (
                  <div key={course.id} className="flex items-center justify-between p-4 bg-slate-800/50 rounded-lg border border-cf-border">
                    <div>
                      <h4 className="font-medium text-white">{course.name}</h4>
                      <p className="text-xs text-slate-400">{course.id}</p>
                    </div>
                    <div className="flex items-center">
                      <div className="w-32 h-2 bg-slate-700 rounded-full overflow-hidden mr-3">
                        <div className="h-full bg-cf-orange" style={{ width: `${course.progress}%` }}></div>
                      </div>
                      <span className="text-sm font-medium text-slate-300 w-8">{course.progress}%</span>
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
            <p className="text-sm text-slate-400 mb-4">Select an application to launch. Access is determined by your role.</p>
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
