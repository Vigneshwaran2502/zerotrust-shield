export const users = {
  student: {
    id: "STU-2026-1042",
    name: "Arjun Kumar",
    email: "arjun.k@zerotrustcampus.edu",
    role: "Student",
    department: "Computer Science",
    status: "Active",
    mfa: true,
    deviceTrusted: true,
    avatar: "https://i.pravatar.cc/150?u=arjun"
  },
  faculty: {
    id: "FAC-2021-0084",
    name: "Dr. Priya Sharma",
    email: "p.sharma@zerotrustcampus.edu",
    role: "Faculty",
    department: "Computer Science",
    status: "Active",
    mfa: true,
    deviceTrusted: true,
    avatar: "https://i.pravatar.cc/150?u=priya"
  },
  admin: {
    id: "ADM-2019-0001",
    name: "Admin User",
    email: "admin@zerotrustcampus.edu",
    role: "Administrator",
    department: "IT Security",
    status: "Active",
    mfa: true,
    deviceTrusted: true,
    avatar: "https://i.pravatar.cc/150?u=admin"
  }
};

export const applications = [
  { id: 'app_student', name: 'Student Portal', icon: 'graduation-cap', description: 'Access courses, grades, and attendance.' },
  { id: 'app_faculty', name: 'Faculty Portal', icon: 'book-open', description: 'Manage courses, students, and evaluations.' },
  { id: 'app_admin', name: 'Admin Portal', icon: 'shield-alert', description: 'System configuration and access policies.' }
];

export const accessPolicies = {
  'Student': ['app_student'],
  'Faculty': ['app_faculty', 'app_student'],
  'Administrator': ['app_admin', 'app_faculty', 'app_student']
};

export const accessLogs = [];

export const studentCourses = [
  { id: 'CS301', name: 'Computer Networks', progress: 75 },
  { id: 'CS302', name: 'Cloud Computing', progress: 60 },
  { id: 'CS303', name: 'Cyber Security', progress: 90 },
  { id: 'CS304', name: 'Database Management', progress: 85 },
  { id: 'CS305', name: 'Operating Systems', progress: 40 },
];
