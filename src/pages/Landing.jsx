import { Link } from 'react-router-dom';
import { Shield, Lock, Users, Server, CheckCircle2 } from 'lucide-react';

export default function Landing() {
  return (
    <div className="min-h-screen bg-cf-dark text-slate-200">
      {/* Header */}
      <header className="container mx-auto px-6 py-6 flex justify-between items-center">
        <div className="flex items-center space-x-3">
          <Shield className="w-8 h-8 text-cf-orange" />
          <span className="font-bold text-xl tracking-tight text-white">ZeroTrust Campus</span>
        </div>
        <div className="flex space-x-4">
          <Link to="/login" className="btn-secondary">View Demo</Link>
          <Link to="/login" className="btn-primary">Sign In</Link>
        </div>
      </header>

      {/* Hero */}
      <main className="container mx-auto px-6 pt-20 pb-16 text-center slide-up">
        <h1 className="text-5xl md:text-7xl font-extrabold tracking-tight text-white mb-6">
          Secure Access to <br/>
          <span className="text-transparent bg-clip-text bg-gradient-to-r from-cf-orange to-amber-500">
            Campus Applications
          </span>
        </h1>
        <p className="text-xl text-slate-400 max-w-2xl mx-auto mb-10 leading-relaxed">
          ZeroTrust Campus is a university application platform designed around the Zero Trust security model. Every user receives access only to the applications and resources required for their role.
        </p>
        <div className="flex flex-col sm:flex-row justify-center items-center space-y-4 sm:space-y-0 sm:space-x-4">
          <Link to="/login" className="btn-primary text-lg px-8 py-3">Get Started</Link>
        </div>
      </main>

      {/* Architecture Visual */}
      <section className="py-16 bg-cf-card/30 border-y border-cf-border fade-in" style={{ animationDelay: '0.2s' }}>
        <div className="container mx-auto px-6">
          <h2 className="text-2xl font-bold text-center mb-12 text-white">How It Works</h2>
          <div className="flex flex-col md:flex-row items-center justify-center space-y-6 md:space-y-0 md:space-x-8">
            <div className="flex flex-col items-center p-6 glass-panel w-48">
              <Users className="w-10 h-10 text-blue-400 mb-3" />
              <span className="font-medium text-white">User</span>
            </div>
            <div className="hidden md:block text-cf-border">→</div>
            <div className="flex flex-col items-center p-6 glass-panel w-48 border-cf-orange/50 relative overflow-hidden">
              <div className="absolute inset-0 bg-cf-orange/10"></div>
              <Shield className="w-10 h-10 text-cf-orange mb-3 relative z-10" />
              <span className="font-medium text-white relative z-10 text-center">Identity & Policy<br/><span className="text-xs text-cf-orange">Zero Trust</span></span>
            </div>
            <div className="hidden md:block text-cf-border">→</div>
            <div className="flex flex-col items-center p-6 glass-panel w-48">
              <Server className="w-10 h-10 text-green-400 mb-3" />
              <span className="font-medium text-white text-center">Campus<br/>Application</span>
            </div>
          </div>
        </div>
      </section>

      {/* Principles & Apps */}
      <section className="container mx-auto px-6 py-24 grid md:grid-cols-2 gap-16">
        <div>
          <h3 className="text-2xl font-bold text-white mb-6">Zero Trust Principles</h3>
          <ul className="space-y-4">
            {[
              "Verify explicitly based on identity and context",
              "Least privilege access controls",
              "Assume breach mentality",
              "Continuous verification for all sessions"
            ].map((principle, i) => (
              <li key={i} className="flex items-start">
                <CheckCircle2 className="w-6 h-6 text-cf-orange mr-3 shrink-0" />
                <span className="text-slate-300 text-lg">{principle}</span>
              </li>
            ))}
          </ul>
        </div>
        
        <div>
          <h3 className="text-2xl font-bold text-white mb-6">Campus Applications</h3>
          <div className="space-y-4">
            {[
              { title: "Student Portal", desc: "Course materials and grades" },
              { title: "Faculty Portal", desc: "Course management and grading" },
              { title: "Admin Portal", desc: "System configuration and security" }
            ].map((app, i) => (
              <div key={i} className="glass-panel p-5 flex items-center justify-between hover:border-slate-500 transition-colors">
                <div>
                  <h4 className="font-semibold text-white text-lg">{app.title}</h4>
                  <p className="text-slate-400 text-sm">{app.desc}</p>
                </div>
                <Lock className="w-5 h-5 text-cf-orange" />
              </div>
            ))}
          </div>
        </div>
      </section>

      <footer className="border-t border-cf-border py-8 text-center text-slate-500">
        <p>ZeroTrust Campus • Security Research Project • Powered by Cloudflare Concepts</p>
      </footer>
    </div>
  );
}
