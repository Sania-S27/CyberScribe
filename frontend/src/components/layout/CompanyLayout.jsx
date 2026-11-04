// frontend/src/components/layout/CompanyLayout.jsx
import React, { useState } from 'react'
import { Link, NavLink, Outlet, useNavigate } from 'react-router-dom'
import {
  ShieldCheck,
  LayoutDashboard,
  BarChart3,
  AlertOctagon,
  Wrench,
  ShieldAlert,
  FileText,
  Radio,
  User,
  LogOut,
  Menu,
  X,
  ExternalLink,
  Activity,
  FileCode2
} from 'lucide-react'

export default function CompanyLayout({ userProfile }) {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  const navigate = useNavigate()

  const handleLogout = () => {
    localStorage.removeItem('access_token')
    navigate('/login')
  }

  const navItems = [
    { to: '/dashboard', label: 'Overview', icon: LayoutDashboard, end: true },
    { to: '/company/findings', label: 'Threats', icon: AlertOctagon },
    { to: '/company/analytics', label: 'Analytics', icon: BarChart3 },
    { to: '/company/containment', label: 'Containment', icon: ShieldAlert },
    { to: '/company/remediation', label: 'Remediation', icon: Wrench },
    { to: '/company/reports', label: 'Threat Reports', icon: FileText },
  ]

  const tenantName = userProfile?.company_name || 'Enterprise Tenant'
  const userEmail = userProfile?.email || 'analyst@organization.local'

  return (
    <div className="h-screen w-screen bg-[#070b14] text-slate-100 flex flex-col md:flex-row font-sans overflow-hidden">
      {/* Mobile Top Header */}
      <header className="md:hidden flex items-center justify-between px-4 py-3 bg-slate-950 border-b border-slate-800 z-50">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30">
            <ShieldCheck className="w-5 h-5 text-cyan-400" />
          </div>
          <div>
            <h1 className="text-sm font-bold tracking-wider text-slate-100 font-mono">CyberScribe</h1>
            <p className="text-[10px] text-slate-400 font-mono truncate max-w-[150px]">{tenantName}</p>
          </div>
        </div>
        <button
          onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          className="p-2 text-slate-400 hover:text-slate-100 hover:bg-slate-900 rounded-lg"
          aria-label="Toggle navigation menu"
        >
          {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
        </button>
      </header>

      {/* Persistent Sidebar Navigation */}
      <aside 
        className={`fixed md:static inset-y-0 left-0 z-40 w-64 bg-slate-950 border-r border-slate-800/80 p-4 flex flex-col justify-between flex-shrink-0 transition-transform duration-200 ease-in-out md:translate-x-0 ${
          mobileMenuOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        <div className="space-y-6">
          {/* Brand & Organization Block */}
          <div className="hidden md:flex items-center gap-3 px-2 py-1">
            <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30">
              <ShieldCheck className="w-5 h-5 text-cyan-400" />
            </div>
            <div className="overflow-hidden">
              <h2 className="text-sm font-bold tracking-wider uppercase text-slate-100 font-mono">
                CyberScribe
              </h2>
              <p className="text-[10px] text-cyan-400/80 font-mono truncate">
                {tenantName}
              </p>
            </div>
          </div>

          {/* Environment Status Pill */}
          <div className="px-2.5 py-1.5 rounded-lg bg-slate-900/60 border border-slate-800/80 flex items-center justify-between text-[11px] font-mono">
            <span className="flex items-center gap-1.5 text-slate-400">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              Tenant Isolated
            </span>
            <span className="text-slate-400 font-semibold">SOC v2.1</span>
          </div>

          {/* Navigation Links */}
          <nav className="space-y-1">
            <p className="px-2 pb-1 text-[10px] font-mono uppercase tracking-wider text-slate-400 font-semibold">
              Security Console
            </p>
            {navItems.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                onClick={() => setMobileMenuOpen(false)}
                className={({ isActive }) =>
                  `flex items-center justify-between px-3 py-2 rounded-lg text-xs font-mono transition duration-150 ${
                    isActive
                      ? 'bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 font-semibold shadow-sm'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60 border border-transparent'
                  }`
                }
              >
                <div className="flex items-center gap-2.5">
                  <item.icon className="w-4 h-4 flex-shrink-0" />
                  <span>{item.label}</span>
                </div>
                {item.badge && (
                  <span className="text-[9px] px-1.5 py-0.2 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 font-bold">
                    {item.badge}
                  </span>
                )}
              </NavLink>
            ))}
          </nav>
        </div>

        {/* User Session Footer */}
        <div className="space-y-2 pt-4 border-t border-slate-900">
          <div className="px-2.5 py-2 rounded-lg bg-slate-900/40 border border-slate-850 flex items-center gap-2.5">
            <div className="w-7 h-7 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-xs font-mono text-cyan-400 flex-shrink-0">
              {userEmail.charAt(0).toUpperCase()}
            </div>
            <div className="overflow-hidden">
              <p className="text-xs text-slate-200 font-mono truncate">{userEmail}</p>
              <p className="text-[10px] text-slate-400 font-mono">Tenant Analyst</p>
            </div>
          </div>

          <div className="flex items-center gap-1.5">
            <NavLink
              to="/company/profile"
              onClick={() => setMobileMenuOpen(false)}
              className="flex-1 flex items-center justify-center gap-1.5 px-2.5 py-2 rounded-lg bg-slate-900/60 hover:bg-slate-850 border border-slate-800 text-slate-400 hover:text-slate-200 text-xs font-mono transition"
            >
              <User className="w-3.5 h-3.5" /> Profile
            </NavLink>
            <button
              onClick={handleLogout}
              className="flex-1 flex items-center justify-center gap-1.5 px-2.5 py-2 rounded-lg bg-slate-900/60 hover:bg-rose-500/10 border border-slate-800 hover:border-rose-500/30 text-slate-400 hover:text-rose-400 text-xs font-mono transition cursor-pointer"
            >
              <LogOut className="w-3.5 h-3.5" /> Logout
            </button>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="flex-1 h-full overflow-y-auto bg-[#070b14] text-slate-100 flex flex-col min-w-0">
        <div className="flex-1 p-4 md:p-8 max-w-7xl w-full mx-auto space-y-6">
          <Outlet context={{ userProfile }} />
        </div>
      </main>
    </div>
  )
}
