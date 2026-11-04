// frontend/src/components/layout/AdminLayout.jsx
import React, { useState } from 'react'
import { Link, NavLink, Outlet, useNavigate } from 'react-router-dom'
import {
  ShieldAlert,
  Cpu,
  Users2,
  Radio,
  Flame,
  Network,
  FileCode2,
  Activity,
  LogOut,
  Menu,
  X,
  Lock
} from 'lucide-react'

export default function AdminLayout({ userProfile }) {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  const navigate = useNavigate()

  const handleLogout = () => {
    localStorage.removeItem('access_token')
    navigate('/login')
  }

  const adminNavItems = [
    { to: '/admin', label: 'Overview', icon: Cpu, end: true },
    { to: '/admin/users', label: 'Users & Access', icon: Users2 },
    { to: '/admin/threats', label: 'Threat Intelligence', icon: Radio },
    { to: '/admin/containment', label: 'Containment', icon: Flame },
    { to: '/admin/integrations', label: 'Integrations', icon: Network },
    { to: '/admin/audit', label: 'Audit Logs', icon: FileCode2 },
    { to: '/admin/health', label: 'System Health', icon: Activity },
  ]

  const userEmail = userProfile?.email || 'admin@cyberscribe.internal'

  return (
    <div className="h-screen w-screen bg-[#070b14] text-slate-100 flex flex-col md:flex-row font-sans overflow-hidden">
      {/* Mobile Top Header */}
      <header className="md:hidden flex items-center justify-between px-4 py-3 bg-slate-950 border-b border-slate-800 z-50">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded-lg bg-indigo-500/10 border border-indigo-500/30">
            <Lock className="w-5 h-5 text-indigo-400" />
          </div>
          <div>
            <h1 className="text-sm font-bold tracking-wider text-slate-100 font-mono">CyberScribe</h1>
            <p className="text-[10px] text-indigo-400 font-mono">Platform Admin</p>
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
          {/* Brand & Super Admin Block */}
          <div className="hidden md:flex items-center gap-3 px-2 py-1">
            <div className="p-2 rounded-lg bg-indigo-500/15 border border-indigo-500/30">
              <Lock className="w-5 h-5 text-indigo-400" />
            </div>
            <div className="overflow-hidden">
              <h2 className="text-sm font-bold tracking-wider uppercase text-slate-100 font-mono">
                CyberScribe
              </h2>
              <p className="text-[10px] text-indigo-400 font-mono">
                Platform Operations
              </p>
            </div>
          </div>

          {/* Operational Scope Pill */}
          <div className="px-2.5 py-1.5 rounded-lg bg-indigo-950/30 border border-indigo-500/20 flex items-center justify-between text-[11px] font-mono">
            <span className="flex items-center gap-1.5 text-indigo-300">
              <span className="w-1.5 h-1.5 rounded-full bg-indigo-400 animate-pulse" />
              Root Scope
            </span>
            <span className="text-indigo-400 font-semibold">SUPER_ADMIN</span>
          </div>

          {/* Navigation Links */}
          <nav className="space-y-1">
            <p className="px-2 pb-1 text-[10px] font-mono uppercase tracking-wider text-slate-400 font-semibold">
              Platform Controls
            </p>
            {adminNavItems.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                onClick={() => setMobileMenuOpen(false)}
                className={({ isActive }) =>
                  `flex items-center justify-between px-3 py-2 rounded-lg text-xs font-mono transition duration-150 ${
                    isActive
                      ? 'bg-indigo-500/15 border border-indigo-500/30 text-indigo-300 font-semibold shadow-sm'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60 border border-transparent'
                  }`
                }
              >
                <div className="flex items-center gap-2.5">
                  <item.icon className="w-4 h-4 flex-shrink-0" />
                  <span>{item.label}</span>
                </div>
                {item.badge && (
                  <span className="text-[9px] px-1.5 py-0.2 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 font-bold">
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
            <div className="w-7 h-7 rounded-full bg-indigo-900/40 border border-indigo-700/50 flex items-center justify-center text-xs font-mono text-indigo-300 flex-shrink-0">
              {userEmail.charAt(0).toUpperCase()}
            </div>
            <div className="overflow-hidden">
              <p className="text-xs text-slate-200 font-mono truncate">{userEmail}</p>
              <p className="text-[10px] text-indigo-400 font-mono">Platform Super Admin</p>
            </div>
          </div>

          <button
            onClick={handleLogout}
            className="w-full flex items-center justify-center gap-1.5 px-2.5 py-2 rounded-lg bg-slate-900/60 hover:bg-rose-500/10 border border-slate-800 hover:border-rose-500/30 text-slate-400 hover:text-rose-400 text-xs font-mono transition cursor-pointer"
          >
            <LogOut className="w-3.5 h-3.5" /> Logout Platform
          </button>
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
