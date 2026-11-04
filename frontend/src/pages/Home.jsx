import { Link } from 'react-router-dom'
import { ShieldCheck } from 'lucide-react'

export default function Home() {
  return (
    <div className="min-h-screen bg-[#070b14] text-slate-100 font-sans flex flex-col justify-between">
      {/* Top Header Navigation */}
      <header className="border-b border-slate-800/80 bg-slate-950/60 backdrop-blur-md px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30">
            <ShieldCheck className="w-6 h-6 text-cyan-400" />
          </div>
          <span className="text-lg font-bold tracking-wider uppercase text-slate-100">CyberScribe</span>
        </div>
        <div className="flex gap-3">
          <Link 
            to="/admin" 
            className="px-4 py-2 rounded-lg border border-slate-800 text-slate-300 hover:border-slate-700 hover:text-white text-xs font-mono transition"
          >
            Admin Portal
          </Link>
          <Link 
            to="/login" 
            className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold uppercase tracking-wider transition"
          >
            SOC Login
          </Link>
        </div>
      </header>

      {/* Hero Section */}
      <main className="max-w-4xl mx-auto px-6 py-20 text-center space-y-8">
       
        <h1 className="text-4xl md:text-6xl font-extrabold tracking-tight text-slate-100 leading-tight">
          Autonomous Cyber Threat Intelligence Platform
        </h1>
        <p className="text-base md:text-lg text-slate-400 max-w-2xl mx-auto leading-relaxed">
          Bridging the intelligence gap with continuous OSINT ingestion, LangGraph multi-agent reasoning, STIX 2.1 standardization, and automated SOAR remediation playbooks.
        </p>
        <div className="flex justify-center gap-4 pt-4 flex-wrap">
          <Link 
            to="/explorer" 
            className="px-6 py-3 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-semibold uppercase tracking-wider transition shadow-lg shadow-cyan-600/20"
          >
            Explore Global OSINT
          </Link>
          <Link 
            to="/login" 
            className="px-6 py-3 rounded-lg bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-200 text-sm font-semibold uppercase tracking-wider transition"
          >
            Company SOC Login
          </Link>
          <Link 
            to="/register" 
            className="px-6 py-3 rounded-lg bg-slate-950 border border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/10 text-sm font-semibold uppercase tracking-wider transition"
          >
            Register Tenant
          </Link>
        </div>
      </main>

      {/* Minimal Footer */}
      <footer className="border-t border-slate-800/80 bg-slate-950/60 px-6 py-4 text-center text-xs text-slate-500 font-mono">
        CyberScribe Autonomous CTI Platform
      </footer>
    </div>
  )
}