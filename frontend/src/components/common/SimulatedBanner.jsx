// frontend/src/components/common/SimulatedBanner.jsx
import React from 'react'
import { ShieldAlert, Info } from 'lucide-react'

export default function SimulatedBanner({ title = 'Simulation-Only Autonomous Containment', description }) {
  return (
    <div className="bg-slate-900/80 border border-cyan-500/30 rounded-xl p-4 flex items-start gap-3 text-xs text-slate-300 font-sans shadow-sm">
      <div className="p-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 flex-shrink-0 mt-0.5">
        <ShieldAlert className="w-4 h-4" />
      </div>
      <div className="space-y-1">
        <div className="flex items-center gap-2">
          <span className="font-mono font-bold uppercase tracking-wider text-cyan-300">
            {title}
          </span>
          <span className="px-1.5 py-0.2 rounded text-[10px] font-mono uppercase bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
            SIMULATION GUARD ACTIVE
          </span>
        </div>
        <p className="text-slate-400 font-mono text-[11px] leading-relaxed">
          {description || 'Network indicators are evaluated autonomously under deterministic policy rules and executed in simulated firewall adapter mode. Live Linux netfilter/iptables rule execution is strictly prohibited by safety policy.'}
        </p>
      </div>
    </div>
  )
}
