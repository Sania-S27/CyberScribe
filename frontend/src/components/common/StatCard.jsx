// frontend/src/components/common/StatCard.jsx
import React from 'react'

export default function StatCard({ 
  title, 
  value, 
  icon: Icon, 
  subtitle, 
  accent = 'cyan', 
  onClick,
  badge
}) {
  const accentStyles = {
    cyan: {
      border: 'border-slate-800 hover:border-cyan-500/40',
      iconBg: 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20',
      valColor: 'text-slate-100',
    },
    emerald: {
      border: 'border-slate-800 hover:border-emerald-500/40',
      iconBg: 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20',
      valColor: 'text-emerald-400',
    },
    rose: {
      border: 'border-slate-800 hover:border-rose-500/40',
      iconBg: 'bg-rose-500/10 text-rose-400 border border-rose-500/20',
      valColor: 'text-rose-400',
    },
    amber: {
      border: 'border-slate-800 hover:border-amber-500/40',
      iconBg: 'bg-amber-500/10 text-amber-400 border border-amber-500/20',
      valColor: 'text-amber-400',
    },
    purple: {
      border: 'border-slate-800 hover:border-purple-500/40',
      iconBg: 'bg-purple-500/10 text-purple-400 border border-purple-500/20',
      valColor: 'text-purple-300',
    }
  }

  const style = accentStyles[accent] || accentStyles.cyan

  return (
    <div 
      onClick={onClick}
      className={`bg-slate-950/80 backdrop-blur-sm border ${style.border} rounded-xl p-4 transition-all duration-150 ${onClick ? 'cursor-pointer hover:bg-slate-900/60' : ''}`}
    >
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs font-mono font-medium text-slate-400 uppercase tracking-wider">{title}</span>
        {Icon && (
          <div className={`p-1.5 rounded-lg ${style.iconBg}`}>
            <Icon className="w-4 h-4" />
          </div>
        )}
      </div>
      <div className="flex items-baseline gap-2">
        <span className={`text-2xl font-bold font-mono ${style.valColor}`}>
          {value}
        </span>
        {badge && (
          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800">
            {badge}
          </span>
        )}
      </div>
      {subtitle && (
        <p className="text-[11px] font-mono text-slate-500 mt-1">
          {subtitle}
        </p>
      )}
    </div>
  )
}
