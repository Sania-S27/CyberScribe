// frontend/src/components/common/Badges.jsx
import React from 'react'
import { AlertTriangle, ShieldCheck, HelpCircle, CheckCircle2, Clock, Ban, Activity } from 'lucide-react'

export function SeverityBadge({ severity }) {
  const s = (severity || 'medium').toLowerCase()
  
  if (s === 'critical') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-semibold uppercase bg-rose-500/15 text-rose-400 border border-rose-500/30">
        <span className="w-1.5 h-1.5 rounded-full bg-rose-500 animate-pulse" />
        Critical
      </span>
    )
  }
  if (s === 'high') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-semibold uppercase bg-orange-500/15 text-orange-400 border border-orange-500/30">
        <span className="w-1.5 h-1.5 rounded-full bg-orange-400" />
        High
      </span>
    )
  }
  if (s === 'medium') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-semibold uppercase bg-amber-500/15 text-amber-400 border border-amber-500/30">
        <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
        Medium
      </span>
    )
  }
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-semibold uppercase bg-blue-500/15 text-blue-400 border border-blue-500/30">
      <span className="w-1.5 h-1.5 rounded-full bg-blue-400" />
      Low
    </span>
  )
}

export function StatusBadge({ status }) {
  const st = (status || 'OPEN').toUpperCase()

  if (st === 'VERIFIED') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-medium uppercase bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
        <CheckCircle2 className="w-3 h-3 text-emerald-400" />
        Verified
      </span>
    )
  }
  if (st === 'APPLIED' || st === 'ACTIVE') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-medium uppercase bg-indigo-500/15 text-indigo-400 border border-indigo-500/30">
        <ShieldCheck className="w-3 h-3 text-indigo-400" />
        Applied
      </span>
    )
  }
  if (st === 'RESOLVED' || st === 'PATCHED' || st === 'MITIGATED') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-medium uppercase bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
        <CheckCircle2 className="w-3 h-3 text-emerald-400" />
        Resolved
      </span>
    )
  }
  if (st === 'IN_PROGRESS') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-medium uppercase bg-sky-500/15 text-sky-400 border border-sky-500/30">
        <Clock className="w-3 h-3 text-sky-400" />
        In Progress
      </span>
    )
  }
  if (st === 'SIMULATED') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-medium uppercase bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
        <Activity className="w-3 h-3 text-cyan-400" />
        Simulated
      </span>
    )
  }
  if (st === 'REJECTED' || st === 'FAILED') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-medium uppercase bg-rose-500/15 text-rose-400 border border-rose-500/30">
        <Ban className="w-3 h-3 text-rose-400" />
        {st}
      </span>
    )
  }
  if (st === 'ROLLED_BACK' || st === 'EXPIRED') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-medium uppercase bg-purple-500/15 text-purple-400 border border-purple-500/30">
        <Clock className="w-3 h-3 text-purple-400" />
        {st}
      </span>
    )
  }
  // Default OPEN / UNMITIGATED
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-medium uppercase bg-amber-500/15 text-amber-300 border border-amber-500/30">
      <AlertTriangle className="w-3 h-3 text-amber-400" />
      Open
    </span>
  )
}

export function OutcomeBadge({ outcome }) {
  const o = (outcome || 'NEEDS_REVIEW').toUpperCase()

  if (o === 'AFFECTED') {
    return (
      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-[11px] font-mono font-semibold bg-rose-500/15 text-rose-400 border border-rose-500/30">
        <AlertTriangle className="w-3 h-3 text-rose-400" />
        AFFECTED
      </span>
    )
  }
  if (o === 'NOT_AFFECTED') {
    return (
      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-[11px] font-mono font-semibold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
        <ShieldCheck className="w-3 h-3 text-emerald-400" />
        NOT AFFECTED
      </span>
    )
  }
  return (
    <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-[11px] font-mono font-semibold bg-amber-500/15 text-amber-300 border border-amber-500/30">
      <HelpCircle className="w-3 h-3 text-amber-400" />
      NEEDS REVIEW
    </span>
  )
}
