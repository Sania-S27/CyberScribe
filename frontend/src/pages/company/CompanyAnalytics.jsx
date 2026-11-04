// frontend/src/pages/company/CompanyAnalytics.jsx
import React, { useState, useEffect } from 'react'
import axios from 'axios'
import {
  BarChart3,
  PieChart,
  ShieldAlert,
  ShieldCheck,
  Layers,
  Clock,
  CheckCircle2,
  AlertTriangle,
  ArrowUpRight,
  RefreshCw
} from 'lucide-react'
import StatCard from '../../components/common/StatCard'

const API_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8001'

export default function CompanyAnalytics() {
  const [loading, setLoading] = useState(true)
  const [matches, setMatches] = useState([])
  const [summary, setSummary] = useState({
    active_affected: 0,
    review_required: 0,
    resolved: 0,
    not_affected: 0,
    total_correlated: 0,
    health_score: 100,
    top_components: [],
    component_exposure: {}
  })

  useEffect(() => {
    const fetchAnalytics = async () => {
      try {
        const token = localStorage.getItem('access_token')
        const res = await axios.get(`${API_URL}/threats/matches`, {
          params: { page: 1, page_size: 50, view: 'all' },
          headers: { Authorization: `Bearer ${token}` }
        })

        if (res.data) {
          setMatches(res.data.matches || [])
          if (res.data.summary) {
            setSummary({
              ...res.data.summary,
              top_components: res.data.summary.top_components || res.data.top_components || [],
              component_exposure: res.data.summary.component_exposure || res.data.component_exposure || {}
            })
          } else if (res.data.top_components) {
            setSummary(prev => ({
              ...prev,
              top_components: res.data.top_components || [],
              component_exposure: res.data.component_exposure || {}
            }))
          }
        }
      } catch (err) {
        console.error('Failed to load analytics data', err)
      } finally {
        setLoading(false)
      }
    }

    fetchAnalytics()
  }, [])

  // Authoritative severity metrics calculation from backend summary
  let severityCounts = summary.severity_counts
  if (!severityCounts) {
    severityCounts = { critical: 0, high: 0, medium: 0, low: 0 }
    matches.forEach((m) => {
      const sev = (m.severity || 'medium').toLowerCase()
      if (severityCounts[sev] !== undefined) {
        severityCounts[sev]++
      }
    })
  }

  // Distinct component exposure calculation
  // 1. Prefer authoritative backend summary calculated across the tenant's full inventory
  // 2. Fall back to distinct active threats per component (excluding NOT_AFFECTED and RESOLVED)
  let topPackages = []
  if (summary.top_components && Array.isArray(summary.top_components) && summary.top_components.length > 0) {
    topPackages = summary.top_components.slice(0, 6)
  } else if (summary.component_exposure && typeof summary.component_exposure === 'object' && Object.keys(summary.component_exposure).length > 0) {
    topPackages = Object.entries(summary.component_exposure)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6)
  } else {
    const compThreatMap = {}
    matches.forEach((m) => {
      const outcome = (m.assessment_outcome || '').toUpperCase()
      const st = (m.status || '').toUpperCase()
      if (outcome === 'NOT_AFFECTED' || st === 'RESOLVED' || st === 'PATCHED' || st === 'MITIGATED') return
      const comp = m.matched_component || 'Other'
      const threatKey = m.threat_id || m.cve_id || m.id
      if (!compThreatMap[comp]) {
        compThreatMap[comp] = new Set()
      }
      compThreatMap[comp].add(threatKey)
    })
    const packageExposure = {}
    Object.entries(compThreatMap).forEach(([comp, threatSet]) => {
      packageExposure[comp] = threatSet.size
    })
    topPackages = Object.entries(packageExposure)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6)
  }

  const totalSev = summary.total_correlated || summary.severity_total || Object.values(severityCounts).reduce((a, b) => a + b, 0) || 1
  const critPct = Math.round(((severityCounts.critical || 0) / totalSev) * 100)
  const highPct = Math.round(((severityCounts.high || 0) / totalSev) * 100)
  const medPct = Math.round(((severityCounts.medium || 0) / totalSev) * 100)
  const lowPct = Math.round(((severityCounts.low || 0) / totalSev) * 100)

  const resolutionRate = summary.active_affected + summary.resolved > 0
    ? Math.round((summary.resolved / (summary.active_affected + summary.resolved)) * 100)
    : 100

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800/80">
        <div>
          <h1 className="text-xl font-bold font-mono tracking-tight text-slate-100 flex items-center gap-2">
            <BarChart3 className="w-5 h-5 text-cyan-400" />
            Vulnerability Telemetry & Threat Analytics
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Statistical breakdown of vulnerability severity, component exposure, and resolution velocity.
          </p>
        </div>
      </div>

      {/* KPI Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Resolution Velocity"
          value={`${resolutionRate}%`}
          icon={CheckCircle2}
          accent="emerald"
          subtitle={`${summary.resolved} resolved vs ${summary.active_affected} unresolved`}
        />
        <StatCard
          title="Critical & High"
          value={severityCounts.critical + severityCounts.high}
          icon={ShieldAlert}
          accent="rose"
          subtitle={`${severityCounts.critical} Critical / ${severityCounts.high} High`}
        />
        <StatCard
          title="Posture Health"
          value={`${summary.health_score}%`}
          icon={ShieldCheck}
          accent="cyan"
          subtitle="Enterprise Tenant Score"
        />
        <StatCard
          title="Total Correlated"
          value={summary.total_correlated || matches.length}
          icon={Layers}
          accent="purple"
          subtitle="Audit ledger detections"
        />
      </div>

      {/* Analytics Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity Distribution Chart */}
        <div className="bg-slate-950/80 border border-slate-800/80 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-xs font-mono uppercase tracking-wider font-bold text-slate-200">
              Severity Distribution (Real Telemetry)
            </h2>
            <span className="text-[11px] font-mono text-slate-400">Total: {totalSev}</span>
          </div>

          <div className="space-y-3 pt-2">
            <div>
              <div className="flex justify-between text-xs font-mono mb-1">
                <span className="text-rose-400 font-semibold flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-rose-500" /> Critical ({severityCounts.critical})
                </span>
                <span className="text-slate-400">{critPct}%</span>
              </div>
              <div className="h-2 w-full bg-slate-900 rounded-full overflow-hidden">
                <div style={{ width: `${critPct}%` }} className="h-full bg-rose-500 rounded-full" />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs font-mono mb-1">
                <span className="text-orange-400 font-semibold flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-orange-400" /> High ({severityCounts.high})
                </span>
                <span className="text-slate-400">{highPct}%</span>
              </div>
              <div className="h-2 w-full bg-slate-900 rounded-full overflow-hidden">
                <div style={{ width: `${highPct}%` }} className="h-full bg-orange-400 rounded-full" />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs font-mono mb-1">
                <span className="text-amber-400 font-semibold flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-amber-400" /> Medium ({severityCounts.medium})
                </span>
                <span className="text-slate-400">{medPct}%</span>
              </div>
              <div className="h-2 w-full bg-slate-900 rounded-full overflow-hidden">
                <div style={{ width: `${medPct}%` }} className="h-full bg-amber-400 rounded-full" />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs font-mono mb-1">
                <span className="text-blue-400 font-semibold flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-blue-400" /> Low ({severityCounts.low})
                </span>
                <span className="text-slate-400">{lowPct}%</span>
              </div>
              <div className="h-2 w-full bg-slate-900 rounded-full overflow-hidden">
                <div style={{ width: `${lowPct}%` }} className="h-full bg-blue-400 rounded-full" />
              </div>
            </div>
          </div>
        </div>

        {/* Component Exposure Ranking */}
        <div className="bg-slate-950/80 border border-slate-800/80 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-xs font-mono uppercase tracking-wider font-bold text-slate-200">
              Top Impacted Software Components
            </h2>
            <span className="text-[11px] font-mono text-slate-400">By Vulnerability Count</span>
          </div>

          {topPackages.length === 0 ? (
            <p className="text-xs font-mono text-slate-500 py-6 text-center">
              No component exposures found.
            </p>
          ) : (
            <div className="space-y-3 pt-2">
              {topPackages.map(([pkg, count]) => {
                const maxCount = topPackages[0][1] || 1
                const pct = Math.round((count / maxCount) * 100)
                return (
                  <div key={pkg} className="space-y-1">
                    <div className="flex justify-between text-xs font-mono">
                      <span className="text-cyan-300 font-semibold">{pkg}</span>
                      <span className="text-slate-400">{count} {count === 1 ? 'threat' : 'threats'}</span>
                    </div>
                    <div className="h-2 w-full bg-slate-900 rounded-full overflow-hidden">
                      <div 
                        style={{ width: `${pct}%` }} 
                        className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 rounded-full" 
                      />
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      </div>

      {/* Assessment Decision Matrix */}
      <div className="bg-slate-950/80 border border-slate-800/80 rounded-xl p-5 space-y-4">
        <h2 className="text-xs font-mono uppercase tracking-wider font-bold text-slate-200">
          Deterministic Assessment Outcome Breakdown
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-2">
          <div className="p-4 rounded-xl bg-slate-900/40 border border-rose-500/20 space-y-1">
            <div className="text-xs font-mono text-rose-400 uppercase font-semibold">
              Confirmed [AFFECTED]
            </div>
            <div className="text-2xl font-bold font-mono text-rose-300">
              {summary.active_affected}
            </div>
            <p className="text-[11px] font-mono text-slate-400">
              Installed version directly satisfies vulnerable constraint. Requires active patching or mitigations.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/40 border border-amber-500/20 space-y-1">
            <div className="text-xs font-mono text-amber-400 uppercase font-semibold">
              Ambiguous [NEEDS REVIEW]
            </div>
            <div className="text-2xl font-bold font-mono text-amber-300">
              {summary.review_required}
            </div>
            <p className="text-[11px] font-mono text-slate-400">
              Unspecified or complex constraint requiring manual SOC validation.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/40 border border-emerald-500/20 space-y-1">
            <div className="text-xs font-mono text-emerald-400 uppercase font-semibold">
              Excluded [NOT AFFECTED]
            </div>
            <div className="text-2xl font-bold font-mono text-emerald-300">
              {summary.not_affected}
            </div>
            <p className="text-[11px] font-mono text-slate-400">
              Installed version outside vulnerable range. Retained in database and audit history.
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}
