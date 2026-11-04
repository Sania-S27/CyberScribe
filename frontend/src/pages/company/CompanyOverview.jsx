// frontend/src/pages/company/CompanyOverview.jsx
import React, { useState, useEffect, useMemo } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import axios from 'axios'
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  ArrowRight,
  RefreshCw,
  Activity,
  Clock,
  Sparkles,
  ExternalLink,
  ChevronRight,
  FileText,
  FileCode,
  Wrench,
  Flame
} from 'lucide-react'
import StatCard from '../../components/common/StatCard'
import { SeverityBadge, StatusBadge, OutcomeBadge } from '../../components/common/Badges'

const API_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8001'

export default function CompanyOverview() {
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  
  // Data states from live backend scoped to authenticated tenant
  const [summary, setSummary] = useState({
    health_score: 100,
    active_affected: 0,
    review_required: 0,
    resolved: 0,
    not_affected: 0,
    total_correlated: 0
  })
  const [allMatches, setAllMatches] = useState([])
  const [containmentActions, setContainmentActions] = useState([])
  const [reportSummary, setReportSummary] = useState(null)
  const [notification, setNotification] = useState('')

  const navigate = useNavigate()

  const loadOverviewData = async (isManual = false) => {
    if (isManual) setRefreshing(true)
    const token = localStorage.getItem('access_token')
    if (!token) return

    try {
      // 1. Fetch matched threats scoped to authenticated tenant
      const matchesPromise = axios.get(`${API_URL}/threats/matches`, {
        params: { page: 1, page_size: 50, view: 'all' },
        headers: { Authorization: `Bearer ${token}` }
      }).catch(err => {
        console.warn('Matches fetch error', err)
        return { data: { matches: [], summary: null } }
      })

      // 2. Fetch tenant-scoped containment actions (response status)
      const actionsPromise = axios.get(`${API_URL}/tenants/containment/actions`, {
        headers: { Authorization: `Bearer ${token}` }
      }).catch(err => {
        console.warn('Actions fetch error', err)
        return { data: { actions: [] } }
      })

      // 3. Fetch tenant report posture summary
      const reportPromise = axios.get(`${API_URL}/tenants/reports/summary`, {
        headers: { Authorization: `Bearer ${token}` }
      }).catch(err => {
        console.warn('Report summary fetch error', err)
        return { data: null }
      })

      const [matchesRes, actionsRes, reportRes] = await Promise.all([
        matchesPromise,
        actionsPromise,
        reportPromise
      ])

      if (matchesRes.data) {
        if (matchesRes.data.summary) {
          setSummary(matchesRes.data.summary)
        }
        setAllMatches(matchesRes.data.matches || [])
      }

      if (actionsRes.data && Array.isArray(actionsRes.data.actions)) {
        setContainmentActions(actionsRes.data.actions)
      }

      if (reportRes.data) {
        setReportSummary(reportRes.data)
      }

      if (isManual) {
        setNotification('Tenant security posture synchronized successfully.')
        setTimeout(() => setNotification(''), 4000)
      }
    } catch (err) {
      console.error('Failed to load overview data', err)
    } finally {
      setLoading(false)
      if (isManual) setRefreshing(false)
    }
  }

  useEffect(() => {
    loadOverviewData()
  }, [])

  // 1. Threat Overview Metrics Calculation from Authoritative Backend Summary
  const threatOverview = useMemo(() => {
    const counts = summary.severity_counts || {}
    const totalCount = summary.total_correlated || summary.severity_total || allMatches.length
    const criticalCount = counts.critical !== undefined ? counts.critical : allMatches.filter(m => (m.severity || '').toLowerCase() === 'critical').length
    const highCount = counts.high !== undefined ? counts.high : allMatches.filter(m => (m.severity || '').toLowerCase() === 'high').length

    return {
      total: totalCount,
      critical: criticalCount,
      high: highCount
    }
  }, [allMatches, summary])

  // 2. Threat Distribution by Severity (Authoritative across all tenant records)
  const severityDistribution = useMemo(() => {
    let counts = summary.severity_counts
    let total = summary.total_correlated || summary.severity_total

    if (!counts || total === undefined) {
      counts = { critical: 0, high: 0, medium: 0, low: 0 }
      allMatches.forEach((m) => {
        const sev = (m.severity || 'medium').toLowerCase()
        if (counts[sev] !== undefined) {
          counts[sev]++
        } else {
          counts.medium++
        }
      })
      total = allMatches.length || 1
    }

    const safeTotal = total || 1
    return {
      counts: {
        critical: counts.critical || 0,
        high: counts.high || 0,
        medium: counts.medium || 0,
        low: counts.low || 0
      },
      percentages: {
        critical: Math.round(((counts.critical || 0) / safeTotal) * 100),
        high: Math.round(((counts.high || 0) / safeTotal) * 100),
        medium: Math.round(((counts.medium || 0) / safeTotal) * 100),
        low: Math.round(((counts.low || 0) / safeTotal) * 100)
      },
      total: total
    }
  }, [allMatches, summary])

  // 3. Recent Threats (Top 5 most relevant/recent)
  const recentThreats = useMemo(() => {
    return allMatches.slice(0, 5)
  }, [allMatches])

  // 4. Tenant Response Status (Response actions & remediation posture relevant to tenant)
  const tenantResponseStatus = useMemo(() => {
    const simulatedActions = containmentActions.filter(a => a.status === 'SIMULATED').length
    const pendingActions = containmentActions.filter(a => a.status === 'PENDING').length
    const rolledBackActions = containmentActions.filter(a => a.status === 'ROLLED_BACK').length
    const expiredActions = containmentActions.filter(a => a.status === 'EXPIRED').length
    const verifiedActions = containmentActions.filter(a => a.status === 'VERIFIED' || a.status === 'APPLIED').length
    const totalActions = containmentActions.length

    return {
      totalActions,
      simulatedActions,
      pendingActions,
      rolledBackActions,
      expiredActions,
      verifiedActions,
      resolvedThreats: summary.resolved,
      recentActions: containmentActions.slice(0, 3)
    }
  }, [containmentActions, summary])

  const healthScore = summary.health_score ?? reportSummary?.health_score ?? 100

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800/80">
        <div>
          <h1 className="text-xl font-bold font-mono tracking-tight text-slate-100 flex items-center gap-2.5">
            <ShieldCheck className="w-5 h-5 text-cyan-400" />
            Security Posture &amp; Threat Overview
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Live threat intelligence correlation, severity analysis, and tenant response status.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => loadOverviewData(true)}
            disabled={refreshing}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-850 border border-slate-800 text-slate-300 hover:text-cyan-300 text-xs font-mono transition cursor-pointer disabled:opacity-50"
            title="Synchronize Tenant Posture Telemetry"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh Posture
          </button>
        </div>
      </div>

      {notification && (
        <div className="p-3 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 text-xs font-mono flex items-center justify-between">
          <span>{notification}</span>
          <button onClick={() => setNotification('')} className="text-cyan-400 hover:text-cyan-200">&times;</button>
        </div>
      )}

      {/* 1. THREAT OVERVIEW: Stat Cards Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3.5">
        <StatCard
          title="Total Threats"
          value={threatOverview.total}
          icon={Activity}
          accent="cyan"
          subtitle="Correlated security advisories"
          onClick={() => navigate('/company/findings')}
        />
        <StatCard
          title="Critical Threats"
          value={threatOverview.critical}
          icon={ShieldAlert}
          accent="rose"
          subtitle="Immediate action recommended"
          onClick={() => navigate('/company/findings?view=active')}
        />
        <StatCard
          title="High Severity"
          value={threatOverview.high}
          icon={AlertTriangle}
          accent="amber"
          subtitle="Elevated vulnerability risk"
          onClick={() => navigate('/company/findings')}
        />
        <StatCard
          title="Confirmed Affected"
          value={summary.active_affected}
          icon={Clock}
          accent="rose"
          subtitle={`${summary.active_affected} active / ${summary.resolved} resolved`}
          onClick={() => navigate('/company/findings?view=active')}
        />
      </div>

      {/* 2. THREAT DISTRIBUTION & TENANT RESPONSE STATUS ROW */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Threat Distribution (Span 2) */}
        <div className="lg:col-span-2 bg-slate-950/80 border border-slate-800/80 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-xs font-mono uppercase tracking-wider font-bold text-slate-200 flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-cyan-400" />
                Threat Severity Distribution
              </h2>
              <p className="text-[11px] text-slate-400 font-mono mt-0.5">
                Breakdown of {severityDistribution.total} security advisories by CVSS rating
              </p>
            </div>
            <Link
              to="/company/analytics"
              className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1 transition"
            >
              Full Analytics <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          {/* Clean Distribution Progress Bar */}
          <div className="h-3 w-full bg-slate-900 rounded-full overflow-hidden flex">
            {severityDistribution.percentages.critical > 0 && (
              <div
                style={{ width: `${severityDistribution.percentages.critical}%` }}
                className="bg-rose-500 hover:bg-rose-400 transition-all"
                title={`Critical: ${severityDistribution.counts.critical} (${severityDistribution.percentages.critical}%)`}
              />
            )}
            {severityDistribution.percentages.high > 0 && (
              <div
                style={{ width: `${severityDistribution.percentages.high}%` }}
                className="bg-orange-500 hover:bg-orange-400 transition-all"
                title={`High: ${severityDistribution.counts.high} (${severityDistribution.percentages.high}%)`}
              />
            )}
            {severityDistribution.percentages.medium > 0 && (
              <div
                style={{ width: `${severityDistribution.percentages.medium}%` }}
                className="bg-amber-500 hover:bg-amber-400 transition-all"
                title={`Medium: ${severityDistribution.counts.medium} (${severityDistribution.percentages.medium}%)`}
              />
            )}
            {severityDistribution.percentages.low > 0 && (
              <div
                style={{ width: `${severityDistribution.percentages.low}%` }}
                className="bg-blue-500 hover:bg-blue-400 transition-all"
                title={`Low: ${severityDistribution.counts.low} (${severityDistribution.percentages.low}%)`}
              />
            )}
          </div>

          {/* Legend and Exact Counts */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono pt-1">
            <div className="p-2.5 rounded-lg bg-slate-900/40 border border-slate-850 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-rose-500" />
                <span className="text-slate-400">Critical</span>
              </div>
              <span className="text-slate-100 font-bold">{severityDistribution.counts.critical}</span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-900/40 border border-slate-850 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-orange-400" />
                <span className="text-slate-400">High</span>
              </div>
              <span className="text-slate-100 font-bold">{severityDistribution.counts.high}</span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-900/40 border border-slate-850 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-amber-400" />
                <span className="text-slate-400">Medium</span>
              </div>
              <span className="text-slate-100 font-bold">{severityDistribution.counts.medium}</span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-900/40 border border-slate-850 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-blue-400" />
                <span className="text-slate-400">Low</span>
              </div>
              <span className="text-slate-100 font-bold">{severityDistribution.counts.low}</span>
            </div>
          </div>
        </div>

        {/* Tenant Response Status (Span 1) */}
        <div className="bg-slate-950/80 border border-slate-800/80 rounded-xl p-5 space-y-4 flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Flame className="w-4 h-4 text-cyan-400" />
                <h2 className="text-xs font-mono uppercase tracking-wider font-bold text-slate-200">
                  Tenant Response Status
                </h2>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded font-bold bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">
                GUARDED
              </span>
            </div>

            <p className="text-[11px] text-slate-400 font-mono">
              Autonomous response actions and remediation execution status scoped to this organization.
            </p>

            <div className="space-y-2 font-mono text-xs pt-1">
              <div className="p-2.5 rounded-lg bg-slate-900/50 border border-slate-850 flex items-center justify-between">
                <span className="text-slate-400 flex items-center gap-2">
                  <Activity className="w-3.5 h-3.5 text-cyan-400" />
                  Active Staged Rules
                </span>
                <span className="text-cyan-300 font-semibold">{tenantResponseStatus.simulatedActions} Rules</span>
              </div>

              <div className="p-2.5 rounded-lg bg-slate-900/50 border border-slate-850 flex items-center justify-between">
                <span className="text-slate-400 flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  Resolved Vulnerabilities
                </span>
                <span className="text-emerald-400 font-semibold">{tenantResponseStatus.resolvedThreats} Fixed</span>
              </div>

              <div className="p-2.5 rounded-lg bg-slate-900/50 border border-slate-850 flex items-center justify-between">
                <span className="text-slate-400 flex items-center gap-2">
                  <Clock className="w-3.5 h-3.5 text-amber-400" />
                  Pending Review / Action
                </span>
                <span className="text-amber-400 font-semibold">{summary.review_required} Advisories</span>
              </div>
            </div>
          </div>

          <div className="pt-2 border-t border-slate-900 flex items-center justify-between text-[11px] font-mono text-slate-400">
            <span>{tenantResponseStatus.totalActions} total containment actions</span>
            <Link to="/company/containment" className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1">
              Manage Actions &rarr;
            </Link>
          </div>
        </div>
      </div>

      {/* 3. RECENT THREATS & THREAT REPORTS ROW */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Recent Correlated Threats (Span 2) */}
        <div className="lg:col-span-2 bg-slate-950/80 border border-slate-800/80 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-cyan-400" />
              <div>
                <h2 className="text-xs font-mono uppercase tracking-wider font-bold text-slate-200">
                  Recent Correlated Threats
                </h2>
                <p className="text-[11px] text-slate-400 font-mono">
                  Identified vulnerabilities matched with your monitored SBOM components
                </p>
              </div>
            </div>
            <Link
              to="/company/findings"
              className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1 transition"
            >
              View All ({allMatches.length}) <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          {loading ? (
            <div className="py-10 text-center text-xs font-mono text-slate-500">
              Loading recent threat findings...
            </div>
          ) : recentThreats.length === 0 ? (
            <div className="py-8 text-center space-y-2">
              <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto" />
              <p className="text-xs font-mono text-emerald-300 font-semibold">
                No active threat vulnerabilities currently matched.
              </p>
              <p className="text-[11px] font-mono text-slate-500">
                All monitored inventory components satisfy current vulnerability thresholds.
              </p>
            </div>
          ) : (
            <div className="space-y-2.5">
              {recentThreats.map((finding) => {
                const affectedSoftware = finding.matched_component
                  ? `${finding.matched_component}${finding.installed_version ? ` (${finding.installed_version})` : ''}`
                  : null

                return (
                  <div
                    key={finding.id}
                    className="p-3.5 rounded-lg bg-slate-900/50 hover:bg-slate-900 border border-slate-800/80 hover:border-slate-700 transition flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                  >
                    <div className="space-y-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-xs font-mono font-bold text-cyan-300">
                          {finding.cve_id || 'CVE-PENDING'}
                        </span>
                        <SeverityBadge severity={finding.severity} />
                        <OutcomeBadge outcome={finding.assessment_outcome} />
                        {finding.date && (
                          <span className="text-[10px] font-mono text-slate-500">
                            {finding.date}
                          </span>
                        )}
                      </div>
                      <p className="text-xs text-slate-200 font-medium truncate max-w-xl">
                        {finding.threat_title}
                      </p>
                      <p className="text-[11px] font-mono text-slate-400">
                        Affected Software: {affectedSoftware ? (
                          <span className="text-slate-300 font-semibold">{affectedSoftware}</span>
                        ) : (
                          <span className="text-slate-500 italic">Inventory Software Match</span>
                        )}
                      </p>
                    </div>

                    <Link
                      to={`/company/findings?search=${encodeURIComponent(finding.cve_id || finding.threat_title)}`}
                      className="flex-shrink-0 self-end sm:self-center px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-cyan-500/20 border border-slate-700 hover:border-cyan-500/40 text-slate-300 hover:text-cyan-300 text-xs font-mono transition"
                    >
                      Investigate
                    </Link>
                  </div>
                )
              })}
            </div>
          )}
        </div>

        {/* Threat Reports & STIX 2.1 Posture (Span 1) */}
        <div className="bg-slate-950/80 border border-slate-800/80 rounded-xl p-5 space-y-4 flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <FileText className="w-4 h-4 text-cyan-400" />
                <h2 className="text-xs font-mono uppercase tracking-wider font-bold text-slate-200">
                  Threat Reports &amp; STIX
                </h2>
              </div>
              <span className="inline-flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded font-bold bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">
                OASIS STIX 2.1
              </span>
            </div>

            <p className="text-[11px] text-slate-400 font-mono">
              Deterministic CVE assessment reports and OASIS STIX 2.1 threat intelligence bundles.
            </p>

            <div className="space-y-2 font-mono text-xs pt-1">
              <div className="p-2.5 rounded-lg bg-slate-900/50 border border-slate-850 flex items-center justify-between">
                <span className="text-slate-400">Total Monitored Assets:</span>
                <span className="text-slate-100 font-semibold">{reportSummary?.monitored_assets ?? 0} Packages</span>
              </div>

              <div className="p-2.5 rounded-lg bg-slate-900/50 border border-slate-850 flex items-center justify-between">
                <span className="text-slate-400">Correlated Threat Bundles:</span>
                <span className="text-cyan-300 font-semibold">{summary.total_correlated || allMatches.length} Exportable</span>
              </div>

              <div className="p-2.5 rounded-lg bg-slate-900/50 border border-slate-850 flex items-center justify-between">
                <span className="text-slate-400">Executive Briefing:</span>
                <span className="text-emerald-400 font-semibold">Ready for Export</span>
              </div>
            </div>
          </div>

          <div className="pt-3 border-t border-slate-900 space-y-2">
            <Link
              to="/company/reports"
              className="w-full flex items-center justify-center gap-2 py-2 rounded-lg bg-slate-900 hover:bg-slate-850 border border-slate-800 hover:border-cyan-500/30 text-slate-300 hover:text-cyan-300 text-xs font-mono transition"
            >
              <FileCode className="w-3.5 h-3.5 text-cyan-400" />
              Open Threat Reports Portal <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>
        </div>
      </div>
    </div>
  )
}
