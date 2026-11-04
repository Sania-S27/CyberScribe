// frontend/src/pages/admin/AdminOverview.jsx
import React, { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import axios from 'axios'
import {
  Cpu,
  Database,
  Building2,
  Layers,
  Activity,
  Flame,
  Radio,
  ArrowRight,
  RefreshCw,
  CheckCircle2,
  ShieldCheck,
  ShieldAlert,
  Lock,
  Network,
  Clock,
  FileCode2,
  Bell
} from 'lucide-react'
import StatCard from '../../components/common/StatCard'
import { StatusBadge } from '../../components/common/Badges'

const API_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8001'

export default function AdminOverview() {
  const [loading, setLoading] = useState(true)
  const [metrics, setMetrics] = useState({
    total_threats_ingested: 0,
    total_tenants: 0,
    total_threat_matches: 0,
    monitored_assets: 0,
    total_containment_actions: 0,
    system_status: 'Operational',
    active_collectors: '6 OSINT Feeds + NVD REST 2.0'
  })
  const [tenants, setTenants] = useState([])
  const [recentActions, setRecentActions] = useState([])
  const [refreshing, setRefreshing] = useState(false)

  const fetchAdminData = async (isManual = false) => {
    if (isManual) setRefreshing(true)
    const token = localStorage.getItem('access_token')
    if (!token) return

    try {
      // 1. Fetch exact admin metrics
      const mRes = await axios.get(`${API_URL}/admin/metrics`, {
        headers: { Authorization: `Bearer ${token}` }
      })
      if (mRes.data) setMetrics(mRes.data)

      // 2. Fetch tenant summary
      const tRes = await axios.get(`${API_URL}/admin/tenants`, {
        headers: { Authorization: `Bearer ${token}` }
      })
      if (tRes.data && Array.isArray(tRes.data.tenants)) {
        setTenants(tRes.data.tenants)
      }

      // 3. Fetch recent containment actions for workflow visibility
      const cRes = await axios.get(`${API_URL}/admin/containment/actions`, {
        headers: { Authorization: `Bearer ${token}` }
      })
      if (cRes.data && Array.isArray(cRes.data.actions)) {
        setRecentActions(cRes.data.actions.slice(0, 5))
      }
    } catch (err) {
      console.error('Failed to load admin overview metrics', err)
    } finally {
      setLoading(false)
      if (isManual) setRefreshing(false)
    }
  }

  useEffect(() => {
    fetchAdminData()
  }, [])

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800/80">
        <div>
          <h1 className="text-xl font-bold font-mono tracking-tight text-slate-100 flex items-center gap-2">
            <Cpu className="w-5 h-5 text-indigo-400" />
            Platform Security Operations &amp; Telemetry
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Cross-tenant threat intelligence, affected inventory, autonomous containment, and incident response.
          </p>
        </div>

        <button
          onClick={() => fetchAdminData(true)}
          disabled={refreshing}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-850 border border-slate-800 text-slate-300 hover:text-indigo-300 text-xs font-mono transition cursor-pointer disabled:opacity-50"
          title="Synchronize Platform Metrics"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* KPI Workflow Metric Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        <StatCard
          title="Ingested Threats"
          value={metrics.total_threats_ingested}
          icon={Database}
          accent="cyan"
          subtitle="OSINT feeds & NVD catalog"
        />
        <StatCard
          title="Monitored Assets"
          value={metrics.monitored_assets}
          icon={Cpu}
          accent="emerald"
          subtitle="Total inventory SBOMs"
        />
        <StatCard
          title="Vulnerability Matches"
          value={metrics.total_threat_matches}
          icon={Layers}
          accent="amber"
          subtitle="Cross-tenant correlations"
        />
        <StatCard
          title="Containment Actions"
          value={metrics.total_containment_actions}
          icon={Flame}
          accent="rose"
          subtitle="Autonomous & verified blocks"
        />
        <StatCard
          title="Active Tenants"
          value={metrics.total_tenants}
          icon={Building2}
          accent="purple"
          subtitle="Protected organizations"
        />
      </div>

      {/* Two Column Grid: Main Workflow (Span 2) & Pipeline Status (Span 1) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Tenant Protection Directory & Recent Containment Actions (Span 2) */}
        <div className="lg:col-span-2 space-y-6">
          {/* Tenant Organizations Table */}
          <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Building2 className="w-4 h-4 text-indigo-400" />
                <h2 className="text-xs font-mono uppercase tracking-wider font-bold text-slate-200">
                  Protected Organizations &amp; Exposure
                </h2>
              </div>
              <Link
                to="/admin/tenants"
                className="text-xs font-mono text-indigo-400 hover:text-indigo-300 flex items-center gap-1 transition"
              >
                Manage Tenants <ArrowRight className="w-3.5 h-3.5" />
              </Link>
            </div>

            {loading ? (
              <div className="py-10 text-center text-xs font-mono text-slate-500">
                Loading tenant telemetry...
              </div>
            ) : tenants.length === 0 ? (
              <div className="py-10 text-center text-xs font-mono text-slate-500">
                No registered tenants found in database.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="border-b border-slate-800 bg-slate-900/60 text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                      <th className="py-2.5 px-3">Organization</th>
                      <th className="py-2.5 px-3">SBOM Assets</th>
                      <th className="py-2.5 px-3">Correlated</th>
                      <th className="py-2.5 px-3">Confirmed Affected</th>
                      <th className="py-2.5 px-3">SOAR Webhook</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 text-xs font-mono">
                    {tenants.map((t) => (
                      <tr key={t.id} className="hover:bg-slate-900/40 transition">
                        <td className="py-3 px-3">
                          <span className="font-bold text-slate-200 block">{t.company_name}</span>
                          <span className="text-[10px] text-slate-500 truncate max-w-xs block">{t.id}</span>
                        </td>
                        <td className="py-3 px-3 text-cyan-300 font-bold">
                          {t.asset_count}
                        </td>
                        <td className="py-3 px-3 text-slate-300 font-bold">
                          {t.match_count}
                        </td>
                        <td className="py-3 px-3">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            t.active_affected_count > 0 
                              ? 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
                              : 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                          }`}>
                            {t.active_affected_count}
                          </span>
                        </td>
                        <td className="py-3 px-3">
                          {t.webhook_url ? (
                            <span className="text-emerald-400 flex items-center gap-1.5 text-[11px]">
                              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" /> Connected
                            </span>
                          ) : (
                            <span className="text-slate-500 text-[11px]">Unconfigured</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Recent Autonomous Containment Actions */}
          <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Flame className="w-4 h-4 text-rose-400" />
                <h2 className="text-xs font-mono uppercase tracking-wider font-bold text-slate-200">
                  Recent Containment &amp; Response Actions
                </h2>
              </div>
              <Link
                to="/admin/containment"
                className="text-xs font-mono text-indigo-400 hover:text-indigo-300 flex items-center gap-1 transition"
              >
                All Containment Actions <ArrowRight className="w-3.5 h-3.5" />
              </Link>
            </div>

            {loading ? (
              <div className="py-8 text-center text-xs font-mono text-slate-500">
                Loading containment history...
              </div>
            ) : recentActions.length === 0 ? (
              <div className="py-8 text-center text-xs font-mono text-slate-500">
                No active or historical containment actions recorded.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="border-b border-slate-800 bg-slate-900/60 text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                      <th className="py-2 px-3">Action ID</th>
                      <th className="py-2 px-3">Target Indicator</th>
                      <th className="py-2 px-3">Type</th>
                      <th className="py-2 px-3">Tenant</th>
                      <th className="py-2 px-3">Status</th>
                      <th className="py-2 px-3">Timestamp</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 text-xs font-mono">
                    {recentActions.map((a) => (
                      <tr key={a.id || a.action_id} className="hover:bg-slate-900/40 transition">
                        <td className="py-2.5 px-3 text-indigo-400 font-bold">
                          {a.action_id}
                        </td>
                        <td className="py-2.5 px-3 text-slate-200">
                          {a.indicator_value}
                        </td>
                        <td className="py-2.5 px-3 text-slate-400">
                          {a.action_type || 'BLOCK'}
                        </td>
                        <td className="py-2.5 px-3 text-slate-300">
                          {a.tenant_name || 'Campus Guide'}
                        </td>
                        <td className="py-2.5 px-3">
                          <StatusBadge status={a.status} />
                        </td>
                        <td className="py-2.5 px-3 text-[11px] text-slate-500">
                          {a.created_at || a.applied_at || 'Recent'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Platform Incident Posture & Dedicated Navigation */}
        <div className="space-y-6">
          {/* Incident Response Pipeline Status */}
          <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              <h2 className="text-xs font-mono uppercase tracking-wider font-bold text-slate-200">
                Incident Response Pipeline
              </h2>
            </div>

            <div className="space-y-2.5 font-mono text-xs">
              <div className="p-2.5 rounded-lg bg-slate-900/50 border border-slate-850 flex items-center justify-between">
                <span className="text-slate-400 text-[11px]">Threat Ingestion:</span>
                <span className="text-cyan-300 font-bold flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
                  Active
                </span>
              </div>

              <div className="p-2.5 rounded-lg bg-slate-900/50 border border-slate-850 flex items-center justify-between">
                <span className="text-slate-400 text-[11px]">SBOM Correlation:</span>
                <span className="text-emerald-400 font-bold flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                  Operational
                </span>
              </div>

              <div className="p-2.5 rounded-lg bg-slate-900/50 border border-slate-850 flex items-center justify-between">
                <span className="text-slate-400 text-[11px]">Containment Engine:</span>
                <span className="text-indigo-400 font-bold flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-indigo-400" />
                  Enforced
                </span>
              </div>

              <div className="p-2.5 rounded-lg bg-slate-900/50 border border-slate-850 flex items-center justify-between">
                <span className="text-slate-400 text-[11px]">SOAR Dispatch:</span>
                <span className="text-emerald-400 font-bold flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                  Connected
                </span>
              </div>

              <div className="p-2.5 rounded-lg bg-slate-900/50 border border-slate-850 flex items-center justify-between">
                <span className="text-slate-400 text-[11px]">Compliance Audit:</span>
                <span className="text-purple-400 font-bold flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-purple-400" />
                  Verified
                </span>
              </div>
            </div>
          </div>

          {/* Quick Operations Navigation */}
          <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-5 space-y-3">
            <h2 className="text-xs font-mono uppercase tracking-wider font-bold text-slate-200">
              Operations Center
            </h2>
            <div className="space-y-2 font-mono text-xs">
              <Link
                to="/admin/threats"
                className="w-full flex items-center justify-between p-2.5 rounded-lg bg-slate-900 hover:bg-slate-850 border border-slate-850 text-slate-300 hover:text-cyan-300 transition"
              >
                <span className="flex items-center gap-2">
                  <Radio className="w-3.5 h-3.5 text-cyan-400" />
                  Threat Intelligence Catalog
                </span>
                <ArrowRight className="w-3.5 h-3.5 text-slate-500" />
              </Link>

              <Link
                to="/admin/containment"
                className="w-full flex items-center justify-between p-2.5 rounded-lg bg-slate-900 hover:bg-slate-850 border border-slate-850 text-slate-300 hover:text-rose-300 transition"
              >
                <span className="flex items-center gap-2">
                  <Flame className="w-3.5 h-3.5 text-rose-400" />
                  Containment &amp; Rollback
                </span>
                <ArrowRight className="w-3.5 h-3.5 text-slate-500" />
              </Link>

              <Link
                to="/admin/integrations"
                className="w-full flex items-center justify-between p-2.5 rounded-lg bg-slate-900 hover:bg-slate-850 border border-slate-850 text-slate-300 hover:text-emerald-300 transition"
              >
                <span className="flex items-center gap-2">
                  <Network className="w-3.5 h-3.5 text-emerald-400" />
                  SOAR &amp; Email Integrations
                </span>
                <ArrowRight className="w-3.5 h-3.5 text-slate-500" />
              </Link>

              <Link
                to="/admin/audit"
                className="w-full flex items-center justify-between p-2.5 rounded-lg bg-slate-900 hover:bg-slate-850 border border-slate-850 text-slate-300 hover:text-purple-300 transition"
              >
                <span className="flex items-center gap-2">
                  <FileCode2 className="w-3.5 h-3.5 text-purple-400" />
                  Security Audit Logs
                </span>
                <ArrowRight className="w-3.5 h-3.5 text-slate-500" />
              </Link>

              <Link
                to="/admin/health"
                className="w-full flex items-center justify-between p-2.5 rounded-lg bg-slate-900 hover:bg-slate-850 border border-slate-850 text-slate-300 hover:text-indigo-300 transition"
              >
                <span className="flex items-center gap-2">
                  <Activity className="w-3.5 h-3.5 text-indigo-400" />
                  System Diagnostics &amp; Health
                </span>
                <ArrowRight className="w-3.5 h-3.5 text-slate-500" />
              </Link>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
