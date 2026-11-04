// frontend/src/pages/company/CompanyContainment.jsx
import React, { useState, useEffect } from 'react'
import axios from 'axios'
import {
  ShieldAlert,
  Flame,
  Search,
  RefreshCw,
  Clock,
  Ban,
  CheckCircle2,
  Terminal,
  Activity,
  ChevronDown,
  ChevronUp,
  FileText,
  AlertTriangle,
  Info,
  RotateCcw
} from 'lucide-react'
import StatCard from '../../components/common/StatCard'
import { StatusBadge } from '../../components/common/Badges'

const API_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8001'

export default function CompanyContainment() {
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [actions, setActions] = useState([])
  const [statusFilter, setStatusFilter] = useState('ALL')
  const [searchQuery, setSearchQuery] = useState('')
  const [expandedActionId, setExpandedActionId] = useState(null)
  const [actionFeedback, setActionFeedback] = useState('')
  const [processingId, setProcessingId] = useState(null)

  const fetchContainmentData = async (isManual = false) => {
    if (isManual) setRefreshing(true)
    const token = localStorage.getItem('access_token')
    if (!token) return

    try {
      // Fetch tenant-isolated containment actions
      const actionsRes = await axios.get(`${API_URL}/tenants/containment/actions`, {
        headers: { Authorization: `Bearer ${token}` }
      })
      if (actionsRes.data && Array.isArray(actionsRes.data.actions)) {
        setActions(actionsRes.data.actions)
      } else {
        setActions([])
      }
    } catch (err) {
      console.error('Failed to load containment actions', err)
    } finally {
      setLoading(false)
      if (isManual) setRefreshing(false)
    }
  }

  useEffect(() => {
    fetchContainmentData()
  }, [])

  const toggleExpand = (id) => {
    setExpandedActionId(expandedActionId === id ? null : id)
  }

  const handleRollback = async (actionId) => {
    setProcessingId(actionId)
    setActionFeedback('')
    const token = localStorage.getItem('access_token')
    try {
      await axios.post(
        `${API_URL}/tenants/containment/actions/${actionId}/rollback`,
        {},
        { headers: { Authorization: `Bearer ${token}` } }
      )
      setActionFeedback(`Containment action ${actionId.slice(0, 8)} successfully rolled back.`)
      await fetchContainmentData()
    } catch (err) {
      setActionFeedback(err.response?.data?.detail || 'Failed to rollback action.')
    } finally {
      setProcessingId(null)
      setTimeout(() => setActionFeedback(''), 5000)
    }
  }

  // Filter actions
  const filteredActions = actions.filter((a) => {
    const matchesStatus = statusFilter === 'ALL' || (a.status || '').toUpperCase() === statusFilter.toUpperCase()
    const matchesSearch = !searchQuery.trim() || 
      (a.indicator_value || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
      (a.action_id || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
      (a.policy_rule || '').toLowerCase().includes(searchQuery.toLowerCase())
    return matchesStatus && matchesSearch
  })

  const stagedCount = actions.filter(a => a.status === 'SIMULATED').length
  const pendingCount = actions.filter(a => a.status === 'PENDING').length
  const verifiedCount = actions.filter(a => a.status === 'VERIFIED' || a.status === 'APPLIED').length
  const rolledBackCount = actions.filter(a => a.status === 'ROLLED_BACK').length
  const expiredCount = actions.filter(a => a.status === 'EXPIRED').length
  const releasedCount = rolledBackCount + expiredCount

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800/80">
        <div>
          <h1 className="text-xl font-bold font-mono tracking-tight text-slate-100 flex items-center gap-2">
            <Flame className="w-5 h-5 text-cyan-400" />
            Autonomous Threat Containment
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Active containment policies, automated isolation rules, and rollback safeguards.
          </p>
        </div>

        <button
          onClick={() => fetchContainmentData(true)}
          disabled={refreshing}
          className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-850 border border-slate-800 text-slate-400 hover:text-slate-200 transition self-start sm:self-center cursor-pointer"
          title="Refresh Containment Actions"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {actionFeedback && (
        <div className="p-3 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 text-xs font-mono flex items-center justify-between">
          <span>{actionFeedback}</span>
          <button onClick={() => setActionFeedback('')} className="text-cyan-400 hover:text-cyan-200 cursor-pointer">&times;</button>
        </div>
      )}

      {/* Containment Policy & Safeguards Bar */}
      <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-start sm:items-center gap-3">
          <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 flex-shrink-0">
            <Flame className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-bold uppercase text-slate-100">
                Autonomous Containment Policy
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
                GUARDRAIL STAGED
              </span>
            </div>
            <p className="text-xs text-slate-400 font-sans mt-0.5">
              Network isolation rules are evaluated against threat indicators and staged with automated TTL expiration and integrity validation.
            </p>
          </div>
        </div>
        <div className="hidden lg:flex items-center gap-4 text-xs font-mono text-slate-400 border-l border-slate-800 pl-4 flex-shrink-0">
          <div>
            <span className="text-slate-500 block text-[10px] uppercase">Confidence Gate</span>
            <span className="text-cyan-300 font-bold">&ge; 85.0% Required</span>
          </div>
          <div>
            <span className="text-slate-500 block text-[10px] uppercase">Rollback Safety</span>
            <span className="text-emerald-400 font-bold">Auto on Release</span>
          </div>
        </div>
      </div>

      {/* KPI Row */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        <StatCard
          title="Staged Containment Rules"
          value={stagedCount}
          icon={Activity}
          accent="cyan"
          subtitle="Active staged isolation rules"
        />
        <StatCard
          title="Pending Evaluation"
          value={pendingCount}
          icon={Clock}
          accent="amber"
          subtitle="Awaiting policy execution"
        />
        <StatCard
          title="Verified Active"
          value={verifiedCount}
          icon={CheckCircle2}
          accent="emerald"
          subtitle="Active host isolation verified"
        />
        <StatCard
          title="Rolled Back / Released"
          value={releasedCount}
          icon={ShieldAlert}
          accent="purple"
          subtitle={`${rolledBackCount} rolled back, ${expiredCount} expired TTL`}
        />
      </div>

      {/* Filters Bar */}
      <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-3.5 flex flex-col md:flex-row items-center justify-between gap-3">
        <div className="relative w-full md:w-80">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search indicator IP, rule, action ID..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/50"
          />
        </div>

        <div className="flex items-center gap-2 w-full md:w-auto">
          <span className="text-xs font-mono text-slate-400">Status:</span>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500/50"
          >
            <option value="ALL">All Statuses</option>
            <option value="SIMULATED">Simulated</option>
            <option value="PENDING">Pending</option>
            <option value="ROLLED_BACK">Rolled Back</option>
            <option value="EXPIRED">Expired</option>
          </select>
        </div>
      </div>

      {/* Actions Table */}
      <div className="bg-slate-950/80 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        {loading ? (
          <div className="py-16 text-center space-y-2">
            <RefreshCw className="w-6 h-6 text-cyan-400 animate-spin mx-auto" />
            <p className="text-xs font-mono text-slate-400">Loading simulated actions...</p>
          </div>
        ) : filteredActions.length === 0 ? (
          <div className="py-16 text-center space-y-2">
            <ShieldAlert className="w-8 h-8 text-slate-600 mx-auto" />
            <p className="text-sm font-mono text-slate-300 font-bold">No containment actions found.</p>
            <p className="text-xs font-mono text-slate-500">Autonomous containment will trigger when verified high-confidence IOCs match inventory.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-900/60 text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                  <th className="py-3 px-4">Action ID</th>
                  <th className="py-3 px-4">Target Indicator</th>
                  <th className="py-3 px-4">Action Type</th>
                  <th className="py-3 px-4">Policy Decision</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">TTL Countdown</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-xs font-mono">
                {filteredActions.map((action) => {
                  const isExpanded = expandedActionId === action.id
                  return (
                    <React.Fragment key={action.id}>
                      <tr 
                        onClick={() => toggleExpand(action.id)}
                        className="hover:bg-slate-900/40 transition cursor-pointer"
                      >
                        <td className="py-3.5 px-4 font-bold text-cyan-300 whitespace-nowrap">
                          {action.action_id || action.id.slice(0, 12)}
                        </td>
                        <td className="py-3.5 px-4 font-bold text-slate-200">
                          {action.indicator_value}
                        </td>
                        <td className="py-3.5 px-4 text-slate-300">
                          {action.action_type}
                        </td>
                        <td className="py-3.5 px-4">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            action.policy_decision === 'QUALIFIED'
                              ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                              : 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
                          }`}>
                            {action.policy_decision}
                          </span>
                        </td>
                        <td className="py-3.5 px-4">
                          <StatusBadge status={action.status} />
                        </td>
                        <td className="py-3.5 px-4 text-slate-400">
                          {action.ttl_seconds ? `${action.ttl_seconds}s` : 'Standard TTL'}
                        </td>
                        <td className="py-3.5 px-4 text-right space-x-2">
                          {action.status === 'SIMULATED' && (
                            <button
                              onClick={(e) => {
                                e.stopPropagation()
                                handleRollback(action.id)
                              }}
                              disabled={processingId === action.id}
                              className="px-2.5 py-1 rounded bg-slate-900 hover:bg-rose-500/10 border border-slate-800 hover:border-rose-500/30 text-slate-400 hover:text-rose-400 transition text-[11px] disabled:opacity-50 cursor-pointer"
                              title="Rollback containment rule"
                            >
                              <RotateCcw className="w-3 h-3 inline mr-1" />
                              Rollback
                            </button>
                          )}
                          <button
                            onClick={(e) => {
                              e.stopPropagation()
                              toggleExpand(action.id)
                            }}
                            className="p-1 rounded bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200"
                          >
                            {isExpanded ? <ChevronUp className="w-3.5 h-3.5 inline" /> : <ChevronDown className="w-3.5 h-3.5 inline" />}
                          </button>
                        </td>
                      </tr>

                      {/* Expandable Drawer for Execution Output */}
                      {isExpanded && (
                        <tr className="bg-slate-900/40 border-b border-slate-800">
                          <td colSpan={7} className="p-4 space-y-3 font-mono">
                            <div className="space-y-1.5">
                              <div className="flex items-center justify-between">
                                <div className="text-[11px] font-bold uppercase tracking-wider text-cyan-400">
                                  {action.is_simulated ? 'Simulated Firewall Adapter Telemetry (Dry-Run Sandbox)' : 'Live Firewall Executor Telemetry'}
                                </div>
                                <span className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase tracking-wider ${
                                  action.is_simulated
                                    ? 'bg-amber-500/15 text-amber-300 border border-amber-500/30'
                                    : 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                                }`}>
                                  {action.adapter_mode || (action.is_simulated ? 'DRY_RUN / SIMULATED' : 'LIVE_HOST_ENFORCEMENT')}
                                </span>
                              </div>
                              {action.is_simulated && (
                                <p className="text-[11px] text-slate-400 font-sans">
                                  Notice: Operation evaluated in a dry-run sandbox. No modifications were made to physical host firewalls, Windows Defender, or nftables rulesets.
                                </p>
                              )}
                              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 text-xs font-mono leading-relaxed overflow-x-auto whitespace-pre-wrap">
                                {action.execution_output || `[SIMULATION] Dry-run rule evaluated: BLOCK ${action.indicator_value}/32. No netfilter modification.`}
                              </div>
                              {action.verification_output && (
                                <div className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800 text-slate-300 text-xs font-mono">
                                  <span className="text-slate-500 block text-[10px] uppercase font-sans font-semibold mb-0.5">Verification Telemetry:</span>
                                  {action.verification_output}
                                </div>
                              )}
                            </div>

                            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-[11px] pt-1">
                              <div className="p-2 rounded bg-slate-950 border border-slate-850">
                                <span className="text-slate-500 block">Policy Rule:</span>
                                <span className="text-slate-300">{action.policy_rule || 'STRUCTURED_IOC_ELIGIBILITY'}</span>
                              </div>
                              <div className="p-2 rounded bg-slate-950 border border-slate-850">
                                <span className="text-slate-500 block">Expires At:</span>
                                <span className="text-slate-300">{action.expires_at || 'N/A'}</span>
                              </div>
                              <div className="p-2 rounded bg-slate-950 border border-slate-850">
                                <span className="text-slate-500 block">Verified At:</span>
                                <span className="text-slate-300">{action.verified_at || (action.is_simulated ? 'Simulated Verification' : 'Pending Verification')}</span>
                              </div>
                              <div className="p-2 rounded bg-slate-950 border border-slate-850">
                                <span className="text-slate-500 block">Adapter Mode:</span>
                                <span className={`font-bold ${action.is_simulated ? 'text-amber-300' : 'text-emerald-400'}`}>
                                  {action.adapter_mode || (action.is_simulated ? 'DRY_RUN / SIMULATED' : 'LIVE_HOST_ENFORCEMENT')}
                                </span>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
