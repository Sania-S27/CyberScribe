// frontend/src/pages/company/CompanyContainment.jsx
import React, { useState, useEffect } from 'react'
import axios from 'axios'
import {
  ShieldAlert,
  Flame,
  Search,
  RefreshCw,
  Clock,
  CheckCircle2,
  Terminal,
  ChevronDown,
  ChevronUp,
  AlertTriangle,
  RotateCcw
} from 'lucide-react'
import { StatusBadge } from '../../components/common/Badges'

const API_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8001'

export default function CompanyContainment() {
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [loadError, setLoadError] = useState(null)
  const [actions, setActions] = useState([])
  const [backendStats, setBackendStats] = useState(null)
  const [historyStats, setHistoryStats] = useState(null)
  const [statusFilter, setStatusFilter] = useState('ALL')
  const [searchQuery, setSearchQuery] = useState('')
  const [expandedActionId, setExpandedActionId] = useState(null)
  const [actionFeedback, setActionFeedback] = useState('')
  const [processingId, setProcessingId] = useState(null)

  const fetchContainmentData = async (isManual = false) => {
    if (isManual) setRefreshing(true)
    const token = localStorage.getItem('access_token')
    if (!token) {
      setLoadError('Authentication required. Please sign in to retrieve containment state.')
      setLoading(false)
      if (isManual) setRefreshing(false)
      return
    }

    try {
      // Fetch tenant-isolated containment actions and authoritative metrics
      const actionsRes = await axios.get(`${API_URL}/tenants/containment/actions`, {
        headers: { Authorization: `Bearer ${token}` }
      })
      if (actionsRes.data && Array.isArray(actionsRes.data.actions)) {
        setActions(actionsRes.data.actions)
        if (actionsRes.data.stats) {
          setBackendStats(actionsRes.data.stats)
        }
        if (actionsRes.data.history_stats) {
          setHistoryStats(actionsRes.data.history_stats)
        }
        setLoadError(null)
      } else {
        throw new Error('Invalid response structure received from containment API.')
      }
    } catch (err) {
      console.error('Failed to load containment actions', err)
      const errorMsg = err.response?.data?.detail || err.message || 'Failed to determine containment state from backend.'
      setLoadError(errorMsg)
    } finally {
      setLoading(false)
      if (isManual) setRefreshing(false)
    }
  }

  useEffect(() => {
    fetchContainmentData()
    // Periodic refresh to capture background containment execution and verification
    const pollInterval = setInterval(() => {
      fetchContainmentData()
    }, 8000)
    return () => clearInterval(pollInterval)
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

  const handleVerify = async (actionId) => {
    setProcessingId(actionId)
    setActionFeedback('')
    const token = localStorage.getItem('access_token')
    try {
      const res = await axios.post(
        `${API_URL}/tenants/containment/actions/${actionId}/verify`,
        {},
        { headers: { Authorization: `Bearer ${token}` } }
      )
      const msg = res.data?.message || `Rule verified active on firewall (${actionId.slice(0, 8)}).`
      setActionFeedback(msg)
      await fetchContainmentData()
    } catch (err) {
      setActionFeedback(err.response?.data?.detail || 'Failed to verify active rule.')
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

  // Authoritative containment history metrics derived from persisted state / API stats
  const rolledBackCount = backendStats?.rolled_back ?? actions.filter(a => (a.status || '').toUpperCase() === 'ROLLED_BACK').length
  const totalActions = historyStats?.total_actions ?? actions.length
  const successfullyVerified = historyStats?.successfully_verified ?? actions.filter(a => a.verified_at || (a.status || '').toUpperCase() === 'VERIFIED').length
  const historyRolledBack = historyStats?.rolled_back ?? rolledBackCount
  const historyFailed = historyStats?.failed ?? actions.filter(a => (a.status || '').toUpperCase() === 'FAILED' || !!a.error_message).length
  const historySimulated = historyStats?.simulated ?? actions.filter(a => a.is_simulated || (a.execution_mode || '').toUpperCase() === 'SIMULATION').length

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

      {loadError && (
        <div className="p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs font-mono flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>Containment telemetry unavailable: {loadError}</span>
          </div>
          <button
            onClick={() => fetchContainmentData(true)}
            className="px-2.5 py-1 rounded bg-rose-500/20 hover:bg-rose-500/30 border border-rose-500/40 text-rose-200 text-[11px] font-bold cursor-pointer transition hover:bg-rose-500/40"
          >
            Retry
          </button>
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

      {/* Compact Containment History Section */}
      <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-4 space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
            <Clock className="w-3.5 h-3.5 text-purple-400" />
            Containment History & Audit Telemetry
          </span>
          <span className="text-[10px] font-mono text-slate-500">Cumulative Lifecycle Records</span>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 font-mono">
          <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800/80">
            <span className="text-[11px] text-slate-400 block uppercase font-medium">Total Actions</span>
            <span className="text-lg font-bold text-slate-100 mt-0.5 block">{loadError ? '—' : totalActions}</span>
          </div>
          <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800/80">
            <span className="text-[11px] text-emerald-400/90 block uppercase font-medium">Successfully Verified</span>
            <span className="text-lg font-bold text-emerald-400 mt-0.5 block">{loadError ? '—' : successfullyVerified}</span>
          </div>
          <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800/80">
            <span className="text-[11px] text-purple-400/90 block uppercase font-medium">Rolled Back</span>
            <span className="text-lg font-bold text-purple-400 mt-0.5 block">{loadError ? '—' : historyRolledBack}</span>
          </div>
          <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800/80">
            <span className="text-[11px] text-rose-400/90 block uppercase font-medium">Failed</span>
            <span className="text-lg font-bold text-rose-400 mt-0.5 block">{loadError ? '—' : historyFailed}</span>
          </div>
          <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800/80">
            <span className="text-[11px] text-cyan-400/90 block uppercase font-medium">Simulated</span>
            <span className="text-lg font-bold text-cyan-300 mt-0.5 block">{loadError ? '—' : historySimulated}</span>
          </div>
        </div>
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
            <option value="VERIFIED">Verified Active</option>
            <option value="SIMULATED">Simulated</option>
            <option value="PENDING">Pending</option>
            <option value="ROLLED_BACK">Rolled Back</option>
            <option value="EXPIRED">Expired</option>
            <option value="FAILED">Failed</option>
          </select>
        </div>
      </div>

      {/* Recent Containment Activity Table */}
      <div className="bg-slate-950/80 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
          <span className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
            <Terminal className="w-3.5 h-3.5 text-cyan-400" />
            Recent Containment Activity & History
          </span>
          <span className="text-[11px] font-mono text-slate-500">
            {filteredActions.length} {filteredActions.length === 1 ? 'record' : 'records'}
          </span>
        </div>
        {loading ? (
          <div className="py-16 text-center space-y-2">
            <RefreshCw className="w-6 h-6 text-cyan-400 animate-spin mx-auto" />
            <p className="text-xs font-mono text-slate-400">Loading containment actions...</p>
          </div>
        ) : loadError ? (
          <div className="py-16 text-center space-y-2">
            <AlertTriangle className="w-8 h-8 text-rose-500 mx-auto" />
            <p className="text-sm font-mono text-rose-300 font-bold">Containment Telemetry Unavailable</p>
            <p className="text-xs font-mono text-slate-500 max-w-md mx-auto">{loadError}</p>
          </div>
        ) : filteredActions.length === 0 ? (
          <div className="py-16 text-center space-y-2">
            <ShieldAlert className="w-8 h-8 text-slate-600 mx-auto" />
            <p className="text-sm font-mono text-slate-300 font-bold">No containment actions found.</p>
            <p className="text-xs font-mono text-slate-500">Autonomous containment will trigger when verified high-confidence IOCs match inventory.</p>
          </div>
        ) : (
          <div className="overflow-x-auto w-full">
            <table className="w-full text-left border-collapse">
              <thead className="bg-slate-900/70 border-b border-slate-800">
                <tr className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                  <th className="py-3.5 px-4 font-semibold whitespace-nowrap align-middle">Action ID</th>
                  <th className="py-3.5 px-4 font-semibold whitespace-nowrap align-middle">Target Indicator</th>
                  <th className="py-3.5 px-4 font-semibold whitespace-nowrap align-middle">Action Type</th>
                  <th className="py-3.5 px-4 font-semibold whitespace-nowrap align-middle">Mode</th>
                  <th className="py-3.5 px-4 font-semibold whitespace-nowrap align-middle">Verification</th>
                  <th className="py-3.5 px-4 font-semibold whitespace-nowrap align-middle">Current Status</th>
                  <th className="py-3.5 px-4 font-semibold whitespace-nowrap align-middle text-right">Actions</th>
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
                          <span className="block text-[10px] font-normal text-slate-500">{action.indicator_type || 'ipv4'}</span>
                        </td>
                        <td className="py-3.5 px-4 text-slate-300">
                          {action.action_type}
                        </td>
                        <td className="py-3.5 px-4">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            action.execution_mode === 'LIVE' || !action.is_simulated
                              ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                              : 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30'
                          }`}>
                            {action.execution_mode || (action.is_simulated ? 'SIMULATION' : 'LIVE')}
                          </span>
                        </td>
                        <td className="py-3.5 px-4">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            action.verification_status === 'VERIFIED'
                              ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                              : action.verification_status === 'FAILED'
                              ? 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
                              : 'bg-slate-800 text-slate-400 border border-slate-700'
                          }`}>
                            {action.verification_status || (action.verified_at ? 'VERIFIED' : (action.is_simulated ? 'N/A (SIM)' : 'UNVERIFIED'))}
                          </span>
                        </td>
                        <td className="py-3.5 px-4">
                          <StatusBadge status={action.status} />
                        </td>
                        <td className="py-3.5 px-4 text-right space-x-2">
                          {['SIMULATED', 'VERIFIED', 'APPLIED'].includes(action.status) && (
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
                          {['VERIFIED', 'APPLIED'].includes(action.status) && (
                            <button
                              onClick={(e) => {
                                e.stopPropagation()
                                handleVerify(action.id)
                              }}
                              disabled={processingId === action.id}
                              className="px-2.5 py-1 rounded bg-slate-900 hover:bg-emerald-500/10 border border-slate-800 hover:border-emerald-500/30 text-slate-400 hover:text-emerald-400 transition text-[11px] disabled:opacity-50 cursor-pointer"
                              title="Verify active host firewall rule"
                            >
                              <CheckCircle2 className="w-3 h-3 inline mr-1" />
                              Verify
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
                              {action.error_message && (
                                <div className="p-2.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs font-mono">
                                  <span className="text-rose-400 block text-[10px] uppercase font-sans font-semibold mb-0.5">Failure Diagnostic:</span>
                                  {action.error_message}
                                </div>
                              )}
                            </div>

                            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-[11px] pt-1">
                              <div className="p-2 rounded bg-slate-950 border border-slate-850">
                                <span className="text-slate-500 block">Execution Result:</span>
                                <span className="text-slate-300 font-bold">{action.execution_result || action.status}</span>
                              </div>
                              <div className="p-2 rounded bg-slate-950 border border-slate-850">
                                <span className="text-slate-500 block">Created At:</span>
                                <span className="text-slate-300">{action.created_at || 'N/A'}</span>
                              </div>
                              <div className="p-2 rounded bg-slate-950 border border-slate-850">
                                <span className="text-slate-500 block">Verified At:</span>
                                <span className="text-slate-300">{action.verified_at || (action.is_simulated ? 'N/A (Simulated)' : 'Pending')}</span>
                              </div>
                              <div className="p-2 rounded bg-slate-950 border border-slate-850">
                                <span className="text-slate-500 block">Rolled Back At:</span>
                                <span className="text-slate-300">{action.rolled_back_at || 'Active / Not Rolled Back'}</span>
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
