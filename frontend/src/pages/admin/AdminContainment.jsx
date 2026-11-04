// frontend/src/pages/admin/AdminContainment.jsx
import React, { useState, useEffect } from 'react'
import axios from 'axios'
import {
  Flame,
  Search,
  RefreshCw,
  Clock,
  Ban,
  Activity,
  Terminal,
  ChevronDown,
  ChevronUp,
  ShieldAlert,
  Building2,
  RotateCcw,
  CheckCircle2,
  AlertTriangle,
  X,
  Lock,
  ArrowRight
} from 'lucide-react'
import StatCard from '../../components/common/StatCard'
import { StatusBadge } from '../../components/common/Badges'

const API_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8001'

export default function AdminContainment() {
  const [actions, setActions] = useState([])
  const [loading, setLoading] = useState(true)
  const [searchQuery, setSearchQuery] = useState('')
  const [statusFilter, setStatusFilter] = useState('ALL')
  const [expandedId, setExpandedId] = useState(null)
  const [refreshing, setRefreshing] = useState(false)
  const [adapterMode, setAdapterMode] = useState('SIMULATED')

  // Modal and action execution states
  const [triggerModalOpen, setTriggerModalOpen] = useState(false)
  const [rollbackModalAction, setRollbackModalAction] = useState(null)
  const [confirmedSafetyCheck, setConfirmedSafetyCheck] = useState(false)
  const [isSubmittingTrigger, setIsSubmittingTrigger] = useState(false)
  const [isSubmittingRollback, setIsSubmittingRollback] = useState(false)
  const [alertBanner, setAlertBanner] = useState(null)

  const fetchActions = async (isManual = false) => {
    if (isManual) setRefreshing(true)
    const token = localStorage.getItem('access_token')
    if (!token) return

    try {
      const res = await axios.get(`${API_URL}/admin/containment/actions`, {
        headers: { Authorization: `Bearer ${token}` }
      })
      if (res.data) {
        if (Array.isArray(res.data.actions)) {
          setActions(res.data.actions)
        }
        if (res.data.mode) {
          setAdapterMode(res.data.mode)
        }
      }
    } catch (err) {
      console.error('Failed to load containment actions', err)
      setAlertBanner({
        type: 'error',
        message: err.response?.data?.detail || 'Failed to communicate with containment backend.'
      })
    } finally {
      setLoading(false)
      if (isManual) setRefreshing(false)
    }
  }

  useEffect(() => {
    fetchActions()
  }, [])

  const toggleExpand = (id) => {
    setExpandedId(expandedId === id ? null : id)
  }

  // Handle Manual Containment Trigger
  const handleTriggerContainment = async () => {
    setIsSubmittingTrigger(true)
    setAlertBanner(null)
    const token = localStorage.getItem('access_token')

    try {
      const res = await axios.post(
        `${API_URL}/admin/containment/actions/trigger`,
        {
          target_ip: '192.168.56.101',
          target_port: 8000,
          direction: 'inbound',
          protocol: 'tcp',
          reason: 'Admin demonstration containment trigger'
        },
        {
          headers: { Authorization: `Bearer ${token}` }
        }
      )

      setAlertBanner({
        type: 'success',
        message: res.data?.message || `Containment action ${res.data?.action_id} successfully created with status ${res.data?.status}.`,
        details: res.data
      })
      setTriggerModalOpen(false)
      setConfirmedSafetyCheck(false)
      await fetchActions()
    } catch (err) {
      const errMsg = err.response?.data?.detail || err.message || 'Containment trigger failed.'
      setAlertBanner({
        type: 'error',
        message: errMsg
      })
    } finally {
      setIsSubmittingTrigger(false)
    }
  }

  // Handle Containment Rollback
  const handleRollback = async () => {
    if (!rollbackModalAction) return
    setIsSubmittingRollback(true)
    setAlertBanner(null)
    const token = localStorage.getItem('access_token')

    try {
      const res = await axios.post(
        `${API_URL}/admin/containment/actions/${rollbackModalAction.action_id}/rollback`,
        {},
        {
          headers: { Authorization: `Bearer ${token}` }
        }
      )

      setAlertBanner({
        type: 'success',
        message: res.data?.message || `Rule CyberScribe_${rollbackModalAction.action_id} successfully rolled back.`,
        details: res.data
      })
      setRollbackModalAction(null)
      await fetchActions()
    } catch (err) {
      const errMsg = err.response?.data?.detail || err.message || 'Rollback execution failed.'
      setAlertBanner({
        type: 'error',
        message: errMsg
      })
    } finally {
      setIsSubmittingRollback(false)
    }
  }

  const eligibleForRollback = (status) => {
    return ['SIMULATED', 'APPLIED', 'VERIFIED', 'RECEIVED', 'DISPATCHED'].includes(status)
  }

  const filtered = actions.filter((a) => {
    const q = searchQuery.toLowerCase()
    const matchesSearch = !q ||
      (a.indicator_value || '').toLowerCase().includes(q) ||
      (a.action_id || '').toLowerCase().includes(q) ||
      (a.tenant_name || '').toLowerCase().includes(q) ||
      (a.policy_rule || '').toLowerCase().includes(q)
    const matchesStatus = statusFilter === 'ALL' || (a.status || '').toUpperCase() === statusFilter.toUpperCase()
    return matchesSearch && matchesStatus
  })

  const simulatedCount = actions.filter(a => a.status === 'SIMULATED').length
  const activeCount = actions.filter(a => ['SIMULATED', 'APPLIED', 'VERIFIED'].includes(a.status)).length
  const rejectedCount = actions.filter(a => a.status === 'REJECTED').length

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800/80">
        <div>
          <h1 className="text-xl font-bold font-mono tracking-tight text-slate-100 flex items-center gap-2">
            <Flame className="w-5 h-5 text-indigo-400" />
            Platform Autonomous Containment Monitor
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Cross-tenant policy qualification, deterministic rules, and containment lifecycle tracking.
          </p>
        </div>

        <div className="flex items-center gap-2.5 self-start sm:self-center">
          <button
            onClick={() => {
              setAlertBanner(null)
              setConfirmedSafetyCheck(false)
              setTriggerModalOpen(true)
            }}
            disabled={isSubmittingTrigger}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-rose-600/20 hover:bg-rose-600/30 border border-rose-500/40 text-rose-300 hover:text-rose-200 text-xs font-mono font-semibold transition cursor-pointer disabled:opacity-50 shadow-sm"
            title="Manual Containment Trigger (Admin Demo / Override)"
          >
            <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
            <span>Trigger Containment</span>
          </button>

          <button
            onClick={() => fetchActions(true)}
            disabled={refreshing}
            className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-400 hover:text-slate-200 transition"
            title="Refresh Containment Status"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Primary Workflow Notice */}
      <div className="bg-slate-950/70 border border-slate-800/80 rounded-xl p-3 flex items-center justify-between gap-3 text-xs font-mono text-slate-400">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          <span>
            <strong className="text-slate-200">Primary Workflow:</strong> Automated threat ingestion and deterministic policy qualification orchestrate real-time containment. Manual controls provide admin demonstration and emergency recovery fallback with verified safety guardrails.
          </span>
        </div>
        <div className="hidden lg:flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-[11px] text-cyan-300 font-bold whitespace-nowrap">
          <span>Engine: {adapterMode}</span>
        </div>
      </div>

      {/* Real Backend Alert Banner */}
      {alertBanner && (
        <div className={`p-4 rounded-xl border flex items-start justify-between gap-3 font-mono text-xs animate-in fade-in duration-200 ${
          alertBanner.type === 'success'
            ? 'bg-emerald-950/40 border-emerald-500/30 text-emerald-200'
            : 'bg-rose-950/40 border-rose-500/30 text-rose-200'
        }`}>
          <div className="flex items-start gap-2.5">
            {alertBanner.type === 'success' ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
            ) : (
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
            )}
            <div className="space-y-1">
              <p className="font-bold">{alertBanner.message}</p>
              {alertBanner.details?.execution_output && (
                <pre className="text-[11px] opacity-80 whitespace-pre-wrap max-h-24 overflow-y-auto bg-black/30 p-2 rounded">
                  {alertBanner.details.execution_output}
                </pre>
              )}
            </div>
          </div>
          <button
            onClick={() => setAlertBanner(null)}
            className="text-slate-400 hover:text-slate-200 p-0.5 rounded cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        <StatCard
          title="Containment Actions"
          value={actions.filter(a => ['SIMULATED', 'APPLIED', 'VERIFIED', 'ROLLED_BACK'].includes(a.status)).length}
          icon={Activity}
          accent="cyan"
          subtitle="Enforced & staged actions"
        />
        <StatCard
          title="Policy Rejections"
          value={rejectedCount}
          icon={Ban}
          accent="rose"
          subtitle="Confidence/recency fail"
        />
        <StatCard
          title="Total Evaluated"
          value={actions.length}
          icon={Flame}
          accent="purple"
          subtitle="Platform-wide ledger"
        />
        <StatCard
          title="Safety Policy"
          value="ENFORCED"
          icon={ShieldAlert}
          accent="emerald"
          subtitle="Tenant isolation & verification"
        />
      </div>

      {/* Filters Bar */}
      <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-3.5 flex flex-col sm:flex-row items-center justify-between gap-3">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search IP, action ID, tenant..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500/50"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <span className="text-xs font-mono text-slate-400">Status:</span>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-200 focus:outline-none focus:border-indigo-500/50"
          >
            <option value="ALL">All Statuses</option>
            <option value="SIMULATED">Simulated</option>
            <option value="APPLIED">Applied</option>
            <option value="VERIFIED">Verified</option>
            <option value="PENDING">Pending</option>
            <option value="REJECTED">Rejected</option>
            <option value="ROLLED_BACK">Rolled Back</option>
            <option value="EXPIRED">Expired</option>
          </select>
        </div>
      </div>

      {/* Containment Table */}
      <div className="bg-slate-950/80 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        {loading ? (
          <div className="py-16 text-center space-y-2">
            <RefreshCw className="w-6 h-6 text-indigo-400 animate-spin mx-auto" />
            <p className="text-xs font-mono text-slate-400">Loading containment actions...</p>
          </div>
        ) : filtered.length === 0 ? (
          <div className="py-16 text-center space-y-2">
            <Flame className="w-8 h-8 text-slate-600 mx-auto" />
            <p className="text-sm font-mono text-slate-300 font-bold">No containment actions found.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-900/60 text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                  <th className="py-3 px-4">Action ID</th>
                  <th className="py-3 px-4">Tenant Scope</th>
                  <th className="py-3 px-4">Indicator (IP)</th>
                  <th className="py-3 px-4">Action Type</th>
                  <th className="py-3 px-4">Policy Decision</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Applied At</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-xs font-mono">
                {filtered.map((action) => {
                  const isExpanded = expandedId === action.id
                  const canRollback = eligibleForRollback(action.status)
                  return (
                    <React.Fragment key={action.id}>
                      <tr
                        onClick={() => toggleExpand(action.id)}
                        className="hover:bg-slate-900/40 transition cursor-pointer"
                      >
                        <td className="py-3.5 px-4 font-bold text-indigo-300">
                          <div className="flex items-center gap-1.5">
                            {isExpanded ? <ChevronUp className="w-3.5 h-3.5 text-slate-400" /> : <ChevronDown className="w-3.5 h-3.5 text-slate-400" />}
                            <span className="truncate max-w-[130px]">{action.action_id}</span>
                          </div>
                        </td>
                        <td className="py-3.5 px-4 text-slate-200">
                          {action.tenant_name}
                        </td>
                        <td className="py-3.5 px-4 font-bold text-slate-100">
                          {action.indicator_value}
                        </td>
                        <td className="py-3.5 px-4 text-slate-300">
                          {action.action_type}
                        </td>
                        <td className="py-3.5 px-4">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            action.policy_decision === 'QUALIFIED'
                              ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30'
                              : 'bg-rose-500/15 text-rose-300 border border-rose-500/30'
                          }`}>
                            {action.policy_decision}
                          </span>
                        </td>
                        <td className="py-3.5 px-4">
                          <StatusBadge status={action.status} />
                        </td>
                        <td className="py-3.5 px-4 text-slate-400">
                          {action.applied_at || action.created_at || 'Pending'}
                        </td>
                        <td className="py-3.5 px-4 text-right">
                          <div className="flex items-center justify-end gap-2">
                            {canRollback && (
                              <button
                                onClick={(e) => {
                                  e.stopPropagation()
                                  setRollbackModalAction(action)
                                }}
                                disabled={isSubmittingRollback}
                                className="px-2.5 py-1 rounded bg-rose-500/15 hover:bg-rose-500/25 border border-rose-500/40 text-rose-300 text-[11px] font-mono transition flex items-center gap-1 cursor-pointer disabled:opacity-50"
                                title="Rollback containment rule"
                              >
                                <RotateCcw className="w-3 h-3" />
                                <span>Rollback</span>
                              </button>
                            )}
                            <button
                              onClick={(e) => {
                                e.stopPropagation()
                                toggleExpand(action.id)
                              }}
                              className="p-1 rounded bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200"
                              title="Toggle Diagnostic Telemetry"
                            >
                              {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                            </button>
                          </div>
                        </td>
                      </tr>

                      {/* Expandable Diagnostic Drawer */}
                      {isExpanded && (
                        <tr className="bg-slate-900/60 border-b border-slate-800">
                          <td colSpan={8} className="p-4 space-y-3 font-mono text-xs">
                            <div className="flex items-center justify-between">
                              <span className="text-indigo-400 font-bold uppercase text-[11px] flex items-center gap-1.5">
                                <Terminal className="w-3.5 h-3.5" /> Adapter Execution &amp; Verification Telemetry
                              </span>
                              {canRollback && (
                                <button
                                  onClick={(e) => {
                                    e.stopPropagation()
                                    setRollbackModalAction(action)
                                  }}
                                  disabled={isSubmittingRollback}
                                  className="px-2.5 py-1 rounded bg-rose-500/15 hover:bg-rose-500/25 border border-rose-500/40 text-rose-300 text-[11px] font-mono transition flex items-center gap-1 cursor-pointer disabled:opacity-50"
                                >
                                  <RotateCcw className="w-3 h-3" />
                                  <span>Rollback Action</span>
                                </button>
                              )}
                            </div>

                            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 font-mono text-xs overflow-x-auto whitespace-pre-wrap">
                              {action.execution_output || action.error_message || `[SIMULATION] Rule for ${action.indicator_value} staged in safe telemetry mode.`}
                            </div>

                            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-[11px]">
                              <div className="p-2 rounded bg-slate-950 border border-slate-850">
                                <span className="text-slate-500 block">Policy Rule:</span>
                                <span className="text-slate-300">{action.policy_rule || 'STRUCTURED_IOC'}</span>
                              </div>
                              <div className="p-2 rounded bg-slate-950 border border-slate-850">
                                <span className="text-slate-500 block">Target Scope:</span>
                                <span className="text-slate-300">Port 8000 (TCP, Inbound)</span>
                              </div>
                              <div className="p-2 rounded bg-slate-950 border border-slate-850">
                                <span className="text-slate-500 block">TTL Countdown:</span>
                                <span className="text-slate-300">{action.ttl_seconds}s</span>
                              </div>
                              <div className="p-2 rounded bg-slate-950 border border-slate-850">
                                <span className="text-slate-500 block">Adapter Engine:</span>
                                <span className="text-cyan-300 font-bold">{action.rule_spec?.adapter || adapterMode}</span>
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

      {/* Confirmation Modal: Trigger Containment */}
      {triggerModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700/80 rounded-2xl max-w-lg w-full p-6 shadow-2xl font-mono text-xs space-y-5 animate-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2 text-rose-400 font-bold text-sm">
                <ShieldAlert className="w-5 h-5" />
                <span>Confirm Demonstration Containment</span>
              </div>
              <button
                onClick={() => setTriggerModalOpen(false)}
                disabled={isSubmittingTrigger}
                className="text-slate-400 hover:text-slate-200 p-1 rounded"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <p className="text-slate-300 leading-relaxed">
              You are about to manually trigger host containment for demonstration purposes. This will invoke the active containment adapter using identical policy validation, executor tokens, and verification logic as the automated pipeline.
            </p>

            {/* Target Spec Summary */}
            <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-2 text-slate-200">
              <div className="grid grid-cols-2 gap-2 text-[11px]">
                <div>
                  <span className="text-slate-500 block">Target IPv4:</span>
                  <span className="font-bold text-rose-300">192.168.56.101</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Target Port:</span>
                  <span className="font-bold text-slate-100">8000 (TCP)</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Traffic Direction:</span>
                  <span className="font-bold text-slate-100">Inbound (Exploit Block)</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Target Service:</span>
                  <span className="font-bold text-cyan-300">Campus Guide Backend</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Engine Mode:</span>
                  <span className="font-bold text-indigo-300">{adapterMode}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Rule Owner:</span>
                  <span className="text-slate-300">CyberScribe Managed</span>
                </div>
              </div>
            </div>

            {/* Safety Confirmation Checkbox */}
            <label className="flex items-start gap-2.5 p-3 rounded-lg bg-slate-950/60 border border-slate-800 cursor-pointer">
              <input
                type="checkbox"
                checked={confirmedSafetyCheck}
                onChange={(e) => setConfirmedSafetyCheck(e.target.checked)}
                className="mt-0.5 rounded border-slate-700 text-rose-600 focus:ring-rose-500 cursor-pointer"
              />
              <span className="text-[11px] text-slate-300 leading-normal">
                I verify that this action targets the authorized Fedora lab VM (192.168.56.101) on port 8000.
              </span>
            </label>

            {/* Action Buttons */}
            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={() => setTriggerModalOpen(false)}
                disabled={isSubmittingTrigger}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-750 text-slate-300 text-xs font-semibold cursor-pointer disabled:opacity-50"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleTriggerContainment}
                disabled={!confirmedSafetyCheck || isSubmittingTrigger}
                className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-semibold text-xs transition cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed shadow-md"
              >
                {isSubmittingTrigger ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Applying Containment...</span>
                  </>
                ) : (
                  <>
                    <ShieldAlert className="w-3.5 h-3.5" />
                    <span>Apply Containment</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Confirmation Modal: Rollback Action */}
      {rollbackModalAction && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700/80 rounded-2xl max-w-lg w-full p-6 shadow-2xl font-mono text-xs space-y-5 animate-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2 text-indigo-400 font-bold text-sm">
                <RotateCcw className="w-5 h-5" />
                <span>Confirm Containment Rollback</span>
              </div>
              <button
                onClick={() => setRollbackModalAction(null)}
                disabled={isSubmittingRollback}
                className="text-slate-400 hover:text-slate-200 p-1 rounded"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <p className="text-slate-300 leading-relaxed">
              Rollback will delete the exact firewall rule <span className="text-cyan-300 font-bold">CyberScribe_{rollbackModalAction.action_id}</span> created by CyberScribe and independently verify its complete absence.
            </p>

            {/* Target Spec Summary */}
            <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-2 text-slate-200">
              <div className="grid grid-cols-2 gap-2 text-[11px]">
                <div>
                  <span className="text-slate-500 block">Action ID:</span>
                  <span className="font-bold text-indigo-300">{rollbackModalAction.action_id}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Current Status:</span>
                  <span className="font-bold text-amber-300">{rollbackModalAction.status}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Target IP:</span>
                  <span className="font-bold text-slate-100">{rollbackModalAction.indicator_value}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Target Port / Direction:</span>
                  <span className="font-bold text-slate-100">8000 (TCP, Inbound)</span>
                </div>
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={() => setRollbackModalAction(null)}
                disabled={isSubmittingRollback}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-750 text-slate-300 text-xs font-semibold cursor-pointer disabled:opacity-50"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleRollback}
                disabled={isSubmittingRollback}
                className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-xs transition cursor-pointer disabled:opacity-50 shadow-md"
              >
                {isSubmittingRollback ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Executing Rollback...</span>
                  </>
                ) : (
                  <>
                    <RotateCcw className="w-3.5 h-3.5" />
                    <span>Confirm &amp; Rollback</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
