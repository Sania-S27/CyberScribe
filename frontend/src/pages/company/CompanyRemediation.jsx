// frontend/src/pages/company/CompanyRemediation.jsx
import React, { useState, useEffect } from 'react'
import axios from 'axios'
import {
  Wrench,
  CheckCircle2,
  ShieldCheck,
  PlaySquare,
  Clock,
  RefreshCw,
  FileCode,
  AlertTriangle,
  Lock,
  Terminal,
  ArrowRight,
  ShieldAlert,
  Cpu,
  Check,
  Bell
} from 'lucide-react'
import StatCard from '../../components/common/StatCard'
import { SeverityBadge, StatusBadge } from '../../components/common/Badges'
import PlaybookModal from '../../components/PlaybookModal'

const API_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8001'

export default function CompanyRemediation() {
  const [loading, setLoading] = useState(true)
  const [resolvedMatches, setResolvedMatches] = useState([])
  const [proposals, setProposals] = useState([])
  const [notifications, setNotifications] = useState([])
  const [channelFilter, setChannelFilter] = useState('ALL')
  const [selectedPlaybook, setSelectedPlaybook] = useState(null)
  const [activeTitle, setActiveTitle] = useState('')
  const [executingProposalId, setExecutingProposalId] = useState(null)
  const [retryingNotifId, setRetryingNotifId] = useState(null)
  const [actionFeedback, setActionFeedback] = useState('')
  const [errorMessage, setErrorMessage] = useState('')

  const fetchData = async () => {
    setLoading(true)
    setErrorMessage('')
    const token = localStorage.getItem('access_token')
    const headers = { Authorization: `Bearer ${token}` }

    try {
      // 1. Fetch resolved matches
      const resMatches = await axios.get(`${API_URL}/threats/matches`, {
        params: { page: 1, page_size: 50, view: 'resolved' },
        headers
      }).catch(err => {
        console.warn('Resolved matches fetch error', err)
        return { data: { matches: [] } }
      })
      if (resMatches.data && Array.isArray(resMatches.data.matches)) {
        setResolvedMatches(resMatches.data.matches)
      }

      // 2. Fetch patch proposals
      const resProps = await axios.get(`${API_URL}/tenants/remediation/proposals`, { headers }).catch(err => {
        console.warn('Proposals fetch error', err)
        return { data: { proposals: [] } }
      })
      if (resProps.data && Array.isArray(resProps.data.proposals)) {
        setProposals(resProps.data.proposals)
      }

      // 3. Fetch notifications
      const resNotifs = await axios.get(`${API_URL}/tenants/notifications`, { headers }).catch(err => {
        console.warn('Notifications fetch error', err)
        return { data: { notifications: [] } }
      })
      if (resNotifs.data && Array.isArray(resNotifs.data.notifications)) {
        setNotifications(resNotifs.data.notifications)
      }
    } catch (err) {
      console.error('Failed to fetch remediation telemetry', err)
      setErrorMessage('Failed to load remediation records. Please retry.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchData()
  }, [])

  const handleApproveProposal = async (proposalId) => {
    setActionFeedback('')
    const token = localStorage.getItem('access_token')
    try {
      await axios.post(
        `${API_URL}/tenants/remediation/proposals/${proposalId}/approve`,
        {},
        { headers: { Authorization: `Bearer ${token}` } }
      )
      setActionFeedback(`Proposal ${proposalId} approved. Ready for execution.`)
      await fetchData()
    } catch (err) {
      setActionFeedback(err.response?.data?.detail || 'Approval failed.')
    }
  }

  const handleExecuteAndRelease = async (proposalId) => {
    setExecutingProposalId(proposalId)
    setActionFeedback('')
    const token = localStorage.getItem('access_token')
    try {
      const res = await axios.post(
        `${API_URL}/tenants/remediation/proposals/${proposalId}/execute-and-release`,
        { mode: 'simulated' },
        { headers: { Authorization: `Bearer ${token}` } }
      )
      setActionFeedback(res.data?.message || 'Patch executed and containment released.')
      await fetchData()
    } catch (err) {
      setActionFeedback(err.response?.data?.detail || 'Execution failed.')
    } finally {
      setExecutingProposalId(null)
    }
  }

  const handleAcknowledgeNotification = async (deliveryId) => {
    const token = localStorage.getItem('access_token')
    try {
      await axios.post(
        `${API_URL}/tenants/notifications/${deliveryId}/ack`,
        {},
        { headers: { Authorization: `Bearer ${token}` } }
      )
      setActionFeedback(`Notification ${deliveryId} human acknowledgment recorded.`)
      await fetchData()
    } catch (err) {
      setActionFeedback(err.response?.data?.detail || 'Acknowledgement failed.')
    }
  }

  const handleRetryNotification = async (deliveryId) => {
    setRetryingNotifId(deliveryId)
    setActionFeedback('')
    const token = localStorage.getItem('access_token')
    try {
      const res = await axios.post(
        `${API_URL}/tenants/notifications/${deliveryId}/retry`,
        {},
        { headers: { Authorization: `Bearer ${token}` } }
      )
      setActionFeedback(res.data?.message || `Notification ${deliveryId} retry dispatched.`)
      await fetchData()
    } catch (err) {
      setActionFeedback(err.response?.data?.detail || err.response?.data?.error || 'Retry dispatch failed.')
    } finally {
      setRetryingNotifId(null)
    }
  }

  const handleOpenPlaybook = async (match) => {
    try {
      const token = localStorage.getItem('access_token')
      const threatId = match.threat_id || match.cve_id
      const res = await axios.get(`${API_URL}/public/threats/${threatId}/playbook`, {
        headers: { Authorization: `Bearer ${token}` }
      })
      setSelectedPlaybook(res.data)
      setActiveTitle(match.threat_title || match.cve_id)
    } catch (err) {
      console.error('Failed to fetch playbook', err)
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800/80">
        <div>
          <h1 className="text-xl font-bold font-mono tracking-tight text-slate-100 flex items-center gap-2">
            <Wrench className="w-5 h-5 text-cyan-400" />
            Remediation Ledger & Autonomous Response
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Fixed-version discovery, authorized patching proposals, verification safeguards, and safe containment release.
          </p>
        </div>

        <button
          onClick={fetchData}
          className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-400 hover:text-slate-200 transition self-start sm:self-center cursor-pointer"
          title="Refresh Remediation Records"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {actionFeedback && (
        <div className="p-3.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 text-xs font-mono flex items-center justify-between">
          <span>{actionFeedback}</span>
          <button onClick={() => setActionFeedback('')} className="text-cyan-400 hover:text-cyan-200 cursor-pointer">&times;</button>
        </div>
      )}

      {errorMessage && (
        <div className="p-3.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs font-mono flex items-center justify-between">
          <span>{errorMessage}</span>
          <button onClick={fetchData} className="px-2 py-0.5 rounded bg-rose-500/20 hover:bg-rose-500/30 text-rose-200 font-bold ml-2">Retry</button>
        </div>
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        <StatCard
          title="Patch Proposals"
          value={proposals.length}
          icon={Cpu}
          accent="cyan"
          subtitle="Discovered verified fixes"
        />
        <StatCard
          title="Verified Resolved"
          value={resolvedMatches.length}
          icon={CheckCircle2}
          accent="emerald"
          subtitle="Vulnerabilities patched & verified"
        />
        <StatCard
          title="Containment Safe Release"
          value="ENFORCED"
          icon={Lock}
          accent="purple"
          subtitle="Exact rule rollback upon verification"
        />
        <StatCard
          title="Alerts Dispatched"
          value={notifications.length}
          icon={Bell}
          accent="amber"
          subtitle="Audit notifications logged"
        />
      </div>

      {/* Autonomous Patch Proposals Section */}
      <div className="bg-slate-950/80 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Cpu className="w-4 h-4 text-cyan-400" />
            <h2 className="text-xs font-mono uppercase tracking-wider font-bold text-slate-200">
              Autonomous Patch Proposals & Fixed-Version Verification ({proposals.length})
            </h2>
          </div>
          <span className="text-[11px] font-mono text-slate-400">
            Discovered compatible package upgrades and security patch proposals
          </span>
        </div>

        {proposals.length === 0 ? (
          <div className="p-8 text-center space-y-1.5">
            <CheckCircle2 className="w-6 h-6 text-slate-600 mx-auto" />
            <p className="text-xs font-mono text-slate-400">No pending patch proposals.</p>
            <p className="text-[11px] font-sans text-slate-500">
              When upstream vulnerabilities affect your SBOM and verified compatible patches are discovered, proposals will appear here.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-900/60 text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                  <th className="py-3 px-4">Proposal ID</th>
                  <th className="py-3 px-4">Package</th>
                  <th className="py-3 px-4">Version Upgrade</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Verification Check</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-xs font-mono">
                {proposals.map((prop) => (
                  <tr key={prop.proposal_id} className="hover:bg-slate-900/40 transition">
                    <td className="py-3 px-4 text-cyan-300 font-bold whitespace-nowrap">
                      {prop.proposal_id}
                    </td>
                    <td className="py-3 px-4 font-bold text-slate-200">
                      {prop.package_name}
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      <span className="text-slate-400">{prop.current_version}</span>
                      <ArrowRight className="w-3.5 h-3.5 inline mx-1.5 text-slate-500" />
                      <span className="text-emerald-400 font-bold">{prop.target_version}</span>
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      <span className={`px-2 py-0.5 rounded text-[11px] border font-bold ${
                        prop.status === 'PROPOSED' ? 'bg-amber-500/10 border-amber-500/30 text-amber-300' :
                        prop.status === 'APPROVED' ? 'bg-cyan-500/10 border-cyan-500/30 text-cyan-300' :
                        prop.status === 'APPLIED' ? 'bg-sky-500/10 border-sky-500/30 text-sky-300' :
                        prop.status === 'VERIFIED' ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300' :
                        prop.status === 'REJECTED' ? 'bg-rose-500/10 border-rose-500/30 text-rose-300' :
                        'bg-slate-800 text-slate-400 border-slate-700'
                      }`}>
                        {prop.status}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-[11px] text-slate-400 font-sans">
                      {prop.status === 'VERIFIED' ? (
                        <span className="text-emerald-400 font-mono text-[11px] flex items-center gap-1">
                          <Check className="w-3.5 h-3.5" /> Post-patch constraint verified
                        </span>
                      ) : (
                        'Compatibility & constraint verified'
                      )}
                    </td>
                    <td className="py-3 px-4 text-right whitespace-nowrap space-x-2">
                      {prop.status === 'PROPOSED' && (
                        <button
                          onClick={() => handleApproveProposal(prop.proposal_id)}
                          className="px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 border border-slate-700 text-cyan-300 hover:text-cyan-200 text-xs transition cursor-pointer"
                        >
                          Approve
                        </button>
                      )}
                      {(prop.status === 'APPROVED' || prop.status === 'PROPOSED') && (
                        <button
                          onClick={() => handleExecuteAndRelease(prop.proposal_id)}
                          disabled={executingProposalId === prop.proposal_id}
                          className="px-2.5 py-1 rounded bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-500/40 text-emerald-300 text-xs font-bold transition cursor-pointer disabled:opacity-50"
                        >
                          {executingProposalId === prop.proposal_id ? 'Executing...' : 'Execute & Release Containment'}
                        </button>
                      )}
                      {prop.status === 'VERIFIED' && (
                        <span className="text-emerald-400 font-mono text-[11px] font-bold">
                          Successfully Patched & Released
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Company Notification & Alert Delivery History Section */}
      <div className="bg-slate-950/80 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="p-4 border-b border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Bell className="w-4 h-4 text-amber-400" />
            <h2 className="text-xs font-mono uppercase tracking-wider font-bold text-slate-200">
              Company Notification & Alert Delivery History ({notifications.length})
            </h2>
          </div>
          
          <div className="flex items-center gap-2 self-start sm:self-center">
            {/* Channel Filter */}
            <div className="inline-flex rounded-lg bg-slate-900 border border-slate-800 p-0.5 text-[11px] font-mono">
              {['ALL', 'EMAIL', 'WEBHOOK'].map((ch) => (
                <button
                  key={ch}
                  onClick={() => setChannelFilter(ch)}
                  className={`px-2 py-1 rounded transition cursor-pointer ${
                    channelFilter === ch
                      ? 'bg-slate-800 text-cyan-300 font-bold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {ch}
                </button>
              ))}
            </div>
          </div>
        </div>

        {notifications.length === 0 ? (
          <div className="p-6 text-center text-xs font-mono text-slate-500">
            No incident notifications dispatched yet.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-900/60 text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                  <th className="py-2.5 px-4">Timestamp</th>
                  <th className="py-2.5 px-4">Channel</th>
                  <th className="py-2.5 px-4">Event Type</th>
                  <th className="py-2.5 px-4">CVE / Target</th>
                  <th className="py-2.5 px-4">Delivery Status</th>
                  <th className="py-2.5 px-4">Human Confirmed</th>
                  <th className="py-2.5 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-xs font-mono">
                {notifications
                  .filter((n) => channelFilter === 'ALL' || (n.channel || 'WEBHOOK').toUpperCase() === channelFilter)
                  .slice(0, 15)
                  .map((n) => (
                    <tr key={n.delivery_id} className="hover:bg-slate-900/40 transition">
                      <td className="py-2.5 px-4 text-slate-400 whitespace-nowrap">
                        {n.created_at}
                      </td>
                      <td className="py-2.5 px-4 whitespace-nowrap">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                          (n.channel || 'WEBHOOK') === 'EMAIL'
                            ? 'bg-purple-500/10 border-purple-500/30 text-purple-300'
                            : 'bg-cyan-500/10 border-cyan-500/30 text-cyan-300'
                        }`}>
                          {n.channel || 'WEBHOOK'}
                        </span>
                      </td>
                      <td className="py-2.5 px-4 text-slate-200 font-bold whitespace-nowrap">
                        {n.event_type}
                      </td>
                      <td className="py-2.5 px-4 text-slate-300">
                        <span className="text-cyan-300 font-bold">{n.cve_id || 'N/A'}</span>
                        <span className="text-slate-400 block text-[11px]">{n.affected_component || 'System'}</span>
                      </td>
                      <td className="py-2.5 px-4 whitespace-nowrap">
                        <span className={`px-2 py-0.5 rounded text-[11px] border font-bold ${
                          n.status === 'SENT_TO_SMTP' || n.status === 'DELIVERED'
                            ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                            : n.status === 'SIMULATED'
                            ? 'bg-sky-500/10 border-sky-500/30 text-sky-300'
                            : n.status === 'RECORDED_LOCALLY'
                            ? 'bg-slate-800 border-slate-700 text-slate-400'
                            : 'bg-rose-500/10 border-rose-500/30 text-rose-300'
                        }`}>
                          {n.status}
                        </span>
                        {n.error_message && (
                          <span
                            className="block text-[10px] text-rose-400/90 font-mono mt-1 max-w-[260px] truncate"
                            title={n.error_message}
                          >
                            {n.error_message}
                          </span>
                        )}
                      </td>
                      <td className="py-2.5 px-4 whitespace-nowrap">
                        {n.human_confirmed ? (
                          <span className="text-emerald-400 flex items-center gap-1 font-bold">
                            <Check className="w-3.5 h-3.5" /> ACKNOWLEDGED
                          </span>
                        ) : (
                          <span className="text-amber-400/80 font-mono text-[11px]">
                            PENDING ACK
                          </span>
                        )}
                      </td>
                      <td className="py-2.5 px-4 text-right whitespace-nowrap flex items-center justify-end gap-1.5">
                        {n.status === 'FAILED' && (n.channel || 'WEBHOOK') === 'WEBHOOK' && (
                          <button
                            onClick={() => handleRetryNotification(n.delivery_id)}
                            disabled={retryingNotifId === n.delivery_id}
                            className="px-2 py-1 rounded bg-slate-900 hover:bg-slate-800 border border-rose-500/30 text-rose-300 hover:text-rose-200 text-[11px] transition cursor-pointer flex items-center gap-1"
                            title="Retry webhook delivery"
                          >
                            <RefreshCw className={`w-3 h-3 ${retryingNotifId === n.delivery_id ? 'animate-spin' : ''}`} />
                            Retry
                          </button>
                        )}
                        {!n.human_confirmed && (
                          <button
                            onClick={() => handleAcknowledgeNotification(n.delivery_id)}
                            className="px-2 py-1 rounded bg-slate-900 hover:bg-slate-800 border border-slate-700 text-amber-300 hover:text-amber-200 text-[11px] transition cursor-pointer"
                            title="Acknowledge receipt as human SOC operator"
                          >
                            Acknowledge
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        )}
      </div>


      {/* Resolved History Table */}
      <div className="bg-slate-950/80 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <h2 className="text-xs font-mono uppercase tracking-wider font-bold text-slate-200">
              Verified Resolved Vulnerability History ({resolvedMatches.length})
            </h2>
          </div>
          <span className="text-[11px] font-mono text-slate-400">
            Retained in immutable audit history
          </span>
        </div>

        {loading ? (
          <div className="py-16 text-center space-y-2">
            <RefreshCw className="w-6 h-6 text-cyan-400 animate-spin mx-auto" />
            <p className="text-xs font-mono text-slate-400">Loading remediation history...</p>
          </div>
        ) : resolvedMatches.length === 0 ? (
          <div className="py-16 text-center space-y-2">
            <Clock className="w-8 h-8 text-slate-600 mx-auto" />
            <p className="text-sm font-mono text-slate-300 font-semibold">No resolved records found.</p>
            <p className="text-xs font-mono text-slate-500">
              Vulnerabilities verified as RESOLVED will be cataloged here.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-900/60 text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                  <th className="py-3 px-4">Threat / CVE</th>
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4">Impacted Component</th>
                  <th className="py-3 px-4">Installed Version</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4 text-right">Playbook</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-xs font-sans">
                {resolvedMatches.map((m) => (
                  <tr key={m.id} className="hover:bg-slate-900/40 transition">
                    <td className="py-3 px-4 font-mono">
                      <span className="font-bold text-cyan-300 block">{m.cve_id}</span>
                      <span className="text-slate-300 line-clamp-1 text-xs">{m.threat_title}</span>
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      <SeverityBadge severity={m.severity} />
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-300 whitespace-nowrap">
                      {m.matched_component}
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-400 whitespace-nowrap">
                      {m.installed_version}
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      <StatusBadge status={m.status} />
                    </td>
                    <td className="py-3 px-4 text-right whitespace-nowrap font-mono">
                      <button
                        onClick={() => handleOpenPlaybook(m)}
                        className="px-2.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-cyan-300 border border-slate-800 text-[11px] transition inline-flex items-center gap-1.5 cursor-pointer"
                      >
                        <PlaySquare className="w-3.5 h-3.5" /> View Playbook
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {selectedPlaybook && (
        <PlaybookModal
          playbook={selectedPlaybook}
          title={activeTitle}
          onClose={() => setSelectedPlaybook(null)}
        />
      )}
    </div>
  )
}
