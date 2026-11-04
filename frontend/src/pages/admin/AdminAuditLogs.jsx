// frontend/src/pages/admin/AdminAuditLogs.jsx
import React, { useState, useEffect, useMemo } from 'react'
import axios from 'axios'
import {
  FileCode2,
  Search,
  RefreshCw,
  Clock,
  ShieldCheck,
  ChevronDown,
  ChevronUp,
  Activity,
  Building2,
  Ban,
  AlertTriangle,
  Radio,
  CheckCircle2,
  XCircle,
  Copy,
  Check,
  Terminal
} from 'lucide-react'
import StatCard from '../../components/common/StatCard'

const API_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8001'

export default function AdminAuditLogs() {
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [auditLogs, setAuditLogs] = useState([])
  const [containmentActions, setContainmentActions] = useState([])
  const [feedTelemetry, setFeedTelemetry] = useState([])
  const [expandedLogId, setExpandedLogId] = useState(null)
  const [copiedId, setCopiedId] = useState(null)

  // Filter States
  const [searchQuery, setSearchQuery] = useState('')
  const [categoryFilter, setCategoryFilter] = useState('ALL') // ALL, REJECTION, CONTAINMENT, FAILURE, OSINT
  const [statusFilter, setStatusFilter] = useState('ALL') // ALL, SUCCESS, FAILED, WARNING
  const [dateFilter, setDateFilter] = useState('ALL') // ALL, 24H, 7D, 30D

  const fetchAuditData = async (isManual = false) => {
    if (isManual) setRefreshing(true)
    const token = localStorage.getItem('access_token')
    if (!token) return

    try {
      // 1. Fetch platform containment audit logs
      const auditPromise = axios.get(`${API_URL}/admin/containment/audit-logs`, {
        headers: { Authorization: `Bearer ${token}` }
      }).catch(err => {
        console.warn('Could not fetch admin containment audit logs', err)
        return { data: { logs: [] } }
      })

      // 2. Fetch all containment actions for execution and failure telemetry across tenants
      const actionsPromise = axios.get(`${API_URL}/admin/containment/actions`, {
        headers: { Authorization: `Bearer ${token}` }
      }).catch(err => {
        console.warn('Could not fetch admin containment actions', err)
        return { data: { actions: [] } }
      })

      // 3. Fetch OSINT feed ingestion telemetry & failure logs
      const feedPromise = axios.get(`${API_URL}/admin/threats/sources/status`, {
        headers: { Authorization: `Bearer ${token}` }
      }).catch(() => {
        return axios.get(`${API_URL}/admin/integrations`, {
          headers: { Authorization: `Bearer ${token}` }
        }).catch(err => {
          console.warn('Could not fetch feed status', err)
          return { data: { sources: [] } }
        })
      })

      const [auditRes, actionsRes, feedRes] = await Promise.all([auditPromise, actionsPromise, feedPromise])

      if (auditRes.data && Array.isArray(auditRes.data.logs)) {
        setAuditLogs(auditRes.data.logs)
      } else {
        setAuditLogs([])
      }

      if (actionsRes.data && Array.isArray(actionsRes.data.actions)) {
        setContainmentActions(actionsRes.data.actions)
      } else {
        setContainmentActions([])
      }

      const sourcesList = feedRes.data?.sources || feedRes.data?.feeds || []
      if (Array.isArray(sourcesList)) {
        setFeedTelemetry(sourcesList)
      } else {
        setFeedTelemetry([])
      }
    } catch (err) {
      console.error('Failed to load administrative security audit data', err)
    } finally {
      setLoading(false)
      if (isManual) setRefreshing(false)
    }
  }

  useEffect(() => {
    fetchAuditData()
  }, [])

  // Synthesize and normalize all log events into a unified administrative ledger
  const unifiedLogs = useMemo(() => {
    const list = []

    // 1. Core Containment Audit Logs
    auditLogs.forEach((item) => {
      const eventType = item.event_type || 'SYSTEM_EVENT'
      const details = item.details || {}
      const isRejection = eventType.includes('REJECTION') || details.reason?.startsWith('REJECTED')
      const isFailure = eventType.includes('FAIL') || details.error || (item.new_status === 'FAILED')

      let category = 'CONTAINMENT'
      if (isRejection) category = 'REJECTION'
      else if (isFailure) category = 'FAILURE'

      let severity = 'SUCCESS'
      if (isRejection) severity = 'WARNING'
      if (isFailure) severity = 'FAILED'

      list.push({
        id: item.id || `audit-${Math.random()}`,
        source: 'CONTAINMENT_LEDGER',
        tenantName: item.tenant_name || 'Global System',
        tenantId: item.tenant_id,
        category,
        eventType,
        actor: item.actor || 'AUTONOMOUS_POLICY_ENGINE',
        previousStatus: item.previous_status,
        newStatus: item.new_status,
        timestamp: item.created_at,
        details: item.details,
        actionId: item.action_id,
        severity,
        summary: details.reason || details.explanation || `Status transition: ${item.previous_status || 'INIT'} -> ${item.new_status || 'N/A'}`
      })
    })

    // 2. Action Execution & Validation Failures from Containment Actions
    containmentActions.forEach((action) => {
      if (action.error_message || action.status === 'FAILED') {
        list.push({
          id: `action-err-${action.id}`,
          source: 'CONTAINMENT_ACTION',
          tenantName: action.tenant_name || 'Tenant Orgs',
          tenantId: action.tenant_id,
          category: 'FAILURE',
          eventType: 'AGENT_EXECUTION_FAILURE',
          actor: action.applied_by || 'SOAR_DISPATCHER',
          previousStatus: action.status,
          newStatus: 'FAILED',
          timestamp: action.updated_at || action.created_at,
          details: {
            error_message: action.error_message,
            execution_output: action.execution_output,
            target_ip: action.indicator_value,
            rule_spec: action.rule_spec
          },
          actionId: action.action_id || action.id,
          severity: 'FAILED',
          summary: action.error_message || 'Containment agent validation or execution failed'
        })
      }
    })

    // 3. OSINT Feed Ingestion Errors and Retry Events
    feedTelemetry.forEach((feed) => {
      if (feed.failures > 0 || feed.last_error || feed.status === 'ERROR' || feed.status === 'WARNING') {
        list.push({
          id: `feed-err-${(feed.name || 'feed').replace(/\s+/g, '-').toLowerCase()}`,
          source: 'OSINT_COLLECTOR',
          tenantName: 'Platform Global',
          tenantId: null,
          category: 'OSINT',
          eventType: feed.status === 'ERROR' ? 'OSINT_INGESTION_ERROR' : 'OSINT_RETRY_WARNING',
          actor: 'OSINT_COLLECTOR_WORKER',
          previousStatus: 'ACTIVE',
          newStatus: feed.status,
          timestamp: feed.last_attempt || feed.last_sync,
          details: {
            feed_name: feed.name,
            feed_url: feed.url,
            feed_type: feed.type,
            failures_count: feed.failures,
            last_error: feed.last_error,
            duplicates_skipped: feed.duplicates_skipped,
            new_items: feed.new_items
          },
          actionId: null,
          severity: feed.status === 'ERROR' ? 'FAILED' : 'WARNING',
          summary: feed.last_error || `${feed.name}: Ingestion sync encountered retries/warnings (${feed.failures} recorded failures)`
        })
      }
    })

    // Sort descending by timestamp
    return list.sort((a, b) => {
      const timeA = a.timestamp ? new Date(a.timestamp).getTime() : 0
      const timeB = b.timestamp ? new Date(b.timestamp).getTime() : 0
      return timeB - timeA
    })
  }, [auditLogs, containmentActions, feedTelemetry])

  // Apply User Filters
  const filteredLogs = useMemo(() => {
    return unifiedLogs.filter((log) => {
      if (categoryFilter !== 'ALL' && log.category !== categoryFilter) return false
      if (statusFilter !== 'ALL' && log.severity !== statusFilter) return false

      if (dateFilter !== 'ALL' && log.timestamp) {
        const logTime = new Date(log.timestamp).getTime()
        const now = Date.now()
        if (dateFilter === '24H' && now - logTime > 24 * 60 * 60 * 1000) return false
        if (dateFilter === '7D' && now - logTime > 7 * 24 * 60 * 60 * 1000) return false
        if (dateFilter === '30D' && now - logTime > 30 * 24 * 60 * 60 * 1000) return false
      }

      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase()
        const inType = log.eventType?.toLowerCase().includes(q)
        const inActor = log.actor?.toLowerCase().includes(q)
        const inTenant = log.tenantName?.toLowerCase().includes(q)
        const inSummary = log.summary?.toLowerCase().includes(q)
        const inActionId = log.actionId?.toLowerCase().includes(q)
        const inDetails = log.details ? JSON.stringify(log.details).toLowerCase().includes(q) : false
        if (!inType && !inActor && !inTenant && !inSummary && !inActionId && !inDetails) {
          return false
        }
      }

      return true
    })
  }, [unifiedLogs, categoryFilter, statusFilter, dateFilter, searchQuery])

  // Aggregate Metrics
  const stats = useMemo(() => {
    let rejections = 0
    let failures = 0
    let actions = 0
    let osintIssues = 0

    unifiedLogs.forEach((l) => {
      if (l.category === 'REJECTION') rejections++
      else if (l.category === 'FAILURE') failures++
      else if (l.category === 'CONTAINMENT') actions++
      else if (l.category === 'OSINT') osintIssues++
    })

    return {
      total: unifiedLogs.length,
      rejections,
      failures,
      actions,
      osintIssues
    }
  }, [unifiedLogs])

  const copyToClipboard = (text, id) => {
    navigator.clipboard.writeText(typeof text === 'object' ? JSON.stringify(text, null, 2) : text)
    setCopiedId(id)
    setTimeout(() => setCopiedId(null), 2000)
  }

  const formatTimestamp = (ts) => {
    if (!ts) return 'Unknown Time'
    try {
      const d = new Date(ts)
      return d.toLocaleString(undefined, {
        year: 'numeric',
        month: 'short',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
      })
    } catch {
      return String(ts)
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800/80">
        <div>
          <h1 className="text-xl font-bold font-mono tracking-tight text-slate-100 flex items-center gap-2">
            <FileCode2 className="w-5 h-5 text-indigo-400" />
            Platform Security Audit &amp; System Logs
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Centralized deterministic ledger for cross-tenant policy rejections, agent failures, OSINT synchronization diagnostics, and containment state transitions.
          </p>
        </div>

        <button
          onClick={() => fetchAuditData(true)}
          disabled={refreshing}
          className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-400 hover:text-slate-200 transition self-start sm:self-center"
          title="Refresh Audit Ledger"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {/* KPI Stats Row */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
        <StatCard
          title="Total Events"
          value={stats.total}
          icon={Activity}
          accent="purple"
          subtitle="All platform records"
          onClick={() => { setCategoryFilter('ALL'); setStatusFilter('ALL') }}
        />
        <StatCard
          title="Policy Rejections"
          value={stats.rejections}
          icon={Ban}
          accent="amber"
          subtitle="Denied by policy rules"
          onClick={() => setCategoryFilter('REJECTION')}
        />
        <StatCard
          title="Containment Transitions"
          value={stats.actions}
          icon={ShieldCheck}
          accent="emerald"
          subtitle="Simulated / applied actions"
          onClick={() => setCategoryFilter('CONTAINMENT')}
        />
        <StatCard
          title="Agent Failures"
          value={stats.failures}
          icon={AlertTriangle}
          accent="rose"
          subtitle="Execution & validation errors"
          onClick={() => setCategoryFilter('FAILURE')}
        />
        <StatCard
          title="OSINT Ingestion Issues"
          value={stats.osintIssues}
          icon={Radio}
          accent={stats.osintIssues > 0 ? 'rose' : 'cyan'}
          subtitle="Feed retries & sync faults"
          onClick={() => setCategoryFilter('OSINT')}
        />
      </div>

      {/* Search and Filters Bar */}
      <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-4 space-y-3">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
          {/* Search Input */}
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search event type, actor, tenant, rejection reason, indicator IP, or action ID..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500/50"
            />
          </div>

          {(searchQuery || categoryFilter !== 'ALL' || statusFilter !== 'ALL' || dateFilter !== 'ALL') && (
            <button
              onClick={() => {
                setSearchQuery('')
                setCategoryFilter('ALL')
                setStatusFilter('ALL')
                setDateFilter('ALL')
              }}
              className="text-xs font-mono text-indigo-400 hover:text-indigo-300 self-end md:self-center transition"
            >
              Reset Filters
            </button>
          )}
        </div>

        {/* Filter Tabs and Dropdowns */}
        <div className="flex flex-wrap items-center justify-between gap-2 pt-1 border-t border-slate-900 text-xs font-mono">
          {/* Category Tabs */}
          <div className="flex flex-wrap items-center gap-1.5">
            {[
              { id: 'ALL', label: 'All Platform Events' },
              { id: 'REJECTION', label: 'Policy Rejections' },
              { id: 'CONTAINMENT', label: 'Containment Actions' },
              { id: 'FAILURE', label: 'Agent Failures' },
              { id: 'OSINT', label: 'OSINT Feed Diagnostics' }
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setCategoryFilter(tab.id)}
                className={`px-2.5 py-1 rounded-md transition ${
                  categoryFilter === tab.id
                    ? 'bg-indigo-500/20 text-indigo-300 border border-indigo-500/40 font-semibold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900 border border-transparent'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* Dropdown Filters */}
          <div className="flex items-center gap-2">
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 focus:outline-none focus:border-indigo-500/50 text-xs font-mono"
            >
              <option value="ALL">Status: All</option>
              <option value="SUCCESS">Status: Executed / Normal</option>
              <option value="WARNING">Status: Rejected / Warning</option>
              <option value="FAILED">Status: Failed / Execution Error</option>
            </select>

            <select
              value={dateFilter}
              onChange={(e) => setDateFilter(e.target.value)}
              className="px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 focus:outline-none focus:border-indigo-500/50 text-xs font-mono"
            >
              <option value="ALL">Time: All Time</option>
              <option value="24H">Time: Last 24 Hours</option>
              <option value="7D">Time: Last 7 Days</option>
              <option value="30D">Time: Last 30 Days</option>
            </select>
          </div>
        </div>
      </div>

      {/* Ledger Table */}
      <div className="bg-slate-950/80 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-indigo-400" />
            <h2 className="text-xs font-mono uppercase tracking-wider font-bold text-slate-200">
              Platform Audit &amp; System Event Stream
            </h2>
            <span className="text-[11px] font-mono text-slate-500">
              ({filteredLogs.length} events)
            </span>
          </div>

          <span className="text-[11px] font-mono text-slate-400 flex items-center gap-1">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            Platform Root Scope — Secrets Redacted
          </span>
        </div>

        {loading ? (
          <div className="py-16 text-center space-y-2">
            <RefreshCw className="w-6 h-6 text-indigo-400 animate-spin mx-auto" />
            <p className="text-xs font-mono text-slate-400">Loading platform security audit ledger...</p>
          </div>
        ) : filteredLogs.length === 0 ? (
          <div className="py-16 text-center space-y-2">
            <CheckCircle2 className="w-8 h-8 text-slate-600 mx-auto" />
            <p className="text-sm font-mono text-slate-300 font-bold">No audit events match the selected criteria.</p>
            <p className="text-xs font-mono text-slate-500">Try adjusting your query or filter parameters above.</p>
          </div>
        ) : (
          <div className="divide-y divide-slate-800/80">
            {filteredLogs.map((log) => {
              const isExpanded = expandedLogId === log.id
              return (
                <div key={log.id} className="p-4 hover:bg-slate-900/40 transition">
                  {/* Top Row: Severity, Event Type, Actor, Tenant Scope, Timestamp */}
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
                    <div className="flex items-center gap-2.5 flex-wrap">
                      {log.severity === 'FAILED' ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-rose-500/20 text-rose-300 border border-rose-500/40">
                          <XCircle className="w-3 h-3 text-rose-400" />
                          Failure
                        </span>
                      ) : log.severity === 'WARNING' ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-amber-500/20 text-amber-300 border border-amber-500/40">
                          <Ban className="w-3 h-3 text-amber-400" />
                          Policy Rejection
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                          <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                          Executed
                        </span>
                      )}

                      <span className="text-xs font-mono font-bold text-slate-100">
                        {log.eventType}
                      </span>

                      <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-900 text-slate-300 border border-slate-800">
                        Actor: <span className="text-indigo-300">{log.actor}</span>
                      </span>

                      <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-900 text-slate-300 border border-slate-800 flex items-center gap-1">
                        <Building2 className="w-3 h-3 text-slate-400" />
                        {log.tenantName}
                      </span>

                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                        {log.source}
                      </span>
                    </div>

                    <div className="flex items-center gap-3 self-end sm:self-center">
                      <span className="text-[11px] font-mono text-slate-400 flex items-center gap-1">
                        <Clock className="w-3 h-3 text-slate-500" />
                        {formatTimestamp(log.timestamp)}
                      </span>
                      <button
                        onClick={() => setExpandedLogId(isExpanded ? null : log.id)}
                        className="p-1 rounded bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition"
                        title={isExpanded ? 'Collapse' : 'Inspect JSON telemetry'}
                      >
                        {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>

                  {/* Summary text */}
                  <div className="mt-2 text-xs font-mono text-slate-300 break-words flex items-start gap-2">
                    <span className="text-slate-500">&gt;</span>
                    <span className={log.severity === 'FAILED' ? 'text-rose-300 font-semibold' : log.severity === 'WARNING' ? 'text-amber-200' : 'text-slate-200'}>
                      {log.summary}
                    </span>
                  </div>

                  {/* State transition indicator */}
                  {(log.previousStatus || log.newStatus) && (
                    <div className="mt-1.5 flex items-center gap-2 text-[10px] font-mono text-slate-400">
                      <span>State:</span>
                      <span className="text-slate-400">{log.previousStatus || 'INIT'}</span>
                      <span>&rarr;</span>
                      <span className="text-cyan-300 font-bold">{log.newStatus}</span>
                      {log.actionId && (
                        <span className="text-slate-500 ml-2">Action ID: {log.actionId.slice(0, 16)}...</span>
                      )}
                    </div>
                  )}

                  {/* Expanded Telemetry Details */}
                  {isExpanded && (
                    <div className="mt-3 p-3.5 rounded-lg bg-slate-950 border border-slate-800 space-y-2.5">
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 font-bold">
                          Detailed Audit Telemetry &amp; Diagnostics
                        </span>
                        <button
                          onClick={() => copyToClipboard(log.details || log, log.id)}
                          className="flex items-center gap-1 text-[10px] font-mono text-indigo-400 hover:text-indigo-300 transition"
                        >
                          {copiedId === log.id ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                          {copiedId === log.id ? 'Copied' : 'Copy JSON'}
                        </button>
                      </div>

                      <pre className="p-2.5 rounded bg-slate-900 border border-slate-800 text-[11px] font-mono text-slate-300 overflow-x-auto max-h-64">
                        {JSON.stringify(log.details || { event: log.eventType, summary: log.summary }, null, 2)}
                      </pre>

                      <div className="flex items-center justify-between text-[10px] font-mono text-slate-500 pt-1 border-t border-slate-900">
                        <span>Event ID: {log.id}</span>
                        <span>Tenant Scope: {log.tenantName} ({log.tenantId || 'Global'})</span>
                      </div>
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}
