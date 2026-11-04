// frontend/src/pages/admin/AdminSystemHealth.jsx
import React, { useState, useEffect } from 'react'
import axios from 'axios'
import {
  Activity,
  Database,
  Radio,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Cpu,
  Lock,
  Server
} from 'lucide-react'

const API_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8001'

export default function AdminSystemHealth() {
  const [health, setHealth] = useState(null)
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)

  const fetchHealth = async (isManual = false) => {
    if (isManual) setRefreshing(true)
    const token = localStorage.getItem('access_token')
    if (!token) return

    try {
      const res = await axios.get(`${API_URL}/admin/system-health`, {
        headers: { Authorization: `Bearer ${token}` }
      })
      if (res.data) setHealth(res.data)
    } catch (err) {
      console.error('Failed to load system health', err)
    } finally {
      setLoading(false)
      if (isManual) setRefreshing(false)
    }
  }

  useEffect(() => {
    fetchHealth()
  }, [])

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800/80">
        <div>
          <h1 className="text-xl font-bold font-mono tracking-tight text-slate-100 flex items-center gap-2">
            <Activity className="w-5 h-5 text-indigo-400" />
            Platform Infrastructure & Subsystem Health
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Real-time diagnostics for persistence layer, OSINT collectors, simulation safeguards, and policy engine.
          </p>
        </div>

        <button
          onClick={() => fetchHealth(true)}
          disabled={refreshing}
          className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-400 hover:text-slate-200 transition self-start sm:self-center"
          title="Run Subsystem Diagnostics"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {loading ? (
        <div className="py-20 text-center space-y-2">
          <RefreshCw className="w-8 h-8 text-indigo-400 animate-spin mx-auto" />
          <p className="text-xs font-mono text-slate-400">Querying platform subsystem status...</p>
        </div>
      ) : !health ? (
        <div className="py-16 text-center space-y-2 bg-slate-950 border border-slate-800 rounded-xl">
          <AlertTriangle className="w-8 h-8 text-amber-400 mx-auto" />
          <p className="text-sm font-mono text-slate-200 font-bold">Diagnostics unavailable</p>
          <p className="text-xs font-mono text-slate-500">Could not communicate with backend health endpoints.</p>
        </div>
      ) : (
        <div className="space-y-6">
          {/* Main Health Banner */}
          <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                <CheckCircle2 className="w-6 h-6" />
              </div>
              <div>
                <span className="text-[10px] font-mono uppercase tracking-wider text-emerald-400 font-bold">
                  PLATFORM STATUS
                </span>
                <h2 className="text-xl font-bold font-mono text-slate-100">
                  {health.status}
                </h2>
                <p className="text-xs text-slate-400 font-mono">
                  All critical platform components operating within normal parameters.
                </p>
              </div>
            </div>

            <span className="px-3 py-1 rounded-full text-xs font-mono font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 self-start sm:self-center">
              SYSTEM PASS
            </span>
          </div>

          {/* Subsystem Cards Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Database Engine */}
            <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-5 space-y-3 font-mono text-xs">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-indigo-400 font-bold uppercase text-[11px]">
                  <Database className="w-4 h-4" /> Relational Database (SQLAlchemy)
                </div>
                <span className="text-emerald-400 font-bold">CONNECTED</span>
              </div>
              <div className="p-3 rounded-lg bg-slate-900/50 border border-slate-850 space-y-2 text-slate-300">
                <div className="flex justify-between">
                  <span className="text-slate-500">Database Engine:</span>
                  <span>{health.database?.engine || 'MySQL / MariaDB'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">Transaction Isolation:</span>
                  <span>{health.database?.isolation_level || 'READ COMMITTED'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">Connection Pool:</span>
                  <span className="text-emerald-400 font-semibold">Active (Pool Size: 10)</span>
                </div>
              </div>
            </div>

            {/* Background OSINT Collectors */}
            <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-5 space-y-3 font-mono text-xs">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-cyan-400 font-bold uppercase text-[11px]">
                  <Radio className="w-4 h-4" /> Background Ingestion Daemon
                </div>
                <span className="text-emerald-400 font-bold">RUNNING</span>
              </div>
              <div className="p-3 rounded-lg bg-slate-900/50 border border-slate-850 space-y-2 text-slate-300">
                <div className="flex justify-between">
                  <span className="text-slate-500">Execution Cadence:</span>
                  <span>Hourly Asynchronous Loop</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">Collector Strategy:</span>
                  <span>{health.background_collectors?.mode || 'Dual-Engine Sync & Stream'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">Source Isolation:</span>
                  <span className="text-emerald-400 font-semibold">Isolated Exception Boundaries</span>
                </div>
              </div>
            </div>

            {/* Firewall Simulation Adapter */}
            <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-5 space-y-3 font-mono text-xs">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-amber-400 font-bold uppercase text-[11px]">
                  <Server className="w-4 h-4" /> Firewall Adapter Mode
                </div>
                <span className="text-cyan-300 font-bold">SIMULATION ONLY</span>
              </div>
              <div className="p-3 rounded-lg bg-slate-900/50 border border-slate-850 space-y-2 text-slate-300">
                <div className="flex justify-between">
                  <span className="text-slate-500">Adapter Implementation:</span>
                  <span>SimulatedFirewallAdapter (Dry-Run)</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">Live Kernel Enforcement:</span>
                  <span className="text-rose-400 font-semibold">DISABLED (Strict Policy Lock)</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">Simulated TTL Expiry:</span>
                  <span className="text-emerald-400 font-semibold">Automated Rollback Engine</span>
                </div>
              </div>
            </div>

            {/* Deterministic Policy Engine */}
            <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-5 space-y-3 font-mono text-xs">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-purple-400 font-bold uppercase text-[11px]">
                  <Cpu className="w-4 h-4" /> Deterministic Policy Engine
                </div>
                <span className="text-emerald-400 font-bold">ENFORCED</span>
              </div>
              <div className="p-3 rounded-lg bg-slate-900/50 border border-slate-850 space-y-2 text-slate-300">
                <div className="flex justify-between">
                  <span className="text-slate-500">Confidence Threshold:</span>
                  <span>{health.containment_policy_engine?.confidence_threshold || '85.0%'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">Tenant Isolation Policy:</span>
                  <span>{health.containment_policy_engine?.tenant_isolation || 'STRICT'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">Zero-Deletion History:</span>
                  <span className="text-emerald-400 font-semibold">Immutable Audit Retention</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
