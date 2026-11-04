// frontend/src/pages/admin/AdminIntegrations.jsx
import React, { useState, useEffect } from 'react'
import axios from 'axios'
import {
  Network,
  RefreshCw,
  Radio,
  Webhook,
  CheckCircle2,
  AlertTriangle,
  Lock,
  Layers,
  ShieldCheck,
  Mail,
  Info,
  Check
} from 'lucide-react'

const API_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8001'

export default function AdminIntegrations() {
  const [integrations, setIntegrations] = useState({
    feeds: [],
    tenant_webhooks: [],
    email_integration: null,
    firewall_mode: 'SIMULATION_ONLY'
  })
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)

  const fetchIntegrations = async (isManual = false) => {
    if (isManual) setRefreshing(true)
    const token = localStorage.getItem('access_token')
    if (!token) return

    try {
      const res = await axios.get(`${API_URL}/admin/integrations`, {
        headers: { Authorization: `Bearer ${token}` }
      })
      if (res.data) setIntegrations(res.data)
    } catch (err) {
      console.error('Failed to load integrations', err)
    } finally {
      setLoading(false)
      if (isManual) setRefreshing(false)
    }
  }



  useEffect(() => {
    fetchIntegrations()
  }, [])

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800/80">
        <div>
          <h1 className="text-xl font-bold font-mono tracking-tight text-slate-100 flex items-center gap-2">
            <Network className="w-5 h-5 text-indigo-400" />
            External Threat Feeds & SOAR Webhook Integrations
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Ingestion feed frequency, source trust level, and tenant SOAR webhook connectivity with secret redaction.
          </p>
        </div>

        <button
          onClick={() => fetchIntegrations(true)}
          disabled={refreshing}
          className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-400 hover:text-slate-200 transition self-start sm:self-center"
          title="Refresh Integration Health"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {/* Safety Policy Pill */}
      <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 flex items-start gap-3 text-xs font-mono">
        <Lock className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
        <div className="space-y-1">
          <span className="text-slate-200 font-bold uppercase">Security & Redaction Safeguards</span>
          <p className="text-slate-400 font-sans leading-relaxed">
            All tenant bearer tokens and KMS key secrets are masked with cryptographic redaction. Webhook integrations operate over TLS and require tenant HMAC/Bearer signatures. Firewall mode is strictly enforced as <strong>SIMULATION ONLY</strong>.
          </p>
        </div>
      </div>

      {/* Ingestion Feeds Card */}
      <div className="bg-slate-950/80 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Radio className="w-4 h-4 text-cyan-400 animate-pulse" />
            <h2 className="text-xs font-mono uppercase tracking-wider font-bold text-slate-200">
              Active Ingestion Threat Intelligence Feeds ({integrations.feeds?.length || 0})
            </h2>
          </div>
          <span className="text-[11px] font-mono text-emerald-400">All Systems Operational</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-900/60 text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                <th className="py-3 px-4">Feed Source</th>
                <th className="py-3 px-4">Indicator / Advisory Type</th>
                <th className="py-3 px-4">Polling Cadence</th>
                <th className="py-3 px-4">Last Sync</th>
                <th className="py-3 px-4">Discovered / Updated / Skipped</th>
                <th className="py-3 px-4">Review Queue</th>
                <th className="py-3 px-4">Health Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-xs font-mono">
              {(integrations.feeds || []).map((f, idx) => (
                <tr key={idx} className="hover:bg-slate-900/40 transition">
                  <td className="py-3.5 px-4">
                    <div className="font-bold text-slate-100">{f.name}</div>
                    {f.url && (
                      <div className="text-[10px] text-slate-400 truncate max-w-[220px]" title={f.url}>
                        {f.url}
                      </div>
                    )}
                  </td>
                  <td className="py-3.5 px-4 text-cyan-300">
                    {f.type}
                  </td>
                  <td className="py-3.5 px-4 text-slate-400">
                    {f.frequency}
                  </td>
                  <td className="py-3.5 px-4 text-slate-300">
                    {f.last_sync ? (
                      <span className="text-[11px] text-slate-300">{f.last_sync.replace('T', ' ').slice(0, 19)}</span>
                    ) : (
                      <span className="text-[11px] text-slate-400">Pending initial sync</span>
                    )}
                  </td>
                  <td className="py-3.5 px-4">
                    <div className="flex items-center gap-2 text-[11px]">
                      <span className="text-emerald-400 font-bold" title="Newly discovered items">+{f.new_items || 0} new</span>
                      <span className="text-slate-600">/</span>
                      <span className="text-cyan-400 font-semibold" title="Updated advisories">{f.updated_items || 0} upd</span>
                      <span className="text-slate-600">/</span>
                      <span className="text-slate-400" title="Duplicates skipped">{f.duplicates_skipped || 0} skip</span>
                    </div>
                  </td>
                  <td className="py-3.5 px-4">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/10 text-amber-400 border border-amber-500/30">
                      {f.awaiting_review || 0} review
                    </span>
                  </td>
                  <td className="py-3.5 px-4">
                    {f.status === 'ERROR' ? (
                      <div>
                        <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/15 text-rose-400 border border-rose-500/30">
                          <span className="w-1.5 h-1.5 rounded-full bg-rose-400" />
                          FAILED ({f.failures || 1})
                        </span>
                        {f.last_error && (
                          <div className="text-[10px] text-rose-400 truncate max-w-[180px] mt-0.5" title={f.last_error}>
                            {f.last_error}
                          </div>
                        )}
                      </div>
                    ) : f.status === 'SYNCING' ? (
                      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-500/15 text-cyan-400 border border-cyan-500/30">
                        <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
                        SYNCING
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                        {f.status || 'HEALTHY'}
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Tenant Webhook Endpoints */}
      <div className="bg-slate-950/80 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Webhook className="w-4 h-4 text-indigo-400" />
            <h2 className="text-xs font-mono uppercase tracking-wider font-bold text-slate-200">
              Tenant SOAR Webhook Delivery Connections ({integrations.tenant_webhooks?.length || 0})
            </h2>
          </div>
          <span className="text-[11px] font-mono text-slate-400">Isolated Dispatch Routing</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-900/60 text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                <th className="py-3 px-4">Tenant Organization</th>
                <th className="py-3 px-4">Configured Webhook Receiver</th>
                <th className="py-3 px-4">Auth Token</th>
                <th className="py-3 px-4">Connection Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-xs font-mono">
              {(integrations.tenant_webhooks || []).map((w) => (
                <tr key={w.tenant_id} className="hover:bg-slate-900/40 transition">
                  <td className="py-3.5 px-4 font-bold text-slate-100">
                    {w.company_name}
                  </td>
                  <td className="py-3.5 px-4 text-slate-300 max-w-xs truncate">
                    {w.webhook_url}
                  </td>
                  <td className="py-3.5 px-4 text-slate-500">
                    {w.has_auth_token ? '••••••••••••••••' : 'None'}
                  </td>
                  <td className="py-3.5 px-4">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      w.status === 'CONNECTED'
                        ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                        : 'bg-slate-900 text-slate-500 border border-slate-800'
                    }`}>
                      {w.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Global Brevo Email & SMTP Notification Integration Card */}
      <div className="bg-slate-950/80 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="p-4 border-b border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Mail className="w-4 h-4 text-purple-400" />
            <div>
              <h2 className="text-xs font-mono uppercase tracking-wider font-bold text-slate-200">
                Global Email Notification Service & Brevo SMTP Relay
              </h2>
              <p className="text-[11px] text-slate-400 font-mono">
                Platform-wide incident notification delivery, Brevo SMTP configuration, and administrator diagnostics.
              </p>
            </div>
          </div>
          <div>
            <span className={`px-2.5 py-1 rounded text-xs font-mono font-bold border ${
              integrations.email_integration?.status === 'ACTIVE_SMTP'
                ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                : 'bg-amber-500/15 text-amber-400 border-amber-500/30'
            }`}>
              {integrations.email_integration?.status === 'ACTIVE_SMTP'
                ? 'ACTIVE SMTP (BREVO)'
                : 'SIMULATED (SAFE MODE)'}
            </span>
          </div>
        </div>

        <div className="p-5 space-y-5">
          {/* Email Service Configuration Grid */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-xs font-mono">
            <div className="p-3 rounded-lg bg-slate-900/50 border border-slate-850 space-y-1">
              <span className="text-[10px] uppercase text-slate-400">Email Provider</span>
              <p className="text-slate-100 font-bold uppercase">
                {integrations.email_integration?.provider || 'Brevo'}
              </p>
              <span className="text-[10px] text-purple-400 font-medium">Verified Integration</span>
            </div>

            <div className="p-3 rounded-lg bg-slate-900/50 border border-slate-850 space-y-1">
              <span className="text-[10px] uppercase text-slate-400">Relay Host / Port</span>
              <p className="text-slate-100 font-bold truncate" title={integrations.email_integration?.host}>
                {integrations.email_integration?.host || 'smtp-relay.brevo.com'}
              </p>
              <span className="text-[10px] text-slate-400">Port {integrations.email_integration?.port || 587} (TLS)</span>
            </div>

            <div className="p-3 rounded-lg bg-slate-900/50 border border-slate-850 space-y-1">
              <span className="text-[10px] uppercase text-slate-400">Sender Identity</span>
              <p className="text-slate-100 font-bold truncate" title={integrations.email_integration?.from_email}>
                {integrations.email_integration?.from_email || 'Not Configured'}
              </p>
              <span className="text-[10px] text-slate-400 truncate block">
                {integrations.email_integration?.from_name || 'CyberScribe Security'}
              </span>
            </div>

            <div className="p-3 rounded-lg bg-slate-900/50 border border-slate-850 space-y-1">
              <span className="text-[10px] uppercase text-slate-400">Security Credentials</span>
              <p className="text-emerald-400 font-bold flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5" />
                {integrations.email_integration?.has_credentials ? 'Configured & Encrypted' : 'Missing Credentials'}
              </p>
              <span className="text-[10px] text-slate-400">Role-Restricted Scope</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
