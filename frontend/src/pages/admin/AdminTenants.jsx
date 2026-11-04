// frontend/src/pages/admin/AdminTenants.jsx
import React, { useState, useEffect } from 'react'
import axios from 'axios'
import {
  Building2,
  Search,
  RefreshCw,
  Layers,
  Users,
  Webhook,
  Calendar,
  ChevronDown,
  ChevronUp,
  ShieldCheck,
  AlertTriangle,
  ExternalLink
} from 'lucide-react'

const API_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8001'

export default function AdminTenants() {
  const [tenants, setTenants] = useState([])
  const [loading, setLoading] = useState(true)
  const [searchQuery, setSearchQuery] = useState('')
  const [expandedTenantId, setExpandedTenantId] = useState(null)
  const [refreshing, setRefreshing] = useState(false)

  const fetchTenants = async (isManual = false) => {
    if (isManual) setRefreshing(true)
    const token = localStorage.getItem('access_token')
    if (!token) return

    try {
      const res = await axios.get(`${API_URL}/admin/tenants`, {
        headers: { Authorization: `Bearer ${token}` }
      })
      if (res.data && Array.isArray(res.data.tenants)) {
        setTenants(res.data.tenants)
      }
    } catch (err) {
      console.error('Failed to load tenants', err)
    } finally {
      setLoading(false)
      if (isManual) setRefreshing(false)
    }
  }

  useEffect(() => {
    fetchTenants()
  }, [])

  const toggleExpand = (id) => {
    setExpandedTenantId(expandedTenantId === id ? null : id)
  }

  const filteredTenants = tenants.filter((t) => {
    const q = searchQuery.toLowerCase()
    return !q || 
      (t.company_name || '').toLowerCase().includes(q) ||
      (t.id || '').toLowerCase().includes(q) ||
      (t.tech_stack || '').toLowerCase().includes(q)
  })

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800/80">
        <div>
          <h1 className="text-xl font-bold font-mono tracking-tight text-slate-100 flex items-center gap-2">
            <Building2 className="w-5 h-5 text-indigo-400" />
            Tenant Organizations Directory
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Platform-wide tenant isolation management, monitored asset counts, and active threat postures.
          </p>
        </div>

        <button
          onClick={() => fetchTenants(true)}
          disabled={refreshing}
          className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-400 hover:text-slate-200 transition self-start sm:self-center"
          title="Refresh Tenants"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {/* Search Bar */}
      <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-3.5 flex items-center justify-between gap-3">
        <div className="relative w-full sm:w-96">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search tenant name, UUID, tech stack..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500/50"
          />
        </div>
        <span className="text-xs font-mono text-slate-500 hidden sm:inline">
          {filteredTenants.length} of {tenants.length} tenants
        </span>
      </div>

      {/* Tenants Table */}
      <div className="bg-slate-950/80 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        {loading ? (
          <div className="py-16 text-center space-y-2">
            <RefreshCw className="w-6 h-6 text-indigo-400 animate-spin mx-auto" />
            <p className="text-xs font-mono text-slate-400">Loading tenant database...</p>
          </div>
        ) : filteredTenants.length === 0 ? (
          <div className="py-16 text-center space-y-2">
            <Building2 className="w-8 h-8 text-slate-600 mx-auto" />
            <p className="text-sm font-mono text-slate-300 font-bold">No tenants found.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-900/60 text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                  <th className="py-3 px-4">Organization / UUID</th>
                  <th className="py-3 px-4">Monitored Assets</th>
                  <th className="py-3 px-4">Matches</th>
                  <th className="py-3 px-4">Active Affected</th>
                  <th className="py-3 px-4">Users</th>
                  <th className="py-3 px-4">SOAR Webhook</th>
                  <th className="py-3 px-4">Created Date</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-xs font-mono">
                {filteredTenants.map((tenant) => {
                  const isExpanded = expandedTenantId === tenant.id
                  return (
                    <React.Fragment key={tenant.id}>
                      <tr
                        onClick={() => toggleExpand(tenant.id)}
                        className="hover:bg-slate-900/40 transition cursor-pointer"
                      >
                        <td className="py-3.5 px-4 font-bold text-slate-100">
                          <div className="flex items-center gap-1.5">
                            {isExpanded ? <ChevronUp className="w-3.5 h-3.5 text-slate-400" /> : <ChevronDown className="w-3.5 h-3.5 text-slate-400" />}
                            <span>{tenant.company_name}</span>
                          </div>
                          <span className="text-[10px] text-slate-500 font-mono block pl-5">
                            {tenant.id}
                          </span>
                        </td>
                        <td className="py-3.5 px-4 text-cyan-300">
                          {tenant.asset_count}
                        </td>
                        <td className="py-3.5 px-4 text-slate-300">
                          {tenant.match_count}
                        </td>
                        <td className="py-3.5 px-4">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            tenant.active_affected_count > 0 
                              ? 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
                              : 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                          }`}>
                            {tenant.active_affected_count}
                          </span>
                        </td>
                        <td className="py-3.5 px-4 text-slate-300">
                          {tenant.user_count}
                        </td>
                        <td className="py-3.5 px-4">
                          {tenant.webhook_url ? (
                            <span className="text-emerald-400 flex items-center gap-1 text-[11px]">
                              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" /> Connected
                            </span>
                          ) : (
                            <span className="text-slate-500 text-[11px]">Unconfigured</span>
                          )}
                        </td>
                        <td className="py-3.5 px-4 text-slate-400">
                          {tenant.created_at ? tenant.created_at.slice(0, 10) : 'Registered'}
                        </td>
                      </tr>

                      {/* Expanded Tenant Details Drawer */}
                      {isExpanded && (
                        <tr className="bg-slate-900/60 border-b border-slate-800">
                          <td colSpan={7} className="p-4 space-y-3 font-mono text-xs">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                              <div className="space-y-1.5">
                                <span className="text-indigo-400 font-bold uppercase text-[11px] block">
                                  Monitored Tech Stack / SBOM Tags
                                </span>
                                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 text-xs">
                                  {tenant.tech_stack || 'No explicit tech stack registered.'}
                                </div>
                              </div>

                              <div className="space-y-1.5">
                                <span className="text-indigo-400 font-bold uppercase text-[11px] block">
                                  SOAR Webhook Endpoint & Secret Status
                                </span>
                                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 text-xs space-y-1">
                                  <div>
                                    <span className="text-slate-500">Receiver URL: </span>
                                    <span>{tenant.webhook_url || 'None'}</span>
                                  </div>
                                  <div>
                                    <span className="text-slate-500">Auth Token: </span>
                                    <span>{tenant.has_auth_token ? '••••••••••••••••' : 'None'}</span>
                                  </div>
                                  <div>
                                    <span className="text-slate-500">Tenant Isolation: </span>
                                    <span className="text-emerald-400 font-semibold">STRICT (Row-Level ForeignKey Linked)</span>
                                  </div>
                                </div>
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
