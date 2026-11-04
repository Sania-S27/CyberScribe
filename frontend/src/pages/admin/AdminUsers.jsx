// frontend/src/pages/admin/AdminUsers.jsx
import React, { useState, useEffect } from 'react'
import axios from 'axios'
import {
  Users2,
  Search,
  RefreshCw,
  ShieldCheck,
  Lock,
  Building2,
  CheckCircle2,
  XCircle
} from 'lucide-react'

const API_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8001'

export default function AdminUsers() {
  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(true)
  const [searchQuery, setSearchQuery] = useState('')
  const [roleFilter, setRoleFilter] = useState('ALL')
  const [refreshing, setRefreshing] = useState(false)

  const fetchUsers = async (isManual = false) => {
    if (isManual) setRefreshing(true)
    const token = localStorage.getItem('access_token')
    if (!token) return

    try {
      const res = await axios.get(`${API_URL}/admin/users`, {
        headers: { Authorization: `Bearer ${token}` }
      })
      if (res.data && Array.isArray(res.data.users)) {
        setUsers(res.data.users)
      }
    } catch (err) {
      console.error('Failed to load users', err)
    } finally {
      setLoading(false)
      if (isManual) setRefreshing(false)
    }
  }

  useEffect(() => {
    fetchUsers()
  }, [])

  const filteredUsers = users.filter((u) => {
    const q = searchQuery.toLowerCase()
    const matchesSearch = !q || (u.email || '').toLowerCase().includes(q) || (u.tenant_name || '').toLowerCase().includes(q)
    const matchesRole = roleFilter === 'ALL' || (u.role || '').toLowerCase() === roleFilter.toLowerCase()
    return matchesSearch && matchesRole
  })

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800/80">
        <div>
          <h1 className="text-xl font-bold font-mono tracking-tight text-slate-100 flex items-center gap-2">
            <Users2 className="w-5 h-5 text-indigo-400" />
            Users, Roles & Security Access Control
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Platform administrators and isolated tenant user accounts, role boundaries, and MFA status.
          </p>
        </div>

        <button
          onClick={() => fetchUsers(true)}
          disabled={refreshing}
          className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-400 hover:text-slate-200 transition self-start sm:self-center"
          title="Refresh User List"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-3.5 flex flex-col sm:flex-row items-center justify-between gap-3">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search email, tenant organization..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500/50"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <span className="text-xs font-mono text-slate-400">Role:</span>
          <select
            value={roleFilter}
            onChange={(e) => setRoleFilter(e.target.value)}
            className="px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-200 focus:outline-none focus:border-indigo-500/50"
          >
            <option value="ALL">All Roles</option>
            <option value="super_admin">Super Admin</option>
            <option value="tenant_admin">Tenant Admin</option>
            <option value="analyst">Analyst</option>
          </select>
        </div>
      </div>

      {/* Users Table */}
      <div className="bg-slate-950/80 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        {loading ? (
          <div className="py-16 text-center space-y-2">
            <RefreshCw className="w-6 h-6 text-indigo-400 animate-spin mx-auto" />
            <p className="text-xs font-mono text-slate-400">Loading user accounts...</p>
          </div>
        ) : filteredUsers.length === 0 ? (
          <div className="py-16 text-center space-y-2">
            <Users2 className="w-8 h-8 text-slate-600 mx-auto" />
            <p className="text-sm font-mono text-slate-300 font-bold">No users matched criteria.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-900/60 text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                  <th className="py-3 px-4">User Email</th>
                  <th className="py-3 px-4">Role</th>
                  <th className="py-3 px-4">Scope</th>
                  <th className="py-3 px-4">Associated Organization</th>
                  <th className="py-3 px-4">MFA Status</th>
                  <th className="py-3 px-4">Created Date</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-xs font-mono">
                {filteredUsers.map((user) => {
                  const isSuper = user.role === 'super_admin'
                  return (
                    <tr key={user.id} className="hover:bg-slate-900/40 transition">
                      <td className="py-3.5 px-4 font-bold text-slate-100">
                        {user.email}
                      </td>
                      <td className="py-3.5 px-4">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          isSuper 
                            ? 'bg-indigo-500/20 text-indigo-300 border border-indigo-500/40' 
                            : 'bg-slate-900 text-slate-300 border border-slate-800'
                        }`}>
                          {user.role}
                        </span>
                      </td>
                      <td className="py-3.5 px-4 text-slate-300">
                        {user.scope}
                      </td>
                      <td className="py-3.5 px-4 text-slate-200">
                        {user.tenant_name}
                      </td>
                      <td className="py-3.5 px-4">
                        {user.is_mfa_enabled ? (
                          <span className="text-emerald-400 flex items-center gap-1 text-[11px]">
                            <CheckCircle2 className="w-3.5 h-3.5" /> Enforced
                          </span>
                        ) : (
                          <span className="text-slate-500 flex items-center gap-1 text-[11px]">
                            <XCircle className="w-3.5 h-3.5 text-slate-600" /> Optional
                          </span>
                        )}
                      </td>
                      <td className="py-3.5 px-4 text-slate-500">
                        {user.created_at ? user.created_at.slice(0, 10) : 'Registered'}
                      </td>
                    </tr>
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
