// frontend/src/pages/admin/AdminThreatIntel.jsx
import React, { useState, useEffect } from 'react'
import axios from 'axios'
import {
  Radio,
  Search,
  Filter,
  RefreshCw,
  FileCode,
  ExternalLink,
  ChevronLeft,
  ChevronRight,
  Database,
  Calendar,
  AlertCircle
} from 'lucide-react'
import { SeverityBadge } from '../../components/common/Badges'
import StixModal from '../../components/StixModal'

const API_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8001'

export default function AdminThreatIntel() {
  const [threats, setThreats] = useState([])
  const [totalCount, setTotalCount] = useState(0)
  const [totalPages, setTotalPages] = useState(1)
  const [currentPage, setCurrentPage] = useState(1)
  const [pageSize, setPageSize] = useState(10)
  const [searchQuery, setSearchQuery] = useState('')
  const [severityFilter, setSeverityFilter] = useState('ALL')
  const [daysFilter, setDaysFilter] = useState('90')
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [sweeping, setSweeping] = useState(false)
  const [showSweepConfirm, setShowSweepConfirm] = useState(false)
  const [feedbackMessage, setFeedbackMessage] = useState('')
  const [selectedStix, setSelectedStix] = useState(null)
  const [activeTitle, setActiveTitle] = useState('')

  const fetchThreats = async (isManual = false) => {
    if (isManual) setRefreshing(true)
    setLoading(true)
    try {
      const params = {
        page: currentPage,
        page_size: pageSize,
        days: daysFilter
      }
      if (searchQuery.trim()) params.search = searchQuery.trim()
      if (severityFilter !== 'ALL') params.severity = severityFilter.toLowerCase()

      const res = await axios.get(`${API_URL}/public/threats`, { params })
      if (res.data && Array.isArray(res.data.threats)) {
        setThreats(res.data.threats)
        setTotalCount(res.data.total || 0)
        setTotalPages(res.data.total_pages || 1)
      }
    } catch (err) {
      console.error('Failed to load global threats', err)
    } finally {
      setLoading(false)
      if (isManual) setRefreshing(false)
    }
  }

  useEffect(() => {
    fetchThreats()
  }, [currentPage, pageSize, severityFilter, daysFilter])

  const handleSearchSubmit = (e) => {
    e.preventDefault()
    setCurrentPage(1)
    fetchThreats()
  }

  const handleSweepConfirm = async () => {
    setShowSweepConfirm(false)
    setSweeping(true)
    setFeedbackMessage('')
    try {
      const token = localStorage.getItem('access_token')
      const res = await axios.post(`${API_URL}/admin/threats/trigger-osint-sweep`, {}, {
        headers: { Authorization: `Bearer ${token}` }
      })
      setFeedbackMessage(res.data?.message || 'OSINT sweep completed successfully.')
      await fetchThreats()
    } catch (err) {
      setFeedbackMessage('Failed to trigger OSINT collection sweep.')
    } finally {
      setSweeping(false)
      setTimeout(() => setFeedbackMessage(''), 5000)
    }
  }

  const handleInspectStix = async (threat) => {
    try {
      const res = await axios.get(`${API_URL}/public/threats/${threat.id}/stix`)
      setSelectedStix(res.data)
      setActiveTitle(threat.title || threat.cve)
    } catch (err) {
      console.error('Failed to load STIX bundle', err)
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800/80">
        <div>
          <h1 className="text-xl font-bold font-mono tracking-tight text-slate-100 flex items-center gap-2">
            <Radio className="w-5 h-5 text-indigo-400" />
            Global Threat Intelligence Ingestion Feed
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Aggregated CVE catalog, CISA KEV alerts, Feodo Tracker network IOCs, and NVD advisories.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowSweepConfirm(true)}
            disabled={sweeping}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-indigo-500/15 hover:bg-indigo-500/25 border border-indigo-500/30 text-indigo-300 text-xs font-mono transition cursor-pointer disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${sweeping ? 'animate-spin' : ''}`} />
            Trigger OSINT Sweep
          </button>
          <button
            onClick={() => fetchThreats(true)}
            disabled={refreshing}
            className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-400 hover:text-slate-200 transition"
            title="Refresh Ingestion Feed"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {feedbackMessage && (
        <div className="p-3 rounded-lg bg-indigo-500/10 border border-indigo-500/30 text-indigo-300 text-xs font-mono">
          {feedbackMessage}
        </div>
      )}

      {/* Confirmation Dialog Modal */}
      {showSweepConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-xs">
          <div className="bg-slate-950 border border-indigo-500/40 rounded-xl p-6 max-w-md w-full space-y-4">
            <div className="flex items-center gap-2 text-indigo-400 font-mono font-bold text-sm">
              <AlertCircle className="w-5 h-5" /> Confirm OSINT Collection Sweep
            </div>
            <p className="text-xs font-mono text-slate-300 leading-relaxed">
              This initiates an asynchronous harvest across external OSINT sources (Feodo Tracker C2 feeds, CISA KEV, NVD REST API 2.0). All newly ingested items will be correlated across active tenants.
            </p>
            <div className="flex justify-end gap-2 pt-2">
              <button
                onClick={() => setShowSweepConfirm(false)}
                className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 text-xs font-mono"
              >
                Cancel
              </button>
              <button
                onClick={handleSweepConfirm}
                className="px-4 py-1.5 rounded-lg bg-indigo-500 hover:bg-indigo-400 text-slate-950 font-bold text-xs font-mono"
              >
                Execute Sweep
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Search and Filters Bar */}
      <form onSubmit={handleSearchSubmit} className="bg-slate-950/80 border border-slate-800 rounded-xl p-3.5 flex flex-col md:flex-row items-center justify-between gap-3">
        <div className="relative w-full md:w-80">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search CVE ID or keyword..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500/50"
          />
        </div>

        <div className="flex items-center gap-3 w-full md:w-auto flex-wrap">
          <div className="flex items-center gap-1.5">
            <span className="text-xs font-mono text-slate-400">Time Range:</span>
            <select
              value={daysFilter}
              onChange={(e) => {
                setDaysFilter(e.target.value)
                setCurrentPage(1)
              }}
              className="px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-200 focus:outline-none focus:border-indigo-500/50"
            >
              <option value="30">Last 30 Days</option>
              <option value="90">Last 90 Days</option>
              <option value="365">Last 1 Year</option>
              <option value="all">Full Historical Catalog</option>
            </select>
          </div>

          <div className="flex items-center gap-1.5">
            <span className="text-xs font-mono text-slate-400">Severity:</span>
            <select
              value={severityFilter}
              onChange={(e) => {
                setSeverityFilter(e.target.value)
                setCurrentPage(1)
              }}
              className="px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-200 focus:outline-none focus:border-indigo-500/50"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>
        </div>
      </form>

      {/* Threats Table */}
      <div className="bg-slate-950/80 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        {loading ? (
          <div className="py-16 text-center space-y-2">
            <RefreshCw className="w-6 h-6 text-indigo-400 animate-spin mx-auto" />
            <p className="text-xs font-mono text-slate-400">Loading threat intelligence feed...</p>
          </div>
        ) : threats.length === 0 ? (
          <div className="py-16 text-center space-y-2">
            <Database className="w-8 h-8 text-slate-600 mx-auto" />
            <p className="text-sm font-mono text-slate-300 font-bold">No threat reports found.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-900/60 text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                  <th className="py-3 px-4">CVE ID</th>
                  <th className="py-3 px-4">Threat Advisory Title</th>
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4">Published Date</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-xs font-mono">
                {threats.map((threat) => (
                  <tr key={threat.id} className="hover:bg-slate-900/40 transition">
                    <td className="py-3.5 px-4 font-bold text-indigo-300 whitespace-nowrap">
                      {threat.cve || 'CVE-PENDING'}
                    </td>
                    <td className="py-3.5 px-4 font-sans text-slate-200 max-w-md">
                      <p className="font-semibold line-clamp-1">{threat.title}</p>
                      <p className="text-[11px] text-slate-500 line-clamp-1 font-mono">{threat.summary}</p>
                    </td>
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <SeverityBadge severity={threat.severity} />
                    </td>
                    <td className="py-3.5 px-4 text-slate-400 whitespace-nowrap">
                      {threat.published_at || threat.date || 'Recent'}
                    </td>
                    <td className="py-3.5 px-4 text-right whitespace-nowrap space-x-1.5">
                      <button
                        onClick={() => handleInspectStix(threat)}
                        className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-indigo-300 border border-slate-800 transition"
                        title="Inspect STIX 2.1 Bundle"
                      >
                        <FileCode className="w-3.5 h-3.5 inline" />
                      </button>
                      {threat.source && (
                        <a
                          href={threat.source}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800 transition inline-block"
                          title="Open Source Link"
                        >
                          <ExternalLink className="w-3.5 h-3.5 inline" />
                        </a>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Footer */}
        <div className="p-3.5 border-t border-slate-800 bg-slate-950 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs font-mono text-slate-400">
          <div>
            Showing {threats.length} of {totalCount} advisories (Page {currentPage} of {totalPages})
          </div>

          <div className="flex items-center gap-1.5">
            <button
              onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
              disabled={currentPage <= 1}
              className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 disabled:opacity-40 border border-slate-800 transition"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span className="px-2 font-semibold text-slate-200">
              {currentPage} / {totalPages}
            </span>
            <button
              onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
              disabled={currentPage >= totalPages}
              className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 disabled:opacity-40 border border-slate-800 transition"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {selectedStix && (
        <StixModal
          stix={selectedStix}
          title={activeTitle}
          onClose={() => setSelectedStix(null)}
        />
      )}
    </div>
  )
}
