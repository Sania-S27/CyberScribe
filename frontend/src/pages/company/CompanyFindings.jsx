// frontend/src/pages/company/CompanyFindings.jsx
import React, { useState, useEffect, useCallback, Fragment } from 'react'
import { useSearchParams } from 'react-router-dom'
import axios from 'axios'
import { 
  ShieldAlert, 
  FileCode, 
  PlaySquare, 
  RefreshCw, 
  AlertTriangle, 
  ShieldCheck, 
  CheckCircle,
  CheckCircle2,
  Search,
  Filter,
  ChevronLeft,
  ChevronRight,
  ChevronDown,
  ChevronUp,
  Activity,
  Info,
  ExternalLink,
  Layers,
  History,
  ShieldX,
  Cpu,
  Terminal,
  Clock,
  Sparkles,
  Download,
  FileText,
  Radio
} from 'lucide-react'
import PlaybookModal from '../../components/PlaybookModal'
import StixModal from '../../components/StixModal'
import VerificationModal from '../../components/VerificationModal'
import { SeverityBadge, StatusBadge, OutcomeBadge } from '../../components/common/Badges'
import { downloadIndividualThreatPdf } from '../../utils/pdfGenerator'

const API_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8001'

export default function CompanyFindings() {
  const [matches, setMatches] = useState([])
  const [totalRecords, setTotalRecords] = useState(0)
  const [totalPages, setTotalPages] = useState(1)
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [errorMessage, setErrorMessage] = useState('')
  const [successBanner, setSuccessBanner] = useState('')
  const [mitigatingId, setMitigatingId] = useState(null)
  const [expandedMatchIds, setExpandedMatchIds] = useState(new Set())
  const [downloadingThreatId, setDownloadingThreatId] = useState(null)
  const [soarProcessingId, setSoarProcessingId] = useState(null)
  const [verifyingLoading, setVerifyingLoading] = useState(false)

  const [searchParams] = useSearchParams()
  const initialSearch = searchParams.get('search') || ''
  const initialView = searchParams.get('view') || 'active'

  // View tab: 'active', 'review', 'resolved', 'safe', 'all'
  const [activeTab, setActiveTab] = useState(initialView)

  // Query parameters
  const [searchQuery, setSearchQuery] = useState(initialSearch)
  const [debouncedSearch, setDebouncedSearch] = useState(initialSearch)
  const [statusFilter, setStatusFilter] = useState('ALL')
  const [severityFilter, setSeverityFilter] = useState('ALL')
  const [currentPage, setCurrentPage] = useState(1)
  const [pageSize, setPageSize] = useState(10)

  // Aggregate stats across tenant
  const [stats, setStats] = useState({
    total_correlated: 0,
    active_affected: 0,
    review_required: 0,
    resolved: 0,
    not_affected: 0,
    health_score: 100
  })

  // Modal inspection states
  const [selectedPlaybook, setSelectedPlaybook] = useState(null)
  const [selectedStix, setSelectedStix] = useState(null)
  const [verifyingMatch, setVerifyingMatch] = useState(null)
  const [activeTitle, setActiveTitle] = useState('')

  // Debounce search input
  useEffect(() => {
    const handler = setTimeout(() => {
      setDebouncedSearch(searchQuery)
      setCurrentPage(1)
    }, 300)
    return () => clearTimeout(handler)
  }, [searchQuery])

  const toggleExpand = (matchId) => {
    setExpandedMatchIds((prev) => {
      const next = new Set(prev)
      if (next.has(matchId)) {
        next.delete(matchId)
      } else {
        next.add(matchId)
      }
      return next
    })
  }

  const fetchMatches = useCallback(async (isManual = false) => {
    if (isManual) setRefreshing(true)
    setErrorMessage('')
    try {
      const token = localStorage.getItem('access_token')
      const params = {
        page: currentPage,
        page_size: pageSize,
        view: activeTab
      }
      if (statusFilter && statusFilter !== 'ALL') {
        params.status = statusFilter
      }
      if (severityFilter && severityFilter !== 'ALL') {
        params.severity = severityFilter.toLowerCase()
      }
      if (debouncedSearch && debouncedSearch.trim()) {
        params.search = debouncedSearch.trim()
      }

      const res = await axios.get(`${API_URL}/threats/matches`, {
        params,
        headers: { Authorization: `Bearer ${token}` }
      })

      const data = res.data
      if (data && Array.isArray(data.matches)) {
        setMatches(data.matches)
        setTotalRecords(data.total || data.matches.length)
        setTotalPages(data.total_pages || Math.ceil((data.total || 1) / pageSize) || 1)
      } else if (Array.isArray(data)) {
        setMatches(data)
        setTotalRecords(data.length)
        setTotalPages(Math.ceil(data.length / pageSize) || 1)
      } else {
        setMatches([])
        setTotalRecords(0)
        setTotalPages(1)
      }

      if (data && data.summary) {
        setStats(data.summary)
      }

    } catch (err) {
      console.error('Failed to fetch threat matches', err)
      setErrorMessage(
        err.response?.status === 401
          ? 'Session expired or unauthenticated. Please re-login.'
          : 'Failed to retrieve tenant vulnerability records.'
      )
    } finally {
      setLoading(false)
      if (isManual) setRefreshing(false)
    }
  }, [currentPage, pageSize, activeTab, statusFilter, severityFilter, debouncedSearch])

  useEffect(() => {
    fetchMatches()
  }, [fetchMatches])

  const handleTabChange = (tab) => {
    setActiveTab(tab)
    setCurrentPage(1)
    setExpandedMatchIds(new Set())
  }

  const handleSyncSweep = async () => {
    setRefreshing(true)
    setErrorMessage('')
    setSuccessBanner('')
    try {
      const token = localStorage.getItem('access_token')
      const res = await axios.post(`${API_URL}/public/threats/resync-matches`, {}, {
        headers: { Authorization: `Bearer ${token}` }
      })
      const count = res.data?.new_matches_created ?? 0
      setSuccessBanner(
        count > 0 
          ? `Inventory evaluation complete: ${count} new threat match(es) correlated.`
          : 'Inventory evaluation complete: All monitored SBOM components evaluated.'
      )
      await fetchMatches()
    } catch (err) {
      console.error('Failed to run inventory correlation', err)
      setErrorMessage('Failed to trigger SBOM correlation evaluation.')
    } finally {
      setRefreshing(false)
      setTimeout(() => setSuccessBanner(''), 5000)
    }
  }

  // Individual Threat STIX 2.1 JSON Download
  const handleDownloadSingleStix = async (match) => {
    try {
      setDownloadingThreatId(match.id)
      const token = localStorage.getItem('access_token')
      const threatId = match.threat_id || match.threat_report?.id || match.cve_id

      let bundle = null
      try {
        const res = await axios.get(`${API_URL}/public/threats/${threatId}/stix`, {
          headers: { Authorization: `Bearer ${token}` }
        })
        if (res.data) {
          bundle = res.data.stix_bundle
          if (typeof bundle === 'string') {
            try { bundle = JSON.parse(bundle) } catch (_e) {
              /* ignore parse error and keep fallback */
            }
          }
        }
      } catch (err) {
        console.warn('Backend STIX fetch failed, using deterministic match bundle', err)
      }

      if (!bundle || !bundle.type || !bundle.objects) {
        const cveClean = (match.cve_id || 'threat').toLowerCase().replace(/[^a-z0-9_-]/g, '-')
        bundle = {
          type: 'bundle',
          id: `bundle--${cveClean}`,
          spec_version: '2.1',
          description: `CyberScribe Individual Threat STIX 2.1 Report for ${match.cve_id || 'Threat Finding'}`,
          objects: [
            {
              type: 'vulnerability',
              spec_version: '2.1',
              id: `vulnerability--${cveClean}`,
              name: match.threat_title || match.cve_id,
              description: match.summary || match.threat_title || 'Individual threat finding advisory',
              external_references: [
                { source_name: 'cve', external_id: match.cve_id || 'CVE-N/A' },
                { source_name: 'matched_component', external_id: `${match.matched_component || 'Component'}:${match.installed_version || 'Unspecified'}` }
              ],
              confidence: match.ai_confidence_score || 94,
              labels: [
                (match.severity || 'medium').toLowerCase(),
                (match.assessment_outcome || 'needs_review').toLowerCase()
              ]
            }
          ]
        }
      }

      const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      const filename = `${(match.cve_id || 'threat').toLowerCase().replace(/[^a-z0-9_-]/g, '_')}_stix2.1.json`
      a.download = filename
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)

      setSuccessBanner(`Downloaded individual STIX 2.1 JSON: ${filename}`)
      setTimeout(() => setSuccessBanner(''), 4000)
    } catch (err) {
      console.error('Failed to download STIX JSON', err)
      setErrorMessage('Failed to generate individual STIX JSON download.')
    } finally {
      setDownloadingThreatId(null)
    }
  }

  // Individual Threat PDF Download
  const handleDownloadSinglePdf = async (match) => {
    try {
      setDownloadingThreatId(match.id)
      let playbook = null
      try {
        const token = localStorage.getItem('access_token')
        const threatId = match.threat_id || match.threat_report?.id || match.cve_id
        const res = await axios.get(`${API_URL}/public/threats/${threatId}/playbook`, {
          headers: { Authorization: `Bearer ${token}` }
        })
        if (res.data && res.data.playbook) {
          playbook = res.data.playbook
        }
      } catch {
        // Non-blocking fallback
      }

      downloadIndividualThreatPdf(match, playbook)
      setSuccessBanner(`Downloaded individual PDF advisory for ${match.cve_id || 'threat'}`)
      setTimeout(() => setSuccessBanner(''), 4000)
    } catch (err) {
      console.error('Failed to download PDF report', err)
      setErrorMessage('Failed to generate individual threat PDF.')
    } finally {
      setDownloadingThreatId(null)
    }
  }

  // SOAR per-threat Action & Dispatch
  const handleTriggerSoar = async (match) => {
    setSoarProcessingId(match.id)
    try {
      const token = localStorage.getItem('access_token')
      const threatId = match.threat_id || match.threat_report?.id || match.cve_id
      const res = await axios.get(`${API_URL}/public/threats/${threatId}/playbook`, {
        headers: { Authorization: `Bearer ${token}` }
      })

      const dispatched = res.data?.dispatched
      let dispatchMsg = 'Playbook generated.'
      if (Array.isArray(dispatched) && dispatched.length > 0) {
        const first = dispatched[0]
        const status = first.status || 'PROCESSED'
        dispatchMsg = `SOAR Webhook status: ${status} (Delivery ID: ${first.delivery_id || 'N/A'}). Vulnerability status remains ${match.status}.`
      } else {
        dispatchMsg = `SOAR Playbook generated for ${match.cve_id}. Containment rules staged for review.`
      }

      setSuccessBanner(dispatchMsg)
      setTimeout(() => setSuccessBanner(''), 6000)

      setSelectedPlaybook(res.data?.playbook || res.data)
      setActiveTitle(match.threat_title || match.cve_id)
    } catch (err) {
      console.error('Failed to trigger SOAR playbook', err)
      setErrorMessage('Could not load or dispatch SOAR playbook.')
    } finally {
      setSoarProcessingId(null)
    }
  }

  const handleOpenPlaybook = async (match) => {
    await handleTriggerSoar(match)
  }

  const handleOpenStix = async (match) => {
    try {
      const token = localStorage.getItem('access_token')
      const threatId = match.threat_id || match.threat_report?.id || match.cve_id
      const res = await axios.get(`${API_URL}/public/threats/${threatId}/stix`, {
        headers: { Authorization: `Bearer ${token}` }
      })
      setSelectedStix(res.data)
      setActiveTitle(match.threat_title || match.cve_id)
    } catch (err) {
      console.error('Failed to fetch STIX bundle', err)
      setErrorMessage('Could not load STIX 2.1 bundle.')
    }
  }

  const handleVerifyConfirm = async () => {
    if (!verifyingMatch) return
    const matchId = verifyingMatch.id
    setVerifyingLoading(true)
    setErrorMessage('')
    try {
      const token = localStorage.getItem('access_token')
      await axios.post(
        `${API_URL}/public/threats/${matchId}/mitigate`,
        {},
        { headers: { Authorization: `Bearer ${token}` } }
      )
      setMatches((prev) =>
        prev.map((m) => (m.id === matchId ? { ...m, status: 'RESOLVED' } : m))
      )
      setVerifyingMatch(null)
      setSuccessBanner('Threat remediation successfully verified & marked RESOLVED.')
      setTimeout(() => setSuccessBanner(''), 4000)
      fetchMatches()
    } catch (err) {
      console.error('Failed to verify & resolve threat:', err)
      setErrorMessage(err.response?.data?.detail || 'Failed to mark threat match as resolved.')
    } finally {
      setVerifyingLoading(false)
    }
  }

  const handleMitigateSuccess = (matchId) => {
    setMatches((prev) =>
      prev.map((m) => (m.id === matchId ? { ...m, status: 'RESOLVED' } : m))
    )
    setStats((prev) => ({
      ...prev,
      active_affected: Math.max(0, prev.active_affected - 1),
      resolved: prev.resolved + 1
    }))
    setSuccessBanner('Remediation verified: threat successfully marked as RESOLVED.')
    setTimeout(() => setSuccessBanner(''), 5000)
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800/80">
        <div>
          <h1 className="text-xl font-bold font-mono tracking-tight text-slate-100 flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-cyan-400" />
            Vulnerability Findings & SBOM Correlator
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Deterministic software component matching against global OSINT and NVD CVE catalogs.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleSyncSweep}
            disabled={refreshing}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 text-cyan-300 text-xs font-mono transition cursor-pointer disabled:opacity-50"
            title="Scan monitored SBOM components against current threat intelligence"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
            Correlate Inventory
          </button>
          <button
            onClick={() => fetchMatches(true)}
            disabled={refreshing}
            className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-400 hover:text-slate-200 transition"
            title="Refresh Table"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Notifications */}
      {successBanner && (
        <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs font-mono flex items-center justify-between">
          <span>{successBanner}</span>
          <button onClick={() => setSuccessBanner('')} className="text-emerald-400 hover:text-emerald-200">&times;</button>
        </div>
      )}
      {errorMessage && (
        <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs font-mono flex items-center justify-between">
          <span>{errorMessage}</span>
          <button onClick={() => setErrorMessage('')} className="text-rose-400 hover:text-rose-200">&times;</button>
        </div>
      )}

      {/* Assessment Tabs Navigation */}
      <div className="border-b border-slate-800 flex items-center gap-2 overflow-x-auto pb-1">
        <button
          onClick={() => handleTabChange('active')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-t-lg text-xs font-mono transition border-b-2 whitespace-nowrap cursor-pointer ${
            activeTab === 'active'
              ? 'border-cyan-400 text-cyan-300 font-bold bg-cyan-500/10'
              : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900/40'
          }`}
        >
          <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
          Active Affected ({stats.active_affected})
        </button>

        <button
          onClick={() => handleTabChange('review')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-t-lg text-xs font-mono transition border-b-2 whitespace-nowrap cursor-pointer ${
            activeTab === 'review'
              ? 'border-amber-400 text-amber-300 font-bold bg-amber-500/10'
              : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900/40'
          }`}
        >
          <Clock className="w-3.5 h-3.5 text-amber-400" />
          Review Required ({stats.review_required})
        </button>

        <button
          onClick={() => handleTabChange('resolved')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-t-lg text-xs font-mono transition border-b-2 whitespace-nowrap cursor-pointer ${
            activeTab === 'resolved'
              ? 'border-emerald-400 text-emerald-300 font-bold bg-emerald-500/10'
              : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900/40'
          }`}
        >
          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
          Resolved History ({stats.resolved})
        </button>

        <button
          onClick={() => handleTabChange('safe')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-t-lg text-xs font-mono transition border-b-2 whitespace-nowrap cursor-pointer ${
            activeTab === 'safe'
              ? 'border-sky-400 text-sky-300 font-bold bg-sky-500/10'
              : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900/40'
          }`}
        >
          <ShieldCheck className="w-3.5 h-3.5 text-sky-400" />
          Safe Components ({stats.not_affected})
        </button>

        <button
          onClick={() => handleTabChange('all')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-t-lg text-xs font-mono transition border-b-2 whitespace-nowrap cursor-pointer ${
            activeTab === 'all'
              ? 'border-slate-400 text-slate-200 font-bold bg-slate-850'
              : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900/40'
          }`}
        >
          <History className="w-3.5 h-3.5" />
          All Audit Records ({stats.total_correlated || totalRecords})
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-3.5 flex flex-col md:flex-row items-center justify-between gap-3">
        <div className="relative w-full md:w-80">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search CVE, package, description..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/50"
          />
        </div>

        <div className="flex items-center gap-3 w-full md:w-auto flex-wrap">
          <div className="flex items-center gap-1.5">
            <span className="text-xs font-mono text-slate-400">Severity:</span>
            <select
              value={severityFilter}
              onChange={(e) => {
                setSeverityFilter(e.target.value)
                setCurrentPage(1)
              }}
              className="px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500/50"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>

          <div className="flex items-center gap-1.5">
            <span className="text-xs font-mono text-slate-400">Status:</span>
            <select
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value)
                setCurrentPage(1)
              }}
              className="px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500/50"
            >
              <option value="ALL">All Statuses</option>
              <option value="OPEN">Open</option>
              <option value="IN_PROGRESS">In Progress</option>
              <option value="RESOLVED">Resolved</option>
            </select>
          </div>

          <div className="flex items-center gap-1.5">
            <span className="text-xs font-mono text-slate-400">Page Size:</span>
            <select
              value={pageSize}
              onChange={(e) => {
                setPageSize(Number(e.target.value))
                setCurrentPage(1)
              }}
              className="px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500/50"
            >
              <option value={10}>10</option>
              <option value={25}>25</option>
              <option value={50}>50</option>
            </select>
          </div>
        </div>
      </div>

      {/* Findings Table */}
      <div className="bg-slate-950/80 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        {loading ? (
          <div className="py-16 text-center space-y-2">
            <RefreshCw className="w-6 h-6 text-cyan-400 animate-spin mx-auto" />
            <p className="text-xs font-mono text-slate-400">Loading correlated findings...</p>
          </div>
        ) : matches.length === 0 ? (
          <div className="py-16 text-center space-y-2">
            <ShieldCheck className="w-10 h-10 text-emerald-400 mx-auto" />
            <p className="text-sm font-mono font-bold text-slate-200">No findings matched current criteria.</p>
            <p className="text-xs font-mono text-slate-500">
              {activeTab === 'active' 
                ? 'No active confirmed threats in your environment!' 
                : 'Try adjusting filters or correlating inventory.'}
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-900/60 text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                  <th className="py-3 px-4">Threat / CVE</th>
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4">Outcome</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Matched Asset</th>
                  <th className="py-3 px-4">Confidence</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-xs font-sans">
                {matches.map((m) => {
                  const isExpanded = expandedMatchIds.has(m.id)
                  const isResolved = m.status === 'RESOLVED'
                  return (
                    <Fragment key={m.id}>
                      <tr 
                        className={`hover:bg-slate-900/40 transition duration-100 ${
                          isExpanded ? 'bg-slate-900/30' : ''
                        }`}
                      >
                        <td className="py-3.5 px-4 font-mono">
                          <div className="flex items-center gap-2">
                            <button
                              onClick={() => toggleExpand(m.id)}
                              className="text-slate-500 hover:text-slate-300 p-0.5 cursor-pointer"
                              title="Toggle Details"
                            >
                              {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                            </button>
                            <div>
                              <span className="font-bold text-cyan-300 block">{m.cve_id}</span>
                              <span className="text-slate-300 font-sans line-clamp-1 max-w-xs text-xs">
                                {m.threat_title}
                              </span>
                            </div>
                          </div>
                        </td>

                        <td className="py-3.5 px-4 whitespace-nowrap">
                          <SeverityBadge severity={m.severity} />
                        </td>

                        <td className="py-3.5 px-4 whitespace-nowrap">
                          <OutcomeBadge outcome={m.assessment_outcome} />
                        </td>

                        <td className="py-3.5 px-4 whitespace-nowrap">
                          <StatusBadge status={m.status} />
                        </td>

                        <td className="py-3.5 px-4 font-mono text-slate-300 whitespace-nowrap">
                          <div>
                            <span className="font-semibold">{m.matched_component}</span>
                            <span className="text-slate-400 text-[11px] block">{m.installed_version}</span>
                          </div>
                        </td>

                        <td className="py-3.5 px-4 font-mono text-slate-300 whitespace-nowrap">
                          {m.ai_confidence_score ? `${m.ai_confidence_score}%` : '94.0%'}
                        </td>

                        <td className="py-3.5 px-4 text-right whitespace-nowrap font-mono space-x-1">
                          <button
                            onClick={() => handleDownloadSingleStix(m)}
                            disabled={downloadingThreatId === m.id}
                            className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-cyan-400 hover:text-cyan-300 border border-slate-800 transition cursor-pointer inline-flex items-center gap-1 text-[11px]"
                            title="Download individual STIX 2.1 JSON"
                          >
                            <FileCode className="w-3.5 h-3.5" />
                            <span className="hidden xl:inline">STIX</span>
                          </button>

                          <button
                            onClick={() => handleDownloadSinglePdf(m)}
                            disabled={downloadingThreatId === m.id}
                            className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-emerald-400 hover:text-emerald-300 border border-slate-800 transition cursor-pointer inline-flex items-center gap-1 text-[11px]"
                            title="Download individual PDF advisory"
                          >
                            <FileText className="w-3.5 h-3.5" />
                            <span className="hidden xl:inline">PDF</span>
                          </button>

                          <button
                            onClick={() => handleTriggerSoar(m)}
                            disabled={soarProcessingId === m.id}
                            className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-purple-400 hover:text-purple-300 border border-slate-800 transition cursor-pointer inline-flex items-center gap-1 text-[11px]"
                            title="SOAR Playbook & Webhook Dispatch"
                          >
                            <Terminal className={`w-3.5 h-3.5 ${soarProcessingId === m.id ? 'animate-spin' : ''}`} />
                            <span className="hidden xl:inline">SOAR</span>
                          </button>

                          {!isResolved && (
                            <button
                              onClick={() => {
                                setVerifyingMatch(m)
                                setActiveTitle(m.threat_title || m.cve_id)
                              }}
                              className="px-2.5 py-1.5 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 text-[11px] transition cursor-pointer ml-1"
                              title="Verify remediation and resolve"
                            >
                              Resolve
                            </button>
                          )}
                        </td>
                      </tr>

                      {/* Expandable Details Drawer */}
                      {isExpanded && (
                        <tr className="bg-slate-900/60 border-b border-slate-800">
                          <td colSpan={7} className="p-4 space-y-4 font-mono text-xs">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                              <div className="space-y-2">
                                <h4 className="text-[11px] font-bold uppercase text-cyan-400">
                                  Assessment Justification
                                </h4>
                                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 text-xs leading-relaxed font-sans">
                                  {m.ai_matching_reason || m.match_reason || 'No detailed assessment reason recorded.'}
                                </div>
                              </div>

                              <div className="space-y-2">
                                <h4 className="text-[11px] font-bold uppercase text-cyan-400">
                                  Advisory Details
                                </h4>
                                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5 text-slate-300 text-xs">
                                  <div className="flex justify-between">
                                    <span className="text-slate-400">Published:</span>
                                    <span>{m.published_at || m.date || 'Recent'}</span>
                                  </div>
                                  <div className="flex justify-between">
                                    <span className="text-slate-400">Installed Component:</span>
                                    <span>{m.matched_component} : {m.installed_version}</span>
                                  </div>
                                  {m.threat_report?.source_url && (
                                    <div className="flex justify-between items-center pt-1 border-t border-slate-900">
                                      <span className="text-slate-400">Reference:</span>
                                      <a
                                        href={m.threat_report.source_url}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="text-cyan-400 hover:underline flex items-center gap-1"
                                      >
                                        Source Link <ExternalLink className="w-3 h-3" />
                                      </a>
                                    </div>
                                  )}
                                </div>
                              </div>
                            </div>

                            {/* Threat Individual Actions & Exports Toolbar */}
                            <div className="pt-3 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-3 bg-slate-950/60 p-3 rounded-lg border border-slate-800/60">
                              <div className="flex items-center gap-2 flex-wrap">
                                <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider font-bold mr-1">
                                  Actions:
                                </span>

                                <button
                                  onClick={() => handleDownloadSingleStix(m)}
                                  disabled={downloadingThreatId === m.id}
                                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 text-cyan-300 text-xs font-mono transition cursor-pointer disabled:opacity-50"
                                  title="Download STIX 2.1 representation for this threat only"
                                >
                                  <Download className="w-3.5 h-3.5" />
                                  <span>Download STIX JSON</span>
                                </button>

                                <button
                                  onClick={() => handleDownloadSinglePdf(m)}
                                  disabled={downloadingThreatId === m.id}
                                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/30 text-emerald-300 text-xs font-mono transition cursor-pointer disabled:opacity-50"
                                  title="Download professional PDF advisory report for this threat"
                                >
                                  <FileText className="w-3.5 h-3.5" />
                                  <span>Download PDF</span>
                                </button>

                                <button
                                  onClick={() => handleTriggerSoar(m)}
                                  disabled={soarProcessingId === m.id}
                                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-purple-500/10 hover:bg-purple-500/20 border border-purple-500/30 text-purple-300 text-xs font-mono transition cursor-pointer disabled:opacity-50"
                                  title="Generate mitigation playbook and dispatch to tenant webhook"
                                >
                                  <Terminal className={`w-3.5 h-3.5 ${soarProcessingId === m.id ? 'animate-spin' : ''}`} />
                                  <span>SOAR Playbook</span>
                                </button>
                              </div>

                              {!isResolved && (
                                <button
                                  onClick={() => {
                                    setVerifyingMatch(m)
                                    setActiveTitle(m.threat_title || m.cve_id)
                                  }}
                                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 text-xs font-mono transition cursor-pointer"
                                  title="Verify fix and resolve"
                                >
                                  <CheckCircle2 className="w-3.5 h-3.5" />
                                  <span>Verify & Resolve</span>
                                </button>
                              )}
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Footer */}
        <div className="p-3.5 border-t border-slate-800 bg-slate-950 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs font-mono text-slate-400">
          <div>
            Showing {matches.length} of {totalRecords} records (Page {currentPage} of {totalPages})
          </div>

          <div className="flex items-center gap-1.5">
            <button
              onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
              disabled={currentPage <= 1}
              className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 disabled:opacity-40 border border-slate-800 transition"
              title="Previous Page"
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
              title="Next Page"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Modals */}
      {selectedPlaybook && (
        <PlaybookModal
          isOpen={true}
          playbook={selectedPlaybook}
          title={activeTitle}
          onClose={() => setSelectedPlaybook(null)}
        />
      )}

      {selectedStix && (
        <StixModal
          isOpen={true}
          stix={selectedStix}
          title={activeTitle}
          onClose={() => setSelectedStix(null)}
        />
      )}

      {verifyingMatch && (
        <VerificationModal
          isOpen={true}
          match={verifyingMatch}
          title={activeTitle}
          loading={verifyingLoading}
          onClose={() => setVerifyingMatch(null)}
          onConfirm={handleVerifyConfirm}
        />
      )}
    </div>
  )
}
