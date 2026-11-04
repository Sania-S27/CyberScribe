// frontend/src/pages/GuestDashboard.jsx
import { useState, useEffect, useCallback } from 'react'
import { Link, useLocation } from 'react-router-dom'
import axios from 'axios'
import { 
  Radio, 
  FileJson, 
  Terminal, 
  ExternalLink, 
  Home, 
  Search, 
  ChevronLeft, 
  ChevronRight,
  Filter,
  Calendar,
  Layers,
  AlertCircle,
  Hash
} from 'lucide-react'
import PlaybookModal from '../components/PlaybookModal'
import StixModal from '../components/StixModal'

const API_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8001'

export default function GuestDashboard() {
  const [threats, setThreats] = useState([])
  const [totalRecords, setTotalRecords] = useState(0)
  const [totalPages, setTotalPages] = useState(1)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const [selectedPlaybook, setSelectedPlaybook] = useState(null)
  const [selectedStix, setSelectedStix] = useState(null)
  const [activeTitle, setActiveTitle] = useState('')

  // Query state parameters
  const [searchQuery, setSearchQuery] = useState('')
  const [debouncedSearch, setDebouncedSearch] = useState('')
  const [selectedSeverity, setSelectedSeverity] = useState('ALL')
  const [dateRange, setDateRange] = useState('90') // '90' (default 3 months), '30', or 'all'
  const [currentPage, setCurrentPage] = useState(1)
  const [pageSize, setPageSize] = useState(10)

  const location = useLocation()
  const isPublicRoute = !location.pathname.startsWith('/admin') && !location.pathname.startsWith('/dashboard')

  // Debounce search input by 300ms
  useEffect(() => {
    const handler = setTimeout(() => {
      setDebouncedSearch(searchQuery)
      setCurrentPage(1)
    }, 300)
    return () => clearTimeout(handler)
  }, [searchQuery])

  // Fetch threat intelligence with server-side pagination
  const fetchPublicThreats = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const params = {
        page: currentPage,
        page_size: pageSize,
        days: dateRange
      }
      if (selectedSeverity && selectedSeverity !== 'ALL') {
        params.severity = selectedSeverity.toLowerCase()
      }
      if (debouncedSearch && debouncedSearch.trim()) {
        params.search = debouncedSearch.trim()
      }

      const response = await axios.get(`${API_URL}/public/threats`, { params })
      const data = response.data

      if (data && Array.isArray(data.threats)) {
        setThreats(data.threats)
        setTotalRecords(typeof data.total === 'number' ? data.total : data.threats.length)
        const calcPages = typeof data.total_pages === 'number' 
          ? data.total_pages 
          : Math.max(1, Math.ceil((data.total || 0) / pageSize))
        setTotalPages(calcPages)
      } else if (Array.isArray(data)) {
        // Fallback for flat array response
        setThreats(data)
        setTotalRecords(data.length)
        setTotalPages(Math.max(1, Math.ceil(data.length / pageSize)))
      } else {
        setThreats([])
        setTotalRecords(0)
        setTotalPages(1)
      }
    } catch (err) {
      console.error('Failed to load public threats', err)
      setError('Unable to load threat intelligence feed. Verify backend connectivity on port 8001.')
      setThreats([])
    } finally {
      setLoading(false)
    }
  }, [currentPage, pageSize, selectedSeverity, debouncedSearch, dateRange])

  useEffect(() => {
    fetchPublicThreats()
  }, [fetchPublicThreats])

  const handlePageChange = (newPage) => {
    if (newPage < 1 || newPage > totalPages || newPage === currentPage) return
    setCurrentPage(newPage)
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }

  const handleSearchChange = (e) => {
    setSearchQuery(e.target.value)
  }

  const handleSeverityChange = (sev) => {
    setSelectedSeverity(sev)
    setCurrentPage(1)
  }

  const handleDateRangeChange = (range) => {
    setDateRange(range)
    setCurrentPage(1)
  }

  const handlePageSizeChange = (e) => {
    const newSize = Number(e.target.value)
    setPageSize(newSize)
    setCurrentPage(1)
  }

  const openPlaybook = async (reportId, title) => {
    setActiveTitle(title)
    try {
      const res = await axios.get(`${API_URL}/public/threats/${reportId}/playbook`)
      setSelectedPlaybook(res.data.playbook)
    } catch (err) {
      console.error('Failed to fetch playbook:', err)
    }
  }

  const openStix = async (reportId, title) => {
    setActiveTitle(title)
    try {
      const res = await axios.get(`${API_URL}/public/threats/${reportId}/stix`)
      setSelectedStix(res.data.stix_bundle)
    } catch (err) {
      console.error('Failed to fetch STIX bundle:', err)
    }
  }

  const getSeverityBadge = (severity) => {
    const sev = (severity || 'medium').toLowerCase()
    if (sev === 'critical') return 'bg-rose-500/10 text-rose-400 border-rose-500/30'
    if (sev === 'high') return 'bg-amber-500/10 text-amber-400 border-amber-500/30'
    if (sev === 'medium') return 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30'
    return 'bg-slate-500/10 text-slate-400 border-slate-500/30'
  }

  // Generate numbered pagination items
  const renderPaginationButtons = () => {
    const buttons = []
    const maxButtons = 5
    let start = Math.max(1, currentPage - 2)
    let end = Math.min(totalPages, start + maxButtons - 1)

    if (end - start < maxButtons - 1) {
      start = Math.max(1, end - maxButtons + 1)
    }

    if (start > 1) {
      buttons.push(
        <button
          key={1}
          onClick={() => handlePageChange(1)}
          className={`px-3 py-1.5 rounded text-xs font-mono transition cursor-pointer ${
            currentPage === 1
              ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold shadow-sm'
              : 'border border-slate-800 bg-slate-900/80 text-slate-400 hover:text-slate-200 hover:bg-slate-800'
          }`}
        >
          1
        </button>
      )
      if (start > 2) {
        buttons.push(<span key="dots-1" className="text-slate-600 px-1 font-mono">...</span>)
      }
    }

    for (let i = start; i <= end; i++) {
      buttons.push(
        <button
          key={i}
          onClick={() => handlePageChange(i)}
          className={`px-3 py-1.5 rounded text-xs font-mono transition cursor-pointer ${
            currentPage === i
              ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold shadow-sm'
              : 'border border-slate-800 bg-slate-900/80 text-slate-400 hover:text-slate-200 hover:bg-slate-800'
          }`}
        >
          {i}
        </button>
      )
    }

    if (end < totalPages) {
      if (end < totalPages - 1) {
        buttons.push(<span key="dots-2" className="text-slate-600 px-1 font-mono">...</span>)
      }
      buttons.push(
        <button
          key={totalPages}
          onClick={() => handlePageChange(totalPages)}
          className={`px-3 py-1.5 rounded text-xs font-mono transition cursor-pointer ${
            currentPage === totalPages
              ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold shadow-sm'
              : 'border border-slate-800 bg-slate-900/80 text-slate-400 hover:text-slate-200 hover:bg-slate-800'
          }`}
        >
          {totalPages}
        </button>
      )
    }

    return buttons
  }

  const startRecordIdx = totalRecords === 0 ? 0 : (currentPage - 1) * pageSize + 1
  const endRecordIdx = Math.min(currentPage * pageSize, totalRecords)

  const content = (
    <div className="space-y-4 max-w-7xl mx-auto font-sans">
      {/* Header section */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <Radio className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <h1 className="text-base md:text-lg font-bold tracking-wide uppercase text-slate-100">
              Global OSINT Explorer
            </h1>
            <p className="text-xs text-slate-400 font-mono">
              Live Multi-Feed Ingestion (NVD, CISA, SecurityWeek, BleepingComputer, Krebs, Hacker News, Dark Reading)
            </p>
          </div>
        </div>

        {isPublicRoute && (
          <div className="flex items-center gap-2">
            <Link
              to="/"
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-800 text-slate-300 hover:border-slate-700 hover:text-slate-100 text-xs font-mono transition"
            >
              <Home className="w-3.5 h-3.5" /> Home
            </Link>
            <Link
              to="/login"
              className="px-3.5 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-bold uppercase tracking-wider transition font-mono"
            >
              SOC Login
            </Link>
          </div>
        )}
      </div>

      {/* Toolbar: Search, Date Range, Severity & Page Size */}
      <div className="flex flex-col lg:flex-row gap-3 items-stretch lg:items-center justify-between pt-1">
        {/* Search */}
        <div className="relative flex-1 max-w-md">
          <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            value={searchQuery}
            onChange={handleSearchChange}
            placeholder="Filter by CVE, software, title, or keyword..."
            className="w-full bg-slate-900/80 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs font-mono text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Date Window Toggle */}
          <div className="flex items-center rounded-lg border border-slate-800 bg-slate-900/60 p-0.5">
            <button
              onClick={() => handleDateRangeChange('90')}
              className={`flex items-center gap-1 px-2.5 py-1 rounded text-xs font-mono transition cursor-pointer ${
                dateRange === '90'
                  ? 'bg-cyan-500/20 text-cyan-300 font-bold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Calendar className="w-3 h-3" /> Last 3 Months
            </button>
            <button
              onClick={() => handleDateRangeChange('30')}
              className={`flex items-center gap-1 px-2.5 py-1 rounded text-xs font-mono transition cursor-pointer ${
                dateRange === '30'
                  ? 'bg-cyan-500/20 text-cyan-300 font-bold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Last 30 Days
            </button>
            <button
              onClick={() => handleDateRangeChange('all')}
              className={`flex items-center gap-1 px-2.5 py-1 rounded text-xs font-mono transition cursor-pointer ${
                dateRange === 'all'
                  ? 'bg-cyan-500/20 text-cyan-300 font-bold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Layers className="w-3 h-3" /> All Time
            </button>
          </div>

          {/* Severity Filters */}
          <div className="flex items-center gap-1">
            <Filter className="w-3 h-3 text-slate-500 mr-0.5 hidden sm:inline" />
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
              <button
                key={sev}
                onClick={() => handleSeverityChange(sev)}
                className={`px-2 py-1 rounded text-[11px] font-mono transition uppercase ${
                  selectedSeverity === sev
                    ? 'bg-cyan-500/10 border border-cyan-500/40 text-cyan-400 font-bold'
                    : 'bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-200'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>

          {/* Page Size Selector */}
          <div className="flex items-center gap-1.5 pl-1">
            <span className="text-[11px] font-mono text-slate-500">Page Size:</span>
            <select
              value={pageSize}
              onChange={handlePageSizeChange}
              className="bg-slate-900 border border-slate-800 rounded px-2 py-1 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500 transition cursor-pointer"
            >
              <option value={10}>10</option>
              <option value={25}>25</option>
              <option value={50}>50</option>
            </select>
          </div>
        </div>
      </div>

      {/* Quick Summary Pill */}
      <div className="flex items-center justify-between px-3 py-1.5 bg-slate-950/40 border border-slate-800/60 rounded-lg text-[11px] font-mono text-slate-400">
        <div className="flex items-center gap-2">
          <Hash className="w-3 h-3 text-cyan-400" />
          <span>
            Showing <strong className="text-slate-200">{startRecordIdx}–{endRecordIdx}</strong> of <strong className="text-cyan-400">{totalRecords}</strong> intelligence reports
          </span>
          <span className="text-slate-600">|</span>
          <span>Page <strong className="text-slate-200">{currentPage}</strong> of <strong className="text-slate-200">{totalPages}</strong></span>
        </div>
        <div className="text-slate-500">
          {dateRange === '90' ? 'Active Filter: Last 90 Days' : dateRange === '30' ? 'Active Filter: Last 30 Days' : 'Active Filter: All Historical Data'}
        </div>
      </div>

      {/* Error Message */}
      {error && (
        <div className="flex items-center gap-2 p-3 bg-rose-500/10 border border-rose-500/30 rounded-xl text-rose-400 text-xs font-mono">
          <AlertCircle className="w-4 h-4 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Main List */}
      {loading ? (
        <div className="text-center py-20 text-slate-400 font-mono text-xs space-y-2">
          <div className="w-6 h-6 border-2 border-cyan-500/30 border-t-cyan-500 rounded-full animate-spin mx-auto"></div>
          <p>Querying threat intelligence database (Page {currentPage} of {totalPages})...</p>
        </div>
      ) : threats.length === 0 ? (
        <div className="text-center py-16 bg-slate-900/30 border border-slate-800 rounded-xl text-slate-400 font-mono text-xs space-y-2">
          <p>No threat reports found matching the selected criteria.</p>
          {dateRange === '30' && (
            <p className="text-slate-500 text-[11px]">
              Try switching to <button onClick={() => handleDateRangeChange('all')} className="text-cyan-400 underline hover:text-cyan-300 cursor-pointer">All Time</button> to inspect historical intelligence.
            </p>
          )}
        </div>
      ) : (
        <div className="space-y-4">
          <div className="bg-slate-900/40 border border-slate-800/80 rounded-xl overflow-hidden divide-y divide-slate-800/60 shadow-lg shadow-black/20">
            {threats.map((threat) => (
              <div
                key={threat.id}
                className="p-4 hover:bg-slate-900/70 transition flex flex-col md:flex-row md:items-center justify-between gap-3"
              >
                <div className="space-y-1.5 max-w-3xl">
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded-full border ${getSeverityBadge(
                        threat.severity
                      )}`}
                    >
                      {threat.severity}
                    </span>
                    {threat.published_at ? (
                      <span className="text-[11px] font-mono text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded border border-emerald-500/30">
                        Published {threat.published_at}
                      </span>
                    ) : (
                      <span className="text-[11px] font-mono text-slate-400 bg-slate-800/40 px-1.5 py-0.5 rounded border border-slate-700/50" title="Source publication date unavailable; showing record ingestion discovery time">
                        Publication date unavailable · Ingested {threat.created_at || threat.date}
                      </span>
                    )}
                    {threat.published_at && threat.created_at && threat.created_at !== threat.published_at && (
                      <span className="text-[10px] font-mono text-slate-500">
                        (Ingested: {threat.created_at})
                      </span>
                    )}
                    {threat.cve && threat.cve !== 'N/A' && threat.cve !== 'CVE-N/A' && (
                      <span className="text-[11px] font-mono text-purple-400 bg-purple-500/10 px-1.5 py-0.5 rounded border border-purple-500/30">
                        {threat.cve}
                      </span>
                    )}
                  </div>
                  <h3 className="text-sm font-semibold text-slate-100 line-clamp-1">{threat.title}</h3>
                  <p className="text-xs text-slate-400 line-clamp-2 leading-relaxed">{threat.summary}</p>
                </div>

                <div className="flex items-center gap-2 self-end md:self-center flex-shrink-0">
                  <button
                    onClick={() => openStix(threat.id, threat.title)}
                    className="flex items-center gap-1 px-2.5 py-1 rounded-md bg-slate-950 border border-slate-800 hover:border-cyan-500/50 text-cyan-400 text-[11px] font-mono transition cursor-pointer"
                  >
                    <FileJson className="w-3 h-3" /> STIX 2.1
                  </button>
                  <button
                    onClick={() => openPlaybook(threat.id, threat.title)}
                    className="flex items-center gap-1 px-2.5 py-1 rounded-md bg-cyan-500/10 border border-cyan-500/30 hover:bg-cyan-500/20 text-cyan-300 text-[11px] font-mono transition cursor-pointer"
                  >
                    <Terminal className="w-3 h-3" /> SOAR Playbook
                  </button>
                  {threat.source && (
                    <a
                      href={threat.source}
                      target="_blank"
                      rel="noreferrer"
                      className="p-1.5 rounded-md text-slate-500 hover:text-slate-300 hover:bg-slate-800 transition"
                      title="Open source advisory URL"
                    >
                      <ExternalLink className="w-3.5 h-3.5" />
                    </a>
                  )}
                </div>
              </div>
            ))}
          </div>

          {/* Prominent Pagination Controls Bar */}
          <div className="flex flex-col sm:flex-row items-center justify-between gap-4 p-4 bg-slate-900/90 border border-slate-800 rounded-xl text-xs font-mono text-slate-400 shadow-xl backdrop-blur">
            <div className="flex items-center gap-2">
              <span>
                Showing <strong className="text-slate-100">{startRecordIdx}</strong>–<strong className="text-slate-100">{endRecordIdx}</strong> of <strong className="text-cyan-400">{totalRecords}</strong> reports
              </span>
              {dateRange === '90' && <span className="text-slate-500 text-[11px]">(Last 3 Months)</span>}
              {dateRange === '30' && <span className="text-slate-500 text-[11px]">(Last 30 Days)</span>}
              {dateRange === 'all' && <span className="text-slate-500 text-[11px]">(All Time)</span>}
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <button
                disabled={currentPage <= 1 || loading}
                onClick={() => handlePageChange(currentPage - 1)}
                className="flex items-center gap-1 px-3 py-1.5 rounded border border-slate-800 bg-slate-950 hover:bg-slate-800 disabled:opacity-30 disabled:pointer-events-none text-slate-300 transition cursor-pointer font-semibold"
              >
                <ChevronLeft className="w-4 h-4" /> Previous
              </button>

              <div className="flex items-center gap-1">
                {renderPaginationButtons()}
              </div>

              <button
                disabled={currentPage >= totalPages || loading}
                onClick={() => handlePageChange(currentPage + 1)}
                className="flex items-center gap-1 px-3 py-1.5 rounded border border-slate-800 bg-slate-950 hover:bg-slate-800 disabled:opacity-30 disabled:pointer-events-none text-slate-300 transition cursor-pointer font-semibold"
              >
                Next <ChevronRight className="w-4 h-4" />
              </button>

              <div className="flex items-center gap-1.5 pl-2 border-l border-slate-800">
                <span className="text-slate-500 text-[11px]">Per Page:</span>
                <select
                  value={pageSize}
                  onChange={handlePageSizeChange}
                  className="bg-slate-950 border border-slate-800 rounded px-2 py-1 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500 transition cursor-pointer"
                >
                  <option value={10}>10</option>
                  <option value={25}>25</option>
                  <option value={50}>50</option>
                </select>
              </div>
            </div>
          </div>
        </div>
      )}

      <PlaybookModal
        isOpen={Boolean(selectedPlaybook)}
        onClose={() => setSelectedPlaybook(null)}
        playbookData={selectedPlaybook}
        threatTitle={activeTitle}
      />
      <StixModal
        isOpen={Boolean(selectedStix)}
        onClose={() => setSelectedStix(null)}
        stixData={selectedStix}
        threatTitle={activeTitle}
      />
    </div>
  )

  if (isPublicRoute) {
    return (
      <div className="min-h-screen bg-[#070b14] text-slate-100 p-4 md:p-8 font-sans">
        {content}
      </div>
    )
  }

  return content
}