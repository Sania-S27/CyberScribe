// frontend/src/pages/company/CompanyReports.jsx
import React, { useState, useEffect } from 'react'
import axios from 'axios'
import {
  FileText,
  Download,
  AlertTriangle,
  RefreshCw,
  FileCode,
  Layers,
  Building2
} from 'lucide-react'
import { downloadExecutiveReportPdf } from '../../utils/pdfGenerator'

const API_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8001'

export default function CompanyReports() {
  const [loading, setLoading] = useState(true)
  const [reportSummary, setReportSummary] = useState(null)
  const [matches, setMatches] = useState([])
  const [errorMessage, setErrorMessage] = useState('')
  const [downloadingPdf, setDownloadingPdf] = useState(false)
  const [downloadingStix, setDownloadingStix] = useState(false)
  const [downloadingCsv, setDownloadingCsv] = useState(false)

  const fetchReportData = async () => {
    setLoading(true)
    setErrorMessage('')
    const token = localStorage.getItem('access_token')
    if (!token) return

    try {
      // 1. Fetch executive summary
      const summaryRes = await axios.get(`${API_URL}/tenants/reports/summary`, {
        headers: { Authorization: `Bearer ${token}` }
      })
      setReportSummary(summaryRes.data)

      // 2. Fetch all matched records for export datasets (unpaginated up to 1000)
      const matchesRes = await axios.get(`${API_URL}/threats/matches`, {
        params: { page: 1, page_size: 1000, view: 'all' },
        headers: { Authorization: `Bearer ${token}` }
      })
      if (matchesRes.data && Array.isArray(matchesRes.data.matches)) {
        setMatches(matchesRes.data.matches)
      } else if (Array.isArray(matchesRes.data)) {
        setMatches(matchesRes.data)
      }
    } catch (err) {
      console.error('Failed to load report data', err)
      setErrorMessage('Failed to generate executive report data from tenant telemetry.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchReportData()
  }, [])

  // 1. Export Executive Company Report as PDF
  const handleExportExecutivePdf = () => {
    if (!reportSummary) return
    setDownloadingPdf(true)
    try {
      downloadExecutiveReportPdf(reportSummary, matches)
    } catch (err) {
      console.error('Failed to generate executive PDF report', err)
      setErrorMessage('Failed to generate executive PDF report.')
    } finally {
      setDownloadingPdf(false)
    }
  }

  // 2. Export Bulk STIX 2.1 Bundle for Tenant
  const handleExportStixBundle = () => {
    setDownloadingStix(true)
    try {
      const bundle = {
        type: 'bundle',
        id: `bundle--tenant-${reportSummary?.tenant_id || 'cyberscribe'}`,
        spec_version: '2.1',
        description: `CyberScribe Threat Posture STIX 2.1 Bundle for ${reportSummary?.company_name || 'Enterprise Tenant'}`,
        created: new Date().toISOString(),
        objects: matches.map((m) => ({
          type: 'vulnerability',
          spec_version: '2.1',
          id: `vulnerability--${(m.cve_id || 'threat').toLowerCase().replace(/[^a-z0-9_-]/g, '-')}`,
          name: m.threat_title || m.cve_id,
          description: m.summary || m.threat_title,
          external_references: [
            { source_name: 'cve', external_id: m.cve_id },
            { source_name: 'matched_component', external_id: `${m.matched_component}:${m.installed_version}` }
          ],
          confidence: m.ai_confidence_score || 94,
          labels: [
            m.severity?.toLowerCase() || 'medium',
            m.assessment_outcome?.toLowerCase() || 'needs_review'
          ]
        }))
      }

      const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `cyberscribe-stix-bundle-${reportSummary?.company_name?.toLowerCase().replace(/\s+/g, '-') || 'tenant'}.json`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    } catch (err) {
      console.error('Failed to generate STIX bundle', err)
      setErrorMessage('Failed to generate STIX 2.1 bundle export.')
    } finally {
      setDownloadingStix(false)
    }
  }

  // 3. Export CSV of Findings
  const handleExportCsv = () => {
    setDownloadingCsv(true)
    try {
      const headers = ['CVE_ID', 'Threat_Title', 'Severity', 'Assessment_Outcome', 'Status', 'Matched_Component', 'Installed_Version', 'Confidence']
      const rows = matches.map((m) => [
        `"${m.cve_id || ''}"`,
        `"${(m.threat_title || '').replace(/"/g, '""')}"`,
        `"${m.severity || ''}"`,
        `"${m.assessment_outcome || ''}"`,
        `"${m.status || ''}"`,
        `"${m.matched_component || ''}"`,
        `"${m.installed_version || ''}"`,
        `"${m.ai_confidence_score || ''}"`
      ])

      const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n')
      const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `cyberscribe-findings-${new Date().toISOString().slice(0, 10)}.csv`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    } catch (err) {
      console.error('Failed to generate CSV export', err)
      setErrorMessage('Failed to generate CSV export.')
    } finally {
      setDownloadingCsv(false)
    }
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800/80">
        <div>
          <h1 className="text-xl font-bold font-mono tracking-tight text-slate-100 flex items-center gap-2">
            <FileText className="w-5 h-5 text-cyan-400" />
            Executive Reports & Intelligence Export
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Download company-level security audit reports, STIX 2.1 threat intelligence bundles, and findings data.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={fetchReportData}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-400 hover:text-slate-200 text-xs font-mono transition cursor-pointer"
            title="Refresh Report Telemetry"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {errorMessage && (
        <div className="p-3.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs font-mono">
          {errorMessage}
        </div>
      )}

      {loading ? (
        <div className="py-20 text-center space-y-2">
          <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin mx-auto" />
          <p className="text-xs font-mono text-slate-400">Loading export data and posture metrics...</p>
        </div>
      ) : !reportSummary ? (
        <div className="py-16 text-center space-y-2 bg-slate-950 border border-slate-800 rounded-xl">
          <AlertTriangle className="w-8 h-8 text-amber-400 mx-auto" />
          <p className="text-sm font-mono text-slate-200 font-bold">Report data unavailable</p>
          <p className="text-xs font-mono text-slate-500">Ensure backend API is running and tenant is configured.</p>
        </div>
      ) : (
        <div className="space-y-6">
          {/* Organization Context Header Banner */}
          <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30">
                <Building2 className="w-4 h-4 text-cyan-400" />
              </div>
              <div>
                <span className="text-[10px] text-cyan-400 font-bold uppercase tracking-wider block">
                  Report Scope
                </span>
                <span className="text-sm font-bold text-slate-100">
                  {reportSummary.company_name || 'Enterprise Tenant'}
                </span>
              </div>
            </div>

            <div className="flex items-center gap-4 text-slate-400 text-xs">
              <div>
                <span className="text-slate-500">Tenant: </span>
                <span className="text-slate-200 font-semibold">{reportSummary.company_name || 'Enterprise Tenant'}</span>
              </div>
              <div>
                <span className="text-slate-500">Correlated Findings: </span>
                <span className="text-cyan-400 font-bold">{reportSummary.total_threat_matches ?? matches.length}</span>
              </div>
            </div>
          </div>

          {/* Useful Company-Level Export Options (Exactly 3) */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {/* 1. Executive Company Report as PDF */}
            <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-5 flex flex-col justify-between space-y-4">
              <div className="space-y-3">
                <div className="flex items-center gap-2">
                  <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30">
                    <FileText className="w-4 h-4 text-cyan-400" />
                  </div>
                  <h3 className="text-xs font-mono uppercase tracking-wider font-bold text-slate-200">
                    Executive Company Report (PDF)
                  </h3>
                </div>
                <p className="text-xs text-slate-400 font-sans leading-relaxed">
                  Download a formal executive cybersecurity report summarizing current tenant posture, deterministic assessment metrics, and key correlated vulnerabilities.
                </p>
              </div>

              <button
                onClick={handleExportExecutivePdf}
                disabled={downloadingPdf || !reportSummary}
                className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 disabled:opacity-40 text-slate-950 font-mono text-xs font-bold transition cursor-pointer"
              >
                <Download className="w-3.5 h-3.5" />
                {downloadingPdf ? 'Generating PDF...' : 'Download Executive Report (PDF)'}
              </button>
            </div>

            {/* 2. Optional Bulk STIX 2.1 JSON Export */}
            <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-5 flex flex-col justify-between space-y-4">
              <div className="space-y-3">
                <div className="flex items-center gap-2">
                  <div className="p-2 rounded-lg bg-purple-500/10 border border-purple-500/30">
                    <FileCode className="w-4 h-4 text-purple-400" />
                  </div>
                  <h3 className="text-xs font-mono uppercase tracking-wider font-bold text-slate-200">
                    Bulk STIX 2.1 JSON Export
                  </h3>
                </div>
                <p className="text-xs text-slate-400 font-sans leading-relaxed">
                  Export an OASIS-standard STIX 2.1 threat intelligence bundle containing all correlated vulnerability objects, confidence scores, and external CVE references.
                </p>
              </div>

              <button
                onClick={handleExportStixBundle}
                disabled={downloadingStix || matches.length === 0}
                className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-purple-500/10 hover:bg-purple-500/20 disabled:opacity-40 border border-purple-500/30 text-purple-300 font-mono text-xs font-bold transition cursor-pointer"
              >
                <Download className="w-3.5 h-3.5" />
                {downloadingStix ? 'Compiling Bundle...' : `Export STIX 2.1 Bundle (${matches.length} Findings)`}
              </button>
            </div>

            {/* 3. Optional Findings CSV Export */}
            <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-5 flex flex-col justify-between space-y-4">
              <div className="space-y-3">
                <div className="flex items-center gap-2">
                  <div className="p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/30">
                    <Layers className="w-4 h-4 text-emerald-400" />
                  </div>
                  <h3 className="text-xs font-mono uppercase tracking-wider font-bold text-slate-200">
                    Findings Ledger (CSV)
                  </h3>
                </div>
                <p className="text-xs text-slate-400 font-sans leading-relaxed">
                  Download a tabular CSV dataset of all correlated vulnerability findings, installed package versions, severity levels, and assessment outcomes for spreadsheet auditing.
                </p>
              </div>

              <button
                onClick={handleExportCsv}
                disabled={downloadingCsv || matches.length === 0}
                className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-slate-900 hover:bg-slate-850 disabled:opacity-40 border border-slate-700 text-slate-200 font-mono text-xs font-bold transition cursor-pointer"
              >
                <Download className="w-3.5 h-3.5" />
                {downloadingCsv ? 'Generating CSV...' : `Export Findings CSV (${matches.length} Rows)`}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
