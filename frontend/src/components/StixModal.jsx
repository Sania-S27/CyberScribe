// frontend/src/components/StixModal.jsx
import { useState, useEffect } from 'react'
import { X, Copy, Check, Download, FileCode, FileText } from 'lucide-react'
import { downloadIndividualThreatPdf } from '../utils/pdfGenerator'

export default function StixModal({
  isOpen = true,
  onClose,
  stixData,
  stix: stixProp,
  threatTitle,
  title,
  match,
  finding,
  onExportPdf
}) {
  const [copied, setCopied] = useState(false)

  const activeData = stixData || stixProp
  const displayTitle = threatTitle || title || 'STIX 2.1 Bundle'

  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') {
        onClose?.()
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [onClose])

  if (!isOpen || !activeData) return null

  let resolvedData = activeData
  if (activeData && activeData.stix_bundle) {
    resolvedData = activeData.stix_bundle
  }

  const formattedJson =
    typeof resolvedData === 'string'
      ? (() => {
          try {
            return JSON.stringify(JSON.parse(resolvedData), null, 2)
          } catch {
            return resolvedData
          }
        })()
      : JSON.stringify(resolvedData, null, 2)

  const handleCopy = () => {
    navigator.clipboard.writeText(formattedJson)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const handleDownload = () => {
    const blob = new Blob([formattedJson], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `STIX-2.1-${(displayTitle || 'bundle').replace(/\s+/g, '_')}.json`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  const handleExportPdf = () => {
    if (onExportPdf) {
      onExportPdf()
    } else {
      const targetFinding = match || finding || {
        cve_id: activeData?.cve_id || (typeof displayTitle === 'string' && displayTitle.includes('CVE-') ? displayTitle.match(/CVE-\d{4}-\d+/i)?.[0] : null) || 'STIX-2.1',
        threat_title: displayTitle,
        summary: activeData?.summary || activeData?.description || displayTitle,
        severity: activeData?.severity || 'medium',
        assessment_outcome: activeData?.assessment_outcome || 'needs_review'
      }
      downloadIndividualThreatPdf(targetFinding)
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose?.()
      }}
    >
      <div className="bg-[#0b1329] border border-slate-800 rounded-xl w-full max-w-3xl overflow-hidden shadow-2xl flex flex-col max-h-[88vh]">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-950/80">
          <div className="flex items-center gap-2.5">
            <FileCode className="w-5 h-5 text-cyan-400" />
            <div>
              <h2 className="text-sm font-bold font-mono uppercase tracking-wider text-cyan-400 flex items-center gap-2">
                STIX 2.1 JSON Bundle
              </h2>
              <p className="text-xs text-slate-400 font-mono truncate max-w-xl">
                {displayTitle}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={handleCopy}
              className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-800 hover:border-cyan-500/50 text-slate-300 text-xs font-mono transition cursor-pointer"
              title="Copy STIX 2.1 JSON"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied' : 'Copy'}</span>
            </button>
            <button
              onClick={handleExportPdf}
              className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/30 text-emerald-400 text-xs font-mono transition cursor-pointer"
              title="Export Advisory as PDF"
            >
              <FileText className="w-3.5 h-3.5" />
              <span>Export PDF</span>
            </button>
            <button
              onClick={handleDownload}
              className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-bold font-mono transition cursor-pointer"
              title="Download STIX 2.1 JSON"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download JSON</span>
            </button>
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-slate-400 hover:text-rose-400 hover:bg-slate-900 border border-slate-800 hover:border-rose-500/40 transition cursor-pointer ml-1"
              title="Close (Esc)"
              aria-label="Close STIX Modal"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Content View */}
        <div className="p-6 overflow-y-auto flex-1 font-mono text-xs text-slate-300 bg-[#050811]">
          <pre className="whitespace-pre-wrap leading-relaxed">{formattedJson}</pre>
        </div>
      </div>
    </div>
  )
}