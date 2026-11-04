// frontend/src/components/StixModal.jsx
import { useState } from 'react'
import { X, Copy, Check, Download, FileCode } from 'lucide-react'

export default function StixModal({
  isOpen = true,
  onClose,
  stixData,
  stix: stixProp,
  threatTitle,
  title
}) {
  const [copied, setCopied] = useState(false)

  const activeData = stixData || stixProp
  const displayTitle = threatTitle || title || 'STIX 2.1 Bundle'

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

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 backdrop-blur-sm p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-3xl max-h-[85vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
          <div className="flex items-center gap-2.5">
            <FileCode className="w-5 h-5 text-cyan-400" />
            <div>
              <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider font-mono">
                STIX 2.1 JSON Bundle
              </h3>
              <p className="text-[11px] text-slate-400 font-mono truncate max-w-md">
                {displayTitle}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={handleCopy}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-200 transition cursor-pointer"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied' : 'Copy'}</span>
            </button>
            <button
              onClick={handleDownload}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs font-mono transition cursor-pointer"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download</span>
            </button>
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition cursor-pointer"
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