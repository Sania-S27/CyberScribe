import { X, Copy, Check, Terminal, ShieldAlert, Wrench, FileCode, Download, FileText, Info } from 'lucide-react'
import { useState, useEffect } from 'react'
import { downloadPlaybookPdf } from '../utils/pdfGenerator'

export default function PlaybookModal({
  isOpen = true,
  onClose,
  playbookData,
  playbook: playbookProp,
  threatTitle,
  title
}) {
  const [copiedGlobal, setCopiedGlobal] = useState(false)
  const [copiedSection, setCopiedSection] = useState(null)

  const activeData = playbookData || playbookProp
  const displayTitle = threatTitle || title || 'SOAR Remediation Playbook'

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

  // Ensure activeData is a valid object if passed as a JSON string
  let playbook = activeData
  if (typeof activeData === 'string') {
    try {
      playbook = JSON.parse(activeData)
    } catch (err) {
      playbook = { recommended_action: activeData }
    }
  }
  if (playbook && playbook.playbook && typeof playbook.playbook === 'object') {
    playbook = playbook.playbook
  }

  const rawRules = playbook.firewall_rules || playbook.firewall_rule
  const firewallRules = Array.isArray(rawRules) ? rawRules : rawRules ? [rawRules] : []

  // Copy entire playbook as formatted JSON
  const handleCopyAll = () => {
    navigator.clipboard.writeText(JSON.stringify(playbook, null, 2))
    setCopiedGlobal(true)
    setTimeout(() => setCopiedGlobal(false), 2000)
  }

  // Copy specific section text
  const handleCopySection = (sectionKey, text) => {
    navigator.clipboard.writeText(typeof text === 'string' ? text : JSON.stringify(text, null, 2))
    setCopiedSection(sectionKey)
    setTimeout(() => setCopiedSection(null), 2000)
  }

  // Download playbook as valid structured JSON
  const handleDownloadJson = () => {
    const jsonString = JSON.stringify(playbook, null, 2)
    const blob = new Blob([jsonString], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const downloadAnchor = document.createElement('a')
    downloadAnchor.href = url
    const cveSafe = (displayTitle || 'playbook').slice(0, 32).toLowerCase().replace(/[^a-z0-9_-]/g, '_')
    downloadAnchor.download = `playbook_${cveSafe}.json`
    document.body.appendChild(downloadAnchor)
    downloadAnchor.click()
    document.body.removeChild(downloadAnchor)
    URL.revokeObjectURL(url)
  }

  // Download playbook as structured PDF
  const handleDownloadPdf = () => {
    downloadPlaybookPdf(displayTitle, playbook)
  }

  // Helper to split patch guidance text into numbered points
  const renderPatchSteps = (guidanceText) => {
    if (!guidanceText) return null
    const steps = guidanceText.split(/(?=\b\d+\.\s)/).filter(Boolean)

    if (steps.length <= 1) {
      return <p className="text-slate-300 font-sans text-xs leading-relaxed">{guidanceText}</p>
    }

    return (
      <ol className="space-y-2 list-decimal list-inside text-slate-300 font-sans text-xs leading-relaxed">
        {steps.map((step, idx) => {
          const cleanedStep = step.replace(/^\d+\.\s*/, '')
          return (
            <li key={idx} className="pl-1">
              <span className="text-slate-200 font-medium">{cleanedStep}</span>
            </li>
          )
        })}
      </ol>
    )
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose?.()
      }}
    >
      <div className="bg-[#0b1329] border border-slate-800 rounded-xl w-full max-w-3xl overflow-hidden shadow-2xl flex flex-col max-h-[88vh]">

        {/* Modal Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-950/80">
          <div>
            <h2 className="text-sm font-bold font-mono uppercase tracking-wider text-cyan-400 flex items-center gap-2">
              <Terminal className="w-4 h-4" /> SOAR Remediation Playbook
            </h2>
            <p className="text-xs text-slate-400 truncate max-w-xl">{displayTitle}</p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={handleCopyAll}
              className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-800 hover:border-cyan-500/50 text-slate-300 text-xs font-mono transition cursor-pointer"
              title="Copy Full Playbook JSON"
            >
              {copiedGlobal ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedGlobal ? 'Copied' : 'Copy All'}</span>
            </button>
            <button
              onClick={handleDownloadPdf}
              className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/30 text-emerald-400 text-xs font-mono transition cursor-pointer"
              title="Download Playbook as PDF"
            >
              <FileText className="w-3.5 h-3.5" />
              <span>Download PDF</span>
            </button>
            <button
              onClick={handleDownloadJson}
              className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-bold font-mono transition cursor-pointer"
              title="Download Playbook as JSON"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download JSON</span>
            </button>
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-slate-400 hover:text-rose-400 hover:bg-slate-900 border border-slate-800 hover:border-rose-500/40 transition cursor-pointer ml-1"
              title="Close (Esc)"
              aria-label="Close Playbook"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Operational Safety Advisory Banner */}
        <div className="px-6 py-2.5 bg-cyan-500/5 border-b border-cyan-500/20 flex items-center gap-2.5 text-[11px] font-mono text-cyan-300">
          <Info className="w-4 h-4 text-cyan-400 flex-shrink-0" />
          <span>
            <strong className="text-cyan-200">Advisory Mitigation Guidance:</strong> Rules and commands below are deterministic recommendations for SOC evaluation. Viewing or exporting this playbook does not execute changes on your firewalls or hosts.
          </span>
        </div>

        {/* Modal Body / Structured Content */}
        <div className="p-6 overflow-y-auto space-y-5 text-slate-200 text-xs font-mono">

          {/* Recommended Action */}
          {playbook.recommended_action && (
            <div className="space-y-1.5 bg-slate-950/80 border border-slate-800/80 rounded-lg p-4 relative group">
              <div className="flex items-center justify-between">
                <span className="text-[10px] uppercase tracking-widest text-cyan-400 font-bold flex items-center gap-1.5">
                  <ShieldAlert className="w-3.5 h-3.5" /> Recommended Remediation Action
                </span>
                <button
                  onClick={() => handleCopySection('action', playbook.recommended_action)}
                  className="text-[10px] text-slate-400 hover:text-cyan-300 flex items-center gap-1 bg-slate-900 px-2 py-0.5 rounded border border-slate-800 transition cursor-pointer"
                >
                  {copiedSection === 'action' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  {copiedSection === 'action' ? 'Copied' : 'Copy'}
                </button>
              </div>
              <p className="text-slate-300 font-sans text-xs leading-relaxed">{playbook.recommended_action}</p>
            </div>
          )}

          {/* Firewall Rules (Supports both array and string) */}
          {firewallRules.length > 0 && (
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-[10px] uppercase tracking-widest text-amber-400 font-bold flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5" /> Recommended Containment Rules (Advisory — Not Active)
                </span>
                <button
                  onClick={() => handleCopySection('firewall', firewallRules.join('\n'))}
                  className="text-[10px] text-slate-400 hover:text-amber-300 flex items-center gap-1 bg-slate-900 px-2 py-0.5 rounded border border-slate-800 transition cursor-pointer"
                >
                  {copiedSection === 'firewall' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  {copiedSection === 'firewall' ? 'Copied' : 'Copy'}
                </button>
              </div>
              <div className="bg-slate-950 border border-slate-800 rounded-lg p-3 text-emerald-400 font-mono text-[11px] overflow-x-auto space-y-1">
                {firewallRules.map((rule, idx) => (
                  <div key={idx}><code>{rule}</code></div>
                ))}
              </div>
            </div>
          )}
          {/* Sigma Rule */}
          {playbook.sigma_rule && (
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-[10px] uppercase tracking-widest text-purple-400 font-bold flex items-center gap-1.5">
                  <FileCode className="w-3.5 h-3.5" /> Sigma Detection Rule
                </span>
                <button
                  onClick={() => handleCopySection('sigma', String(playbook.sigma_rule).replace(/\\n/g, '\n'))}
                  className="text-[10px] text-slate-400 hover:text-purple-300 flex items-center gap-1 bg-slate-900 px-2 py-0.5 rounded border border-slate-800 transition"
                >
                  {copiedSection === 'sigma' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  {copiedSection === 'sigma' ? 'Copied' : 'Copy'}
                </button>
              </div>
              <div className="bg-slate-950 border border-slate-800 rounded-lg p-3 text-slate-300 font-mono text-[11px] whitespace-pre-wrap overflow-x-auto leading-relaxed">
                {String(playbook.sigma_rule).replace(/\\n/g, '\n')}
              </div>
            </div>
          )}

          {/* Patch Guidance */}
          {playbook.patch_guidance && (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[10px] uppercase tracking-widest text-emerald-400 font-bold flex items-center gap-1.5">
                  <Wrench className="w-3.5 h-3.5" /> Step-by-Step Patch Guidance
                </span>
                <button
                  onClick={() => handleCopySection('patch', playbook.patch_guidance)}
                  className="text-[10px] text-slate-400 hover:text-emerald-300 flex items-center gap-1 bg-slate-900 px-2 py-0.5 rounded border border-slate-800 transition"
                >
                  {copiedSection === 'patch' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  {copiedSection === 'patch' ? 'Copied' : 'Copy'}
                </button>
              </div>
              <div className="bg-slate-950/80 border border-slate-800/80 rounded-lg p-4">
                {renderPatchSteps(playbook.patch_guidance)}
              </div>
            </div>
          )}

        </div>
      </div>
    </div>
  )
}