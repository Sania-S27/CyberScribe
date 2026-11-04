// frontend/src/components/VerificationModal.jsx
import { useState, useEffect } from 'react'
import { ShieldCheck, AlertTriangle, CheckCircle2, X, Terminal, Cpu } from 'lucide-react'

export default function VerificationModal({
  isOpen = true,
  onClose,
  onConfirm,
  onSuccess,
  match,
  loading
}) {
  const [confirmed, setConfirmed] = useState(false)

  useEffect(() => {
    if (isOpen) {
      setConfirmed(false)
    }
  }, [isOpen])

  if (!isOpen || !match) return null

  const report = match.threat_report || match
  const cveId = report.cve_id || match.cve_id || 'Advisory'
  const title = report.title || match.threat_title || 'Threat Finding'
  const component = match.matched_component || 'Component'
  const version = match.installed_version || 'Installed'

  const handleConfirm = () => {
    if (confirmed) {
      if (onConfirm) onConfirm()
      else if (onSuccess) onSuccess()
    }
  }

  return (
    <div className="fixed inset-0 bg-black/75 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div 
        className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-lg shadow-2xl shadow-black/60 overflow-hidden font-mono"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-slate-800 bg-slate-950/80">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wide">
                Verify Threat Remediation
              </h3>
              <p className="text-[11px] text-slate-400">
                Confirm verified fix before resolving active alert
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            disabled={loading}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Body */}
        <div className="p-5 space-y-4 text-xs">
          {/* Target Finding Card */}
          <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-xl space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[10px] uppercase font-bold tracking-wider text-purple-400 bg-purple-500/10 px-2 py-0.5 rounded border border-purple-500/30">
                {cveId}
              </span>
              <span className="text-[10px] text-slate-400">
                Severity: <strong className="text-amber-400 uppercase">{report.severity || match.severity || 'HIGH'}</strong>
              </span>
            </div>

            <p className="text-slate-200 font-semibold text-xs truncate" title={title}>
              {title}
            </p>

            <div className="flex items-center gap-2 pt-1 border-t border-slate-800/80 text-[11px] text-slate-400">
              <Cpu className="w-3.5 h-3.5 text-cyan-400" />
              <span>Target Asset:</span>
              <span className="text-indigo-300 font-medium bg-indigo-500/10 px-1.5 py-0.5 rounded border border-indigo-500/20">
                {component} {version !== 'Unspecified' && version !== 'N/A' ? `v${version}` : ''}
              </span>
            </div>
          </div>

          {/* Verification Warning Notice */}
          <div className="p-3 bg-amber-500/10 border border-amber-500/30 rounded-xl space-y-1.5 text-amber-200">
            <div className="flex items-center gap-2 font-bold text-[11px] text-amber-400">
              <AlertTriangle className="w-4 h-4 flex-shrink-0" />
              <span>SOC Policy: Verification Required</span>
            </div>
            <p className="text-[11px] text-slate-300 leading-relaxed font-sans">
              To protect compliance posture, alerts should only be closed once target dependencies are updated, patches are deployed, or containment firewalls are confirmed active.
            </p>
          </div>

          {/* Confirmation Checkbox */}
          <label className="flex items-start gap-3 p-3 bg-slate-950/60 border border-slate-800/80 rounded-xl cursor-pointer hover:border-emerald-500/40 transition select-none">
            <input
              type="checkbox"
              checked={confirmed}
              onChange={(e) => setConfirmed(e.target.checked)}
              disabled={loading}
              className="mt-0.5 w-4 h-4 rounded border-slate-700 text-emerald-500 focus:ring-emerald-500/30 bg-slate-900 cursor-pointer"
            />
            <span className="text-xs text-slate-300 leading-relaxed font-sans">
              I confirm that vendor patches, version upgrades, or playbook mitigations have been <strong className="text-emerald-400">verified on target systems</strong>.
            </span>
          </label>
        </div>

        {/* Footer Actions */}
        <div className="flex items-center justify-end gap-2.5 px-5 py-3.5 border-t border-slate-800 bg-slate-950/80">
          <button
            type="button"
            onClick={onClose}
            disabled={loading}
            className="px-3.5 py-1.5 rounded-lg border border-slate-800 bg-slate-900 hover:bg-slate-800 text-slate-300 text-xs transition cursor-pointer"
          >
            Cancel
          </button>

          <button
            type="button"
            onClick={handleConfirm}
            disabled={!confirmed || loading}
            className="inline-flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 disabled:bg-slate-800 disabled:text-slate-600 disabled:cursor-not-allowed text-slate-950 text-xs font-bold transition cursor-pointer shadow-lg shadow-emerald-500/20"
          >
            <CheckCircle2 className="w-3.5 h-3.5" />
            <span>{loading ? 'Verifying & Closing...' : 'Confirm Verified & Resolve'}</span>
          </button>
        </div>
      </div>
    </div>
  )
}
