// frontend/src/pages/company/CompanyProfile.jsx
import React, { useState, useEffect, useCallback } from 'react'
import { useOutletContext } from 'react-router-dom'
import axios from 'axios'
import {
  User,
  Building2,
  Layers,
  Upload,
  Save,
  Plus,
  X,
  FileCode,
  Shield,
  Webhook,
  Key,
  Eye,
  EyeOff,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Cpu,
  Lock,
  Mail,
  ShieldCheck
} from 'lucide-react'
import StatCard from '../../components/common/StatCard'

const API_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8001'

const SUGGESTED_TAGS = [
  'AWS', 'Docker@24.x', 'Kubernetes:1.29', 'Node.js@20.x', 
  'PostgreSQL:15', 'MySQL:8.0', 'React@18', 'Python:3.11', 
  'FastAPI:0.110', 'Nginx:1.24', 'Azure', 'GitLab:16.8'
]

export default function CompanyProfile() {
  const context = useOutletContext() || {}
  const userProfile = context.userProfile || {}

  const [profile, setProfile] = useState({
    companyName: userProfile.company_name || 'Enterprise Tenant',
    webhookUrl: '',
    authToken: '',
    remediationPolicy: 'NOTIFY',
    tags: [],
    assets: []
  })

  const [inputValue, setInputValue] = useState('')
  const [showAuthToken, setShowAuthToken] = useState(false)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [successMessage, setSuccessMessage] = useState('')
  const [errorMessage, setErrorMessage] = useState('')
  const [selectedFile, setSelectedFile] = useState(null)

  const fetchProfile = useCallback(async () => {
    try {
      const token = localStorage.getItem('access_token')
      const res = await axios.get(`${API_URL}/tenants/profile`, {
        headers: { Authorization: `Bearer ${token}` }
      })
      const data = res.data || {}
      const rawStack = data.tech_stack || ''
      const parsedTags = rawStack.trim()
        ? rawStack.split(',').map((t) => t.trim()).filter(Boolean)
        : []

      setProfile({
        companyName: data.company_name || userProfile.company_name || 'Enterprise Tenant',
        webhookUrl: data.webhook_url || '',
        authToken: data.auth_token || '',
        remediationPolicy: data.remediation_policy || 'NOTIFY',
        tags: parsedTags,
        assets: data.assets || []
      })
    } catch (err) {
      console.error('Failed to load profile & assets', err)
      setErrorMessage('Failed to fetch profile. Verify backend is operational.')
    } finally {
      setLoading(false)
    }
  }, [userProfile.company_name])

  useEffect(() => {
    fetchProfile()
  }, [fetchProfile])

  const addTag = (tag) => {
    const cleanTag = tag.trim().replace(/^,|,$/g, '')
    if (cleanTag && !profile.tags.some((t) => t.toLowerCase() === cleanTag.toLowerCase())) {
      setProfile((prev) => ({ ...prev, tags: [...prev.tags, cleanTag] }))
    }
    setInputValue('')
  }

  const removeTag = (indexToRemove) => {
    setProfile((prev) => ({
      ...prev,
      tags: prev.tags.filter((_, idx) => idx !== indexToRemove)
    }))
  }

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault()
      addTag(inputValue)
    } else if (e.key === 'Backspace' && !inputValue && profile.tags.length > 0) {
      removeTag(profile.tags.length - 1)
    }
  }

  const handleSaveProfile = async (e) => {
    e.preventDefault()
    setSaving(true)
    setSuccessMessage('')
    setErrorMessage('')

    try {
      const token = localStorage.getItem('access_token')
      const res = await axios.put(
        `${API_URL}/tenants/tech-stack`,
        {
          tech_stack: profile.tags.join(', '),
          webhook_url: profile.webhookUrl,
          auth_token: profile.authToken,
          remediation_policy: profile.remediationPolicy
        },
        { headers: { Authorization: `Bearer ${token}` } }
      )
      if (res.data?.data) {
        setProfile((prev) => ({
          ...prev,
          webhookUrl: res.data.data.webhook_url || '',
          authToken: res.data.data.auth_token || '',
          remediationPolicy: res.data.data.remediation_policy || 'NOTIFY'
        }))
      }
      setSuccessMessage('Profile, tech stack, remediation policy, and SOAR webhook persisted successfully.')
      setTimeout(() => setSuccessMessage(''), 5000)
    } catch (err) {
      console.error('Failed to save configuration', err)
      setErrorMessage('Failed to update tenant configuration.')
    } finally {
      setSaving(false)
    }
  }

  const handleUploadManifest = async (e) => {
    e.preventDefault()
    if (!selectedFile) return

    setUploading(true)
    setSuccessMessage('')
    setErrorMessage('')

    const formData = new FormData()
    formData.append('file', selectedFile)

    try {
      const token = localStorage.getItem('access_token')
      const res = await axios.post(`${API_URL}/tenants/upload-manifest`, formData, {
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'multipart/form-data'
        }
      })
      setSuccessMessage(res.data?.message || 'Manifest parsed and SBOM components ingested.')
      setSelectedFile(null)
      await fetchProfile()
      setTimeout(() => setSuccessMessage(''), 6000)
    } catch (err) {
      console.error('Manifest upload failed', err)
      setErrorMessage(err.response?.data?.detail || 'Failed to parse manifest file.')
    } finally {
      setUploading(false)
    }
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800/80">
        <div>
          <h1 className="text-xl font-bold font-mono tracking-tight text-slate-100 flex items-center gap-2">
            <User className="w-5 h-5 text-cyan-400" />
            Profile, Organization & Software Inventory (SBOM)
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Manage your account credentials, tenant organization settings, monitored technology stack, and SBOM dependencies.
          </p>
        </div>

        <button
          onClick={fetchProfile}
          className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-400 hover:text-slate-200 transition self-start sm:self-center"
          title="Refresh Profile Telemetry"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {/* Notifications */}
      {successMessage && (
        <div className="p-3.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs font-mono flex items-center justify-between">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <span>{successMessage}</span>
          </div>
          <button onClick={() => setSuccessMessage('')} className="text-emerald-400 hover:text-emerald-200">&times;</button>
        </div>
      )}
      {errorMessage && (
        <div className="p-3.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs font-mono flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-rose-400" />
            <span>{errorMessage}</span>
          </div>
          <button onClick={() => setErrorMessage('')} className="text-rose-400 hover:text-rose-200">&times;</button>
        </div>
      )}

      {/* 1. Account & Organization Identity Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* User Account Details */}
        <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center gap-2">
            <User className="w-4 h-4 text-cyan-400" />
            <h2 className="text-xs font-mono uppercase tracking-wider font-bold text-slate-200">
              User Profile Credentials
            </h2>
          </div>

          <div className="space-y-3 font-mono text-xs">
            <div className="p-3 rounded-lg bg-slate-900/50 border border-slate-850 flex items-center justify-between">
              <span className="text-slate-400">Authenticated Email:</span>
              <span className="text-slate-200 font-bold">{userProfile.email || 'analyst@organization.local'}</span>
            </div>

            <div className="p-3 rounded-lg bg-slate-900/50 border border-slate-850 flex items-center justify-between">
              <span className="text-slate-400">Assigned Role:</span>
              <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
                {userProfile.role || 'tenant_admin'}
              </span>
            </div>

            <div className="p-3 rounded-lg bg-slate-900/50 border border-slate-850 flex items-center justify-between">
              <span className="text-slate-400">Security Session:</span>
              <span className="text-emerald-400 font-semibold flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-emerald-400" /> JWT Active (TLS Encrypted)
              </span>
            </div>
          </div>
        </div>

        {/* Company Organization Details */}
        <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center gap-2">
            <Building2 className="w-4 h-4 text-cyan-400" />
            <h2 className="text-xs font-mono uppercase tracking-wider font-bold text-slate-200">
              Tenant Organization Context
            </h2>
          </div>

          <div className="space-y-3 font-mono text-xs">
            <div className="p-3 rounded-lg bg-slate-900/50 border border-slate-850 flex items-center justify-between">
              <span className="text-slate-400">Company Name:</span>
              <span className="text-slate-200 font-bold">{profile.companyName}</span>
            </div>

            <div className="p-3 rounded-lg bg-slate-900/50 border border-slate-850 flex items-center justify-between">
              <span className="text-slate-400">Tenant UUID:</span>
              <span className="text-slate-400 text-[11px] truncate max-w-[180px]">{userProfile.tenant_id || userProfile.id || 'Current Tenant'}</span>
            </div>

            <div className="p-3 rounded-lg bg-slate-900/50 border border-slate-850 flex items-center justify-between">
              <span className="text-slate-400">Data Boundary:</span>
              <span className="text-cyan-400 font-semibold flex items-center gap-1.5">
                <ShieldCheck className="w-4 h-4 text-cyan-400" /> Row-Level Tenant Isolated
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* 2. Configuration Grid: SOAR Webhook & Manifest Upload */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* SOAR Webhook & Tech Stack Form */}
        <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center gap-2">
            <Webhook className="w-4 h-4 text-cyan-400" />
            <h2 className="text-xs font-mono uppercase tracking-wider font-bold text-slate-200">
              Technology Stack & SOAR Webhook
            </h2>
          </div>

          <form onSubmit={handleSaveProfile} className="space-y-4">
            <div className="space-y-1.5">
              <label className="text-[11px] font-mono text-slate-400 uppercase">
                SOAR Webhook Receiver URL
              </label>
              <input
                type="url"
                placeholder="https://soar.internal.company.com/webhook"
                value={profile.webhookUrl}
                onChange={(e) => setProfile({ ...profile, webhookUrl: e.target.value })}
                className="w-full px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500/50"
              />
            </div>

            <div className="space-y-1.5">
              <label className="text-[11px] font-mono text-slate-400 uppercase">
                SOAR Bearer Token / Secret
              </label>
              <div className="relative">
                <input
                  type={showAuthToken ? 'text' : 'password'}
                  placeholder="••••••••••••••••••••••••"
                  value={profile.authToken}
                  onChange={(e) => setProfile({ ...profile, authToken: e.target.value })}
                  className="w-full pl-3 pr-10 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500/50"
                />
                <button
                  type="button"
                  onClick={() => setShowAuthToken(!showAuthToken)}
                  className="absolute right-3 top-2 text-slate-500 hover:text-slate-300"
                >
                  {showAuthToken ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* Autonomous Remediation Policy Selection */}
            <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800 space-y-2.5">
              <div className="flex items-center justify-between">
                <label className="text-[11px] font-mono text-cyan-400 uppercase tracking-wider font-semibold">
                  Autonomous Remediation Policy
                </label>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded border font-semibold ${
                  profile.remediationPolicy === 'AUTO_PATCH' 
                    ? 'bg-amber-500/10 border-amber-500/30 text-amber-300' 
                    : 'bg-cyan-500/10 border-cyan-500/30 text-cyan-300'
                }`}>
                  Current: {profile.remediationPolicy}
                </span>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                <button
                  type="button"
                  onClick={() => setProfile((prev) => ({ ...prev, remediationPolicy: 'NOTIFY' }))}
                  className={`p-2.5 rounded-lg border text-left transition ${
                    profile.remediationPolicy === 'NOTIFY'
                      ? 'bg-cyan-950/40 border-cyan-500 text-cyan-200'
                      : 'bg-slate-900 border-slate-800 text-slate-400 hover:border-slate-700'
                  }`}
                >
                  <div className="font-mono text-xs font-bold flex items-center gap-1.5 text-cyan-300">
                    <span className={`w-2 h-2 rounded-full ${profile.remediationPolicy === 'NOTIFY' ? 'bg-cyan-400' : 'bg-slate-600'}`} />
                    NOTIFY (Advisory)
                  </div>
                  <p className="text-[10px] font-sans text-slate-400 mt-1 leading-snug">
                    Webhooks alert company when verified compatible fix arrives. Requires manual SOC patch sign-off.
                  </p>
                </button>

                <button
                  type="button"
                  onClick={() => setProfile((prev) => ({ ...prev, remediationPolicy: 'AUTO_PATCH' }))}
                  className={`p-2.5 rounded-lg border text-left transition ${
                    profile.remediationPolicy === 'AUTO_PATCH'
                      ? 'bg-amber-950/40 border-amber-500 text-amber-200'
                      : 'bg-slate-900 border-slate-800 text-slate-400 hover:border-slate-700'
                  }`}
                >
                  <div className="font-mono text-xs font-bold flex items-center gap-1.5 text-amber-300">
                    <span className={`w-2 h-2 rounded-full ${profile.remediationPolicy === 'AUTO_PATCH' ? 'bg-amber-400' : 'bg-slate-600'}`} />
                    AUTO_PATCH (Autonomous)
                  </div>
                  <p className="text-[10px] font-sans text-slate-400 mt-1 leading-snug">
                    Automatically approves & stages simulated patch, verifies package, and releases firewall containment.
                  </p>
                </button>
              </div>
            </div>

            {/* Tech Stack Tag Editor */}
            <div className="space-y-1.5">
              <label className="text-[11px] font-mono text-slate-400 uppercase">
                Monitored Infrastructure & Technology Stack
              </label>
              <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 space-y-2">
                <div className="flex flex-wrap gap-1.5">
                  {profile.tags.map((tag, idx) => (
                    <span
                      key={idx}
                      className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-cyan-500/15 border border-cyan-500/30 text-cyan-300 text-xs font-mono"
                    >
                      {tag}
                      <button
                        type="button"
                        onClick={() => removeTag(idx)}
                        className="hover:text-rose-400"
                      >
                        <X className="w-3 h-3" />
                      </button>
                    </span>
                  ))}
                  <input
                    type="text"
                    value={inputValue}
                    onChange={(e) => setInputValue(e.target.value)}
                    onKeyDown={handleKeyDown}
                    placeholder="Add tag and hit Enter..."
                    className="bg-transparent border-none text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none min-w-[140px]"
                  />
                </div>
              </div>

              {/* Suggestions */}
              <div className="flex items-center gap-1.5 flex-wrap pt-1 text-[11px] font-mono">
                <span className="text-slate-500">Quick add:</span>
                {SUGGESTED_TAGS.map((stag) => (
                  <button
                    key={stag}
                    type="button"
                    onClick={() => addTag(stag)}
                    className="text-slate-400 hover:text-cyan-300 hover:underline"
                  >
                    +{stag}
                  </button>
                ))}
              </div>
            </div>

            <button
              type="submit"
              disabled={saving}
              className="w-full flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-slate-850 hover:bg-slate-800 border border-slate-700 text-cyan-300 font-mono text-xs font-bold transition cursor-pointer"
            >
              <Save className={`w-3.5 h-3.5 ${saving ? 'animate-spin' : ''}`} />
              {saving ? 'Persisting Changes...' : 'Save Configuration'}
            </button>
          </form>
        </div>

        {/* SBOM Manifest Ingestion Card */}
        <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center gap-2">
            <Upload className="w-4 h-4 text-cyan-400" />
            <h2 className="text-xs font-mono uppercase tracking-wider font-bold text-slate-200">
              SBOM Manifest Ingestion
            </h2>
          </div>
          <p className="text-xs text-slate-400 font-mono">
            Upload Python <code className="text-cyan-300">requirements.txt</code> or Node.js <code className="text-cyan-300">package.json</code> to automatically parse and monitor dependencies against CVE feeds.
          </p>

          <form onSubmit={handleUploadManifest} className="space-y-4 pt-1">
            <div className="border-2 border-dashed border-slate-800 hover:border-cyan-500/40 rounded-xl p-6 text-center space-y-2 transition bg-slate-900/30">
              <FileCode className="w-8 h-8 text-cyan-400/80 mx-auto" />
              <div className="text-xs font-mono text-slate-300">
                {selectedFile ? (
                  <span className="text-cyan-300 font-semibold">{selectedFile.name} ({(selectedFile.size / 1024).toFixed(1)} KB)</span>
                ) : (
                  <span>Select a manifest file to upload</span>
                )}
              </div>
              <input
                type="file"
                accept=".txt,.json"
                onChange={(e) => setSelectedFile(e.target.files?.[0] || null)}
                className="hidden"
                id="manifest-file-input"
              />
              <label
                htmlFor="manifest-file-input"
                className="inline-block px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono cursor-pointer transition"
              >
                Browse Manifest
              </label>
            </div>

            <button
              type="submit"
              disabled={!selectedFile || uploading}
              className="w-full flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 disabled:opacity-40 text-slate-950 font-mono text-xs font-bold transition cursor-pointer"
            >
              <Upload className={`w-3.5 h-3.5 ${uploading ? 'animate-spin' : ''}`} />
              {uploading ? 'Ingesting SBOM Components...' : 'Ingest Software Manifest'}
            </button>
          </form>
        </div>
      </div>

      {/* 3. Monitored SBOM Asset Inventory Table */}
      <div className="bg-slate-950/80 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Cpu className="w-4 h-4 text-cyan-400" />
            <h2 className="text-xs font-mono uppercase tracking-wider font-bold text-slate-200">
              Monitored Assets & Software Inventory ({profile.assets.length})
            </h2>
          </div>
          <span className="text-[11px] font-mono text-slate-400">
            Isolated to {profile.companyName}
          </span>
        </div>

        {profile.assets.length === 0 ? (
          <div className="py-12 text-center space-y-2">
            <Layers className="w-8 h-8 text-slate-600 mx-auto" />
            <p className="text-xs font-mono text-slate-400">No software components ingested yet.</p>
            <p className="text-[11px] font-mono text-slate-500">
              Upload a manifest file above or register tech stack tags to populate monitored inventory.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-900/60 text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                  <th className="py-3 px-4">Software Name</th>
                  <th className="py-3 px-4">Installed Version</th>
                  <th className="py-3 px-4">Environment</th>
                  <th className="py-3 px-4">Ingested Date</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-xs font-mono text-slate-300">
                {profile.assets.map((asset) => (
                  <tr key={asset.id} className="hover:bg-slate-900/40 transition">
                    <td className="py-3 px-4 font-semibold text-cyan-300">
                      {asset.software_name}
                    </td>
                    <td className="py-3 px-4 text-slate-200">
                      {asset.software_version || 'latest'}
                    </td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded text-[10px] bg-slate-900 border border-slate-800 text-slate-400 uppercase">
                        {asset.environment || 'production'}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-500">
                      {asset.created_at || 'Registered'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
