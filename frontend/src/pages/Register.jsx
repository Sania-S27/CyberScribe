// frontend/src/pages/Register.jsx
import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import axios from 'axios'
import { ShieldPlus, ArrowLeft, Building2, Mail, Lock, AlertCircle, Webhook, Key } from 'lucide-react'

const API_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8001'

export default function Register() {
  const [companyName, setCompanyName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [webhookUrl, setWebhookUrl] = useState('')
  const [authToken, setAuthToken] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()

  const handleRegister = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)

    try {
      await axios.post(`${API_URL}/auth/register`, {
        company_name: companyName,
        email,
        password,
        webhook_url: webhookUrl || null,
        auth_token: authToken || null,
      })

      navigate('/login')
    } catch (err) {
      setError(err.response?.data?.detail || 'Registration failed. Check input details.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-[#070b14] text-slate-100 flex flex-col justify-center items-center px-4 relative py-12">
      {/* Back to Home Navigation */}
      <Link
        to="/"
        className="absolute top-6 left-6 flex items-center gap-2 text-slate-400 hover:text-cyan-400 text-xs font-mono transition border border-slate-800 hover:border-cyan-500/30 px-3 py-1.5 rounded-lg bg-slate-950/60 backdrop-blur"
      >
        <ArrowLeft className="w-4 h-4" /> Back to Home
      </Link>

      <div className="w-full max-w-md bg-slate-950/80 border border-slate-800 rounded-2xl p-8 backdrop-blur space-y-6">
        <div className="text-center space-y-2">
          <div className="inline-flex p-3 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 mb-1">
            <ShieldPlus className="w-7 h-7" />
          </div>
          <h2 className="text-xl font-bold tracking-wide uppercase">Register Tenant</h2>
          <p className="text-xs text-slate-400 font-mono">Create an isolated organization console & SOAR node</p>
        </div>

        {error && (
          <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded-lg text-rose-400 text-xs font-mono flex items-center gap-2">
            <AlertCircle className="w-4 h-4 flex-shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleRegister} className="space-y-4 font-mono text-xs">
          <div>
            <label className="block text-slate-400 mb-1.5 uppercase tracking-wider text-[11px]">Organization / Company</label>
            <div className="relative">
              <Building2 className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
              <input
                type="text"
                required
                value={companyName}
                onChange={(e) => setCompanyName(e.target.value)}
                placeholder="CyberCorp Ltd."
                className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-9 pr-4 py-2.5 text-slate-100 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          <div>
            <label className="block text-slate-400 mb-1.5 uppercase tracking-wider text-[11px]">Admin Work Email</label>
            <div className="relative">
              <Mail className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="admin@cybercorp.com"
                className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-9 pr-4 py-2.5 text-slate-100 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          <div>
            <label className="block text-slate-400 mb-1.5 uppercase tracking-wider text-[11px]">Password</label>
            <div className="relative">
              <Lock className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-9 pr-4 py-2.5 text-slate-100 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          <div>
            <label className="block text-slate-400 mb-1.5 uppercase tracking-wider text-[11px]">SOAR Webhook Endpoint (Optional)</label>
            <div className="relative">
              <Webhook className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
              <input
                type="url"
                value={webhookUrl}
                onChange={(e) => setWebhookUrl(e.target.value)}
                placeholder="https://client-firewall.com/api/webhook"
                className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-9 pr-4 py-2.5 text-slate-100 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          <div>
            <label className="block text-slate-400 mb-1.5 uppercase tracking-wider text-[11px]">Webhook Auth Bearer Token (Optional)</label>
            <div className="relative">
              <Key className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
              <input
                type="text"
                value={authToken}
                onChange={(e) => setAuthToken(e.target.value)}
                placeholder="sec_token_xyz123"
                className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-9 pr-4 py-2.5 text-slate-100 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2.5 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold rounded-lg text-xs uppercase tracking-wider transition disabled:opacity-50 cursor-pointer mt-2"
          >
            {loading ? 'Creating Tenant...' : 'Create Account'}
          </button>
        </form>

        <p className="text-center text-xs text-slate-500 font-mono">
          Already registered?{' '}
          <Link to="/login" className="text-cyan-400 hover:underline">
            Sign In
          </Link>
        </p>
      </div>
    </div>
  )
}