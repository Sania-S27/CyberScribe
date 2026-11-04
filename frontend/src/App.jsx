// frontend/src/App.jsx
import { useState, useEffect } from 'react'
import { 
  BrowserRouter, 
  Routes, 
  Route, 
  Navigate, 
  Outlet, 
  useNavigate, 
  useOutletContext 
} from 'react-router-dom'
import axios from 'axios'

// Public Pages
import Home from './pages/Home'
import GuestDashboard from './pages/GuestDashboard'
import Register from './pages/Register'
import Login from './pages/Login'

// Layouts
import CompanyLayout from './components/layout/CompanyLayout'
import AdminLayout from './components/layout/AdminLayout'

// Company Portal Subpages
import CompanyOverview from './pages/company/CompanyOverview'
import CompanyAnalytics from './pages/company/CompanyAnalytics'
import CompanyFindings from './pages/company/CompanyFindings'
import CompanyProfile from './pages/company/CompanyProfile'
import CompanyRemediation from './pages/company/CompanyRemediation'
import CompanyContainment from './pages/company/CompanyContainment'
import CompanyReports from './pages/company/CompanyReports'

// Admin Portal Subpages
import AdminOverview from './pages/admin/AdminOverview'
import AdminTenants from './pages/admin/AdminTenants'
import AdminUsers from './pages/admin/AdminUsers'
import AdminThreatIntel from './pages/admin/AdminThreatIntel'
import AdminContainment from './pages/admin/AdminContainment'
import AdminIntegrations from './pages/admin/AdminIntegrations'
import AdminAuditLogs from './pages/admin/AdminAuditLogs'
import AdminSystemHealth from './pages/admin/AdminSystemHealth'

const API_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8001'

// 1. Root Protected Layout verifying JWT session profile
const ProtectedLayout = () => {
  const [authStatus, setAuthStatus] = useState(() => {
    const token = localStorage.getItem('access_token')
    return {
      loading: Boolean(token),
      authenticated: false,
      userProfile: null,
    }
  })

  useEffect(() => {
    const token = localStorage.getItem('access_token')
    if (!token) return

    let isMounted = true

    axios
      .get(`${API_URL}/auth/me`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      .then((res) => {
        if (isMounted) {
          setAuthStatus({
            loading: false,
            authenticated: true,
            userProfile: res.data,
          })
        }
      })
      .catch(() => {
        if (isMounted) {
          localStorage.removeItem('access_token')
          setAuthStatus({ loading: false, authenticated: false, userProfile: null })
        }
      })

    return () => {
      isMounted = false
    }
  }, [])

  if (authStatus.loading) {
    return (
      <div className="min-h-screen bg-[#070b14] flex items-center justify-center text-slate-400 font-mono text-xs">
        Verifying security credentials & session context...
      </div>
    )
  }

  if (!authStatus.authenticated) {
    return <Navigate to="/login" replace />
  }

  return <Outlet context={{ userProfile: authStatus.userProfile }} />
}

// 2. Tenant Context & Role Guard (Restricts Company Portal to Authorized Tenant Users)
const TenantGuard = () => {
  const { userProfile } = useOutletContext()
  if (userProfile?.role === 'super_admin') {
    return <Navigate to="/admin" replace />
  }
  return <CompanyLayout userProfile={userProfile} />
}

// 3. Super Admin Context & Role Guard (Strict Platform Administrator Scope)
const SuperAdminGuard = () => {
  const { userProfile } = useOutletContext()
  if (userProfile?.role !== 'super_admin') {
    return <Navigate to="/dashboard" replace />
  }
  return <AdminLayout userProfile={userProfile} />
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* Public Routes */}
        <Route path="/" element={<Home />} />
        <Route path="/explorer" element={<GuestDashboard />} />
        <Route path="/public-threats" element={<GuestDashboard />} />
        <Route path="/threats" element={<GuestDashboard />} />
        <Route path="/osint" element={<GuestDashboard />} />
        <Route path="/register" element={<Register />} />
        <Route path="/login" element={<Login />} />

        {/* Authenticated Application */}
        <Route element={<ProtectedLayout />}>
          {/* Tenant Company Portal Routes (with backward compatibility) */}
          <Route element={<TenantGuard />}>
            <Route path="/dashboard" element={<CompanyOverview />} />
            <Route path="/company/overview" element={<CompanyOverview />} />
            <Route path="/company/threats" element={<CompanyFindings />} />
            <Route path="/company/findings" element={<CompanyFindings />} />
            <Route path="/company/assets" element={<CompanyProfile />} />
            <Route path="/company/profile" element={<CompanyProfile />} />
            <Route path="/company/reports" element={<CompanyReports />} />
            <Route path="/company/containment" element={<CompanyContainment />} />
            <Route path="/company/remediation" element={<CompanyRemediation />} />
            <Route path="/company/analytics" element={<CompanyAnalytics />} />
            
            {/* Backward-compatible redirects: Administrative pages removed from tenant portal */}
            <Route path="/profile" element={<CompanyProfile />} />
            <Route path="/company/audit-logs" element={<Navigate to="/dashboard" replace />} />
            <Route path="/company/logs" element={<Navigate to="/dashboard" replace />} />
            <Route path="/company/audit" element={<Navigate to="/dashboard" replace />} />
            <Route path="/company/explorer" element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard/explorer" element={<Navigate to="/dashboard" replace />} />
          </Route>

          {/* Super Admin Portal Routes (with backward compatibility) */}
          <Route element={<SuperAdminGuard />}>
            <Route path="/admin" element={<AdminOverview />} />
            <Route path="/admin/overview" element={<AdminOverview />} />
            <Route path="/admin/tenants" element={<AdminTenants />} />
            <Route path="/admin/users" element={<AdminUsers />} />
            <Route path="/admin/threats" element={<AdminThreatIntel />} />
            <Route path="/admin/containment" element={<AdminContainment />} />
            <Route path="/admin/integrations" element={<AdminIntegrations />} />
            <Route path="/admin/audit" element={<AdminAuditLogs />} />
            <Route path="/admin/health" element={<AdminSystemHealth />} />

            {/* Backward-compatible redirects */}
            <Route path="/admin/explorer" element={<Navigate to="/admin/threats" replace />} />
          </Route>
        </Route>

        {/* Global Catch-all */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  )
}