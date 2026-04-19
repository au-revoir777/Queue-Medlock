import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider, useAuth } from './context/AuthContext'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import ICU from './pages/ICU'
import Cardiology from './pages/Cardiology'
import Radiology from './pages/Radiology'
import Neurology from './pages/Neurology'
import Oncology from './pages/Oncology'
import Admin from './pages/Admin'
import Compose from './pages/Compose.tsx'
import AuditLog from './pages/AuditLog.tsx'
import Layout from './components/Layout'

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { token } = useAuth()
  if (!token) return <Navigate to="/login" replace />
  return <>{children}</>
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/" element={
            <ProtectedRoute>
              <Layout />
            </ProtectedRoute>
          }>
            <Route index element={<Dashboard />} />
            <Route path="icu" element={<ICU />} />
            <Route path="cardiology" element={<Cardiology />} />
            <Route path="radiology" element={<Radiology />} />
            <Route path="neurology" element={<Neurology />} />
            <Route path="oncology" element={<Oncology />} />
            <Route path="admin" element={<Admin />} />
            <Route path="compose" element={<Compose />} />
            <Route path="audit" element={<AuditLog />} />
          </Route>
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  )
}
