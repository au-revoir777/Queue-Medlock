import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider, useAuth } from './context/AuthContext.tsx'
import Login from './pages/Login.tsx'
import Dashboard from './pages/Dashboard.tsx'
import ICU from './pages/ICU.tsx'
import Cardiology from './pages/Cardiology.tsx'
import Radiology from './pages/Radiology.tsx'
import Neurology from './pages/Neurology.tsx'
import Oncology from './pages/Oncology.tsx'
import Admin from './pages/Admin.tsx'
import Layout from './components/Layout.tsx'

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
          </Route>
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  )
}
