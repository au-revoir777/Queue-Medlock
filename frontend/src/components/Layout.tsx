import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'

const NAV = [
  { path: '/',          label: 'Dashboard',  icon: '⬡' },
  { path: '/icu',       label: 'ICU',        icon: '♥' },
  { path: '/cardiology',label: 'Cardiology', icon: '⚡' },
  { path: '/radiology', label: 'Radiology',  icon: '◎' },
  { path: '/neurology', label: 'Neurology',  icon: '◈' },
  { path: '/oncology',  label: 'Oncology',   icon: '✦' },
  { path: '/admin',     label: 'Admin',      icon: '⊞' },
]

export default function Layout() {
  const { identity, logout } = useAuth()
  const navigate = useNavigate()

  function handleLogout() {
    logout()
    navigate('/login')
  }

  return (
    <div style={{ display: 'flex', height: '100vh', background: 'var(--bg-deep)', color: 'var(--text-primary)', fontFamily: 'var(--font-body)' }}>
      {/* Sidebar */}
      <aside style={{
        width: '220px',
        minWidth: '220px',
        background: 'var(--bg-panel)',
        borderRight: '1px solid var(--border)',
        display: 'flex',
        flexDirection: 'column',
        padding: '0',
      }}>
        {/* Logo */}
        <div style={{
          padding: '28px 24px 20px',
          borderBottom: '1px solid var(--border)',
        }}>
          <div style={{ fontFamily: 'var(--font-display)', fontSize: '20px', color: 'var(--accent-cyan)', letterSpacing: '0.05em', fontWeight: 700 }}>
            MEDLOCK
          </div>
          <div style={{ fontSize: '10px', color: 'var(--text-muted)', letterSpacing: '0.15em', marginTop: '2px' }}>
            ZERO TRUST CLINICAL
          </div>
        </div>

        {/* Identity */}
        <div style={{
          padding: '16px 24px',
          borderBottom: '1px solid var(--border)',
          background: 'rgba(0,255,200,0.03)',
        }}>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '0.1em', marginBottom: '4px' }}>LOGGED IN AS</div>
          <div style={{ fontSize: '13px', color: 'var(--text-primary)', fontWeight: 600 }}>{identity?.staff_id}</div>
          <div style={{ fontSize: '11px', color: 'var(--accent-cyan)', marginTop: '2px' }}>{identity?.hospital_id}</div>
          <div style={{
            display: 'inline-block',
            marginTop: '6px',
            padding: '2px 8px',
            background: 'rgba(0,255,200,0.08)',
            border: '1px solid rgba(0,255,200,0.2)',
            borderRadius: '3px',
            fontSize: '10px',
            color: 'var(--accent-cyan)',
            letterSpacing: '0.08em',
          }}>
            {identity?.department?.toUpperCase()}
          </div>
        </div>

        {/* Nav */}
        <nav style={{ flex: 1, padding: '12px 0' }}>
          {NAV.map(item => (
            <NavLink
              key={item.path}
              to={item.path}
              end={item.path === '/'}
              style={({ isActive }) => ({
                display: 'flex',
                alignItems: 'center',
                gap: '12px',
                padding: '10px 24px',
                textDecoration: 'none',
                color: isActive ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                background: isActive ? 'rgba(0,255,200,0.06)' : 'transparent',
                borderLeft: isActive ? '2px solid var(--accent-cyan)' : '2px solid transparent',
                fontSize: '13px',
                fontWeight: isActive ? 600 : 400,
                letterSpacing: '0.03em',
                transition: 'all 0.15s',
              })}
            >
              <span style={{ fontSize: '16px', width: '20px', textAlign: 'center' }}>{item.icon}</span>
              {item.label}
            </NavLink>
          ))}
        </nav>

        {/* Logout */}
        <div style={{ padding: '16px 24px', borderTop: '1px solid var(--border)' }}>
          <button
            onClick={handleLogout}
            style={{
              width: '100%',
              padding: '8px',
              background: 'transparent',
              border: '1px solid var(--border)',
              borderRadius: '4px',
              color: 'var(--text-muted)',
              fontSize: '12px',
              cursor: 'pointer',
              letterSpacing: '0.08em',
              transition: 'all 0.15s',
            }}
            onMouseEnter={e => {
              (e.target as HTMLButtonElement).style.borderColor = 'var(--accent-red)'
              ;(e.target as HTMLButtonElement).style.color = 'var(--accent-red)'
            }}
            onMouseLeave={e => {
              (e.target as HTMLButtonElement).style.borderColor = 'var(--border)'
              ;(e.target as HTMLButtonElement).style.color = 'var(--text-muted)'
            }}
          >
            SIGN OUT
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main style={{ flex: 1, overflow: 'auto', display: 'flex', flexDirection: 'column' }}>
        <Outlet />
      </main>
    </div>
  )
}
