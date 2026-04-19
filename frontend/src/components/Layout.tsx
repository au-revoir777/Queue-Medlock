import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'

const DEPT_NAV: Record<string, { path: string; label: string; icon: string }> = {
  icu:        { path: '/icu',        label: 'ICU',        icon: '♥' },
  cardiology: { path: '/cardiology', label: 'Cardiology', icon: '⚡' },
  radiology:  { path: '/radiology',  label: 'Radiology',  icon: '◎' },
  neurology:  { path: '/neurology',  label: 'Neurology',  icon: '◈' },
  oncology:   { path: '/oncology',   label: 'Oncology',   icon: '✦' },
}

const ROLE_COLORS: Record<string, string> = {
  doctor: 'var(--accent-cyan)',
  nurse:  '#34d399',
  admin:  '#a78bfa',
}

export default function Layout() {
  const { identity, logout } = useAuth()
  const navigate = useNavigate()
  const role      = (identity as any)?.role || ''
  const dept      = identity?.department || ''
  const isAdmin   = role === 'admin'
  const roleColor = ROLE_COLORS[role] || 'var(--text-muted)'

  // Build nav: always show Dashboard; show only own dept unless admin
  const deptLinks = isAdmin
    ? Object.values(DEPT_NAV)               // admin sees all
    : DEPT_NAV[dept] ? [DEPT_NAV[dept]] : [] // others see only their dept

  function handleLogout() {
    logout()
    navigate('/login')
  }

  return (
    <div style={{ display: 'flex', height: '100vh', background: 'var(--bg-deep)', color: 'var(--text-primary)', fontFamily: 'var(--font-body)' }}>
      {/* Sidebar */}
      <aside style={{
        width: '220px', minWidth: '220px',
        background: 'var(--bg-panel)',
        borderRight: '1px solid var(--border)',
        display: 'flex', flexDirection: 'column',
      }}>
        {/* Logo */}
        <div style={{ padding: '28px 24px 20px', borderBottom: '1px solid var(--border)' }}>
          <div style={{ fontFamily: 'var(--font-display)', fontSize: '20px', color: 'var(--accent-cyan)', letterSpacing: '0.05em', fontWeight: 700 }}>
            MEDLOCK
          </div>
          <div style={{ fontSize: '10px', color: 'var(--text-muted)', letterSpacing: '0.15em', marginTop: '2px' }}>
            ZERO TRUST CLINICAL
          </div>
        </div>

        {/* Identity */}
        <div style={{ padding: '14px 24px', borderBottom: '1px solid var(--border)', background: `${roleColor}08` }}>
          <div style={{ fontSize: '10px', color: 'var(--text-muted)', letterSpacing: '0.1em', marginBottom: '4px' }}>AUTHENTICATED AS</div>
          <div style={{ fontSize: '13px', color: 'var(--text-primary)', fontWeight: 600 }}>{identity?.staff_id}</div>
          <div style={{ fontSize: '11px', color: 'var(--accent-cyan)', marginTop: '1px' }}>{identity?.hospital_id}</div>
          <div style={{ display: 'flex', gap: '6px', marginTop: '8px', flexWrap: 'wrap' }}>
            <span style={tagStyle(roleColor)}>{role.toUpperCase()}</span>
            {!isAdmin && <span style={tagStyle('var(--text-muted)')}>{dept.toUpperCase()}</span>}
            {isAdmin && <span style={tagStyle('#a78bfa')}>ALL DEPTS</span>}
          </div>
        </div>

        {/* Nav */}
        <nav style={{ flex: 1, padding: '10px 0', overflowY: 'auto' }}>

          {/* Dashboard — always visible */}
          <div style={sectionLabel}>OVERVIEW</div>
          <NavLink to="/" end style={({ isActive }) => navStyle(isActive)}>
            <span style={iconStyle}>⬡</span> Dashboard
          </NavLink>

          {/* Clinical — scoped by department/role */}
          <div style={{ ...sectionLabel, marginTop: '12px', borderTop: '1px solid var(--border)', paddingTop: '12px' }}>
            {isAdmin ? 'ALL DEPARTMENTS' : 'MY DEPARTMENT'}
          </div>
          {deptLinks.map(item => (
            <NavLink key={item.path} to={item.path} style={({ isActive }) => navStyle(isActive)}>
              <span style={iconStyle}>{item.icon}</span> {item.label}
            </NavLink>
          ))}

          {/* Admin-only: cross-dept view */}
          {isAdmin && (
            <NavLink to="/admin" style={({ isActive }) => navStyle(isActive, '#a78bfa')}>
              <span style={iconStyle}>⊞</span> Overview
            </NavLink>
          )}

          {/* Zero trust section */}
          <div style={{ ...sectionLabel, marginTop: '12px', borderTop: '1px solid var(--border)', paddingTop: '12px' }}>
            ZERO TRUST
          </div>

          {/* Compose — doctors and nurses only */}
          {(role === 'doctor' || role === 'nurse') && (
            <NavLink to="/compose" style={({ isActive }) => navStyle(isActive, 'var(--accent-cyan)')}>
              <span style={iconStyle}>✉</span> Compose
            </NavLink>
          )}

          {/* Audit log — admin only */}
          {isAdmin && (
            <NavLink to="/audit" style={({ isActive }) => navStyle(isActive, '#a78bfa')}>
              <span style={iconStyle}>⊙</span> Audit Log
            </NavLink>
          )}
        </nav>

        {/* Logout */}
        <div style={{ padding: '16px 24px', borderTop: '1px solid var(--border)' }}>
          <button
            onClick={handleLogout}
            style={{
              width: '100%', padding: '8px',
              background: 'transparent', border: '1px solid var(--border)',
              borderRadius: '4px', color: 'var(--text-muted)',
              fontSize: '12px', cursor: 'pointer', letterSpacing: '0.08em',
              transition: 'all 0.15s', fontFamily: 'inherit',
            }}
            onMouseEnter={e => {
              const el = e.currentTarget
              el.style.borderColor = 'var(--accent-red)'
              el.style.color = 'var(--accent-red)'
            }}
            onMouseLeave={e => {
              const el = e.currentTarget
              el.style.borderColor = 'var(--border)'
              el.style.color = 'var(--text-muted)'
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

// ----------------------------------------------------------------
// Style helpers
// ----------------------------------------------------------------

function tagStyle(color: string): React.CSSProperties {
  return {
    padding: '2px 8px',
    background: `${color}18`,
    border: `1px solid ${color}44`,
    borderRadius: '3px',
    fontSize: '9px',
    color,
    letterSpacing: '0.08em',
    fontFamily: 'var(--font-mono)',
  }
}

function navStyle(isActive: boolean, activeColor = 'var(--accent-cyan)'): React.CSSProperties {
  return {
    display: 'flex', alignItems: 'center', gap: '10px',
    padding: '9px 24px', textDecoration: 'none',
    color: isActive ? activeColor : 'var(--text-secondary)',
    background: isActive ? `${activeColor}0f` : 'transparent',
    borderLeft: isActive ? `2px solid ${activeColor}` : '2px solid transparent',
    fontSize: '13px', fontWeight: isActive ? 600 : 400,
    letterSpacing: '0.03em', transition: 'all 0.15s',
  }
}

const sectionLabel: React.CSSProperties = {
  fontSize: '9px', color: 'var(--text-muted)',
  letterSpacing: '0.15em', padding: '6px 24px 4px',
}

const iconStyle: React.CSSProperties = {
  fontSize: '15px', width: '18px', textAlign: 'center', flexShrink: 0,
}
