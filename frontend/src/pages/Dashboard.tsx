import { useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'

const DEPT_CARDS = [
  { path: '/icu',        label: 'ICU',        icon: '♥', desc: 'Live vitals monitoring',     color: 'var(--accent-red)' },
  { path: '/cardiology', label: 'Cardiology', icon: '⚡', desc: 'ECG reports & cardiac data', color: 'var(--accent-cyan)' },
  { path: '/radiology',  label: 'Radiology',  icon: '◎', desc: 'Scan results & imaging',     color: '#a78bfa' },
  { path: '/neurology',  label: 'Neurology',  icon: '◈', desc: 'Neurological assessments',   color: '#fb923c' },
  { path: '/oncology',   label: 'Oncology',   icon: '✦', desc: 'Treatment plans & cycles',   color: '#34d399' },
  { path: '/admin',      label: 'Admin',      icon: '⊞', desc: 'Cross-department overview',  color: 'var(--text-muted)' },
]

export default function Dashboard() {
  const { identity } = useAuth()
  const navigate = useNavigate()

  return (
    <div style={{ padding: '40px 32px', fontFamily: 'var(--font-body)' }}>
      {/* Welcome */}
      <div style={{ marginBottom: '40px' }}>
        <h1 style={{
          margin: 0,
          fontFamily: 'var(--font-display)',
          fontSize: '28px',
          color: 'var(--text-primary)',
          fontWeight: 700,
          letterSpacing: '0.04em',
        }}>
          Welcome, <span style={{ color: 'var(--accent-cyan)' }}>{identity?.staff_id}</span>
        </h1>
        <p style={{
          margin: '6px 0 0',
          color: 'var(--text-muted)',
          fontSize: '13px',
          letterSpacing: '0.06em',
        }}>
          {identity?.hospital_id?.toUpperCase()} · {identity?.department?.toUpperCase()} · ZERO TRUST SESSION ACTIVE
        </p>
      </div>

      {/* Status bar */}
      <div style={{
        display: 'flex',
        gap: '16px',
        marginBottom: '40px',
        flexWrap: 'wrap',
      }}>
        {[
          { label: 'ENCRYPTION', value: 'PQC ACTIVE', color: 'var(--accent-cyan)' },
          { label: 'AUTH',       value: 'JWT VALID',  color: 'var(--accent-cyan)' },
          { label: 'ISOLATION',  value: identity?.hospital_id?.toUpperCase() || '', color: '#a78bfa' },
          { label: 'ROLE',       value: identity?.department?.toUpperCase() || '', color: '#fb923c' },
        ].map(stat => (
          <div key={stat.label} style={{
            padding: '14px 20px',
            background: 'var(--bg-panel)',
            border: '1px solid var(--border)',
            borderRadius: '6px',
            minWidth: '140px',
          }}>
            <div style={{ fontSize: '10px', color: 'var(--text-muted)', letterSpacing: '0.12em', marginBottom: '4px' }}>
              {stat.label}
            </div>
            <div style={{ fontSize: '13px', color: stat.color, fontWeight: 600, fontFamily: 'var(--font-mono)' }}>
              {stat.value}
            </div>
          </div>
        ))}
      </div>

      {/* Department cards */}
      <div style={{ marginBottom: '16px' }}>
        <div style={{ fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '0.15em', marginBottom: '16px' }}>
          CLINICAL DEPARTMENTS
        </div>
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))',
          gap: '12px',
        }}>
          {DEPT_CARDS.map(card => (
            <button
              key={card.path}
              onClick={() => navigate(card.path)}
              style={{
                padding: '24px',
                background: 'var(--bg-panel)',
                border: `1px solid var(--border)`,
                borderRadius: '8px',
                textAlign: 'left',
                cursor: 'pointer',
                transition: 'all 0.2s',
                color: 'inherit',
                fontFamily: 'inherit',
              }}
              onMouseEnter={e => {
                const el = e.currentTarget
                el.style.borderColor = card.color
                el.style.background  = `${card.color}09`
                el.style.transform   = 'translateY(-2px)'
              }}
              onMouseLeave={e => {
                const el = e.currentTarget
                el.style.borderColor = 'var(--border)'
                el.style.background  = 'var(--bg-panel)'
                el.style.transform   = 'none'
              }}
            >
              <div style={{ fontSize: '28px', marginBottom: '12px', color: card.color }}>
                {card.icon}
              </div>
              <div style={{
                fontFamily: 'var(--font-display)',
                fontSize: '15px',
                fontWeight: 700,
                color: 'var(--text-primary)',
                letterSpacing: '0.05em',
                marginBottom: '4px',
              }}>
                {card.label}
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                {card.desc}
              </div>
            </button>
          ))}
        </div>
      </div>
    </div>
  )
}
