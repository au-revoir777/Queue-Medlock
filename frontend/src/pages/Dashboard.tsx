import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { getMyPermissions, getHospitalRecords } from '../api'

const DEPT_CARDS = [
  { path: '/icu',        label: 'ICU',        icon: '♥',  desc: 'Live vitals monitoring',     color: 'var(--accent-red)' },
  { path: '/cardiology', label: 'Cardiology', icon: '⚡', desc: 'ECG reports & cardiac data', color: 'var(--accent-cyan)' },
  { path: '/radiology',  label: 'Radiology',  icon: '◎', desc: 'Scan results & imaging',     color: '#a78bfa' },
  { path: '/neurology',  label: 'Neurology',  icon: '◈', desc: 'Neurological assessments',   color: '#fb923c' },
  { path: '/oncology',   label: 'Oncology',   icon: '✦', desc: 'Treatment plans & cycles',   color: '#34d399' },
  { path: '/admin',      label: 'Admin',      icon: '⊞', desc: 'Cross-department overview',  color: 'var(--text-muted)' },
]

export default function Dashboard() {
  const { identity, token } = useAuth()
  const navigate = useNavigate()

  const [permissions, setPermissions]   = useState<any>(null)
  const [recordStats, setRecordStats]   = useState<{ total: number; urgent: number } | null>(null)

  useEffect(() => {
    if (!token || !identity) return
    getMyPermissions(token).then(setPermissions).catch(console.error)
    getHospitalRecords(token, identity.hospital_id, 1000)
      .then(d => {
        const urgent = d.records.filter((r: any) => r.urgent).length
        setRecordStats({ total: d.total, urgent })
      })
      .catch(console.error)
  }, [token, identity])

  return (
    <div style={{ padding: '40px 32px', fontFamily: 'var(--font-body)', overflowY: 'auto' }}>

      {/* Welcome */}
      <div style={{ marginBottom: '32px' }}>
        <h1 style={{
          margin: 0, fontFamily: 'var(--font-display)',
          fontSize: '28px', color: 'var(--text-primary)', fontWeight: 700, letterSpacing: '0.04em',
        }}>
          Welcome, <span style={{ color: 'var(--accent-cyan)' }}>{identity?.staff_id}</span>
        </h1>
        <p style={{ margin: '6px 0 0', color: 'var(--text-muted)', fontSize: '13px', letterSpacing: '0.06em' }}>
          {identity?.hospital_id?.toUpperCase()} · {identity?.department?.toUpperCase()} · ZERO TRUST SESSION ACTIVE
        </p>
      </div>

      {/* Status strip */}
      <div style={{ display: 'flex', gap: '12px', marginBottom: '36px', flexWrap: 'wrap' }}>
        {[
          { label: 'ENCRYPTION',   value: 'ML-KEM-768 + X25519',    color: 'var(--accent-cyan)' },
          { label: 'SIGNATURES',   value: 'ML-DSA-65 + Ed25519',    color: 'var(--accent-cyan)' },
          { label: 'HOSPITAL',     value: identity?.hospital_id?.toUpperCase() || '...', color: '#a78bfa' },
          { label: 'ROLE',         value: permissions?.role?.toUpperCase() || '...', color: '#fb923c' },
          { label: 'CAN SEND',     value: permissions ? (permissions.can_send ? 'YES' : 'NO — READ ONLY') : '...', color: permissions?.can_send ? '#34d399' : 'var(--accent-red)' },
          { label: 'TOTAL RECORDS', value: recordStats ? String(recordStats.total) : '...', color: 'var(--text-secondary)' },
        ].map(stat => (
          <div key={stat.label} style={{
            padding: '14px 18px', background: 'var(--bg-panel)',
            border: '1px solid var(--border)', borderRadius: '6px', minWidth: '150px',
          }}>
            <div style={{ fontSize: '10px', color: 'var(--text-muted)', letterSpacing: '0.12em', marginBottom: '4px' }}>{stat.label}</div>
            <div style={{ fontSize: '12px', color: stat.color, fontWeight: 600, fontFamily: 'var(--font-mono)' }}>{stat.value}</div>
          </div>
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: '32px', alignItems: 'start' }}>
        <div>
          {/* Department cards */}
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '0.15em', marginBottom: '14px' }}>CLINICAL DEPARTMENTS</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: '10px', marginBottom: '32px' }}>
            {DEPT_CARDS.map(card => (
              <button
                key={card.path}
                onClick={() => navigate(card.path)}
                style={{
                  padding: '22px', background: 'var(--bg-panel)',
                  border: '1px solid var(--border)', borderRadius: '8px',
                  textAlign: 'left', cursor: 'pointer', transition: 'all 0.2s',
                  color: 'inherit', fontFamily: 'inherit',
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
                <div style={{ fontSize: '26px', marginBottom: '10px', color: card.color }}>{card.icon}</div>
                <div style={{ fontFamily: 'var(--font-display)', fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)', letterSpacing: '0.05em', marginBottom: '4px' }}>
                  {card.label}
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{card.desc}</div>
              </button>
            ))}
          </div>

          {/* Quick actions */}
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '0.15em', marginBottom: '14px' }}>QUICK ACTIONS</div>
          <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
            {permissions?.can_send && (
              <button
                onClick={() => navigate('/compose')}
                style={{
                  padding: '12px 20px',
                  background: 'rgba(0,255,200,0.08)', border: '1px solid rgba(0,255,200,0.3)',
                  borderRadius: '6px', color: 'var(--accent-cyan)', fontSize: '12px',
                  fontWeight: 600, cursor: 'pointer', letterSpacing: '0.08em',
                  fontFamily: 'var(--font-display)', transition: 'all 0.15s',
                }}
              >
                ✉ COMPOSE MESSAGE
              </button>
            )}
            <button
              onClick={() => navigate('/audit')}
              style={{
                padding: '12px 20px',
                background: 'rgba(167,139,250,0.08)', border: '1px solid rgba(167,139,250,0.3)',
                borderRadius: '6px', color: '#a78bfa', fontSize: '12px',
                fontWeight: 600, cursor: 'pointer', letterSpacing: '0.08em',
                fontFamily: 'var(--font-display)', transition: 'all 0.15s',
              }}
            >
              ⊙ VIEW AUDIT LOG
            </button>
          </div>
        </div>

        {/* Zero Trust Proof Panel */}
        <div style={{
          background: 'var(--bg-panel)',
          border: '1px solid var(--border)',
          borderRadius: '8px',
          padding: '24px',
          position: 'sticky',
          top: 0,
        }}>
          <div style={{ fontFamily: 'var(--font-display)', fontSize: '12px', color: 'var(--accent-cyan)', letterSpacing: '0.12em', marginBottom: '20px' }}>
            ZERO TRUST PROOF
          </div>

          {/* Principles */}
          {[
            {
              title:  'Verify Explicitly',
              status: 'ACTIVE',
              color:  'var(--accent-cyan)',
              items:  [
                'JWT token validated on every request',
                'Token bound to staff_id + hospital_id',
                'KMS verifies sender identity on send',
              ],
            },
            {
              title:  'Least Privilege',
              status: 'ACTIVE',
              color:  '#34d399',
              items:  [
                `Role: ${permissions?.role || '...'}`,
                `Dept: ${permissions?.department || '...'}`,
                permissions?.can_send
                  ? `May send: ${(permissions?.message_types || []).join(', ')}`
                  : 'Read-only — cannot send messages',
              ],
            },
            {
              title:  'Hospital Isolation',
              status: 'ENFORCED',
              color:  '#fb923c',
              items:  [
                `Scoped to: ${identity?.hospital_id || '...'}`,
                'Cross-hospital requests return 403',
                'WebSocket streams hospital-isolated',
              ],
            },
            {
              title:  'Assume Breach',
              status: 'LOGGING',
              color:  '#a78bfa',
              items:  [
                'Every message written to audit log',
                'Metadata-only — no plaintext stored',
                'Sequence numbers prevent replay',
              ],
            },
            {
              title:  'Post-Quantum Crypto',
              status: 'ENABLED',
              color:  'var(--accent-cyan)',
              items:  [
                'ML-KEM-768 key encapsulation',
                'ML-DSA-65 message signing',
                'X25519 + Ed25519 classical hybrid',
              ],
            },
          ].map(section => (
            <div key={section.title} style={{ marginBottom: '18px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)' }}>{section.title}</span>
                <span style={{
                  padding: '1px 7px',
                  background: `${section.color}18`,
                  border: `1px solid ${section.color}44`,
                  borderRadius: '3px',
                  fontSize: '9px',
                  color: section.color,
                  letterSpacing: '0.08em',
                  fontFamily: 'var(--font-mono)',
                }}>
                  {section.status}
                </span>
              </div>
              {section.items.map(item => (
                <div key={item} style={{ display: 'flex', gap: '8px', alignItems: 'flex-start', marginBottom: '3px' }}>
                  <span style={{ color: section.color, fontSize: '10px', marginTop: '2px', flexShrink: 0 }}>·</span>
                  <span style={{ fontSize: '11px', color: 'var(--text-muted)', lineHeight: '1.4' }}>{item}</span>
                </div>
              ))}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
