import { useState, useEffect } from 'react'
import { useAuth } from '../context/AuthContext'
import { getAuditLog } from '../api'
import PageHeader from '../components/PageHeader'

interface AuditEntry {
  id: number
  timestamp: number
  producer_id: string
  department: string
  sequence: number
  verified: boolean
  message_type?: string
  patient_name?: string
  urgent?: boolean
}

const DEPT_COLORS: Record<string, string> = {
  icu: 'var(--accent-red)', cardiology: 'var(--accent-cyan)',
  radiology: '#a78bfa', neurology: '#fb923c', oncology: '#34d399',
}

export default function AuditLog() {
  const { token, identity } = useAuth()
  const role = (identity as any)?.role || ''

  const [entries, setEntries] = useState<AuditEntry[]>([])
  const [total, setTotal]     = useState(0)
  const [loading, setLoading] = useState(true)
  const [note, setNote]       = useState('')

  // ── Admin-only gate ──
  if (role !== 'admin') {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
        <PageHeader title="AUDIT LOG" subtitle="ZERO-KNOWLEDGE METADATA TRAIL" icon="⊙" accent="#a78bfa" />
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <div style={{
            padding: '32px 40px', maxWidth: '440px', textAlign: 'center',
            background: 'rgba(255,60,60,0.04)', border: '1px solid rgba(255,60,60,0.2)',
            borderRadius: '8px',
          }}>
            <div style={{ fontSize: '32px', marginBottom: '16px' }}>🔒</div>
            <div style={{ fontFamily: 'var(--font-display)', fontSize: '16px', color: 'var(--accent-red)', letterSpacing: '0.05em', marginBottom: '8px' }}>
              ACCESS DENIED
            </div>
            <div style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: '1.6' }}>
              The audit log is restricted to <strong style={{ color: 'var(--text-primary)' }}>admin</strong> role only.
              Your current role is <strong style={{ color: 'var(--text-primary)' }}>{role || 'unknown'}</strong>.
            </div>
            <div style={{ marginTop: '16px', padding: '10px 14px', background: 'rgba(255,255,255,0.03)', border: '1px solid var(--border)', borderRadius: '4px', fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '0.08em' }}>
              ZERO TRUST · LEAST PRIVILEGE · ACCESS DENIED
            </div>
          </div>
        </div>
      </div>
    )
  }

  // eslint-disable-next-line react-hooks/rules-of-hooks
  useEffect(() => {
    if (!token || !identity) return
    setLoading(true)
    getAuditLog(token, identity.hospital_id, 100)
      .then(d => { setEntries(d.entries); setTotal(d.total); setNote(d.note) })
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [token, identity])

  function formatTs(ts: number) {
    return new Date(ts * 1000).toLocaleString()
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <PageHeader title="AUDIT LOG" subtitle="ZERO-KNOWLEDGE METADATA TRAIL — NO PLAINTEXT STORED" icon="⊙" accent="#a78bfa" />

      {/* Info bar */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: '16px',
        padding: '10px 32px', background: 'rgba(167,139,250,0.04)',
        borderBottom: '1px solid var(--border)', fontSize: '11px', flexWrap: 'wrap',
      }}>
        <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#a78bfa', display: 'inline-block' }} />
        <span style={{ color: 'var(--text-muted)', letterSpacing: '0.08em' }}>{note}</span>
        <span style={{ marginLeft: 'auto', color: '#a78bfa', fontFamily: 'var(--font-mono)' }}>
          {total} ENTRIES
        </span>
      </div>

      {/* Column headers */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: '180px 140px 110px 80px 1fr 100px 70px',
        gap: '0 16px', padding: '10px 32px',
        background: 'var(--bg-panel)', borderBottom: '1px solid var(--border)',
        fontSize: '10px', color: 'var(--text-muted)', letterSpacing: '0.1em',
      }}>
        <span>TIMESTAMP</span><span>PRODUCER</span><span>DEPARTMENT</span>
        <span>SEQ</span><span>MESSAGE TYPE</span><span>PATIENT</span><span>STATUS</span>
      </div>

      {/* Entries */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '0 32px 24px' }}>
        {loading ? (
          <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '12px', letterSpacing: '0.1em' }}>
            LOADING AUDIT TRAIL...
          </div>
        ) : entries.length === 0 ? (
          <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '12px', letterSpacing: '0.1em' }}>
            NO AUDIT ENTRIES YET — SEND A MESSAGE TO GENERATE TRAIL
          </div>
        ) : (
          entries.map((entry, i) => {
            const color = DEPT_COLORS[entry.department] || 'var(--text-muted)'
            return (
              <div key={entry.id} style={{
                display: 'grid',
                gridTemplateColumns: '180px 140px 110px 80px 1fr 100px 70px',
                gap: '0 16px', padding: '10px 0',
                borderBottom: '1px solid rgba(255,255,255,0.03)',
                fontSize: '12px', alignItems: 'center',
                background: i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.01)',
                animation: 'fadeIn 0.2s ease',
              }}>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)' }}>
                  {formatTs(entry.timestamp)}
                </span>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {entry.producer_id}
                </span>
                <span style={{
                  display: 'inline-block', padding: '2px 8px',
                  background: `${color}18`, border: `1px solid ${color}44`,
                  borderRadius: '3px', fontSize: '10px', color,
                  letterSpacing: '0.06em', fontFamily: 'var(--font-mono)', textTransform: 'uppercase',
                }}>
                  {entry.department}
                </span>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)' }}>
                  #{entry.sequence}
                </span>
                <span style={{ fontSize: '11px', color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {entry.message_type || '—'}
                  {entry.urgent && <span style={{ marginLeft: '6px', color: 'var(--accent-red)', fontSize: '10px' }}>⚠ URGENT</span>}
                </span>
                <span style={{ fontSize: '11px', color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {entry.patient_name || '—'}
                </span>
                <span style={{
                  display: 'inline-block', padding: '2px 6px',
                  background: entry.verified ? 'rgba(0,255,200,0.08)' : 'rgba(255,60,60,0.08)',
                  border: `1px solid ${entry.verified ? 'rgba(0,255,200,0.25)' : 'rgba(255,60,60,0.25)'}`,
                  borderRadius: '3px', fontSize: '9px',
                  color: entry.verified ? 'var(--accent-cyan)' : 'var(--accent-red)',
                  letterSpacing: '0.06em', fontFamily: 'var(--font-mono)',
                }}>
                  {entry.verified ? 'VERIFIED' : 'UNVERIF'}
                </span>
              </div>
            )
          })
        )}
      </div>
    </div>
  )
}
