import { useAuth } from '../context/AuthContext'
import { useWebSocket, ClinicalRecord } from '../hooks/useWebSocket'
import PageHeader from '../components/PageHeader'
import RecordFeed from '../components/RecordFeed'

function VitalBadge({ label, value, alert }: { label: string; value: string | number; alert?: boolean }) {
  return (
    <div style={{
      display: 'flex', flexDirection: 'column', alignItems: 'center',
      padding: '8px 14px',
      background: alert ? 'rgba(255,60,60,0.08)' : 'rgba(0,255,200,0.04)',
      border: `1px solid ${alert ? 'rgba(255,60,60,0.3)' : 'rgba(0,255,200,0.15)'}`,
      borderRadius: '4px',
      minWidth: '80px',
    }}>
      <span style={{ fontSize: '10px', color: 'var(--text-muted)', letterSpacing: '0.1em', marginBottom: '4px' }}>{label}</span>
      <span style={{
        fontFamily: 'var(--font-mono)',
        fontSize: '15px',
        fontWeight: 700,
        color: alert ? 'var(--accent-red)' : 'var(--accent-cyan)',
      }}>{value}</span>
    </div>
  )
}

function ICUCard({ record }: { record: ClinicalRecord }) {
  const v   = record.payload?.vitals || {}
  const isUrgent = record.urgent

  return (
    <div style={{
      background: isUrgent ? 'rgba(255,60,60,0.04)' : 'var(--bg-panel)',
      border: `1px solid ${isUrgent ? 'rgba(255,60,60,0.35)' : 'var(--border)'}`,
      borderRadius: '6px',
      padding: '16px 20px',
      animation: 'fadeIn 0.3s ease',
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '14px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)' }}>
              {record.patient_name}
            </span>
            <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              {record.patient_id}
            </span>
            {isUrgent && (
              <span style={{
                padding: '2px 8px', background: 'rgba(255,60,60,0.15)',
                border: '1px solid rgba(255,60,60,0.4)', borderRadius: '3px',
                fontSize: '10px', color: 'var(--accent-red)', letterSpacing: '0.1em',
              }}>⚠ CRITICAL</span>
            )}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
            {record.payload?.attending} · {new Date(record.recorded_at).toLocaleTimeString()}
          </div>
        </div>
        <span style={{
          padding: '3px 10px',
          background: record.payload?.status === 'CRITICAL' ? 'rgba(255,60,60,0.12)' : 'rgba(0,255,200,0.08)',
          border: `1px solid ${record.payload?.status === 'CRITICAL' ? 'rgba(255,60,60,0.3)' : 'rgba(0,255,200,0.2)'}`,
          borderRadius: '3px',
          fontSize: '11px',
          color: record.payload?.status === 'CRITICAL' ? 'var(--accent-red)' : 'var(--accent-cyan)',
          fontFamily: 'var(--font-mono)',
          letterSpacing: '0.08em',
        }}>
          {record.payload?.status}
        </span>
      </div>

      <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
        <VitalBadge label="HR" value={`${v.heart_rate} bpm`} alert={v.heart_rate > 110 || v.heart_rate < 60} />
        <VitalBadge label="BP" value={v.blood_pressure} alert={parseInt(v.blood_pressure) > 160 || parseInt(v.blood_pressure) < 90} />
        <VitalBadge label="SpO₂" value={`${v.spo2_percent}%`} alert={v.spo2_percent < 92} />
        <VitalBadge label="TEMP" value={`${v.temperature_c}°C`} alert={v.temperature_c > 38.5} />
        <VitalBadge label="RR" value={`${v.respiratory_rate}/min`} />
        <VitalBadge label="GCS" value={v.gcs} alert={v.gcs < 13} />
      </div>

      {record.payload?.alerts?.length > 0 && (
        <div style={{ marginTop: '10px', display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
          {record.payload.alerts.map((a: string) => (
            <span key={a} style={{
              padding: '2px 8px',
              background: 'rgba(255,60,60,0.1)',
              border: '1px solid rgba(255,60,60,0.25)',
              borderRadius: '3px',
              fontSize: '10px',
              color: 'var(--accent-red)',
              fontFamily: 'var(--font-mono)',
              letterSpacing: '0.08em',
            }}>{a}</span>
          ))}
        </div>
      )}
    </div>
  )
}

export default function ICU() {
  const { token, identity } = useAuth()
  const role = (identity as any)?.role || ''
  const dept = identity?.department || ''
  const allowed = role === 'admin' || dept === 'icu'
  const { records, connected, error } = useWebSocket({
    hospital_id: identity!.hospital_id,
    department: 'icu',
    token: token!,
  })

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <PageHeader title="ICU MONITORING" subtitle="INTENSIVE CARE UNIT — LIVE VITALS STREAM" icon="♥" accent="var(--accent-red)" />
      {allowed ? (
        <RecordFeed
          records={records}
          connected={connected}
          error={error}
          renderRecord={r => <ICUCard record={r} />}
        />
      ) : (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', flex: 1 }}>
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
              You are not authorised to view the <strong style={{ color: 'var(--text-primary)' }}>ICU</strong> department.
              Your access is scoped to your assigned department only.
            </div>
            <div style={{ marginTop: '16px', padding: '10px 14px', background: 'rgba(255,255,255,0.03)', border: '1px solid var(--border)', borderRadius: '4px', fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '0.08em' }}>
              ZERO TRUST · LEAST PRIVILEGE · ACCESS DENIED
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
