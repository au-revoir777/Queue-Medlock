import { useAuth } from '../context/AuthContext'
import { useWebSocket, ClinicalRecord } from '../hooks/useWebSocket'
import PageHeader from '../components/PageHeader'
import RecordFeed from '../components/RecordFeed'

// ----------------------------------------------------------------
// Access guard — renders an ACCESS DENIED block when the current
// user is not allowed to view this department page.
// Admins can view any department; others only their own.
// ----------------------------------------------------------------
function useDeptAccess(requiredDept: string) {
  const { identity } = useAuth()
  const role = (identity as any)?.role || ''
  const dept = identity?.department || ''
  return role === 'admin' || dept === requiredDept
}

function AccessDenied({ dept }: { dept: string }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', flex: 1, height: '100%' }}>
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
          You are not authorised to view the <strong style={{ color: 'var(--text-primary)', textTransform: 'uppercase' }}>{dept}</strong> department.
          Your access is scoped to your assigned department only.
        </div>
        <div style={{ marginTop: '16px', padding: '10px 14px', background: 'rgba(255,255,255,0.03)', border: '1px solid var(--border)', borderRadius: '4px', fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '0.08em' }}>
          ZERO TRUST · LEAST PRIVILEGE · ACCESS DENIED
        </div>
      </div>
    </div>
  )
}

// ----------------------------------------------------------------
// Cardiology
// ----------------------------------------------------------------
function ECGCard({ record }: { record: ClinicalRecord }) {
  const ecg = record.payload?.ecg || {}
  return (
    <div style={{
      background: record.urgent ? 'rgba(255,60,60,0.04)' : 'var(--bg-panel)',
      border: `1px solid ${record.urgent ? 'rgba(255,60,60,0.35)' : 'var(--border)'}`,
      borderRadius: '6px', padding: '16px 20px',
      animation: 'fadeIn 0.3s ease',
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)' }}>{record.patient_name}</span>
            <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{record.patient_id}</span>
            {record.urgent && <span style={urgentBadge}>⚠ URGENT</span>}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
            {record.payload?.attending} · {new Date(record.recorded_at).toLocaleTimeString()}
          </div>
        </div>
        <span style={{
          fontFamily: 'var(--font-mono)', fontSize: '18px', fontWeight: 700,
          color: 'var(--accent-cyan)',
        }}>{ecg.heart_rate} <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>bpm</span></span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '8px', marginBottom: '10px' }}>
        {[
          { label: 'RHYTHM',  value: ecg.rhythm },
          { label: 'ST',      value: ecg.st_changes },
          { label: 'AXIS',    value: ecg.axis },
          { label: 'PR',      value: `${ecg.pr_interval_ms}ms` },
          { label: 'QRS',     value: `${ecg.qrs_duration_ms}ms` },
          { label: 'QT',      value: `${ecg.qt_interval_ms}ms` },
        ].map(f => (
          <div key={f.label} style={dataCell}>
            <span style={dataLabel}>{f.label}</span>
            <span style={{ ...dataValue, color: f.label === 'ST' && f.value !== 'None' ? 'var(--accent-red)' : 'var(--text-primary)' }}>{f.value}</span>
          </div>
        ))}
      </div>
      <div style={{
        padding: '8px 12px',
        background: 'rgba(0,255,200,0.04)',
        border: '1px solid rgba(0,255,200,0.12)',
        borderRadius: '4px',
        fontSize: '12px',
        color: 'var(--text-secondary)',
        fontStyle: 'italic',
      }}>
        {record.payload?.interpretation}
      </div>
    </div>
  )
}

export function Cardiology() {
  const { token, identity } = useAuth()
  const allowed = useDeptAccess('cardiology')
  const ws = useWebSocket({ hospital_id: identity!.hospital_id, department: 'cardiology', token: token! })
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <PageHeader title="CARDIOLOGY" subtitle="ECG REPORTS & CARDIAC MONITORING" icon="⚡" accent="var(--accent-cyan)" />
      {allowed ? <RecordFeed {...ws} renderRecord={r => <ECGCard record={r} />} /> : <AccessDenied dept="cardiology" />}
    </div>
  )
}

// ----------------------------------------------------------------
// Radiology
// ----------------------------------------------------------------
function ScanCard({ record }: { record: ClinicalRecord }) {
  const scan = record.payload?.scan || {}
  return (
    <div style={{
      background: record.urgent ? 'rgba(255,60,60,0.04)' : 'var(--bg-panel)',
      border: `1px solid ${record.urgent ? 'rgba(255,60,60,0.35)' : 'var(--border)'}`,
      borderRadius: '6px', padding: '16px 20px',
      animation: 'fadeIn 0.3s ease',
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)' }}>{record.patient_name}</span>
            {record.urgent && <span style={urgentBadge}>⚠ URGENT</span>}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
            {record.payload?.radiologist} · {new Date(record.recorded_at).toLocaleTimeString()}
          </div>
        </div>
        <div style={{ display: 'flex', gap: '6px' }}>
          <span style={pillStyle('#a78bfa')}>{scan.modality}</span>
          <span style={pillStyle('#a78bfa')}>{scan.body_part}</span>
        </div>
      </div>
      <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '8px', lineHeight: '1.5' }}>
        <span style={{ color: 'var(--text-muted)', fontSize: '10px', letterSpacing: '0.1em' }}>FINDINGS · </span>
        {record.payload?.findings}
      </div>
      <div style={{
        padding: '8px 12px',
        background: 'rgba(167,139,250,0.06)',
        border: '1px solid rgba(167,139,250,0.2)',
        borderRadius: '4px',
        fontSize: '12px',
        color: '#a78bfa',
      }}>
        <span style={{ fontSize: '10px', opacity: 0.7, letterSpacing: '0.1em' }}>IMPRESSION · </span>
        {record.payload?.impression}
      </div>
    </div>
  )
}

export function Radiology() {
  const { token, identity } = useAuth()
  const allowed = useDeptAccess('radiology')
  const ws = useWebSocket({ hospital_id: identity!.hospital_id, department: 'radiology', token: token! })
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <PageHeader title="RADIOLOGY" subtitle="SCAN RESULTS & IMAGING REPORTS" icon="◎" accent="#a78bfa" />
      {allowed ? <RecordFeed {...ws} renderRecord={r => <ScanCard record={r} />} /> : <AccessDenied dept="radiology" />}
    </div>
  )
}

// ----------------------------------------------------------------
// Neurology
// ----------------------------------------------------------------
function NeuroCard({ record }: { record: ClinicalRecord }) {
  const gcs = record.payload?.gcs || {}
  const severityColor = { SEVERE: 'var(--accent-red)', MODERATE: '#fb923c', MILD: '#34d399' }[record.payload?.severity as string] || 'var(--text-muted)'

  return (
    <div style={{
      background: 'var(--bg-panel)',
      border: '1px solid var(--border)',
      borderRadius: '6px', padding: '16px 20px',
      animation: 'fadeIn 0.3s ease',
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)' }}>{record.patient_name}</span>
            <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{record.patient_id}</span>
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
            {record.payload?.neurologist} · {new Date(record.recorded_at).toLocaleTimeString()}
          </div>
        </div>
        <span style={{ ...pillStyle(severityColor), fontFamily: 'var(--font-mono)' }}>
          {record.payload?.severity}
        </span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '8px', marginBottom: '10px' }}>
        <div style={dataCell}><span style={dataLabel}>GCS</span><span style={{ ...dataValue, color: gcs.total < 13 ? 'var(--accent-red)' : 'var(--accent-cyan)' }}>{gcs.total}/15</span></div>
        <div style={dataCell}><span style={dataLabel}>EYE</span><span style={dataValue}>{gcs.eye}/4</span></div>
        <div style={dataCell}><span style={dataLabel}>VERBAL</span><span style={dataValue}>{gcs.verbal}/5</span></div>
        <div style={dataCell}><span style={dataLabel}>MOTOR</span><span style={dataValue}>{gcs.motor}/6</span></div>
      </div>

      <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '6px' }}>
        <span style={{ color: 'var(--text-muted)', fontSize: '10px', letterSpacing: '0.1em' }}>NIHSS · </span>
        <span style={{ fontFamily: 'var(--font-mono)', color: '#fb923c' }}>{record.payload?.nihss_score}</span>
        <span style={{ marginLeft: '16px', color: 'var(--text-muted)', fontSize: '10px', letterSpacing: '0.1em' }}>PUPILS · </span>
        {record.payload?.pupils}
      </div>
      <div style={{
        padding: '8px 12px', background: 'rgba(251,146,60,0.06)',
        border: '1px solid rgba(251,146,60,0.2)', borderRadius: '4px',
        fontSize: '12px', color: '#fb923c',
      }}>
        {record.payload?.diagnosis}
      </div>
    </div>
  )
}

export function Neurology() {
  const { token, identity } = useAuth()
  const allowed = useDeptAccess('neurology')
  const ws = useWebSocket({ hospital_id: identity!.hospital_id, department: 'neurology', token: token! })
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <PageHeader title="NEUROLOGY" subtitle="NEUROLOGICAL ASSESSMENTS" icon="◈" accent="#fb923c" />
      {allowed ? <RecordFeed {...ws} renderRecord={r => <NeuroCard record={r} />} /> : <AccessDenied dept="neurology" />}
    </div>
  )
}

// ----------------------------------------------------------------
// Oncology
// ----------------------------------------------------------------
function OncologyCard({ record }: { record: ClinicalRecord }) {
  return (
    <div style={{
      background: 'var(--bg-panel)',
      border: '1px solid var(--border)',
      borderRadius: '6px', padding: '16px 20px',
      animation: 'fadeIn 0.3s ease',
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)' }}>{record.patient_name}</span>
            <span style={{ ...pillStyle('#34d399') }}>{record.payload?.stage}</span>
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
            {record.payload?.oncologist} · {new Date(record.recorded_at).toLocaleTimeString()}
          </div>
        </div>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)' }}>
          ECOG {record.payload?.ecog_status}
        </span>
      </div>

      <div style={{ fontSize: '13px', color: '#34d399', marginBottom: '6px', fontWeight: 500 }}>
        {record.payload?.diagnosis}
      </div>
      <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '10px' }}>
        <span style={{ color: 'var(--text-muted)', fontSize: '10px', letterSpacing: '0.1em' }}>PROTOCOL · </span>
        {record.payload?.protocol}
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
          {record.payload?.medications?.map((m: string) => (
            <span key={m} style={{
              padding: '2px 8px',
              background: 'rgba(52,211,153,0.08)',
              border: '1px solid rgba(52,211,153,0.2)',
              borderRadius: '3px',
              fontSize: '10px',
              color: '#34d399',
            }}>{m}</span>
          ))}
        </div>
        <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
          {record.payload?.cycle} · Review {record.payload?.next_review}
        </span>
      </div>
    </div>
  )
}

export function Oncology() {
  const { token, identity } = useAuth()
  const allowed = useDeptAccess('oncology')
  const ws = useWebSocket({ hospital_id: identity!.hospital_id, department: 'oncology', token: token! })
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <PageHeader title="ONCOLOGY" subtitle="TREATMENT PLANS & CYCLE TRACKING" icon="✦" accent="#34d399" />
      {allowed ? <RecordFeed {...ws} renderRecord={r => <OncologyCard record={r} />} /> : <AccessDenied dept="oncology" />}
    </div>
  )
}

// ----------------------------------------------------------------
// Admin — hospital-wide feed
// ----------------------------------------------------------------
function AdminCard({ record }: { record: ClinicalRecord }) {
  const deptColors: Record<string, string> = {
    icu: '#ec0e2f', cardiology: '#3d0cce',
    radiology: '#a78bfa', neurology: '#fb923c', oncology: '#34d399',
  }
  const color = deptColors[record.department] || 'var(--text-muted)'
  return (
    <div style={{
      background: 'var(--bg-panel)',
      border: `1px solid var(--border)`,
      borderLeft: `3px solid ${color}`,
      borderRadius: '6px', padding: '12px 20px',
      display: 'flex', alignItems: 'center', gap: '16px',
      animation: 'fadeIn 0.3s ease',
    }}>
      <span style={{ ...pillStyle(color), minWidth: '90px', textAlign: 'center', fontSize: '10px' }}>
        {record.department.toUpperCase()}
      </span>
      <span style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '13px', minWidth: '140px' }}>
        {record.patient_name}
      </span>
      <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)', flex: 1 }}>
        {record.message_type}
      </span>
      {record.urgent && <span style={urgentBadge}>⚠ URGENT</span>}
      <span style={{ fontSize: '11px', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
        {new Date(record.recorded_at).toLocaleTimeString()}
      </span>
    </div>
  )
}

export function Admin() {
  const { token, identity } = useAuth()
  const role = (identity as any)?.role || ''
  const allowed = role === 'admin'
  const { records, connected, error } = useWebSocket({
    hospital_id: identity!.hospital_id,
    token: token!,
  })
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <PageHeader title="ADMIN" subtitle="CROSS-DEPARTMENT HOSPITAL OVERVIEW" icon="⊞" accent="var(--text-secondary)" />
      {allowed
        ? <RecordFeed records={records} connected={connected} error={error} renderRecord={r => <AdminCard record={r} />} />
        : <AccessDenied dept="admin" />
      }
    </div>
  )
}

// ----------------------------------------------------------------
// Shared style helpers
// ----------------------------------------------------------------
const urgentBadge: React.CSSProperties = {
  padding: '2px 8px',
  background: 'rgba(255,60,60,0.15)',
  border: '1px solid rgba(255,60,60,0.4)',
  borderRadius: '3px',
  fontSize: '10px',
  color: 'var(--accent-red)',
  letterSpacing: '0.1em',
}

function pillStyle(color: string): React.CSSProperties {
  return {
    padding: '2px 10px',
    background: `${color}18`,
    border: `1px solid ${color}44`,
    borderRadius: '3px',
    fontSize: '11px',
    color,
    letterSpacing: '0.06em',
    fontFamily: 'var(--font-mono)',
  }
}

const dataCell: React.CSSProperties = {
  display: 'flex', flexDirection: 'column', alignItems: 'center',
  padding: '6px 10px',
  background: 'rgba(0,255,200,0.03)',
  border: '1px solid rgba(0,255,200,0.1)',
  borderRadius: '4px',
}

const dataLabel: React.CSSProperties = {
  fontSize: '9px',
  color: 'var(--text-muted)',
  letterSpacing: '0.12em',
  marginBottom: '3px',
}

const dataValue: React.CSSProperties = {
  fontFamily: 'var(--font-mono)',
  fontSize: '13px',
  fontWeight: 600,
  color: 'var(--text-primary)',
}
