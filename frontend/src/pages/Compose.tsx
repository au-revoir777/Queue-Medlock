import { useState, useEffect, FormEvent } from 'react'
import { useAuth } from '../context/AuthContext'
import { getMyPermissions, getPatients, sendMessage } from '../api'
import PageHeader from '../components/PageHeader'

interface Patient { id: string; name: string; age?: number; blood_type?: string }
interface Permissions {
  can_send: boolean
  role: string
  department: string
  message_types: string[]
}

// Structured field definitions per message type
const MESSAGE_FIELDS: Record<string, { label: string; key: string; type: string; options?: string[] }[]> = {
  ICU_VITALS: [
    { label: 'Heart Rate (bpm)',     key: 'heart_rate',       type: 'number' },
    { label: 'Blood Pressure',       key: 'blood_pressure',   type: 'text' },
    { label: 'SpO₂ (%)',             key: 'spo2_percent',     type: 'number' },
    { label: 'Temperature (°C)',     key: 'temperature_c',    type: 'number' },
    { label: 'Respiratory Rate',     key: 'respiratory_rate', type: 'number' },
    { label: 'GCS (3–15)',           key: 'gcs',              type: 'number' },
  ],
  PATIENT_OBSERVATION: [
    { label: 'Observation Notes',    key: 'notes',            type: 'textarea' },
    { label: 'Level of Consciousness', key: 'consciousness',  type: 'select', options: ['Alert', 'Verbal', 'Pain', 'Unresponsive'] },
  ],
  CODE_ALERT: [
    { label: 'Code Type',            key: 'code_type',        type: 'select', options: ['Code Blue', 'Code Red', 'Rapid Response'] },
    { label: 'Location',             key: 'location',         type: 'text' },
    { label: 'Details',              key: 'details',          type: 'textarea' },
  ],
  ECG_REPORT: [
    { label: 'Heart Rate (bpm)',     key: 'heart_rate',       type: 'number' },
    { label: 'Rhythm',               key: 'rhythm',           type: 'select', options: ['Normal sinus rhythm', 'Sinus tachycardia', 'Sinus bradycardia', 'Atrial fibrillation', 'First-degree AV block', 'Other'] },
    { label: 'ST Changes',           key: 'st_changes',       type: 'select', options: ['None', 'Elevation', 'Depression'] },
    { label: 'QRS Duration (ms)',    key: 'qrs_duration_ms',  type: 'number' },
    { label: 'Interpretation',       key: 'interpretation',   type: 'textarea' },
  ],
  CARDIOLOGY_CONSULT: [
    { label: 'Reason for Consult',   key: 'reason',           type: 'textarea' },
    { label: 'Priority',             key: 'priority',         type: 'select', options: ['Routine', 'Urgent', 'Emergency'] },
    { label: 'Current Medications',  key: 'medications',      type: 'textarea' },
  ],
  RADIOLOGY_REPORT: [
    { label: 'Modality',             key: 'modality',         type: 'select', options: ['CT', 'MRI', 'X-Ray', 'Ultrasound', 'PET-CT'] },
    { label: 'Body Part',            key: 'body_part',        type: 'select', options: ['Chest', 'Abdomen', 'Brain', 'Spine', 'Pelvis', 'Neck', 'Extremity'] },
    { label: 'Findings',             key: 'findings',         type: 'textarea' },
    { label: 'Impression',           key: 'impression',       type: 'textarea' },
  ],
  IMAGING_REQUEST: [
    { label: 'Modality Requested',   key: 'modality',         type: 'select', options: ['CT', 'MRI', 'X-Ray', 'Ultrasound'] },
    { label: 'Body Part',            key: 'body_part',        type: 'select', options: ['Chest', 'Abdomen', 'Brain', 'Spine', 'Pelvis', 'Neck'] },
    { label: 'Clinical Indication',  key: 'indication',       type: 'textarea' },
    { label: 'Priority',             key: 'priority',         type: 'select', options: ['Routine', 'Urgent', 'Emergency'] },
  ],
  NEURO_ASSESSMENT: [
    { label: 'GCS Total (3–15)',     key: 'gcs_total',        type: 'number' },
    { label: 'Pupils',               key: 'pupils',           type: 'select', options: ['Equal and reactive', 'Unequal', 'Non-reactive', 'Pinpoint'] },
    { label: 'Motor Exam',           key: 'motor_exam',       type: 'select', options: ['No focal deficit', 'Left arm weakness', 'Right arm weakness', 'Left leg weakness', 'Right leg weakness'] },
    { label: 'NIHSS Score (0–42)',   key: 'nihss_score',      type: 'number' },
    { label: 'Diagnosis',            key: 'diagnosis',        type: 'textarea' },
  ],
  STROKE_ALERT: [
    { label: 'Onset Time',           key: 'onset_time',       type: 'text' },
    { label: 'FAST Score',           key: 'fast_score',       type: 'select', options: ['Positive — activate stroke pathway', 'Negative — monitor', 'Uncertain'] },
    { label: 'Last Known Well',      key: 'last_known_well',  type: 'text' },
    { label: 'Clinical Notes',       key: 'notes',            type: 'textarea' },
  ],
  ONCOLOGY_TREATMENT_PLAN: [
    { label: 'Diagnosis',            key: 'diagnosis',        type: 'text' },
    { label: 'Stage',                key: 'stage',            type: 'select', options: ['Stage I', 'Stage II', 'Stage III', 'Stage IV', 'Newly diagnosed', 'Relapsed'] },
    { label: 'Protocol',             key: 'protocol',         type: 'text' },
    { label: 'Cycle',                key: 'cycle',            type: 'text' },
    { label: 'Notes',                key: 'notes',            type: 'textarea' },
  ],
  CHEMO_NOTE: [
    { label: 'Agent(s)',             key: 'agents',           type: 'text' },
    { label: 'Dose',                 key: 'dose',             type: 'text' },
    { label: 'Adverse Effects',      key: 'adverse_effects',  type: 'textarea' },
    { label: 'Response Assessment',  key: 'response',         type: 'select', options: ['Complete response', 'Partial response', 'Stable disease', 'Progressive disease'] },
  ],
}

const MSG_TYPE_LABELS: Record<string, string> = {
  ICU_VITALS:             'ICU Vitals Update',
  PATIENT_OBSERVATION:    'Patient Observation',
  CODE_ALERT:             'Code Alert',
  ECG_REPORT:             'ECG Report',
  CARDIOLOGY_CONSULT:     'Cardiology Consult Request',
  RADIOLOGY_REPORT:       'Radiology Report',
  IMAGING_REQUEST:        'Imaging Request',
  NEURO_ASSESSMENT:       'Neurological Assessment',
  STROKE_ALERT:           'Stroke Alert',
  ONCOLOGY_TREATMENT_PLAN:'Oncology Treatment Plan',
  CHEMO_NOTE:             'Chemotherapy Note',
}

export default function Compose() {
  const { token, identity } = useAuth()

  const [permissions, setPermissions] = useState<Permissions | null>(null)
  const [patients, setPatients]       = useState<Patient[]>([])
  const [selectedType, setSelectedType] = useState('')
  const [selectedPatient, setSelectedPatient] = useState('')
  const [fieldValues, setFieldValues] = useState<Record<string, string>>({})
  const [urgent, setUrgent]           = useState(false)
  const [loading, setLoading]         = useState(false)
  const [result, setResult]           = useState<{ success: boolean; data: any } | null>(null)
  const [error, setError]             = useState('')

  useEffect(() => {
    if (!token) return
    getMyPermissions(token).then(setPermissions).catch(console.error)
    getPatients(token).then(d => setPatients(d.patients)).catch(console.error)
  }, [token])

  useEffect(() => {
    setFieldValues({})
    setResult(null)
    setError('')
  }, [selectedType])

  const fields = selectedType ? (MESSAGE_FIELDS[selectedType] || []) : []
  const patient = patients.find(p => p.id === selectedPatient)

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (!token || !permissions || !selectedPatient || !selectedType) return
    setLoading(true)
    setError('')
    setResult(null)
    try {
      const data = await sendMessage(token, {
        department:   permissions.department,
        patient_id:   selectedPatient,
        patient_name: patient?.name || selectedPatient,
        message_type: selectedType,
        payload:      fieldValues,
        urgent,
      })
      setResult({ success: true, data })
      setFieldValues({})
      setSelectedPatient('')
      setUrgent(false)
    } catch (err: any) {
      setError(err.message || 'Send failed')
      setResult({ success: false, data: { detail: err.message } })
    } finally {
      setLoading(false)
    }
  }

  // ── Not permitted to send ──
  if (permissions && !permissions.can_send) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
        <PageHeader title="COMPOSE" subtitle="CLINICAL MESSAGE AUTHORING" icon="✉" accent="var(--accent-cyan)" />
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: '20px', padding: '40px' }}>
          <div style={{
            padding: '32px 40px',
            background: 'rgba(255,60,60,0.04)',
            border: '1px solid rgba(255,60,60,0.2)',
            borderRadius: '8px',
            textAlign: 'center',
            maxWidth: '480px',
          }}>
            <div style={{ fontSize: '32px', marginBottom: '16px' }}>🔒</div>
            <div style={{ fontFamily: 'var(--font-display)', fontSize: '16px', color: 'var(--accent-red)', letterSpacing: '0.05em', marginBottom: '8px' }}>
              ACCESS DENIED
            </div>
            <div style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: '1.6' }}>
              Your role <strong style={{ color: 'var(--text-primary)' }}>{permissions.role}</strong> does not have permission to send clinical messages.
            </div>
            <div style={{ marginTop: '16px', padding: '10px 14px', background: 'rgba(255,255,255,0.03)', border: '1px solid var(--border)', borderRadius: '4px', fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '0.08em' }}>
              ZERO TRUST ENFORCEMENT ACTIVE · LEAST PRIVILEGE APPLIED
            </div>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <PageHeader title="COMPOSE" subtitle="CLINICAL MESSAGE AUTHORING — ROLE-CONTROLLED" icon="✉" accent="var(--accent-cyan)" />

      <div style={{ flex: 1, overflowY: 'auto', padding: '32px', display: 'flex', gap: '32px', alignItems: 'flex-start' }}>

        {/* Form */}
        <div style={{ flex: 1, maxWidth: '640px' }}>
          {/* Role badge */}
          <div style={{ display: 'flex', gap: '10px', marginBottom: '28px', flexWrap: 'wrap' }}>
            {[
              { label: 'ROLE',       value: permissions?.role || '...' },
              { label: 'DEPARTMENT', value: permissions?.department || '...' },
              { label: 'HOSPITAL',   value: identity?.hospital_id || '...' },
            ].map(b => (
              <div key={b.label} style={{
                padding: '6px 14px',
                background: 'rgba(0,255,200,0.06)',
                border: '1px solid rgba(0,255,200,0.2)',
                borderRadius: '4px',
                fontSize: '11px',
                color: 'var(--accent-cyan)',
                letterSpacing: '0.08em',
              }}>
                <span style={{ color: 'var(--text-muted)', marginRight: '6px' }}>{b.label}</span>
                {b.value.toUpperCase()}
              </div>
            ))}
          </div>

          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>

            {/* Message type */}
            <div>
              <label style={labelStyle}>MESSAGE TYPE</label>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: '8px', marginTop: '10px' }}>
                {(permissions?.message_types || []).map(t => (
                  <button
                    key={t}
                    type="button"
                    onClick={() => setSelectedType(t)}
                    style={{
                      padding: '10px 14px',
                      background: selectedType === t ? 'rgba(0,255,200,0.1)' : 'var(--bg-deep)',
                      border: `1px solid ${selectedType === t ? 'var(--accent-cyan)' : 'var(--border)'}`,
                      borderRadius: '4px',
                      color: selectedType === t ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                      fontSize: '12px',
                      cursor: 'pointer',
                      textAlign: 'left',
                      transition: 'all 0.15s',
                      fontFamily: 'var(--font-body)',
                    }}
                  >
                    {MSG_TYPE_LABELS[t] || t}
                  </button>
                ))}
              </div>
            </div>

            {selectedType && (
              <>
                {/* Patient */}
                <div>
                  <label style={labelStyle}>PATIENT</label>
                  <select
                    value={selectedPatient}
                    onChange={e => setSelectedPatient(e.target.value)}
                    required
                    style={inputStyle}
                  >
                    <option value="">Select patient...</option>
                    {patients.map(p => (
                      <option key={p.id} value={p.id}>
                        {p.name} — {p.id} {p.blood_type ? `(${p.blood_type})` : ''}
                      </option>
                    ))}
                  </select>
                </div>

                {/* Dynamic fields */}
                {fields.map(f => (
                  <div key={f.key}>
                    <label style={labelStyle}>{f.label}</label>
                    {f.type === 'select' ? (
                      <select
                        value={fieldValues[f.key] || ''}
                        onChange={e => setFieldValues(v => ({ ...v, [f.key]: e.target.value }))}
                        style={inputStyle}
                      >
                        <option value="">Select...</option>
                        {f.options?.map(o => <option key={o} value={o}>{o}</option>)}
                      </select>
                    ) : f.type === 'textarea' ? (
                      <textarea
                        value={fieldValues[f.key] || ''}
                        onChange={e => setFieldValues(v => ({ ...v, [f.key]: e.target.value }))}
                        rows={3}
                        style={{ ...inputStyle, resize: 'vertical', minHeight: '72px' }}
                      />
                    ) : (
                      <input
                        type={f.type}
                        value={fieldValues[f.key] || ''}
                        onChange={e => setFieldValues(v => ({ ...v, [f.key]: e.target.value }))}
                        style={inputStyle}
                      />
                    )}
                  </div>
                ))}

                {/* Urgent */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <button
                    type="button"
                    onClick={() => setUrgent(u => !u)}
                    style={{
                      width: '20px', height: '20px',
                      background: urgent ? 'var(--accent-red)' : 'transparent',
                      border: `2px solid ${urgent ? 'var(--accent-red)' : 'var(--border)'}`,
                      borderRadius: '3px',
                      cursor: 'pointer',
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      color: 'white', fontSize: '12px',
                      flexShrink: 0,
                    }}
                  >
                    {urgent ? '✓' : ''}
                  </button>
                  <span style={{ fontSize: '13px', color: urgent ? 'var(--accent-red)' : 'var(--text-secondary)' }}>
                    Mark as URGENT — will trigger priority alert in feed
                  </span>
                </div>

                {/* Error */}
                {error && (
                  <div style={{
                    padding: '12px 16px',
                    background: 'rgba(255,60,60,0.06)',
                    border: '1px solid rgba(255,60,60,0.3)',
                    borderRadius: '4px',
                    fontSize: '12px',
                    color: 'var(--accent-red)',
                    lineHeight: '1.5',
                  }}>
                    <div style={{ fontWeight: 600, letterSpacing: '0.08em', marginBottom: '4px' }}>BLOCKED BY ZERO TRUST</div>
                    {error}
                  </div>
                )}

                {/* Submit */}
                <button
                  type="submit"
                  disabled={loading || !selectedPatient}
                  style={{
                    padding: '13px',
                    background: loading ? 'rgba(0,255,200,0.05)' : 'rgba(0,255,200,0.12)',
                    border: '1px solid var(--accent-cyan)',
                    borderRadius: '4px',
                    color: 'var(--accent-cyan)',
                    fontSize: '13px',
                    fontWeight: 600,
                    letterSpacing: '0.12em',
                    cursor: loading || !selectedPatient ? 'not-allowed' : 'pointer',
                    fontFamily: 'var(--font-display)',
                    transition: 'all 0.15s',
                    opacity: !selectedPatient ? 0.5 : 1,
                  }}
                >
                  {loading ? 'SENDING...' : `SEND ${MSG_TYPE_LABELS[selectedType] || selectedType}`}
                </button>
              </>
            )}
          </form>
        </div>

        {/* Result / proof panel */}
        <div style={{ width: '320px', flexShrink: 0 }}>
          {result?.success && (
            <div style={{
              background: 'rgba(0,255,200,0.04)',
              border: '1px solid rgba(0,255,200,0.2)',
              borderRadius: '8px',
              padding: '20px',
              animation: 'fadeIn 0.3s ease',
            }}>
              <div style={{ fontFamily: 'var(--font-display)', fontSize: '13px', color: 'var(--accent-cyan)', letterSpacing: '0.08em', marginBottom: '16px' }}>
                ✓ MESSAGE SENT
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {[
                  { label: 'RECORD ID',   value: `#${result.data.record_id}` },
                  { label: 'SEQUENCE',    value: result.data.sequence },
                  { label: 'URGENT',      value: result.data.urgent ? 'YES' : 'NO' },
                  { label: 'PAYLOAD HASH', value: result.data.payload_hash?.slice(0, 16) + '...' },
                ].map(r => (
                  <div key={r.label} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px' }}>
                    <span style={{ color: 'var(--text-muted)', letterSpacing: '0.08em' }}>{r.label}</span>
                    <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>{r.value}</span>
                  </div>
                ))}
              </div>
              <div style={{ marginTop: '16px', borderTop: '1px solid var(--border)', paddingTop: '14px' }}>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', letterSpacing: '0.1em', marginBottom: '8px' }}>ZERO TRUST CHECKS PASSED</div>
                {Object.entries(result.data.zero_trust || {}).map(([k, v]) => (
                  <div key={k} style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '11px', marginBottom: '4px' }}>
                    <span style={{ color: 'var(--accent-cyan)', fontSize: '10px' }}>✓</span>
                    <span style={{ color: 'var(--text-secondary)' }}>{k.replace(/_/g, ' ')}</span>
                    <span style={{ marginLeft: 'auto', color: 'var(--accent-cyan)', fontFamily: 'var(--font-mono)', fontSize: '10px' }}>{String(v).toUpperCase()}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {result && !result.success && (
            <div style={{
              background: 'rgba(255,60,60,0.04)',
              border: '1px solid rgba(255,60,60,0.2)',
              borderRadius: '8px',
              padding: '20px',
              animation: 'fadeIn 0.3s ease',
            }}>
              <div style={{ fontFamily: 'var(--font-display)', fontSize: '13px', color: 'var(--accent-red)', letterSpacing: '0.08em', marginBottom: '12px' }}>
                ✗ BLOCKED
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: '1.6' }}>
                {result.data?.detail}
              </div>
              <div style={{ marginTop: '14px', fontSize: '10px', color: 'var(--text-muted)', letterSpacing: '0.08em' }}>
                ZERO TRUST ENFORCEMENT · ACCESS DENIED
              </div>
            </div>
          )}

          {!result && (
            <div style={{
              background: 'var(--bg-panel)',
              border: '1px solid var(--border)',
              borderRadius: '8px',
              padding: '20px',
            }}>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '0.1em', marginBottom: '14px' }}>
                ZERO TRUST ENFORCEMENT
              </div>
              {[
                { check: 'Department isolation', desc: 'You can only send to your assigned department' },
                { check: 'Role-based access',    desc: 'Only permitted message types shown' },
                { check: 'KMS identity check',   desc: 'Sender verified against key registry' },
                { check: 'Audit logging',         desc: 'Every send recorded with metadata hash' },
              ].map(c => (
                <div key={c.check} style={{ marginBottom: '12px' }}>
                  <div style={{ fontSize: '12px', color: 'var(--text-primary)', fontWeight: 500 }}>{c.check}</div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>{c.desc}</div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

const labelStyle: React.CSSProperties = {
  fontSize: '10px', color: 'var(--text-muted)', letterSpacing: '0.15em', fontWeight: 600,
}

const inputStyle: React.CSSProperties = {
  width: '100%', marginTop: '8px', padding: '11px 14px',
  background: 'var(--bg-deep)', border: '1px solid var(--border)',
  borderRadius: '4px', color: 'var(--text-primary)', fontSize: '13px',
  fontFamily: 'var(--font-body)', outline: 'none', boxSizing: 'border-box',
  transition: 'border-color 0.15s',
}
