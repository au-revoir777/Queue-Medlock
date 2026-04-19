import { useState, FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { apiLogin, apiValidate } from '../api'

const HOSPITALS = ['hospital1', 'hospital2']

export default function Login() {
  const { login }  = useAuth()
  const navigate   = useNavigate()
  const [hospital, setHospital] = useState('hospital1')
  const [staffId, setStaffId]   = useState('')
  const [password, setPassword] = useState('')
  const [error, setError]       = useState('')
  const [loading, setLoading]   = useState(false)

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const { access_token } = await apiLogin(hospital, staffId, password)
      const identity         = await apiValidate(access_token)
      login(access_token, {
        hospital_id: identity.hospital_id,
        staff_id:    identity.staff_id,
        department:  identity.department,
        role:        identity.role || 'doctor',
      })
      navigate('/')
    } catch {
      setError('Invalid credentials. Check hospital, staff ID and password.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{
      minHeight: '100vh', background: 'var(--bg-deep)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      fontFamily: 'var(--font-body)', position: 'relative', overflow: 'hidden',
    }}>
      {/* Background grid */}
      <div style={{
        position: 'absolute', inset: 0, opacity: 0.04,
        backgroundImage: 'linear-gradient(var(--accent-cyan) 1px, transparent 1px), linear-gradient(90deg, var(--accent-cyan) 1px, transparent 1px)',
        backgroundSize: '40px 40px',
      }} />
      {/* Glow */}
      <div style={{
        position: 'absolute', top: '30%', left: '50%', transform: 'translate(-50%,-50%)',
        width: '600px', height: '400px',
        background: 'radial-gradient(ellipse, rgba(0,255,200,0.06) 0%, transparent 70%)',
        pointerEvents: 'none',
      }} />

      <div style={{ position: 'relative', width: '100%', maxWidth: '420px', padding: '0 24px' }}>
        {/* Header */}
        <div style={{ textAlign: 'center', marginBottom: '40px' }}>
          <div style={{ fontFamily: 'var(--font-display)', fontSize: '32px', color: 'var(--accent-cyan)', letterSpacing: '0.1em', fontWeight: 700 }}>
            MEDLOCK
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '0.2em', marginTop: '4px' }}>
            ZERO TRUST CLINICAL PLATFORM
          </div>
        </div>

        <div style={{ background: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: '8px', padding: '32px' }}>
          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>

            {/* Hospital */}
            <div>
              <label style={labelStyle}>HOSPITAL</label>
              <div style={{ display: 'flex', gap: '8px', marginTop: '8px' }}>
                {HOSPITALS.map(h => (
                  <button key={h} type="button" onClick={() => setHospital(h)} style={{
                    flex: 1, padding: '10px',
                    background: hospital === h ? 'rgba(0,255,200,0.1)' : 'transparent',
                    border: `1px solid ${hospital === h ? 'var(--accent-cyan)' : 'var(--border)'}`,
                    borderRadius: '4px',
                    color: hospital === h ? 'var(--accent-cyan)' : 'var(--text-muted)',
                    fontSize: '12px', cursor: 'pointer', letterSpacing: '0.05em', transition: 'all 0.15s',
                  }}>{h}</button>
                ))}
              </div>
            </div>

            {/* Staff ID */}
            <div>
              <label style={labelStyle}>STAFF ID</label>
              <input type="text" value={staffId} onChange={e => setStaffId(e.target.value)}
                placeholder="e.g. dr_ahmed" required style={inputStyle} />
            </div>

            {/* Password */}
            <div>
              <label style={labelStyle}>PASSWORD</label>
              <input type="password" value={password} onChange={e => setPassword(e.target.value)}
                placeholder="••••••••" required style={inputStyle} />
            </div>

            {error && (
              <div style={{
                padding: '10px 14px', background: 'rgba(255,60,60,0.08)',
                border: '1px solid rgba(255,60,60,0.3)', borderRadius: '4px',
                color: 'var(--accent-red)', fontSize: '12px',
              }}>{error}</div>
            )}

            <button type="submit" disabled={loading} style={{
              padding: '13px',
              background: loading ? 'rgba(0,255,200,0.05)' : 'rgba(0,255,200,0.12)',
              border: '1px solid var(--accent-cyan)', borderRadius: '4px',
              color: 'var(--accent-cyan)', fontSize: '13px', fontWeight: 600,
              letterSpacing: '0.12em', cursor: loading ? 'not-allowed' : 'pointer',
              transition: 'all 0.15s', fontFamily: 'var(--font-display)',
            }}>
              {loading ? 'AUTHENTICATING...' : 'AUTHENTICATE'}
            </button>
          </form>

          {/* Demo hint */}
          <div style={{
            marginTop: '24px', padding: '12px',
            background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border)',
            borderRadius: '4px', fontSize: '11px', color: 'var(--text-muted)', lineHeight: '1.7',
          }}>
            <div style={{ color: 'var(--text-secondary)', marginBottom: '4px', letterSpacing: '0.08em' }}>DEMO ACCOUNTS</div>
            hospital1: dr_ahmed · nurse_priya · dr_chen · dr_patel · dr_okonkwo<br />
            hospital2: dr_hassan · nurse_sara · admin_lee · dr_reyes · dr_dube<br />
            <span style={{ color: 'var(--accent-cyan)', opacity: 0.7 }}>password: pass123</span>
          </div>
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
  fontFamily: 'var(--font-mono)', outline: 'none', boxSizing: 'border-box',
  transition: 'border-color 0.15s',
}
