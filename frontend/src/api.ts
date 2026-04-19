const CLINICAL_URL = import.meta.env.VITE_CLINICAL_URL || 'http://localhost:8003'
const AUTH_URL     = import.meta.env.VITE_AUTH_URL     || 'http://localhost:8000'

export async function apiLogin(hospital_id: string, staff_id: string, password: string) {
  const resp = await fetch(`${AUTH_URL}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ hospital_id, staff_id, password }),
  })
  if (!resp.ok) throw new Error('Invalid credentials')
  return resp.json()
}

export async function apiValidate(token: string) {
  const resp = await fetch(`${AUTH_URL}/validate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token }),
  })
  if (!resp.ok) throw new Error('Token invalid')
  return resp.json()
}

export async function getMyPermissions(token: string) {
  const resp = await fetch(`${CLINICAL_URL}/me/permissions`, {
    headers: { Authorization: `Bearer ${token}` },
  })
  if (!resp.ok) throw new Error('Failed to fetch permissions')
  return resp.json()
}

export async function getRecords(token: string, hospital_id: string, department: string, limit = 50) {
  const resp = await fetch(
    `${CLINICAL_URL}/records/${hospital_id}/${department}?limit=${limit}`,
    { headers: { Authorization: `Bearer ${token}` } }
  )
  if (!resp.ok) throw new Error('Failed to fetch records')
  return resp.json()
}

export async function getHospitalRecords(token: string, hospital_id: string, limit = 100) {
  const resp = await fetch(
    `${CLINICAL_URL}/records/${hospital_id}?limit=${limit}`,
    { headers: { Authorization: `Bearer ${token}` } }
  )
  if (!resp.ok) throw new Error('Failed to fetch records')
  return resp.json()
}

export async function getPatients(token: string) {
  const resp = await fetch(`${CLINICAL_URL}/patients`, {
    headers: { Authorization: `Bearer ${token}` },
  })
  if (!resp.ok) throw new Error('Failed to fetch patients')
  return resp.json()
}

export async function getAuditLog(token: string, hospital_id: string, limit = 100) {
  const resp = await fetch(`${CLINICAL_URL}/audit/${hospital_id}?limit=${limit}`, {
    headers: { Authorization: `Bearer ${token}` },
  })
  if (!resp.ok) throw new Error('Failed to fetch audit log')
  return resp.json()
}

export interface SendPayload {
  department:   string
  patient_id:   string
  patient_name: string
  message_type: string
  payload:      Record<string, unknown>
  urgent:       boolean
}

export async function sendMessage(token: string, data: SendPayload) {
  const resp = await fetch(`${CLINICAL_URL}/messages/send`, {
    method:  'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body:    JSON.stringify(data),
  })
  const json = await resp.json()
  if (!resp.ok) throw new Error(json.detail || 'Send failed')
  return json
}

export function createWebSocket(hospital_id: string, department: string, token: string): WebSocket {
  const wsBase = CLINICAL_URL.replace('http', 'ws')
  return new WebSocket(`${wsBase}/ws/${hospital_id}/${department}?token=${token}`)
}

export function createHospitalWebSocket(hospital_id: string, token: string): WebSocket {
  const wsBase = CLINICAL_URL.replace('http', 'ws')
  return new WebSocket(`${wsBase}/ws/${hospital_id}?token=${token}`)
}
