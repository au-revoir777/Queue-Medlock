import { useEffect, useRef, useState, useCallback } from 'react'
import { createWebSocket, createHospitalWebSocket } from '../api'

export interface ClinicalRecord {
  id: number
  hospital_id: string
  department: string
  patient_id: string
  patient_name: string
  producer_id: string
  message_type: string
  sequence: number
  urgent: boolean
  recorded_at: string
  payload: Record<string, any>
}

interface UseWebSocketOptions {
  hospital_id: string
  department?: string   // omit for hospital-wide feed
  token: string
  maxRecords?: number
}

export function useWebSocket({
  hospital_id,
  department,
  token,
  maxRecords = 100,
}: UseWebSocketOptions) {
  const [records, setRecords]     = useState<ClinicalRecord[]>([])
  const [connected, setConnected] = useState(false)
  const [error, setError]         = useState<string | null>(null)
  const wsRef                     = useRef<WebSocket | null>(null)

  const connect = useCallback(() => {
    if (wsRef.current) wsRef.current.close()

    const ws = department
      ? createWebSocket(hospital_id, department, token)
      : createHospitalWebSocket(hospital_id, token)

    wsRef.current = ws

    ws.onopen = () => {
      setConnected(true)
      setError(null)
    }

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data)
        if (msg.type === 'snapshot') {
          setRecords(msg.records.slice(-maxRecords).reverse())
        } else if (msg.type === 'record') {
          setRecords(prev => {
            const next = [msg.data, ...prev]
            return next.slice(0, maxRecords)
          })
        } else if (msg.type === 'error') {
          setError(msg.detail)
        }
      } catch {
        // ignore parse errors
      }
    }

    ws.onclose = () => setConnected(false)
    ws.onerror = () => {
      setConnected(false)
      setError('WebSocket connection failed')
    }
  }, [hospital_id, department, token, maxRecords])

  useEffect(() => {
    connect()
    return () => wsRef.current?.close()
  }, [connect])

  return { records, connected, error }
}
