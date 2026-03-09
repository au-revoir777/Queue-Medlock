import { ClinicalRecord } from '../hooks/useWebSocket'

interface Props {
  records: ClinicalRecord[]
  connected: boolean
  error: string | null
  renderRecord: (record: ClinicalRecord) => React.ReactNode
  emptyMessage?: string
}

export default function RecordFeed({ records, connected, error, renderRecord, emptyMessage }: Props) {
  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '0' }}>
      {/* Connection status bar */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        padding: '8px 32px',
        background: 'var(--bg-panel)',
        borderBottom: '1px solid var(--border)',
        fontSize: '11px',
        color: 'var(--text-muted)',
        letterSpacing: '0.08em',
      }}>
        <span style={{
          width: '6px', height: '6px', borderRadius: '50%',
          background: connected ? 'var(--accent-cyan)' : 'var(--accent-red)',
          boxShadow: connected ? '0 0 6px var(--accent-cyan)' : 'none',
          display: 'inline-block',
          animation: connected ? 'pulse 2s infinite' : 'none',
        }} />
        {connected ? 'LIVE — REAL-TIME STREAM ACTIVE' : 'CONNECTING...'}
        {error && <span style={{ color: 'var(--accent-red)', marginLeft: '8px' }}>{error}</span>}
        <span style={{ marginLeft: 'auto' }}>{records.length} RECORDS LOADED</span>
      </div>

      {/* Records */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '24px 32px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
        {records.length === 0 ? (
          <div style={{
            flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center',
            color: 'var(--text-muted)', fontSize: '13px', letterSpacing: '0.1em',
          }}>
            {emptyMessage || 'AWAITING DATA STREAM...'}
          </div>
        ) : (
          records.map(record => (
            <div key={`${record.id}-${record.sequence}`}>
              {renderRecord(record)}
            </div>
          ))
        )}
      </div>
    </div>
  )
}
