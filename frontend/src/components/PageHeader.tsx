interface Props {
  title: string
  subtitle: string
  icon: string
  accent?: string
}

export default function PageHeader({ title, subtitle, icon, accent = 'var(--accent-cyan)' }: Props) {
  return (
    <div style={{
      padding: '28px 32px 24px',
      borderBottom: '1px solid var(--border)',
      background: 'var(--bg-panel)',
      display: 'flex',
      alignItems: 'center',
      gap: '20px',
    }}>
      <div style={{
        width: '48px', height: '48px',
        background: `${accent}11`,
        border: `1px solid ${accent}44`,
        borderRadius: '8px',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        fontSize: '24px',
        flexShrink: 0,
      }}>
        {icon}
      </div>
      <div>
        <h1 style={{
          margin: 0,
          fontFamily: 'var(--font-display)',
          fontSize: '22px',
          fontWeight: 700,
          color: accent,
          letterSpacing: '0.05em',
        }}>
          {title}
        </h1>
        <p style={{
          margin: '2px 0 0',
          fontSize: '12px',
          color: 'var(--text-muted)',
          letterSpacing: '0.08em',
        }}>
          {subtitle}
        </p>
      </div>
    </div>
  )
}
