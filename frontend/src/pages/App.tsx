import React from 'react';

const panel = {
  border: '1px solid #d1d5db',
  borderRadius: 8,
  padding: 16,
  marginBottom: 12,
};

export function App() {
  return (
    <main style={{ fontFamily: 'Inter, sans-serif', padding: 24, maxWidth: 900, margin: '0 auto' }}>
      <h1>MedLock Mesh</h1>
      <p>Zero-Trust Multi-Tenant Clinical Messaging</p>

      <section style={panel}>
        <h2>🔐 Login</h2>
        <p>Hospital ID • Staff ID • Password / Device certificate</p>
      </section>

      <section style={panel}>
        <h2>🏥 Hospital Dashboard</h2>
        <ul>
          <li>Create Departments</li>
          <li>Register Staff Devices</li>
          <li>Assign Roles</li>
        </ul>
      </section>

      <section style={panel}>
        <h2>💬 Secure Messaging</h2>
        <p>Encrypted channel indicator: <strong>ON</strong></p>
        <p>Sender verification badge: ✅ Verified</p>
        <p>Replay protection: active sequence validation</p>
      </section>

      <section style={panel}>
        <h2>🧾 Audit Panel</h2>
        <p>Metadata-only timeline (no plaintext payloads)</p>
      </section>
    </main>
  );
}
