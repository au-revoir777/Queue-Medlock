const express = require('express');
const https   = require('https');
const fs      = require('fs');
const Redis   = require('ioredis');
const client  = require('prom-client');
const mtls    = require('./mtlsClient');

const app = express();
app.use(express.json());

const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');
const AUTH_VALIDATE_URL = process.env.AUTH_VALIDATE_URL || 'https://localhost:8001/validate';

// -----------------------------
// Prometheus Metrics
// -----------------------------
client.collectDefaultMetrics();

const enqueueCounter = new client.Counter({
  name: 'broker_messages_enqueued_total',
  help: 'Total messages enqueued into Redis streams',
  labelNames: ['hospital', 'department']
});

const dequeueCounter = new client.Counter({
  name: 'broker_messages_dequeued_total',
  help: 'Total messages dequeued from Redis streams',
  labelNames: ['hospital', 'department']
});

const ackCounter = new client.Counter({
  name: 'broker_messages_acked_total',
  help: 'Total messages acknowledged by consumers',
  labelNames: ['hospital', 'department']
});

const validationFailures = new client.Counter({
  name: 'broker_validation_failures_total',
  help: 'Total invalid enqueue attempts'
});

const replayFailures = new client.Counter({
  name: 'broker_replay_attempts_total',
  help: 'Detected replay attempts'
});

// -----------------------------
// Helper: Validate Token
// -----------------------------
async function validateToken(authHeader) {
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    throw new Error('Missing token');
  }
  const token = authHeader.split(' ')[1];
  const response = await mtls.post(AUTH_VALIDATE_URL, { token });
  return response.data;
}

// -----------------------------
// Helper: Ensure consumer group exists
// -----------------------------
async function ensureGroup(stream, group) {
  try {
    await redis.xgroup('CREATE', stream, group, '0', 'MKSTREAM');
  } catch (err) {
    if (!err.message.includes('BUSYGROUP')) throw err;
  }
}

// -----------------------------
// Sequence Bootstrap
// GET /sequence/:hospital/:producer_id
// Unauthenticated intentionally — sequence numbers are not secret.
// -----------------------------
app.get('/sequence/:hospital/:producer_id', async (req, res) => {
  const { hospital, producer_id } = req.params;
  const lastSeqKey = `seq:${hospital}:${producer_id}`;
  const lastSeq = await redis.get(lastSeqKey);
  return res.json({ last_sequence: lastSeq ? Number(lastSeq) : 0 });
});

// -----------------------------
// Enqueue
// -----------------------------
app.post('/enqueue', async (req, res) => {
  try {
    const identity = await validateToken(req.headers.authorization);

    const { hospital, department, ciphertext, nonce, producer_id, sequence, envelope } = req.body;

    if (!hospital || !department || !ciphertext || !nonce || !producer_id || typeof sequence !== 'number') {
      validationFailures.inc();
      return res.status(400).json({ error: 'Missing required fields' });
    }

    if (
      identity.hospital_id !== hospital   ||
      identity.staff_id    !== producer_id ||
      identity.department  !== department
    ) {
      validationFailures.inc();
      return res.status(403).json({ error: 'Identity mismatch' });
    }

    const stream = `hospital:${hospital}:dept:${department}`;

    const lastSeqKey = `seq:${hospital}:${producer_id}`;
    const lastSeq = await redis.get(lastSeqKey);

    if (lastSeq && Number(sequence) <= Number(lastSeq)) {
      replayFailures.inc();
      return res.status(409).json({ error: 'Replay detected' });
    }

    await redis.set(lastSeqKey, sequence);

    await redis.xadd(
      stream, '*',
      'ciphertext', ciphertext,
      'nonce', nonce,
      'producer_id', producer_id,
      'sequence', String(sequence),
      'envelope', JSON.stringify(envelope || {})
    );

    enqueueCounter.labels(hospital, department).inc();
    return res.json({ status: 'queued' });

  } catch {
    validationFailures.inc();
    return res.status(401).json({ error: 'Unauthorized' });
  }
});

// -----------------------------
// Dequeue (legacy)
// -----------------------------
app.get('/dequeue/:hospital/:department', async (req, res) => {
  try {
    const identity = await validateToken(req.headers.authorization);
    const { hospital, department } = req.params;

    if (identity.hospital_id !== hospital) {
      validationFailures.inc();
      return res.status(403).json({ error: 'Identity mismatch' });
    }

    const stream = `hospital:${hospital}:dept:${department}`;
    const messages = await redis.xrevrange(stream, '+', '-', 'COUNT', 10);

    const parsed = messages.map(([id, fields]) => {
      const obj = { id };
      for (let i = 0; i < fields.length; i += 2) obj[fields[i]] = fields[i + 1];
      obj.sequence = Number(obj.sequence);
      obj.envelope = obj.envelope ? JSON.parse(obj.envelope) : {};
      return obj;
    }).reverse();

    if (parsed.length > 0) dequeueCounter.labels(hospital, department).inc(parsed.length);
    return res.json({ items: parsed });

  } catch {
    validationFailures.inc();
    return res.status(401).json({ error: 'Unauthorized' });
  }
});

// -----------------------------
// Consumer Group Dequeue
// -----------------------------
app.get('/cg-dequeue/:hospital/:department', async (req, res) => {
  try {
    const identity = await validateToken(req.headers.authorization);
    const { hospital, department } = req.params;
    const { consumer_id, count = '10' } = req.query;

    if (!consumer_id) return res.status(400).json({ error: 'consumer_id query param required' });

    if (identity.hospital_id !== hospital || identity.staff_id !== consumer_id) {
      validationFailures.inc();
      return res.status(403).json({ error: 'Identity mismatch' });
    }

    const stream = `hospital:${hospital}:dept:${department}`;
    const group = `${stream}-consumers`;

    await ensureGroup(stream, group);

    const results = await redis.xreadgroup('GROUP', group, consumer_id, 'COUNT', count, 'STREAMS', stream, '>');

    if (!results || results.length === 0) return res.json({ items: [] });

    const [, messages] = results[0];
    const parsed = messages.map(([id, fields]) => {
      const obj = { id };
      for (let i = 0; i < fields.length; i += 2) obj[fields[i]] = fields[i + 1];
      obj.sequence = Number(obj.sequence);
      obj.envelope = obj.envelope ? JSON.parse(obj.envelope) : {};
      return obj;
    });

    if (parsed.length > 0) dequeueCounter.labels(hospital, department).inc(parsed.length);
    return res.json({ items: parsed });

  } catch {
    validationFailures.inc();
    return res.status(401).json({ error: 'Unauthorized' });
  }
});

// -----------------------------
// Consumer Group ACK
// -----------------------------
app.post('/cg-ack/:hospital/:department', async (req, res) => {
  try {
    const identity = await validateToken(req.headers.authorization);
    const { hospital, department } = req.params;
    const { consumer_id, message_ids } = req.body;

    if (!consumer_id || !Array.isArray(message_ids) || message_ids.length === 0) {
      return res.status(400).json({ error: 'consumer_id and non-empty message_ids required' });
    }

    if (identity.hospital_id !== hospital || identity.staff_id !== consumer_id) {
      validationFailures.inc();
      return res.status(403).json({ error: 'Identity mismatch' });
    }

    const stream = `hospital:${hospital}:dept:${department}`;
    const group = `${stream}-consumers`;

    const acked = await redis.xack(stream, group, ...message_ids);
    ackCounter.labels(hospital, department).inc(acked);
    return res.json({ acked });

  } catch {
    validationFailures.inc();
    return res.status(401).json({ error: 'Unauthorized' });
  }
});

// -----------------------------
// Reclaim Pending
// -----------------------------
app.get('/cg-pending/:hospital/:department', async (req, res) => {
  try {
    const identity = await validateToken(req.headers.authorization);
    const { hospital, department } = req.params;
    const { consumer_id, min_idle_ms = '30000', count = '10' } = req.query;

    if (!consumer_id) return res.status(400).json({ error: 'consumer_id query param required' });

    if (identity.hospital_id !== hospital || identity.staff_id !== consumer_id) {
      validationFailures.inc();
      return res.status(403).json({ error: 'Identity mismatch' });
    }

    const stream = `hospital:${hospital}:dept:${department}`;
    const group = `${stream}-consumers`;

    await ensureGroup(stream, group);

    const [nextCursor, messages] = await redis.xautoclaim(
      stream, group, consumer_id, min_idle_ms, '0-0', 'COUNT', count
    );

    const parsed = (messages || []).map(([id, fields]) => {
      const obj = { id };
      for (let i = 0; i < fields.length; i += 2) obj[fields[i]] = fields[i + 1];
      obj.sequence = Number(obj.sequence);
      obj.envelope = obj.envelope ? JSON.parse(obj.envelope) : {};
      return obj;
    });

    return res.json({ items: parsed, next_cursor: nextCursor });

  } catch {
    validationFailures.inc();
    return res.status(401).json({ error: 'Unauthorized' });
  }
});

// -----------------------------
// Metrics + Health
// -----------------------------
app.get('/metrics', async (req, res) => {
  res.set('Content-Type', client.register.contentType);
  res.end(await client.register.metrics());
});

app.get('/health', (req, res) => res.json({ status: 'ok' }));

// ✅ FIX: Replace plain app.listen() with an mTLS HTTPS server.
// The server now presents its own cert to clients AND requires clients
// to present a cert signed by our private CA (requestCert + rejectUnauthorized).
const CERT_PATH = process.env.MTLS_CERT_PATH;
const KEY_PATH  = process.env.MTLS_KEY_PATH;
const CA_PATH   = process.env.MTLS_CA_PATH;

if (!CERT_PATH || !KEY_PATH || !CA_PATH) {
  console.error('[broker] MTLS_CERT_PATH / MTLS_KEY_PATH / MTLS_CA_PATH must be set');
  process.exit(1);
}

const server = https.createServer({
  cert:               fs.readFileSync(CERT_PATH),
  key:                fs.readFileSync(KEY_PATH),
  ca:                 fs.readFileSync(CA_PATH),
  requestCert:        true,   // ask every client for a certificate
  rejectUnauthorized: true,   // reject clients without a CA-signed cert
}, app);

server.listen(9000, () => console.log('[broker] mTLS HTTPS server listening on :9000'));
