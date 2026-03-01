const express = require('express');
const Redis = require('ioredis');
const client = require('prom-client');
const axios = require('axios');

const app = express();
app.use(express.json());

const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');
const AUTH_VALIDATE_URL = process.env.AUTH_VALIDATE_URL || 'http://localhost:8001/validate';

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
  const response = await axios.post(AUTH_VALIDATE_URL, { token });
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
//
// GET /sequence/:hospital/:producer_id
//
// Unauthenticated intentionally — sequence numbers are not secret,
// they are monotonic counters used only for replay protection.
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

    // 🔐 Enforce identity match: hospital + staff_id + department
    if (
      identity.hospital_id !== hospital   ||
      identity.staff_id    !== producer_id ||
      identity.department  !== department
    ) {
      validationFailures.inc();
      return res.status(403).json({ error: 'Identity mismatch' });
    }

    const stream = `hospital:${hospital}:dept:${department}`;

    // 🔁 Replay protection (sequence check)
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
// Dequeue (legacy — full stream scan, no ACK)
// 🔐 Now requires a valid JWT. Consumer may only read from their own hospital.
// -----------------------------
app.get('/dequeue/:hospital/:department', async (req, res) => {
  try {
    const identity = await validateToken(req.headers.authorization);
    const { hospital, department } = req.params;

    // Consumer must belong to the same hospital they are reading from
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
// GET /cg-dequeue/:hospital/:department?consumer_id=<id>&count=<n>
// 🔐 Requires JWT. consumer_id must match token's staff_id.
// -----------------------------
app.get('/cg-dequeue/:hospital/:department', async (req, res) => {
  try {
    const identity = await validateToken(req.headers.authorization);
    const { hospital, department } = req.params;
    const { consumer_id, count = '10' } = req.query;

    if (!consumer_id) return res.status(400).json({ error: 'consumer_id query param required' });

    // Consumer must belong to the hospital they are reading from,
    // and consumer_id must match the authenticated staff_id
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
// POST /cg-ack/:hospital/:department
// 🔐 Requires JWT. consumer_id must match token's staff_id.
// -----------------------------
app.post('/cg-ack/:hospital/:department', async (req, res) => {
  try {
    const identity = await validateToken(req.headers.authorization);
    const { hospital, department } = req.params;
    const { consumer_id, message_ids } = req.body;

    if (!consumer_id || !Array.isArray(message_ids) || message_ids.length === 0) {
      return res.status(400).json({ error: 'consumer_id and non-empty message_ids required' });
    }

    // Prevent one consumer from ACKing another consumer's messages
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
// Reclaim Pending (crash recovery)
// GET /cg-pending/:hospital/:department?consumer_id=<id>&min_idle_ms=<ms>&count=<n>
// 🔐 Requires JWT. consumer_id must match token's staff_id.
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
// Metrics
// -----------------------------
app.get('/metrics', async (req, res) => {
  res.set('Content-Type', client.register.contentType);
  res.end(await client.register.metrics());
});

app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.listen(9000, () => console.log('Zero-Trust broker listening on :9000'));
