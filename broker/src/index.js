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
// Enqueue
// -----------------------------
app.post('/enqueue', async (req, res) => {
  try {
    const identity = await validateToken(req.headers.authorization);

    const {
      hospital,
      department,
      ciphertext,
      nonce,
      producer_id,
      sequence,
      envelope
    } = req.body;

    if (!hospital || !department || !ciphertext || !nonce || !producer_id || typeof sequence !== 'number') {
      validationFailures.inc();
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // 🔐 Enforce identity match
    if (identity.hospital_id !== hospital || identity.staff_id !== producer_id) {
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
      stream,
      '*',
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
// Dequeue
// -----------------------------
app.get('/dequeue/:hospital/:department', async (req, res) => {

  const { hospital, department } = req.params;
  const stream = `hospital:${hospital}:dept:${department}`;

  const messages = await redis.xrevrange(stream, '+', '-', 'COUNT', 10);

  const parsed = messages.map(([id, fields]) => {
    const obj = { id };
    for (let i = 0; i < fields.length; i += 2) {
      obj[fields[i]] = fields[i + 1];
    }
    obj.sequence = Number(obj.sequence);
    obj.envelope = obj.envelope ? JSON.parse(obj.envelope) : {};
    return obj;
  }).reverse();

  if (parsed.length > 0) {
    dequeueCounter.labels(hospital, department).inc(parsed.length);
  }

  return res.json({ items: parsed });
});

// -----------------------------
// Metrics
// -----------------------------
app.get('/metrics', async (req, res) => {
  res.set('Content-Type', client.register.contentType);
  res.end(await client.register.metrics());
});

// -----------------------------
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.listen(9000, () => {
  console.log('Untrusted Zero-Trust broker listening on :9000');
});
