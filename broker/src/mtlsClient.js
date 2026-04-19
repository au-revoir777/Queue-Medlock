/**
 * mtlsClient.js — mTLS-aware HTTP client for Node.js services
 * ============================================================
 * Drop-in wrapper around axios that loads client certificates from
 * the paths set by environment variables. Used by the broker to make
 * mTLS calls to auth-service and kms-service.
 *
 * Usage:
 *   const mtls = require('./mtlsClient');
 *   const resp = await mtls.post('https://auth-service:8000/validate', { token });
 *
 * Environment variables (same convention as Python mtls_requests.py):
 *   MTLS_CERT_PATH  — path to this service's certificate
 *   MTLS_KEY_PATH   — path to this service's private key
 *   MTLS_CA_PATH    — path to the shared CA certificate
 *   MTLS_REQUIRED   — if "true", throw on missing certs instead of degrading
 */

const fs    = require('fs');
const https = require('https');
const axios = require('axios');

const CERT_PATH = process.env.MTLS_CERT_PATH || '';
const KEY_PATH  = process.env.MTLS_KEY_PATH  || '';
const CA_PATH   = process.env.MTLS_CA_PATH   || '';
const REQUIRED  = (process.env.MTLS_REQUIRED || 'false').toLowerCase() === 'true';

/**
 * Build an https.Agent with mutual TLS configuration.
 * Returns null if certs are not available and MTLS_REQUIRED is false.
 */
function buildAgent() {
  const certsPresent = CERT_PATH && KEY_PATH && CA_PATH;
  const certsExist   = certsPresent
    && fs.existsSync(CERT_PATH)
    && fs.existsSync(KEY_PATH)
    && fs.existsSync(CA_PATH);

  if (certsExist) {
    console.log(`[mtls] mTLS enabled — cert=${CERT_PATH} ca=${CA_PATH}`);
    return new https.Agent({
      cert: fs.readFileSync(CERT_PATH),
      key:  fs.readFileSync(KEY_PATH),
      ca:   fs.readFileSync(CA_PATH),
      // Enforce server cert verification against our private CA
      rejectUnauthorized: true,
    });
  }

  if (REQUIRED) {
    throw new Error(
      `[mtls] MTLS_REQUIRED=true but cert files not found. ` +
      `cert=${CERT_PATH} key=${KEY_PATH} ca=${CA_PATH}`
    );
  }

  console.warn(
    '[mtls] Cert files not found — falling back to plain HTTP. ' +
    'Run infra/certs/gen-certs.sh and mount certs to enable mTLS.'
  );
  return null;
}

const _agent = buildAgent();

/**
 * Build default axios config.
 * If mTLS is enabled, every request presents the client cert.
 */
function _config(extra = {}) {
  if (_agent) {
    return { ...extra, httpsAgent: _agent };
  }
  return extra;
}

module.exports = {
  get:  (url, config = {}) => axios.get(url,  _config(config)),
  post: (url, data, config = {}) => axios.post(url, data, _config(config)),
  put:  (url, data, config = {}) => axios.put(url,  data, _config(config)),

  /**
   * Expose the raw agent for cases where you need to pass it directly
   * (e.g. into a custom axios instance).
   */
  agent: _agent,
};
