"""
mtls_requests.py — Drop-in mTLS wrapper for inter-service HTTP calls
=====================================================================

Every MedLock service that calls another internal service imports this
module instead of `requests` directly. It handles:

  1. Mutual TLS — presents the calling service's client certificate
  2. Server verification — validates the peer cert against the shared CA
  3. Hostname matching — uses Docker Compose service names (which match the
     Subject Alternative Names in each cert)
  4. Graceful degradation — if certs are not mounted (e.g. local dev without
     running gen-certs.sh), falls back to plain HTTPS with a clear warning.
     Set MTLS_REQUIRED=true to make missing certs a hard failure.

Environment variables (set in docker-compose.yml per service):
  MTLS_CERT_PATH   — path to this service's certificate (e.g. /certs/broker.crt)
  MTLS_KEY_PATH    — path to this service's private key  (e.g. /certs/broker.key)
  MTLS_CA_PATH     — path to the shared CA certificate   (e.g. /certs/ca.crt)
  MTLS_REQUIRED    — if "true", raise on missing certs instead of degrading

Usage (replace `import requests` with `import mtls_requests as requests`):

    import mtls_requests as requests
    resp = requests.get("https://auth-service:8000/validate", ...)
    resp = requests.post("https://kms-service:8000/keys/...", json={...})

The returned objects are standard requests.Response — no API changes.

Cloud deployment notes:
  - Mount certs from AWS Secrets Manager / GCP Secret Manager / Vault
    into the same paths — no code changes required.
  - Cert rotation: replace mounted files and send SIGHUP to the process
    (or restart the container). The session object is rebuilt on each
    module import; for zero-downtime rotation you can call reset_session().
"""

import logging
import os
from typing import Any

import requests
from requests import Response
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

log = logging.getLogger(__name__)

# -----------------------------------------------------------------------
# Configuration — read once at import time
# -----------------------------------------------------------------------

CERT_PATH = os.environ.get("MTLS_CERT_PATH", "")
KEY_PATH = os.environ.get("MTLS_KEY_PATH", "")
CA_PATH = os.environ.get("MTLS_CA_PATH", "")
REQUIRED = os.environ.get("MTLS_REQUIRED", "false").lower() == "true"

# -----------------------------------------------------------------------
# Session factory
# -----------------------------------------------------------------------


def _build_session() -> requests.Session:
    """
    Build a requests.Session configured for mTLS.

    - client cert: (CERT_PATH, KEY_PATH) — presented to every server
    - CA bundle:   CA_PATH               — used to verify server certs
    - Retry:       3 retries on 5xx and connection errors with backoff
    """
    session = requests.Session()

    # Retry strategy — safe for idempotent calls (GET/HEAD).
    # POST retries are intentionally excluded to avoid double-writes;
    # callers that need POST retry should handle it themselves.
    retry = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["GET", "HEAD", "OPTIONS"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    certs_present = CERT_PATH and KEY_PATH and CA_PATH
    certs_exist = (
        certs_present
        and os.path.exists(CERT_PATH)
        and os.path.exists(KEY_PATH)
        and os.path.exists(CA_PATH)
    )

    if certs_exist:
        session.cert = (CERT_PATH, KEY_PATH)
        session.verify = CA_PATH
        log.info("[mtls] mTLS enabled — cert=%s ca=%s", CERT_PATH, CA_PATH)
    elif REQUIRED:
        raise RuntimeError(
            f"[mtls] MTLS_REQUIRED=true but cert files not found. "
            f"cert={CERT_PATH} key={KEY_PATH} ca={CA_PATH}"
        )
    else:
        log.warning(
            "[mtls] Cert files not found — falling back to plain HTTP. "
            "Run infra/certs/gen-certs.sh and mount certs to enable mTLS. "
            "Set MTLS_REQUIRED=true to make this a hard failure."
        )

    return session


# Module-level session — shared across all calls from this process.
_session: requests.Session = _build_session()


def reset_session() -> None:
    """
    Rebuild the session (e.g. after cert rotation).
    Thread-safe: Python assignment is atomic under the GIL.
    """
    global _session
    _session = _build_session()


# -----------------------------------------------------------------------
# Public API — mirrors requests module interface
# -----------------------------------------------------------------------


def get(url: str, **kwargs: Any) -> Response:
    return _session.get(url, **kwargs)


def post(url: str, **kwargs: Any) -> Response:
    return _session.post(url, **kwargs)


def put(url: str, **kwargs: Any) -> Response:
    return _session.put(url, **kwargs)


def patch(url: str, **kwargs: Any) -> Response:
    return _session.patch(url, **kwargs)


def delete(url: str, **kwargs: Any) -> Response:
    return _session.delete(url, **kwargs)


def request(method: str, url: str, **kwargs: Any) -> Response:
    return _session.request(method, url, **kwargs)
