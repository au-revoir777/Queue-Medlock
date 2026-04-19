"""
MedLock Red Team - Attacker Script (mTLS edition)
====================================
Simulates three attack vectors against the Zero-Trust broker:

  1. MISROUTE      — valid token, legitimate producer_id, but wrong department
  2. REPLAY        — re-sends a previously captured message to a different dept
  3. IMPERSONATION — forges producer_id to claim to be a different staff member

For each attack, two scenarios are tested:
  - INSIDER  : attacker has a valid JWT (registered staff member)
  - OUTSIDER : attacker has no token at all

Expected outcome for a correctly hardened broker:
  - All attacks should be BLOCKED (4xx responses)
  - Any 200 response is a vulnerability finding

Results are printed as a summary table at the end.

Changes from original (HTTP)
-----------------------------
- All URLs updated to HTTPS on port 8443 (matching mTLS deployment).
- `import requests` replaced with `import mtls_requests as requests` — drop-in
  wrapper; handles client cert + CA verification via env vars automatically.
- VERIFY_SSL config and all manual verify= kwargs removed — mtls_requests
  handles both client cert presentation and CA verification internally.
- Post-attack liveness check updated to use mtls_requests session.
"""

import os
import sys
import time
import base64
import hashlib
import logging
import mtls_requests as requests
from dataclasses import dataclass, field
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import oqs  # liboqs-python — ML-KEM-768 and ML-DSA-65

KEM_ALG = "ML-KEM-768"
DSA_ALG = "ML-DSA-65"
ENVELOPE_VERSION = "hybrid-v1"

logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger("attacker")

# ----------------------------------------------------------------
# Config — override via env vars
# ----------------------------------------------------------------
AUTH_URL = os.environ.get("AUTH_URL", "https://localhost:8443/auth/login")
TENANT_URL = os.environ.get("TENANT_URL", "https://localhost:8443")
BROKER_URL = os.environ.get("BROKER_URL", "https://localhost:8443")
SIM_PASSWORD = os.environ.get("SIM_PASSWORD", "simpassword")

HOSPITAL = "hospital1"  # hospital the attacker legitimately belongs to
VICTIM_HOSPITAL = "hospital2"  # hospital the attacker tries to target
ATTACKER_DEPT = "cardiology"  # attacker's real department
VICTIM_DEPT = "radiology"  # department attacker tries to misroute into
VICTIM_DEPT_2 = "icu"  # second victim dept for replay

# Canary producer used by the liveness check — must be a simulator thread
# that is running independently of the attacker.
CANARY_PRODUCER = f"{HOSPITAL}_{ATTACKER_DEPT}_producer"

# ----------------------------------------------------------------
# Result tracking
# ----------------------------------------------------------------
results = []


def safe_request(method: str, url: str, **kwargs):
    """
    Always returns a response object. On exception, returns a fake
    response with status_code=0 so record() can distinguish between
    a broker rejection (real 4xx) and a network error (0/ERR).

    mTLS (client cert + CA verification) is handled automatically by
    the mtls_requests session — no extra kwargs needed here.
    """
    try:
        resp = requests.request(method, url, **kwargs)
        log.debug("%s %s → HTTP %d %s", method, url, resp.status_code, resp.text[:120])
        return resp
    except Exception as exc:
        log.warning("%s %s → EXCEPTION: %s", method, url, exc)

        class FakeResponse:
            status_code = 0
            text = f"REQUEST_ERROR: {exc}"

            def json(self):
                return {}

        return FakeResponse()


def record(attack: str, scenario: str, expected: int, resp):
    if resp is None:
        actual = None
        verdict = "⚠️  SKIPPED"
        detail = "attack skipped — see log"
    elif resp.status_code == 0:
        actual = None
        verdict = "⚠️  NET_ERROR"
        detail = resp.text[:120]
    elif resp.status_code == 200:
        actual = resp.status_code
        verdict = "🚨 VULNERABILITY"
        detail = resp.text[:120]
    else:
        actual = resp.status_code
        verdict = "✅ BLOCKED"
        detail = resp.text[:120]

    results.append(
        {
            "attack": attack,
            "scenario": scenario,
            "expected": expected,
            "actual": actual,
            "verdict": verdict,
            "detail": detail,
        }
    )
    log.info(
        "[%s] %s | %s → HTTP %s | %s",
        verdict,
        attack,
        scenario,
        actual if actual else "ERR",
        detail[:80],
    )


# ----------------------------------------------------------------
# Crypto helpers (mirrors simulator exactly)
# ----------------------------------------------------------------
def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


@dataclass
class StaffMember:
    hospital_id: str
    staff_id: str
    role: str = "nurse"
    department: str = ATTACKER_DEPT
    token: str = None
    sequence: int = 1

    # Classical keys
    sign_key_obj: ed25519.Ed25519PrivateKey = field(
        default_factory=ed25519.Ed25519PrivateKey.generate
    )
    kx_private_obj: x25519.X25519PrivateKey = field(
        default_factory=x25519.X25519PrivateKey.generate
    )

    # PQC keys — populated in __post_init__
    kem_private_bytes: bytes = field(default=None, repr=False)
    kem_public_bytes: bytes = field(default=None, repr=False)
    dsa_private_bytes: bytes = field(default=None, repr=False)
    dsa_public_bytes: bytes = field(default=None, repr=False)

    # Derived wire-format strings — computed in __post_init__
    sign_key: str = field(init=False, repr=False)  # Ed25519 public key (b64)
    kx_public: str = field(init=False, repr=False)  # X25519 public key (b64)
    kem_public: str = field(init=False, repr=False)  # ML-KEM-768 public key (b64)
    dsa_public: str = field(init=False, repr=False)  # ML-DSA-65 public key (b64)

    def __post_init__(self):
        self.sign_key = _b64(
            self.sign_key_obj.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        )
        self.kx_public = _b64(
            self.kx_private_obj.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        )
        with oqs.KeyEncapsulation(KEM_ALG) as kem:
            self.kem_public_bytes = kem.generate_keypair()
            self.kem_private_bytes = kem.export_secret_key()
        self.kem_public = _b64(self.kem_public_bytes)

        with oqs.Signature(DSA_ALG) as dsa:
            self.dsa_public_bytes = dsa.generate_keypair()
            self.dsa_private_bytes = dsa.export_secret_key()
        self.dsa_public = _b64(self.dsa_public_bytes)


def build_payload(
    *,
    hospital_id,
    department_id,
    producer_id,
    sequence,
    plaintext,
    consumer_kx_public_b64,
    consumer_kem_public_b64,
    sign_key_obj,
    dsa_private_bytes,
):
    """Encrypt a message with hybrid PQC crypto — mirrors simulator exactly."""
    consumer_kx_pub = x25519.X25519PublicKey.from_public_bytes(
        base64.b64decode(consumer_kx_public_b64)
    )
    eph_priv = x25519.X25519PrivateKey.generate()
    eph_pub = eph_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    shared_x25519 = eph_priv.exchange(consumer_kx_pub)

    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        kem_ct, shared_kem = kem.encap_secret(base64.b64decode(consumer_kem_public_b64))

    session_key = HKDF(
        hashes.SHA256(), 32, None, f"{hospital_id}:{department_id}".encode()
    ).derive(shared_x25519 + shared_kem)

    nonce = os.urandom(12)
    aad = f"{producer_id}:{sequence}".encode()
    ciphertext = AESGCM(session_key).encrypt(nonce, plaintext.encode(), aad)
    digest = hashlib.sha256(ciphertext).hexdigest()

    signed_content = f"{producer_id}:{sequence}:{digest}".encode()
    sig_classical = sign_key_obj.sign(signed_content)
    with oqs.Signature(DSA_ALG, secret_key=dsa_private_bytes) as dsa:
        sig_pqc = dsa.sign(signed_content)

    return {
        "nonce": _b64(nonce),
        "ciphertext": _b64(ciphertext),
        "envelope": {
            "version": ENVELOPE_VERSION,
            "ephemeral_public_key": _b64(eph_pub),
            "kem_ciphertext": _b64(kem_ct),
            "signature_classical": _b64(sig_classical),
            "signature_pqc": _b64(sig_pqc),
            "cipher_hash": digest,
        },
    }


# ----------------------------------------------------------------
# Setup: register + authenticate attacker as a legitimate staff member
# ----------------------------------------------------------------
def get_last_sequence(hospital_id: str, producer_id: str) -> int:
    """Ask the broker for the last sequence it has seen for this producer."""
    try:
        resp = requests.get(
            f"{BROKER_URL}/sequence/{hospital_id}/{producer_id}", timeout=5
        )
        if resp.status_code == 200:
            return resp.json().get("last_sequence", 0)
    except Exception as exc:
        log.warning("Could not fetch last sequence: %s", exc)
    return 0


def setup_attacker() -> StaffMember:
    log.info("=== SETUP: registering attacker as legitimate staff ===")
    attacker = StaffMember(hospital_id=HOSPITAL, staff_id=f"{HOSPITAL}_attacker")

    # Register hospital (may already exist — 409 is fine)
    requests.post(
        f"{TENANT_URL}/hospitals",
        json={"id": HOSPITAL, "name": HOSPITAL},
        timeout=5,
    )

    resp = requests.post(
        f"{TENANT_URL}/staff/register",
        json={
            "id": attacker.staff_id,
            "hospital_id": attacker.hospital_id,
            "role": attacker.role,
            "department": attacker.department,
            "public_sign_key": attacker.sign_key,
            "public_kx_key": attacker.kx_public,
            "public_kem_key": attacker.kem_public,
            "public_dsa_key": attacker.dsa_public,
        },
        timeout=5,
    )
    log.info("Staff register → HTTP %d %s", resp.status_code, resp.text[:120])

    resp = requests.post(
        AUTH_URL,
        json={
            "hospital_id": attacker.hospital_id,
            "staff_id": attacker.staff_id,
            "password": "pass123",
        },
        timeout=5,
    )

    if resp.status_code not in (200, 201):
        log.error("Auth failed: %d %s", resp.status_code, resp.text)
        sys.exit(1)

    attacker.token = resp.json().get("access_token")
    attacker.sequence = get_last_sequence(attacker.hospital_id, attacker.staff_id) + 1
    log.info("Attacker authenticated ✓  token=%s…", attacker.token[:20])
    log.info("Attacker starting at sequence %d", attacker.sequence)
    return attacker


# ----------------------------------------------------------------
# ATTACK 1: MISROUTE
# ----------------------------------------------------------------
def attack_misroute(attacker: StaffMember):
    log.info("\n=== ATTACK 1: MISROUTE ===")

    payload = build_payload(
        hospital_id=attacker.hospital_id,
        department_id=VICTIM_DEPT,
        producer_id=attacker.staff_id,
        sequence=attacker.sequence,
        plaintext="MISROUTED: attacker injecting into wrong dept",
        consumer_kx_public_b64=attacker.kx_public,
        consumer_kem_public_b64=attacker.kem_public,
        sign_key_obj=attacker.sign_key_obj,
        dsa_private_bytes=attacker.dsa_private_bytes,
    )
    attacker.sequence += 1

    body = {
        "hospital": attacker.hospital_id,
        "department": VICTIM_DEPT,
        "producer_id": attacker.staff_id,
        "sequence": attacker.sequence,
        **{k: payload[k] for k in ("nonce", "ciphertext", "envelope")},
    }

    # 1a: valid token, own hospital, wrong department
    resp = safe_request(
        "POST",
        f"{BROKER_URL}/enqueue",
        json=body,
        headers={"Authorization": f"Bearer {attacker.token}"},
        timeout=5,
    )
    record("MISROUTE", "insider → wrong dept, same hospital", 403, resp)

    # 1b: valid token, wrong hospital entirely
    resp = safe_request(
        "POST",
        f"{BROKER_URL}/enqueue",
        json={**body, "hospital": VICTIM_HOSPITAL},
        headers={"Authorization": f"Bearer {attacker.token}"},
        timeout=5,
    )
    record("MISROUTE", "insider → different hospital", 403, resp)

    # 1c: no token at all
    resp = safe_request("POST", f"{BROKER_URL}/enqueue", json=body, timeout=5)
    record("MISROUTE", "outsider → no token", 401, resp)


# ----------------------------------------------------------------
# ATTACK 2: REPLAY
# ----------------------------------------------------------------
def attack_replay(attacker: StaffMember):
    log.info("\n=== ATTACK 2: REPLAY ===")

    payload = build_payload(
        hospital_id=attacker.hospital_id,
        department_id=ATTACKER_DEPT,
        producer_id=attacker.staff_id,
        sequence=attacker.sequence,
        plaintext="legitimate message about to be replayed",
        consumer_kx_public_b64=attacker.kx_public,
        consumer_kem_public_b64=attacker.kem_public,
        sign_key_obj=attacker.sign_key_obj,
        dsa_private_bytes=attacker.dsa_private_bytes,
    )
    legitimate_seq = attacker.sequence
    attacker.sequence += 1

    enqueue_resp = safe_request(
        "POST",
        f"{BROKER_URL}/enqueue",
        json={
            "hospital": attacker.hospital_id,
            "department": ATTACKER_DEPT,
            "producer_id": attacker.staff_id,
            "sequence": legitimate_seq,
            **{k: payload[k] for k in ("nonce", "ciphertext", "envelope")},
        },
        headers={"Authorization": f"Bearer {attacker.token}"},
        timeout=5,
    )
    if enqueue_resp.status_code != 200:
        log.warning(
            "Could not enqueue legitimate message for capture: %d",
            enqueue_resp.status_code,
        )

    # 2a: outsider tries to read /dequeue with no token
    resp = safe_request(
        "GET", f"{BROKER_URL}/dequeue/{attacker.hospital_id}/{ATTACKER_DEPT}", timeout=5
    )
    record("REPLAY", "outsider → read /dequeue no token", 401, resp)

    # 2b: insider tries to read /dequeue for a different hospital
    resp = safe_request(
        "GET",
        f"{BROKER_URL}/dequeue/{VICTIM_HOSPITAL}/{ATTACKER_DEPT}",
        headers={"Authorization": f"Bearer {attacker.token}"},
        timeout=5,
    )
    record("REPLAY", "insider → read /dequeue wrong hospital", 403, resp)

    # Capture messages using the attacker's own valid token
    captured_items = []
    dequeue_resp = safe_request(
        "GET",
        f"{BROKER_URL}/dequeue/{attacker.hospital_id}/{ATTACKER_DEPT}",
        headers={"Authorization": f"Bearer {attacker.token}"},
        timeout=5,
    )
    if dequeue_resp.status_code == 200:
        captured_items = dequeue_resp.json().get("items", [])
        log.info(
            "Captured %d message(s) from authenticated /dequeue", len(captured_items)
        )
    else:
        log.warning("Could not read own stream: %d", dequeue_resp.status_code)

    if not captured_items:
        log.warning("No messages captured — skipping re-injection tests")
        record("REPLAY", "insider → replay to different dept", 403, None)
        record("REPLAY", "insider → replay same dept (seq collision)", 409, None)
        record("REPLAY", "outsider → replay no token", 401, None)
        return

    own_messages = [
        m for m in captured_items if m.get("producer_id") == attacker.staff_id
    ]
    if not own_messages:
        log.warning("No attacker-owned messages in stream — using latest message")
        own_messages = captured_items
    captured = own_messages[-1]
    log.info(
        "Using captured message: producer=%s seq=%s",
        captured["producer_id"],
        captured["sequence"],
    )

    body_diff_dept = {
        "hospital": attacker.hospital_id,
        "department": VICTIM_DEPT,
        "producer_id": captured["producer_id"],
        "sequence": captured["sequence"],
        "nonce": captured["nonce"],
        "ciphertext": captured["ciphertext"],
        "envelope": captured["envelope"],
    }

    # 2c: replay to a different department
    resp = safe_request(
        "POST",
        f"{BROKER_URL}/enqueue",
        json=body_diff_dept,
        headers={"Authorization": f"Bearer {attacker.token}"},
        timeout=5,
    )
    record("REPLAY", "insider → replay to different dept", 403, resp)

    # 2d: replay to same dept (sequence already seen)
    resp = safe_request(
        "POST",
        f"{BROKER_URL}/enqueue",
        json={**body_diff_dept, "department": ATTACKER_DEPT},
        headers={"Authorization": f"Bearer {attacker.token}"},
        timeout=5,
    )
    record("REPLAY", "insider → replay same dept (seq collision)", 409, resp)

    # 2e: outsider replays without a token
    resp = safe_request("POST", f"{BROKER_URL}/enqueue", json=body_diff_dept, timeout=5)
    record("REPLAY", "outsider → replay no token", 401, resp)


# ----------------------------------------------------------------
# ATTACK 3: IMPERSONATION
# ----------------------------------------------------------------
def attack_impersonation(attacker: StaffMember):
    log.info("\n=== ATTACK 3: IMPERSONATION ===")

    victim_id = f"{HOSPITAL}_producer"

    payload = build_payload(
        hospital_id=attacker.hospital_id,
        department_id=ATTACKER_DEPT,
        producer_id=victim_id,
        sequence=1,
        plaintext="IMPERSONATION: attacker pretending to be victim",
        consumer_kx_public_b64=attacker.kx_public,
        consumer_kem_public_b64=attacker.kem_public,
        sign_key_obj=attacker.sign_key_obj,
        dsa_private_bytes=attacker.dsa_private_bytes,
    )

    body = {
        "hospital": attacker.hospital_id,
        "department": ATTACKER_DEPT,
        "producer_id": victim_id,
        "sequence": 1,
        **{k: payload[k] for k in ("nonce", "ciphertext", "envelope")},
    }

    # 3a: valid token but producer_id doesn't match token's staff_id
    resp = safe_request(
        "POST",
        f"{BROKER_URL}/enqueue",
        json=body,
        headers={"Authorization": f"Bearer {attacker.token}"},
        timeout=5,
    )
    record("IMPERSONATION", "insider → forged producer_id same hospital", 403, resp)

    # 3b: valid token, forged producer_id, wrong hospital
    resp = safe_request(
        "POST",
        f"{BROKER_URL}/enqueue",
        json={
            **body,
            "hospital": VICTIM_HOSPITAL,
            "producer_id": f"{VICTIM_HOSPITAL}_producer",
        },
        headers={"Authorization": f"Bearer {attacker.token}"},
        timeout=5,
    )
    record(
        "IMPERSONATION", "insider → forged producer_id different hospital", 403, resp
    )

    # 3c: no token
    resp = safe_request("POST", f"{BROKER_URL}/enqueue", json=body, timeout=5)
    record("IMPERSONATION", "outsider → forged producer_id no token", 401, resp)


# ----------------------------------------------------------------
# Post-attack liveness check
# ----------------------------------------------------------------
def liveness_check() -> bool:
    """
    Verify that legitimate simulator traffic is still healthy after all attacks.

    Returns True if the system is live, False if it has been degraded.
    """
    log.info("\n=== POST-ATTACK LIVENESS CHECK ===")
    log.info("Waiting 5s for simulator threads to complete a cycle...")
    time.sleep(5)

    passed = True

    # Check 1: canary broker sequence must still be advancing
    log.info("Check 1: canary broker sequence still advancing")
    seq_before_resp = safe_request(
        "GET", f"{BROKER_URL}/sequence/{HOSPITAL}/{CANARY_PRODUCER}", timeout=5
    )
    time.sleep(3)
    seq_after_resp = safe_request(
        "GET", f"{BROKER_URL}/sequence/{HOSPITAL}/{CANARY_PRODUCER}", timeout=5
    )

    if seq_before_resp.status_code != 200 or seq_after_resp.status_code != 200:
        log.error("  ❌ LIVENESS FAIL — broker sequence endpoint unreachable")
        passed = False
    else:
        before = seq_before_resp.json().get("last_sequence", 0)
        after = seq_after_resp.json().get("last_sequence", 0)
        if after > before:
            log.info("  ✅ Sequence advancing: %d → %d", before, after)
        else:
            log.error(
                "  ❌ LIVENESS FAIL — sequence stalled at %d (was %d before check)",
                after,
                before,
            )
            passed = False

    # Check 2: a fresh legitimate login for the canary producer must succeed
    log.info("Check 2: fresh legitimate login for canary producer")
    login_resp = safe_request(
        "POST",
        AUTH_URL,
        json={
            "hospital_id": HOSPITAL,
            "staff_id": CANARY_PRODUCER,
            "password": "pass123",
        },
        timeout=5,
    )
    if login_resp.status_code == 404:
        log.error(
            "  ❌ LIVENESS FAIL — canary producer returns 404 "
            "(auth state was wiped by attacks)"
        )
        passed = False
    elif login_resp.status_code in (200, 201):
        log.info("  ✅ Login OK (HTTP %d)", login_resp.status_code)
    else:
        log.error(
            "  ❌ LIVENESS FAIL — unexpected login status HTTP %d %s",
            login_resp.status_code,
            login_resp.text[:80],
        )
        passed = False

    # Check 3: tenant health must report database ok
    log.info("Check 3: tenant service health")
    health_resp = safe_request("GET", f"{TENANT_URL}/health", timeout=5)
    if health_resp.status_code == 200:
        body = health_resp.json()
        if body.get("database") not in (None, "ok"):
            log.error("  ❌ LIVENESS FAIL — tenant database unhealthy: %s", body)
            passed = False
        else:
            log.info("  ✅ Tenant healthy: %s", body)
    else:
        log.error("  ❌ LIVENESS FAIL — tenant health endpoint unreachable")
        passed = False

    return passed


# ----------------------------------------------------------------
# Summary table
# ----------------------------------------------------------------
def print_summary(liveness_ok: bool):
    col_w = [22, 44, 10, 10, 18]
    headers = ["ATTACK", "SCENARIO", "EXPECTED", "ACTUAL", "VERDICT"]
    sep = "+" + "+".join("-" * (w + 2) for w in col_w) + "+"
    row_fmt = "| " + " | ".join(f"{{:<{w}}}" for w in col_w) + " |"

    print("\n" + "=" * 115)
    print(" MEDLOCK RED TEAM — RESULTS SUMMARY")
    print("=" * 115)
    print(sep)
    print(row_fmt.format(*headers))
    print(sep)

    vulns = 0
    errors = 0
    for r in results:
        print(
            row_fmt.format(
                r["attack"][: col_w[0]],
                r["scenario"][: col_w[1]],
                str(r["expected"]),
                str(r["actual"]) if r["actual"] else "ERR",
                r["verdict"],
            )
        )
        if "VULNERABILITY" in r["verdict"]:
            vulns += 1
        if "NET_ERROR" in r["verdict"] or "SKIPPED" in r["verdict"]:
            errors += 1

    confirmed_blocks = len(results) - vulns - errors
    print(sep)
    print(f"\n  Total attacks     : {len(results)}")
    print(f"  Confirmed blocked : {confirmed_blocks}  (broker returned 4xx)")
    print(
        f"  Network errors    : {errors}  (no response — broker decision unconfirmed)"
    )
    print(f"  Vulnerabilities   : {vulns}")

    if errors > 0:
        print("\n  ⚠️  Some attacks show NET_ERROR — broker response unconfirmed.")
        print("     Check broker logs to verify these were actually rejected.")
        for r in results:
            if "NET_ERROR" in r["verdict"]:
                print(f"     → [{r['attack']}] {r['scenario']}")
                print(f"        Error: {r['detail']}")

    # Liveness result
    print()
    if liveness_ok:
        print(
            "  ✅ POST-ATTACK LIVENESS: system healthy — simulator traffic still flowing"
        )
    else:
        print(
            "  ❌ POST-ATTACK LIVENESS: system DEGRADED — attacks caused collateral damage!"
        )
        print("     Check auth/tenant service state and simulator thread logs.")

    if vulns == 0 and errors == 0 and liveness_ok:
        print(
            "\n  ✅ All attacks confirmed blocked — Zero-Trust broker is hardened correctly."
        )
    elif vulns > 0:
        print("\n  🚨 VULNERABILITIES DETECTED — review the table above.")
        for r in results:
            if "VULNERABILITY" in r["verdict"]:
                print(f"     → [{r['attack']}] {r['scenario']}")
                print(f"        Response: {r['detail']}")

    print("=" * 115 + "\n")


# ----------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------
if __name__ == "__main__":
    log.info("MedLock Red Team starting... mTLS mode — mtls_requests session active")

    attacker = setup_attacker()

    attack_misroute(attacker)
    attack_replay(attacker)
    attack_impersonation(attacker)

    liveness_ok = liveness_check()

    print_summary(liveness_ok)

    if not liveness_ok:
        sys.exit(1)
