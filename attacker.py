"""
MedLock Red Team - Attacker Script
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
"""

import os
import sys
import base64
import hashlib
import logging
import requests
from dataclasses import dataclass, field
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger("attacker")

# ----------------------------------------------------------------
# Config — override via env vars
# ----------------------------------------------------------------
AUTH_URL = os.environ.get("AUTH_URL", "http://localhost:8000/login")
TENANT_URL = os.environ.get("TENANT_URL", "http://localhost:8000")
BROKER_URL = os.environ.get("BROKER_URL", "http://localhost:9000")
SIM_PASSWORD = os.environ.get("SIM_PASSWORD", "simpassword")

HOSPITAL = "hospital1"  # hospital the attacker legitimately belongs to
VICTIM_HOSPITAL = "hospital2"  # hospital the attacker tries to target
ATTACKER_DEPT = "cardiology"  # attacker's real department
VICTIM_DEPT = "radiology"  # department attacker tries to misroute into
VICTIM_DEPT_2 = "icu"  # second victim dept for replay

# ----------------------------------------------------------------
# Result tracking
# ----------------------------------------------------------------
results = []


def safe_request(method: str, url: str, **kwargs):
    """
    Always returns a response object. On exception, returns a fake
    response with status_code=0 so record() can distinguish between
    a broker rejection (real 4xx) and a network error (0/ERR).
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
    department: str = ATTACKER_DEPT  # fixed to attacker's real department
    token: str = None
    sequence: int = 1
    sign_key_obj: ed25519.Ed25519PrivateKey = field(
        default_factory=ed25519.Ed25519PrivateKey.generate
    )
    kx_private_obj: x25519.X25519PrivateKey = field(
        default_factory=x25519.X25519PrivateKey.generate
    )
    sign_key: str = field(init=False)
    kx_public: str = field(init=False)

    def __post_init__(self):
        self.sign_key = _b64(
            self.sign_key_obj.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
        )
        self.kx_public = _b64(
            self.kx_private_obj.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        )


def build_payload(
    *,
    hospital_id,
    department_id,
    producer_id,
    sequence,
    plaintext,
    consumer_kx_public_b64,
    sign_key_obj,
):
    """Encrypt a message exactly as the legitimate simulator does."""
    consumer_pub = x25519.X25519PublicKey.from_public_bytes(
        base64.b64decode(consumer_kx_public_b64)
    )
    eph_priv = x25519.X25519PrivateKey.generate()
    eph_pub = eph_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    shared = eph_priv.exchange(consumer_pub)

    session_key = HKDF(
        hashes.SHA256(), 32, None, f"{hospital_id}:{department_id}".encode()
    ).derive(shared)
    nonce = os.urandom(12)
    aad = f"{producer_id}:{sequence}".encode()
    ciphertext = AESGCM(session_key).encrypt(nonce, plaintext.encode(), aad)

    digest = hashlib.sha256(ciphertext).hexdigest()
    signature = sign_key_obj.sign(f"{producer_id}:{sequence}:{digest}".encode())

    return {
        "nonce": _b64(nonce),
        "ciphertext": _b64(ciphertext),
        "envelope": {
            "ephemeral_public_key": _b64(eph_pub),
            "signature": _b64(signature),
            "cipher_hash": digest,
        },
    }


# ----------------------------------------------------------------
# Setup: register + authenticate attacker as a legitimate staff member
# ----------------------------------------------------------------
def setup_attacker() -> StaffMember:
    log.info("=== SETUP: registering attacker as legitimate staff ===")
    attacker = StaffMember(hospital_id=HOSPITAL, staff_id=f"{HOSPITAL}_attacker")

    # Register hospital (may already exist — 409 is fine)
    requests.post(
        f"{TENANT_URL}/hospitals", json={"id": HOSPITAL, "name": HOSPITAL}, timeout=5
    )

    # Register attacker staff
    resp = requests.post(
        f"{TENANT_URL}/staff/register",
        json={
            "id": attacker.staff_id,
            "hospital_id": attacker.hospital_id,
            "role": "nurse",
            "department": attacker.department,  # ← required by updated tenant service
            "public_sign_key": attacker.sign_key,
            "public_kx_key": attacker.kx_public,
        },
        timeout=5,
    )
    log.info("Staff register → HTTP %d", resp.status_code)

    # Authenticate — password must match what tenant service forwards to auth ("pass123")
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
    log.info("Attacker authenticated ✓  token=%s…", attacker.token[:20])
    return attacker


# ----------------------------------------------------------------
# ATTACK 1: MISROUTE
# Attacker sends a message using their own legitimate credentials
# but targets a department they don't belong to (or a different hospital).
# Sub-cases:
#   1a — wrong department, same hospital  (broker may allow if no dept restriction)
#   1b — correct dept, wrong hospital     (should fail identity check)
#   1c — outsider (no token) targeting any dept
# ----------------------------------------------------------------
def attack_misroute(attacker: StaffMember):
    log.info("\n=== ATTACK 1: MISROUTE ===")

    payload = build_payload(
        hospital_id=attacker.hospital_id,
        department_id=VICTIM_DEPT,
        producer_id=attacker.staff_id,
        sequence=attacker.sequence,
        plaintext="MISROUTED: attacker injecting into wrong dept",
        consumer_kx_public_b64=attacker.kx_public,  # self-loop, doesn't matter
        sign_key_obj=attacker.sign_key_obj,
    )
    attacker.sequence += 1

    # 1a: valid token, own hospital, wrong department
    body = {
        "hospital": attacker.hospital_id,
        "department": VICTIM_DEPT,  # attacker's real dept is ATTACKER_DEPT
        "producer_id": attacker.staff_id,
        "sequence": attacker.sequence,
        **{k: payload[k] for k in ("nonce", "ciphertext", "envelope")},
    }
    resp = safe_request(
        "POST",
        f"{BROKER_URL}/enqueue",
        json=body,
        headers={"Authorization": f"Bearer {attacker.token}"},
        timeout=5,
    )
    record("MISROUTE", "insider → wrong dept, same hospital", 403, resp)

    # 1b: valid token, wrong hospital entirely
    body_wrong_hosp = {**body, "hospital": VICTIM_HOSPITAL}
    resp = safe_request(
        "POST",
        f"{BROKER_URL}/enqueue",
        json=body_wrong_hosp,
        headers={"Authorization": f"Bearer {attacker.token}"},
        timeout=5,
    )
    record("MISROUTE", "insider → different hospital", 403, resp)

    # 1c: no token at all
    resp = safe_request("POST", f"{BROKER_URL}/enqueue", json=body, timeout=5)
    record("MISROUTE", "outsider → no token", 401, resp)


# ----------------------------------------------------------------
# ATTACK 2: REPLAY
# Attacker captures a legitimate message (by reading from /dequeue
# which is unauthenticated in current broker) and replays it into
# a different department or re-sends it to the same stream.
# Sub-cases:
#   2a — replay to a different department (same hospital)
#   2b — replay exact same message to same dept (sequence collision)
#   2c — outsider replay (no token)
# ----------------------------------------------------------------
def attack_replay(attacker: StaffMember):
    log.info("\n=== ATTACK 2: REPLAY ===")

    # First, enqueue a legitimate message so we have something to capture
    payload = build_payload(
        hospital_id=attacker.hospital_id,
        department_id=ATTACKER_DEPT,
        producer_id=attacker.staff_id,
        sequence=attacker.sequence,
        plaintext="legitimate message about to be replayed",
        consumer_kx_public_b64=attacker.kx_public,
        sign_key_obj=attacker.sign_key_obj,
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

    # Now capture it from the unauthenticated /dequeue endpoint
    captured_items = []
    dequeue_resp = safe_request(
        "GET", f"{BROKER_URL}/dequeue/{attacker.hospital_id}/{ATTACKER_DEPT}", timeout=5
    )
    if dequeue_resp.status_code == 200:
        captured_items = dequeue_resp.json().get("items", [])
        log.info(
            "Captured %d message(s) from unauthenticated /dequeue", len(captured_items)
        )
    else:
        log.warning("Could not read from /dequeue: %d", dequeue_resp.status_code)

    if not captured_items:
        log.warning("No messages captured — skipping replay attacks")
        record("REPLAY", "insider → replay to different dept", 409, None)
        record("REPLAY", "insider → replay same dept (seq collision)", 409, None)
        record("REPLAY", "outsider → replay no token", 401, None)
        return

    captured = captured_items[-1]  # grab the most recent

    # 2a: replay to a different department (ciphertext is wrong for this dept but
    #     broker should reject on sequence/identity grounds before crypto)
    body_diff_dept = {
        "hospital": attacker.hospital_id,
        "department": VICTIM_DEPT,  # different dept
        "producer_id": captured["producer_id"],
        "sequence": captured["sequence"],
        "nonce": captured["nonce"],
        "ciphertext": captured["ciphertext"],
        "envelope": captured["envelope"],
    }
    resp = safe_request(
        "POST",
        f"{BROKER_URL}/enqueue",
        json=body_diff_dept,
        headers={"Authorization": f"Bearer {attacker.token}"},
        timeout=5,
    )
    record("REPLAY", "insider → replay to different dept", 409, resp)

    # 2b: replay exact same message to same dept (sequence already seen)
    body_same_dept = {**body_diff_dept, "department": ATTACKER_DEPT}
    resp = safe_request(
        "POST",
        f"{BROKER_URL}/enqueue",
        json=body_same_dept,
        headers={"Authorization": f"Bearer {attacker.token}"},
        timeout=5,
    )
    record("REPLAY", "insider → replay same dept (seq collision)", 409, resp)

    # 2c: outsider replays without a token
    resp = safe_request("POST", f"{BROKER_URL}/enqueue", json=body_diff_dept, timeout=5)
    record("REPLAY", "outsider → replay no token", 401, resp)


# ----------------------------------------------------------------
# ATTACK 3: IMPERSONATION
# Attacker has a valid token for their own staff_id but sends a
# message with a different producer_id (claiming to be someone else).
# Sub-cases:
#   3a — insider, valid token, forged producer_id (same hospital)
#   3b — insider, valid token, forged producer_id + wrong hospital
#   3c — outsider, no token, forged producer_id
# ----------------------------------------------------------------
def attack_impersonation(attacker: StaffMember):
    log.info("\n=== ATTACK 3: IMPERSONATION ===")

    victim_id = f"{HOSPITAL}_producer"  # a real staff member the attacker knows about

    # Build a payload signed with attacker's own key but claiming to be victim
    payload = build_payload(
        hospital_id=attacker.hospital_id,
        department_id=ATTACKER_DEPT,
        producer_id=victim_id,  # ← forged
        sequence=1,
        plaintext="IMPERSONATION: attacker pretending to be victim",
        consumer_kx_public_b64=attacker.kx_public,
        sign_key_obj=attacker.sign_key_obj,  # attacker's own key, not victim's
    )

    # 3a: valid token but producer_id doesn't match token's staff_id
    body = {
        "hospital": attacker.hospital_id,
        "department": ATTACKER_DEPT,
        "producer_id": victim_id,  # forged — broker checks identity.staff_id == producer_id
        "sequence": 1,
        **{k: payload[k] for k in ("nonce", "ciphertext", "envelope")},
    }
    resp = safe_request(
        "POST",
        f"{BROKER_URL}/enqueue",
        json=body,
        headers={"Authorization": f"Bearer {attacker.token}"},
        timeout=5,
    )
    record("IMPERSONATION", "insider → forged producer_id same hospital", 403, resp)

    # 3b: valid token, forged producer_id, wrong hospital
    body_wrong_hosp = {
        **body,
        "hospital": VICTIM_HOSPITAL,
        "producer_id": f"{VICTIM_HOSPITAL}_producer",
    }
    resp = safe_request(
        "POST",
        f"{BROKER_URL}/enqueue",
        json=body_wrong_hosp,
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
# Summary table
# ----------------------------------------------------------------
def print_summary():
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

    if vulns == 0 and errors == 0:
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
    log.info("MedLock Red Team starting...")

    attacker = setup_attacker()

    attack_misroute(attacker)
    attack_replay(attacker)
    attack_impersonation(attacker)

    print_summary()
