#!/usr/bin/env python3
"""
MedLock RBAC Attack & Verification Script
==========================================
Simulates real attacker scenarios against every protected endpoint.
Each test is labelled BLOCKED (should get 403/401) or ALLOWED (should get 2xx).

Usage (your setup — single HTTPS gateway on port 8443):
    python rbac_attack_test.py

    Defaults:  --base https://localhost:8443
               --auth-prefix /auth
               --api-prefix  /clinical

    Override if your setup differs:
    python rbac_attack_test.py --base https://localhost:PORT
    python rbac_attack_test.py --base http://localhost:8001 --auth-prefix "" --api-prefix ""

SSL note:
    Self-signed certificates are handled automatically (verify=False).
    The InsecureRequestWarning is suppressed — this is intentional for a
    local dev/test environment. Never disable SSL verification in production.

Exit code:
    0 — all tests passed
    1 — one or more RBAC tests failed
    2 — services not reachable (fix Docker first)
"""

import argparse, json, sys, socket, subprocess, platform
import urllib3
from dataclasses import dataclass
from typing import Optional
import requests
from urllib.parse import urlparse

# ── Suppress the InsecureRequestWarning for self-signed certs ──────────────
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ────────────────────────────────────────────────────────────
# CLI args
# ────────────────────────────────────────────────────────────

parser = argparse.ArgumentParser(description="MedLock RBAC Attack Script")
parser.add_argument(
    "--base",
    default="https://localhost:8443",
    help="Gateway base URL (default: https://localhost:8443)",
)
parser.add_argument(
    "--auth-prefix",
    default="/auth",
    help="URL prefix for auth service routes (default: /auth)",
)
parser.add_argument(
    "--api-prefix",
    default="/clinical",
    help="URL prefix for clinical API routes (default: /clinical)",
)
parser.add_argument(
    "--verbose", action="store_true", help="Print full response bodies on failures"
)
args = parser.parse_args()

BASE = args.base.rstrip("/")
AUTH_PREFIX = args.auth_prefix.rstrip("/")
API_PREFIX = args.api_prefix.rstrip("/")


# Convenience builders
def AUTH_URL(path):
    return f"{BASE}{AUTH_PREFIX}{path}"


def API_URL(path):
    return f"{BASE}{API_PREFIX}{path}"


# All requests use verify=False (self-signed cert)
REQ_KWARGS = {"verify": False, "timeout": 8}

# ────────────────────────────────────────────────────────────
# Colours
# ────────────────────────────────────────────────────────────

G = "\033[92m"
R = "\033[91m"
Y = "\033[93m"
C = "\033[96m"
B = "\033[1m"
D = "\033[2m"
X = "\033[0m"


def ok(msg):
    print(f"  {G}✓ PASS{X}  {msg}")


def fail(msg):
    print(f"  {R}✗ FAIL{X}  {msg}")


def info(msg):
    print(f"  {C}ℹ{X}  {msg}")


def warn(msg):
    print(f"  {Y}⚠ WARN{X}  {msg}")


def section(t):
    print(f"\n{B}{C}{'─'*60}{X}\n{B}{C}  {t}{X}\n{B}{C}{'─'*60}{X}")


# ────────────────────────────────────────────────────────────
# Pre-flight
# ────────────────────────────────────────────────────────────


def preflight():
    section("PRE-FLIGHT: Service Connectivity Check")

    p = urlparse(BASE)
    host = p.hostname or "localhost"
    port = p.port or (443 if p.scheme == "https" else 80)

    # TCP check
    tcp_ok = False
    try:
        s = socket.create_connection((host, port), timeout=4)
        s.close()
        tcp_ok = True
    except OSError:
        pass

    if not tcp_ok:
        print(f"  {R}✗{X}  Cannot reach {C}{BASE}{X} on TCP {host}:{port}")
        _docker_hint()
        sys.exit(2)

    # Health checks on both prefixes
    all_ok = True
    for label, url in [
        ("Auth service ", AUTH_URL("/health")),
        ("Clinical API ", API_URL("/health")),
    ]:
        try:
            r = requests.get(url, **REQ_KWARGS)
            if r.status_code < 500:
                print(f"  {G}✓{X}  {label}  {C}{url}{X}  →  HTTP {r.status_code}")
            else:
                print(
                    f"  {Y}⚠{X}  {label}  {C}{url}{X}  →  HTTP {r.status_code} (server error)"
                )
                all_ok = False
        except Exception as e:
            print(f"  {R}✗{X}  {label}  {C}{url}{X}  →  {R}{e}{X}")
            all_ok = False

    if not all_ok:
        print(f"\n{B}{R}  One or more /health endpoints unreachable.{X}")
        print(f"  If your prefixes differ, re-run with:")
        print(
            f"    python rbac_attack_test.py --base {BASE} --auth-prefix /YOUR_AUTH --api-prefix /YOUR_API\n"
        )
        _docker_hint()
        sys.exit(2)

    print(f"\n  {G}{B}All services reachable — starting RBAC tests.{X}\n")


def _docker_hint():
    print(f"\n{B}  Checking Docker...{X}")
    try:
        out = subprocess.run(
            ["docker", "ps", "--format", "table {{.Names}}\t{{.Status}}\t{{.Ports}}"],
            capture_output=True,
            text=True,
            timeout=6,
        )
        if out.returncode == 0:
            lines = out.stdout.strip().splitlines()
            if len(lines) <= 1:
                print(f"  {Y}⚠{X}  Docker running but {Y}no containers are up{X}.")
                print(f"       Run:  {B}docker-compose up -d{X}")
            else:
                print(f"  {G}✓{X}  Running containers:")
                for ln in lines:
                    print(f"       {ln}")
                if not any(
                    k in out.stdout.lower()
                    for k in ["clinical", "auth", "medlock", "broker", "kms"]
                ):
                    print(f"\n  {Y}⚠{X}  MedLock containers not visible.")
                    print(f"       Run:  {B}docker-compose up -d{X}")
        else:
            raise FileNotFoundError
    except FileNotFoundError:
        print(f"  {R}✗{X}  Docker not running.")
        if platform.system() == "Windows":
            print(f"       Open {B}Docker Desktop{X} and wait for the engine to start.")
        else:
            print(f"       Run:  {B}sudo systemctl start docker{X}")

    print(f"\n{B}  Quick-start:{X}")
    print(f"    cd zero-trust-main && docker-compose up -d")
    print(f"    # wait ~15 s, then: python rbac_attack_test.py\n")


preflight()

# ────────────────────────────────────────────────────────────
# Demo accounts  (from Login.tsx)
# ────────────────────────────────────────────────────────────

ACCOUNTS = {
    "dr_ahmed_h1": ("hospital1", "dr_ahmed"),
    "nurse_priya_h1": ("hospital1", "nurse_priya"),
    "dr_chen_h1": ("hospital1", "dr_chen"),
    "dr_patel_h1": ("hospital1", "dr_patel"),
    "dr_okonkwo_h1": ("hospital1", "dr_okonkwo"),
    "dr_hassan_h2": ("hospital2", "dr_hassan"),
    "nurse_sara_h2": ("hospital2", "nurse_sara"),
    "admin_lee_h2": ("hospital2", "admin_lee"),
    "dr_reyes_h2": ("hospital2", "dr_reyes"),
    "dr_dube_h2": ("hospital2", "dr_dube"),
}

ALL_DEPTS = ["icu", "cardiology", "radiology", "neurology", "oncology"]

# ────────────────────────────────────────────────────────────
# Result tracking
# ────────────────────────────────────────────────────────────


@dataclass
class Result:
    name: str
    passed: bool
    expected: str
    got: int | str
    detail: str = ""


results: list[Result] = []


def record(name, passed, expected, got, detail=""):
    results.append(Result(name, passed, str(expected), got, detail))
    msg = f"{name} {D}(expected {expected}, got [{got}]){X}"
    if detail:
        msg += f" — {D}{detail}{X}"
    ok(msg) if passed else fail(msg)
    if args.verbose and not passed and detail:
        print(f"    {D}{detail[:400]}{X}")


# ────────────────────────────────────────────────────────────
# Token / identity cache
# ────────────────────────────────────────────────────────────

_tokens: dict[str, str] = {}
_identities: dict[str, dict] = {}


def get_token(alias: str) -> Optional[str]:
    if alias in _tokens:
        return _tokens[alias]
    hospital, staff_id = ACCOUNTS[alias]
    try:
        r = requests.post(
            AUTH_URL("/login"),
            json={"hospital_id": hospital, "staff_id": staff_id, "password": "pass123"},
            **REQ_KWARGS,
        )
        if r.status_code != 200:
            warn(f"Login failed for {alias}: HTTP {r.status_code}  {r.text[:120]}")
            return None
        data = r.json()
        token = data.get("access_token") or data.get("token")
        if not token:
            warn(f"Login response for {alias} has no token field: {data}")
            return None
        _tokens[alias] = token

        # Fetch identity (role / dept)
        v = requests.post(AUTH_URL("/validate"), json={"token": token}, **REQ_KWARGS)
        if v.status_code == 200:
            _identities[alias] = v.json()
            ident = _identities[alias]
            info(
                f"{alias:20s}  role={ident.get('role','?'):8s}  dept={ident.get('department','?')}"
                f"  hospital={ident.get('hospital_id','?')}"
            )
        else:
            warn(f"Could not validate token for {alias}: {v.status_code}")
        return token
    except Exception as e:
        warn(f"Login failed for {alias}: {e}")
        return None


def hdrs(alias: str) -> dict:
    tok = get_token(alias)
    return {"Authorization": f"Bearer {tok}"} if tok else {}


def ident(alias: str) -> dict:
    return _identities.get(alias, {})


# ────────────────────────────────────────────────────────────
# HTTP test helpers
# ────────────────────────────────────────────────────────────


def GET(path, alias, *, expect, name, detail=""):
    tok = get_token(alias)
    if not tok:
        record(name, False, expect, 0, "could not obtain token")
        return None
    try:
        r = requests.get(API_URL(path), headers=hdrs(alias), **REQ_KWARGS)
        record(name, r.status_code == expect, expect, r.status_code, detail)
        if args.verbose and r.status_code != expect:
            print(f"    {D}body: {r.text[:300]}{X}")
        return r
    except Exception as e:
        record(name, False, expect, 0, str(e))
        return None


def GET_noauth(path, *, name, detail=""):
    try:
        r = requests.get(API_URL(path), **REQ_KWARGS)
        record(name, r.status_code == 401, 401, r.status_code, detail)
    except Exception as e:
        record(name, False, 401, 0, str(e))


def POST(path, alias, body, *, expect, name, detail=""):
    tok = get_token(alias)
    if not tok:
        record(name, False, expect, 0, "could not obtain token")
        return None
    try:
        r = requests.post(API_URL(path), headers=hdrs(alias), json=body, **REQ_KWARGS)
        record(name, r.status_code == expect, expect, r.status_code, detail)
        if args.verbose and r.status_code != expect:
            print(f"    {D}body: {r.text[:300]}{X}")
        return r
    except Exception as e:
        record(name, False, expect, 0, str(e))
        return None


def WS_check(path, alias, *, expect_blocked, name, detail=""):
    try:
        import websocket as ws_lib
    except ImportError:
        warn(f"websocket-client not installed — skipping: {name}")
        warn("  pip install websocket-client")
        return

    tok = get_token(alias)
    if not tok:
        record(name, False, "blocked" if expect_blocked else "open", 0, "no token")
        return

    msgs = []
    errors = []
    closed = []

    def on_msg(ws, m):
        msgs.append(json.loads(m))
        ws.close()

    def on_err(ws, e):
        errors.append(str(e))

    def on_close(ws, c, r):
        closed.append((c, r))

    ws_url = BASE.replace("https://", "wss://").replace("http://", "ws://")
    ws_url += f"{API_PREFIX}{path}?token={tok}"

    wsc = ws_lib.WebSocketApp(
        ws_url, on_message=on_msg, on_error=on_err, on_close=on_close
    )
    wsc.run_forever(ping_timeout=5, sslopt={"cert_reqs": 0})  # skip SSL verify

    got_blocked = (
        any(m.get("type") == "error" for m in msgs)
        or any(c[0] == 1008 for c in closed)
        or bool(errors)
    )
    record(
        name,
        got_blocked == expect_blocked,
        "blocked" if expect_blocked else "open",
        "blocked" if got_blocked else "open",
        detail,
    )


# ────────────────────────────────────────────────────────────
# Helper: find aliases by role/dept/hospital
# ────────────────────────────────────────────────────────────


def find(role=None, dept=None, hospital=None) -> Optional[str]:
    for alias, i in _identities.items():
        if role and i.get("role") != role:
            continue
        if dept and i.get("department") != dept:
            continue
        if hospital and i.get("hospital_id") != hospital:
            continue
        return alias
    return None


def find_admin(hospital=None) -> Optional[str]:
    return find(role="admin", hospital=hospital)


# ════════════════════════════════════════════════════════════
# PHASE 0 — Authenticate all accounts
# ════════════════════════════════════════════════════════════

section("PHASE 0 — Authenticate all demo accounts")
for alias in ACCOUNTS:
    get_token(alias)

admin_alias = find_admin()
if not admin_alias:
    warn("No admin account found in either hospital — some tests will be skipped")

# ════════════════════════════════════════════════════════════
# PHASE 1 — Unauthenticated / forged token (expect 401)
# ════════════════════════════════════════════════════════════

section("PHASE 1 — Unauthenticated Attacks  (expect 401)")

GET_noauth("/records/hospital1", name="No token → hospital records")
GET_noauth("/records/hospital1/icu", name="No token → dept records")
GET_noauth("/records/hospital1/icu/urgent", name="No token → urgent records")
GET_noauth("/records/detail/1", name="No token → record detail")
GET_noauth("/audit/hospital1", name="No token → audit log")
GET_noauth("/patients", name="No token → patient list")
GET_noauth("/me/permissions", name="No token → permissions")

# Forged JWT
try:
    r = requests.get(
        API_URL("/records/hospital1"),
        headers={"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.fake.sig"},
        **REQ_KWARGS,
    )
    record(
        "Forged JWT → hospital records",
        r.status_code == 401,
        401,
        r.status_code,
        "fabricated token must be rejected",
    )
except Exception as e:
    record("Forged JWT → hospital records", False, 401, 0, str(e))

# ════════════════════════════════════════════════════════════
# PHASE 2 — Cross-hospital attacks (expect 403)
# ════════════════════════════════════════════════════════════

section("PHASE 2 — Cross-Hospital Attacks  (expect 403)")

h1_any = find(hospital="hospital1")
h2_any = find(hospital="hospital2")

if h1_any:
    info(f"Attacker: {h1_any} (hospital1)  →  target: hospital2")
    GET(
        "/records/hospital2",
        h1_any,
        expect=403,
        name="h1 user → h2 hospital records",
        detail="cross-hospital read",
    )
    GET(
        "/records/hospital2/icu",
        h1_any,
        expect=403,
        name="h1 user → h2 dept records",
        detail="cross-hospital dept",
    )
    GET(
        "/records/hospital2/icu/urgent",
        h1_any,
        expect=403,
        name="h1 user → h2 urgent records",
        detail="cross-hospital urgent",
    )
    GET(
        "/audit/hospital2",
        h1_any,
        expect=403,
        name="h1 user → h2 audit log",
        detail="cross-hospital audit",
    )
else:
    warn("No hospital1 user logged in — skipping cross-hospital tests")

if h2_any and h2_any != admin_alias:
    info(f"Attacker: {h2_any} (hospital2)  →  target: hospital1")
    GET(
        "/records/hospital1",
        h2_any,
        expect=403,
        name="h2 user → h1 hospital records",
        detail="cross-hospital read",
    )

# ════════════════════════════════════════════════════════════
# PHASE 3 — Cross-department read attacks (expect 403)
# ════════════════════════════════════════════════════════════

section("PHASE 3 — Cross-Department Read Attacks  (expect 403)")

for alias, i in _identities.items():
    if i.get("role") == "admin":
        continue
    dept = i.get("department", "")
    hospital = i.get("hospital_id", "")
    others = [d for d in ALL_DEPTS if d != dept]
    if not others:
        continue

    target = others[0]
    GET(
        f"/records/{hospital}/{target}",
        alias,
        expect=403,
        name=f"{alias} ({dept}) → reads {target} records",
        detail=f"cross-dept: own={dept} target={target}",
    )
    GET(
        f"/records/{hospital}/{target}/urgent",
        alias,
        expect=403,
        name=f"{alias} ({dept}) → reads {target} urgent",
        detail="cross-dept urgent",
    )

# ════════════════════════════════════════════════════════════
# PHASE 4 — Hospital-wide feed, non-admin blocked (expect 403)
# ════════════════════════════════════════════════════════════

section("PHASE 4 — Hospital-Wide Feed  (non-admin blocked, expect 403)")

for alias, i in _identities.items():
    if i.get("role") == "admin":
        continue
    hospital = i.get("hospital_id", "")
    GET(
        f"/records/{hospital}",
        alias,
        expect=403,
        name=f"{alias} ({i.get('role')}/{i.get('department')}) → hospital-wide feed",
        detail="non-admin hospital-wide read must be blocked",
    )

# ════════════════════════════════════════════════════════════
# PHASE 5 — Record ID enumeration attack (expect 403 / 404)
# ════════════════════════════════════════════════════════════

section("PHASE 5 — Record ID Enumeration Attack  (expect 403)")

if admin_alias:
    admin_hospital = ident(admin_alias).get("hospital_id", "")
    r = requests.get(
        API_URL(f"/records/{admin_hospital}"), headers=hdrs(admin_alias), **REQ_KWARGS
    )
    if r.status_code == 200:
        all_recs = r.json().get("records", [])
        dept_ids: dict[str, list[int]] = {}
        for rec in all_recs:
            dept_ids.setdefault(rec.get("department", ""), []).append(rec["id"])

        for alias, i in _identities.items():
            if i.get("role") == "admin":
                continue
            dept = i.get("department", "")
            hospital = i.get("hospital_id", "")
            if hospital != admin_hospital:
                continue
            other_ids = [rid for d, ids in dept_ids.items() if d != dept for rid in ids]
            if not other_ids:
                continue
            GET(
                f"/records/detail/{other_ids[0]}",
                alias,
                expect=403,
                name=f"{alias} ({dept}) → ID-enumerate record from different dept (id={other_ids[0]})",
                detail="ID enumeration cross-dept attack",
            )
            break
    else:
        warn(
            f"Could not fetch hospital records as admin ({r.status_code}) — skipping phase 5"
        )
else:
    warn("No admin token — skipping ID enumeration test")

# ════════════════════════════════════════════════════════════
# PHASE 6 — Audit log, non-admin blocked (expect 403)
# ════════════════════════════════════════════════════════════

section("PHASE 6 — Audit Log Access  (non-admin blocked, expect 403)")

for alias, i in _identities.items():
    if i.get("role") == "admin":
        continue
    GET(
        f"/audit/{i.get('hospital_id','')}",
        alias,
        expect=403,
        name=f"{alias} ({i.get('role')}/{i.get('department')}) → audit log",
        detail="non-admin audit access must be blocked",
    )

# ════════════════════════════════════════════════════════════
# PHASE 7 — Send message RBAC violations (expect 403)
# ════════════════════════════════════════════════════════════

section("PHASE 7 — Send Message RBAC Violations  (expect 403)")

BASE_SEND = {
    "patient_id": "PT-ATTACK-001",
    "patient_name": "Attack Patient",
    "payload": {"note": "rbac test"},
    "urgent": False,
}

# 7a — Doctor sends to a different department
doc = find(role="doctor")
if doc:
    own_dept = ident(doc).get("department", "")
    wrong_dept = next(d for d in ALL_DEPTS if d != own_dept)
    POST(
        "/messages/send",
        doc,
        {**BASE_SEND, "department": wrong_dept, "message_type": "ICU_VITALS"},
        expect=403,
        name=f"{doc} ({own_dept}) → sends to wrong dept ({wrong_dept})",
        detail="department mismatch",
    )

# 7b — Admin tries to send (admin has no send permissions)
if admin_alias:
    admin_dept = ident(admin_alias).get("department", "icu")
    POST(
        "/messages/send",
        admin_alias,
        {**BASE_SEND, "department": admin_dept, "message_type": "ICU_VITALS"},
        expect=403,
        name=f"{admin_alias} (admin) → sends message",
        detail="admin role has no send permissions",
    )

# 7c — Nurse uses a doctor-only message type
nurse_icu = find(role="nurse", dept="icu")
if nurse_icu:
    POST(
        "/messages/send",
        nurse_icu,
        {**BASE_SEND, "department": "icu", "message_type": "CODE_ALERT"},
        expect=403,
        name=f"{nurse_icu} (nurse/icu) → CODE_ALERT (doctor-only)",
        detail="message type not permitted for nurse",
    )

# 7d — Doctor sends wrong message type for their dept
if doc:
    own_dept = ident(doc).get("department", "")
    wrong_msg = "ECG_REPORT" if own_dept != "cardiology" else "ICU_VITALS"
    POST(
        "/messages/send",
        doc,
        {**BASE_SEND, "department": own_dept, "message_type": wrong_msg},
        expect=403,
        name=f"{doc} ({own_dept}) → wrong msg type ({wrong_msg})",
        detail="message type not in permitted list for dept",
    )

# 7e — Nurse in neurology sends a cardiology message type
nurse_neuro = find(role="nurse", dept="neurology")
if nurse_neuro:
    POST(
        "/messages/send",
        nurse_neuro,
        {**BASE_SEND, "department": "neurology", "message_type": "ECG_REPORT"},
        expect=403,
        name=f"{nurse_neuro} (nurse/neurology) → ECG_REPORT (wrong type)",
        detail="ECG_REPORT not in nurse/neurology permitted list",
    )

# ════════════════════════════════════════════════════════════
# PHASE 8 — Patient records dept scoping
# ════════════════════════════════════════════════════════════

section("PHASE 8 — Patient Records Cross-Dept Scoping")

if admin_alias:
    admin_hospital = ident(admin_alias).get("hospital_id", "")
    rp = requests.get(API_URL("/patients"), headers=hdrs(admin_alias), **REQ_KWARGS)
    if rp.status_code == 200:
        patients = rp.json().get("patients", [])
        if patients:
            pid = patients[0]["id"]
            for alias, i in _identities.items():
                if i.get("role") == "admin":
                    continue
                if i.get("hospital_id") != admin_hospital:
                    continue
                dept = i.get("department", "")
                r = requests.get(
                    API_URL(f"/patients/{pid}/records"),
                    headers=hdrs(alias),
                    **REQ_KWARGS,
                )
                if r.status_code == 200:
                    recs = r.json().get("records", [])
                    cross_recs = [x for x in recs if x.get("department") != dept]
                    passed = len(cross_recs) == 0
                    record(
                        f"{alias} ({dept}) patient records — no cross-dept leak",
                        passed,
                        "0 cross-dept records",
                        (
                            f"{len(cross_recs)} cross-dept records leaked"
                            if not passed
                            else "0"
                        ),
                        f"total records returned: {len(recs)}",
                    )
                break
        else:
            warn("No patients in DB — skipping phase 8")
    else:
        warn(f"Could not list patients as admin ({rp.status_code}) — skipping phase 8")
else:
    warn("No admin token — skipping patient records scoping test")

# ════════════════════════════════════════════════════════════
# PHASE 9 — Admin legitimate access (expect 200)
# ════════════════════════════════════════════════════════════

section("PHASE 9 — Admin Legitimate Access  (expect 200)")

if admin_alias:
    h = ident(admin_alias).get("hospital_id", "")
    GET(f"/records/{h}", admin_alias, expect=200, name="admin → hospital-wide records")
    GET(f"/records/{h}/icu", admin_alias, expect=200, name="admin → icu dept records")
    GET(
        f"/records/{h}/oncology",
        admin_alias,
        expect=200,
        name="admin → oncology dept records",
    )
    GET(f"/audit/{h}", admin_alias, expect=200, name="admin → audit log")
    GET("/patients", admin_alias, expect=200, name="admin → patient list")
    GET("/me/permissions", admin_alias, expect=200, name="admin → permissions")
else:
    warn("No admin token — skipping phase 9")

# ════════════════════════════════════════════════════════════
# PHASE 10 — Doctor/nurse legitimate own-dept access (expect 200)
# ════════════════════════════════════════════════════════════

section("PHASE 10 — Legitimate Own-Dept Access  (expect 200)")

tested = set()
for alias, i in _identities.items():
    if i.get("role") == "admin":
        continue
    dept = i.get("department", "")
    hospital = i.get("hospital_id", "")
    if dept in tested:
        continue
    tested.add(dept)
    GET(
        f"/records/{hospital}/{dept}",
        alias,
        expect=200,
        name=f"{alias} ({i.get('role')}/{dept}) → own dept records",
    )
    GET(
        f"/records/{hospital}/{dept}/urgent",
        alias,
        expect=200,
        name=f"{alias} ({i.get('role')}/{dept}) → own dept urgent records",
    )
    GET("/patients", alias, expect=200, name=f"{alias} → patient list (own hospital)")
    GET("/me/permissions", alias, expect=200, name=f"{alias} → permissions endpoint")

# ════════════════════════════════════════════════════════════
# PHASE 11 — WebSocket dept isolation
# ════════════════════════════════════════════════════════════

section("PHASE 11 — WebSocket Department Isolation")

try:
    import websocket  # noqa

    ws_ok = True
except ImportError:
    ws_ok = False
    warn("websocket-client not installed — skipping WS tests")
    warn("  pip install websocket-client")

if ws_ok:
    tested_ws = set()
    for alias, i in _identities.items():
        if i.get("role") == "admin":
            continue
        dept = i.get("department", "")
        hospital = i.get("hospital_id", "")
        others = [d for d in ALL_DEPTS if d != dept]
        if not others or dept in tested_ws:
            continue
        tested_ws.add(dept)
        target = others[0]
        WS_check(
            f"/ws/{hospital}/{target}",
            alias,
            expect_blocked=True,
            name=f"WS: {alias} ({dept}) → {target} feed blocked",
            detail="cross-dept WS must be rejected",
        )
        WS_check(
            f"/ws/{hospital}/{dept}",
            alias,
            expect_blocked=False,
            name=f"WS: {alias} ({dept}) → own dept feed allowed",
            detail="own-dept WS must succeed",
        )

    if admin_alias:
        ah = ident(admin_alias).get("hospital_id", "")
        WS_check(
            f"/ws/{ah}",
            admin_alias,
            expect_blocked=False,
            name=f"WS: {admin_alias} (admin) → hospital-wide feed allowed",
        )
        non_admin = find(hospital=ah, role="doctor") or find(hospital=ah, role="nurse")
        if non_admin:
            WS_check(
                f"/ws/{ah}",
                non_admin,
                expect_blocked=True,
                name=f"WS: {non_admin} (non-admin) → hospital-wide feed blocked",
                detail="non-admin must not open hospital-wide stream",
            )

# ════════════════════════════════════════════════════════════
# Final report
# ════════════════════════════════════════════════════════════

section("RESULTS SUMMARY")

passed = [r for r in results if r.passed]
failed = [r for r in results if not r.passed]

print(f"\n  Total  : {B}{len(results)}{X}")
print(f"  {G}Passed : {len(passed)}{X}")
print(f"  {R if failed else G}Failed : {len(failed)}{X}")

if failed:
    print(f"\n{B}{R}  FAILED TESTS:{X}")
    for r in failed:
        print(f"  {R}✗{X} {r.name}")
        print(f"      expected={r.expected}  got={r.got}  detail={r.detail}")
    print()
    sys.exit(1)
else:
    print(f"\n  {G}{B}All RBAC tests passed. Zero trust enforcement verified. ✓{X}\n")
    sys.exit(0)
