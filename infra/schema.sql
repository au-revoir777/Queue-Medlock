-- Shared infrastructure tables (created by schema.sql at Postgres init time)
-- Services must NOT recreate these in their own _create_tables() calls.

CREATE TABLE IF NOT EXISTS hospitals (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS departments (
  id TEXT PRIMARY KEY,
  hospital_id TEXT NOT NULL REFERENCES hospitals(id) ON DELETE CASCADE,
  name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS staff (
  id TEXT PRIMARY KEY,
  hospital_id TEXT NOT NULL REFERENCES hospitals(id) ON DELETE CASCADE,
  role TEXT NOT NULL,
  public_sign_key TEXT NOT NULL,
  public_kx_key TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGSERIAL PRIMARY KEY,
  timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  producer_id TEXT NOT NULL,
  department TEXT NOT NULL,
  sequence BIGINT NOT NULL,
  verified BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS patients (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    age         INT,
    blood_type  TEXT,
    created_at  DOUBLE PRECISION NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())
);

CREATE TABLE IF NOT EXISTS clinical_records (
    id            BIGSERIAL PRIMARY KEY,
    hospital_id   TEXT NOT NULL,
    department    TEXT NOT NULL,
    patient_id    TEXT REFERENCES patients(id),
    patient_name  TEXT,
    producer_id   TEXT NOT NULL,
    message_type  TEXT NOT NULL,
    sequence      BIGINT NOT NULL,
    payload       JSONB NOT NULL,
    urgent        BOOLEAN DEFAULT FALSE,
    recorded_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_clinical_records_hospital_dept
    ON clinical_records (hospital_id, department);

CREATE INDEX IF NOT EXISTS idx_clinical_records_patient
    ON clinical_records (patient_id);

CREATE INDEX IF NOT EXISTS idx_clinical_records_recorded_at
    ON clinical_records (recorded_at DESC);

-- ✅ Auth service tables
CREATE TABLE IF NOT EXISTS auth_users (
    hospital_id   TEXT NOT NULL,
    staff_id      TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    department    TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'doctor',
    created_at    DOUBLE PRECISION NOT NULL,
    PRIMARY KEY (hospital_id, staff_id)
);

CREATE TABLE IF NOT EXISTS auth_tokens (
    token       TEXT PRIMARY KEY,
    hospital_id TEXT NOT NULL,
    staff_id    TEXT NOT NULL,
    department  TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT 'doctor',
    issued_at   DOUBLE PRECISION NOT NULL,
    expires_at  DOUBLE PRECISION NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_tokens_token
    ON auth_tokens (token);

CREATE INDEX IF NOT EXISTS idx_auth_tokens_expires_at
    ON auth_tokens (expires_at);

CREATE INDEX IF NOT EXISTS idx_auth_tokens_staff
    ON auth_tokens (hospital_id, staff_id);

-- ✅ KMS service tables
CREATE TABLE IF NOT EXISTS kms_keys (
    hospital_id     TEXT    NOT NULL,
    department_id   TEXT    NOT NULL,
    staff_id        TEXT    NOT NULL,
    public_sign_key TEXT    NOT NULL,
    public_kx_key   TEXT    NOT NULL,
    public_kem_key  TEXT    NOT NULL,
    public_dsa_key  TEXT    NOT NULL,
    registered_at   DOUBLE PRECISION NOT NULL,
    PRIMARY KEY (hospital_id, department_id, staff_id)
);

CREATE INDEX IF NOT EXISTS idx_kms_keys_scope
    ON kms_keys (hospital_id, department_id);

-- ✅ Tenant service tables
CREATE TABLE IF NOT EXISTS tenant_hospitals (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    created_at DOUBLE PRECISION NOT NULL
);

CREATE TABLE IF NOT EXISTS tenant_staff (
    id              TEXT PRIMARY KEY,
    hospital_id     TEXT NOT NULL REFERENCES tenant_hospitals(id),
    role            TEXT NOT NULL,
    department      TEXT NOT NULL,
    public_sign_key TEXT NOT NULL,
    public_kx_key   TEXT NOT NULL,
    public_kem_key  TEXT NOT NULL,
    public_dsa_key  TEXT NOT NULL,
    registered_at   DOUBLE PRECISION NOT NULL
);
