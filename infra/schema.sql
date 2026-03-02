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
    id          TEXT PRIMARY KEY,        -- e.g. P1001
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
    message_type  TEXT NOT NULL,         -- ICU_VITALS, ECG_REPORT, etc.
    sequence      BIGINT NOT NULL,
    payload       JSONB NOT NULL,        -- full decrypted record
    urgent        BOOLEAN DEFAULT FALSE,
    recorded_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_clinical_records_hospital_dept
    ON clinical_records (hospital_id, department);

CREATE INDEX IF NOT EXISTS idx_clinical_records_patient
    ON clinical_records (patient_id);

CREATE INDEX IF NOT EXISTS idx_clinical_records_recorded_at
    ON clinical_records (recorded_at DESC);
