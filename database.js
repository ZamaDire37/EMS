const { DatabaseSync } = require('node:sqlite');
const bcrypt = require('bcryptjs');
const path = require('path');

const dbPath = path.join(__dirname, 'bucks_ems.db');
const db = new DatabaseSync(dbPath);

// Enable foreign keys & WAL mode for reliability
db.exec('PRAGMA foreign_keys = ON;');
db.exec('PRAGMA journal_mode = WAL;');

/**
 * Safely add a column to an existing table if it does not already exist.
 * Preserves all existing data.
 */
function ensureColumn(tableName, columnName, columnDef) {
  const cols = db.prepare(`PRAGMA table_info(${tableName})`).all();
  const exists = cols.some(c => c.name === columnName);
  if (!exists) {
    db.exec(`ALTER TABLE ${tableName} ADD COLUMN ${columnName} ${columnDef};`);
  }
}

function initDb() {
  // 1. Core existing tables
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      full_name TEXT NOT NULL,
      role TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
    CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

    CREATE TABLE IF NOT EXISTS patient_records (
      id TEXT PRIMARY KEY,
      patient_name TEXT NOT NULL,
      incident_type TEXT NOT NULL,
      primary_complaint TEXT NOT NULL,
      bp TEXT,
      pulse TEXT,
      spo2 TEXT,
      treatment TEXT,
      hospital TEXT,
      status TEXT NOT NULL,
      created_by TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_patient_records_created_at ON patient_records(created_at DESC);

    CREATE TABLE IF NOT EXISTS vehicle_checks (
      id TEXT PRIMARY KEY,
      vehicle_id TEXT NOT NULL,
      completed_checks TEXT NOT NULL,
      proof TEXT,
      passed INTEGER NOT NULL,
      created_by TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_vehicle_checks_created_at ON vehicle_checks(created_at DESC);

    CREATE TABLE IF NOT EXISTS asset_checks (
      id TEXT PRIMARY KEY,
      asset_name TEXT NOT NULL,
      category TEXT NOT NULL,
      status TEXT NOT NULL,
      notes TEXT,
      created_by TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_asset_checks_created_at ON asset_checks(created_at DESC);

    CREATE TABLE IF NOT EXISTS clinical_audits (
      id TEXT PRIMARY KEY,
      patient_record_id TEXT NOT NULL,
      record_label TEXT NOT NULL,
      outcome TEXT NOT NULL,
      notes TEXT,
      created_by TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_clinical_audits_created_at ON clinical_audits(created_at DESC);

    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      action TEXT NOT NULL,
      detail TEXT NOT NULL,
      role TEXT NOT NULL,
      user_id TEXT,
      timestamp TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
  `);

  // 2. Safe additive migrations on existing tables
  ensureColumn('users', 'position_title', 'TEXT');
  ensureColumn('users', 'fleet_management', 'INTEGER DEFAULT 0');
  ensureColumn('users', 'is_active', 'INTEGER DEFAULT 1');
  ensureColumn('users', 'custom_permissions', 'TEXT');

  ensureColumn('patient_records', 'incident_id', 'TEXT');
  ensureColumn('patient_records', 'patient_age', 'TEXT');
  ensureColumn('patient_records', 'patient_gender', 'TEXT');
  ensureColumn('patient_records', 'triage_priority', 'TEXT');
  ensureColumn('patient_records', 'past_history', 'TEXT');
  ensureColumn('patient_records', 'allergies', 'TEXT');
  ensureColumn('patient_records', 'current_medications', 'TEXT');
  ensureColumn('patient_records', 'resp_rate', 'TEXT');
  ensureColumn('patient_records', 'glucose', 'TEXT');
  ensureColumn('patient_records', 'temp', 'TEXT');
  ensureColumn('patient_records', 'gcs_score', 'TEXT');
  ensureColumn('patient_records', 'pain_score', 'TEXT');
  ensureColumn('patient_records', 'ecg_result', 'TEXT');
  ensureColumn('patient_records', 'airway_support', 'TEXT');
  ensureColumn('patient_records', 'meds_administered', 'TEXT');
  ensureColumn('patient_records', 'iv_fluids', 'TEXT');
  ensureColumn('patient_records', 'handover_doctor', 'TEXT');
  ensureColumn('patient_records', 'disposition', 'TEXT');
  ensureColumn('patient_records', 'is_returning', 'INTEGER DEFAULT 0');
  ensureColumn('patient_records', 'updated_by', 'TEXT');
  ensureColumn('patient_records', 'updated_at', 'TEXT');
  ensureColumn('patient_records', 'client_record_id', 'TEXT');

  ensureColumn('vehicle_checks', 'mileage', 'INTEGER');
  ensureColumn('vehicle_checks', 'notes', 'TEXT');

  ensureColumn('audit_logs', 'record_ref', 'TEXT');
  ensureColumn('audit_logs', 'user_name', 'TEXT');
  ensureColumn('audit_logs', 'ip_address', 'TEXT');

  // Protect audit_logs from modification or deletion at DB level
  db.exec(`
    CREATE TRIGGER IF NOT EXISTS prevent_audit_log_update
    BEFORE UPDATE ON audit_logs
    BEGIN
      SELECT RAISE(ABORT, 'Audit logs are immutable and cannot be modified');
    END;

    CREATE TRIGGER IF NOT EXISTS prevent_audit_log_delete
    BEFORE DELETE ON audit_logs
    BEGIN
      SELECT RAISE(ABORT, 'Audit logs are immutable and cannot be deleted');
    END;
  `);

  // 3. New tables for Incidents & Timeline, Staff Documents, Fleet & Vehicle Compliance, Reminder Settings, Role Permissions
  db.exec(`
    CREATE TABLE IF NOT EXISTS incidents (
      id TEXT PRIMARY KEY,
      call_received_at TEXT NOT NULL,
      caller_info TEXT,
      incident_type TEXT NOT NULL,
      location_address TEXT,
      location_lat REAL,
      location_lng REAL,
      priority TEXT NOT NULL,
      assigned_vehicle_id TEXT,
      assigned_crew TEXT,
      dispatcher_id TEXT,
      dispatcher_name TEXT,
      hospital_destination TEXT,
      patient_record_id TEXT,
      status TEXT NOT NULL,
      handover_confirmed_by TEXT,
      handover_confirmed_role TEXT,
      handover_confirmed_at TEXT,
      handover_notes TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
    CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents(created_at DESC);

    CREATE TABLE IF NOT EXISTS incident_timeline_events (
      id TEXT PRIMARY KEY,
      incident_id TEXT NOT NULL,
      event_type TEXT NOT NULL,
      event_label TEXT NOT NULL,
      occurred_at TEXT NOT NULL,
      recorded_by_id TEXT NOT NULL,
      recorded_by_name TEXT NOT NULL,
      recorded_by_role TEXT NOT NULL,
      gps_lat REAL,
      gps_lng REAL,
      gps_accuracy REAL,
      gps_auto INTEGER DEFAULT 0,
      offline_recorded INTEGER DEFAULT 0,
      client_event_id TEXT UNIQUE,
      is_corrected INTEGER DEFAULT 0,
      correction_reason TEXT,
      corrected_by TEXT,
      corrected_at TEXT,
      original_occurred_at TEXT,
      notes TEXT,
      FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_timeline_incident ON incident_timeline_events(incident_id, occurred_at ASC);

    CREATE TABLE IF NOT EXISTS staff_documents (
      id TEXT PRIMARY KEY,
      staff_user_id TEXT NOT NULL,
      staff_name TEXT NOT NULL,
      staff_role TEXT NOT NULL,
      doc_type TEXT NOT NULL,
      doc_number TEXT,
      issue_date TEXT,
      expiry_date TEXT,
      status TEXT NOT NULL,
      ocr_raw_text TEXT,
      ocr_confidence REAL,
      ocr_verified INTEGER DEFAULT 0,
      storage_filename TEXT NOT NULL,
      original_filename TEXT NOT NULL,
      mime_type TEXT NOT NULL,
      file_size INTEGER NOT NULL,
      sha256_hash TEXT NOT NULL,
      uploaded_by TEXT NOT NULL,
      verified_by TEXT,
      verified_at TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_staff_docs_user ON staff_documents(staff_user_id);
    CREATE INDEX IF NOT EXISTS idx_staff_docs_expiry ON staff_documents(expiry_date);

    CREATE TABLE IF NOT EXISTS reminder_settings (
      id TEXT PRIMARY KEY,
      intervals_days TEXT NOT NULL,
      notify_after_expiry INTEGER DEFAULT 1,
      updated_by TEXT,
      updated_at TEXT
    );

    CREATE TABLE IF NOT EXISTS vehicles (
      id TEXT PRIMARY KEY,
      registration_number TEXT NOT NULL,
      make_model TEXT NOT NULL,
      vehicle_type TEXT NOT NULL,
      status TEXT NOT NULL,
      last_service_date TEXT,
      last_service_mileage INTEGER,
      next_service_due_date TEXT,
      next_service_due_mileage INTEGER,
      service_interval_days INTEGER,
      service_interval_km INTEGER,
      licence_disc_expiry TEXT,
      roadworthy_expiry TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS vehicle_services (
      id TEXT PRIMARY KEY,
      vehicle_id TEXT NOT NULL,
      service_date TEXT NOT NULL,
      recorded_mileage INTEGER,
      work_performed TEXT NOT NULL,
      service_provider TEXT,
      cost REAL,
      next_service_date TEXT,
      next_service_mileage INTEGER,
      created_by TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY (vehicle_id) REFERENCES vehicles(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_vehicle_services_vid ON vehicle_services(vehicle_id, service_date DESC);

    CREATE TABLE IF NOT EXISTS vehicle_documents (
      id TEXT PRIMARY KEY,
      vehicle_id TEXT NOT NULL,
      service_id TEXT,
      doc_category TEXT NOT NULL,
      expiry_date TEXT,
      ocr_raw_text TEXT,
      ocr_verified INTEGER DEFAULT 0,
      storage_filename TEXT NOT NULL,
      original_filename TEXT NOT NULL,
      mime_type TEXT NOT NULL,
      file_size INTEGER NOT NULL,
      sha256_hash TEXT NOT NULL,
      uploaded_by TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY (vehicle_id) REFERENCES vehicles(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_vehicle_docs_vid ON vehicle_documents(vehicle_id);

    CREATE TABLE IF NOT EXISTS role_permissions (
      role TEXT PRIMARY KEY,
      permissions_json TEXT NOT NULL,
      updated_by TEXT,
      updated_at TEXT
    );
  `);

  // 4. Seed / backfill the 8 official positions safely (preserving existing users)
  const salt = bcrypt.genSaltSync(10);
  const defaultPasswordHash = bcrypt.hashSync('Password123!', salt);
  const now = new Date().toISOString();

  const eightPositions = [
    { id: 'usr-doctor', username: 'doctor', email: 'doctor@bucks.ems', full_name: 'Doctor / Medical Director', role: 'MEDICAL_DIRECTOR', position_title: 'Doctor / Medical Director', fleet_management: 0 },
    { id: 'usr-nurse', username: 'nurse', email: 'nurse@bucks.ems', full_name: 'Emergency / Training Nurse', role: 'TRIAGE_NURSE', position_title: 'Emergency / Training Nurse', fleet_management: 0 },
    { id: 'usr-medic', username: 'medic', email: 'medic@bucks.ems', full_name: 'Field Medic', role: 'FIELD_MEDIC', position_title: 'Field Medic', fleet_management: 0 },
    { id: 'usr-flight', username: 'flight', email: 'flight@bucks.ems', full_name: 'Flight Paramedic', role: 'FLIGHT_MEDIC', position_title: 'Flight Paramedic', fleet_management: 0 },
    { id: 'usr-manager', username: 'manager', email: 'manager@bucks.ems', full_name: 'Station Manager', role: 'STATION_MANAGER', position_title: 'Station Manager', fleet_management: 1 },
    { id: 'usr-auditor', username: 'auditor', email: 'auditor@bucks.ems', full_name: 'QA Clinical / Clinical Audit', role: 'QA_AUDITOR', position_title: 'QA Clinical / Clinical Audit', fleet_management: 0 },
    { id: 'usr-dispatcher', username: 'dispatcher', email: 'dispatcher@bucks.ems', full_name: 'EMS Dispatcher', role: 'DISPATCHER', position_title: 'EMS Dispatcher', fleet_management: 0 },
    { id: 'usr-admin', username: 'admin', email: 'admin@bucks.ems', full_name: 'IT Admin', role: 'IT_ADMIN', position_title: 'IT Admin', fleet_management: 0 }
  ];

  const insertUser = db.prepare(`
    INSERT OR IGNORE INTO users (id, username, email, password_hash, full_name, role, position_title, fleet_management, is_active, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
  `);
  for (const u of eightPositions) {
    insertUser.run(u.id, u.username, u.email, defaultPasswordHash, u.full_name, u.role, u.position_title, u.fleet_management, now);
  }
  // Ensure existing Station Manager has fleet_management=1 if not already set
  db.prepare(`UPDATE users SET fleet_management = 1 WHERE role = 'STATION_MANAGER' AND fleet_management IS NULL`).run();

  // 5. Seed default reminder settings
  const remCount = db.prepare('SELECT COUNT(*) as c FROM reminder_settings').get().c;
  if (remCount === 0) {
    const insRem = db.prepare(`INSERT INTO reminder_settings (id, intervals_days, notify_after_expiry, updated_by, updated_at) VALUES (?, ?, 1, 'SYSTEM', ?)`);
    insRem.run('staff_docs', JSON.stringify([30, 14, 7, 0]), now);
    insRem.run('vehicle_docs', JSON.stringify([30, 14, 7, 0]), now);
    insRem.run('vehicle_service', JSON.stringify([30, 14, 7, 0]), now);
  }

  // 6. Seed default vehicles if empty
  const vehCount = db.prepare('SELECT COUNT(*) as c FROM vehicles').get().c;
  if (vehCount === 0) {
    const in12Days = new Date(Date.now() + 12 * 86400000).toISOString().slice(0, 10);
    const in45Days = new Date(Date.now() + 45 * 86400000).toISOString().slice(0, 10);
    const past5Days = new Date(Date.now() - 5 * 86400000).toISOString().slice(0, 10);
    const lastSvc = new Date(Date.now() - 120 * 86400000).toISOString().slice(0, 10);

    const insVeh = db.prepare(`
      INSERT INTO vehicles (id, registration_number, make_model, vehicle_type, status, last_service_date, last_service_mileage, next_service_due_date, next_service_due_mileage, service_interval_days, service_interval_km, licence_disc_expiry, roadworthy_expiry, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    insVeh.run('AMB-001', 'BCK-001-GP', 'Mercedes-Benz Sprinter 516 CDI', 'Ambulance', 'Available', lastSvc, 84200, in45Days, 99200, 180, 15000, in45Days, in45Days, now, now);
    insVeh.run('AMB-002', 'BCK-002-GP', 'Volkswagen Crafter ALS', 'Ambulance', 'Available', lastSvc, 112500, in12Days, 122500, 120, 10000, in12Days, past5Days, now, now);
    insVeh.run('HELI-01', 'ZS-EMS-1', 'Airbus H135 Medevac', 'Helicopter', 'Available', lastSvc, null, in45Days, null, 90, null, in45Days, in45Days, now, now);
  }

  // 7. Seed a sample incident if empty
  const incCount = db.prepare('SELECT COUNT(*) as c FROM incidents').get().c;
  if (incCount === 0) {
    const t0 = new Date(Date.now() - 4800000).toISOString();
    const t1 = new Date(Date.now() - 4560000).toISOString();
    const t2 = new Date(Date.now() - 3900000).toISOString();
    const t3 = new Date(Date.now() - 3240000).toISOString();
    const t4 = new Date(Date.now() - 1980000).toISOString();
    const t5 = new Date(Date.now() - 1500000).toISOString();
    const t6 = new Date(Date.now() - 900000).toISOString();

    db.prepare(`
      INSERT INTO incidents (id, call_received_at, caller_info, incident_type, location_address, priority, assigned_vehicle_id, assigned_crew, dispatcher_id, dispatcher_name, hospital_destination, patient_record_id, status, handover_confirmed_by, handover_confirmed_role, handover_confirmed_at, handover_notes, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      'INC-DEMO-001', t0, 'Bystander Call (Demo)', 'Cardiac Event / STEMI', '14 High Street, Aylesbury, Bucks',
      'Red (P1 - Immediate / Resuscitation)', 'AMB-001', 'Field Medic Crew A', 'usr-dispatcher', 'EMS Dispatcher',
      'Central Hospital Cardiac Cath Lab', 'epcr-demo-001', 'AVAILABLE',
      'Emergency / Training Nurse', 'TRIAGE_NURSE', t5, 'Patient transferred to Cath Lab Bay 2, vitals stable.', t0, t6
    );

    const insEv = db.prepare(`
      INSERT INTO incident_timeline_events (id, incident_id, event_type, event_label, occurred_at, recorded_by_id, recorded_by_name, recorded_by_role, gps_auto)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
    `);
    insEv.run('ev-demo-1', 'INC-DEMO-001', 'CALL_RECEIVED', 'Emergency call received', t0, 'usr-dispatcher', 'EMS Dispatcher', 'DISPATCHER');
    insEv.run('ev-demo-2', 'INC-DEMO-001', 'AMBULANCE_DISPATCHED', 'Ambulance dispatched (AMB-001)', t1, 'usr-dispatcher', 'EMS Dispatcher', 'DISPATCHER');
    insEv.run('ev-demo-3', 'INC-DEMO-001', 'ARRIVED_SCENE', 'Arrived at scene', t2, 'usr-medic', 'Field Medic', 'FIELD_MEDIC');
    insEv.run('ev-demo-4', 'INC-DEMO-001', 'PATIENT_PICKED_UP', 'Patient picked up', t3, 'usr-medic', 'Field Medic', 'FIELD_MEDIC');
    insEv.run('ev-demo-5', 'INC-DEMO-001', 'ARRIVED_HOSPITAL', 'Arrived at hospital', t4, 'usr-medic', 'Field Medic', 'FIELD_MEDIC');
    insEv.run('ev-demo-6', 'INC-DEMO-001', 'PATIENT_HANDED_OVER', 'Patient handed over', t5, 'usr-medic', 'Field Medic', 'FIELD_MEDIC');
    insEv.run('ev-demo-7', 'INC-DEMO-001', 'AMBULANCE_AVAILABLE', 'Ambulance available again', t6, 'usr-dispatcher', 'EMS Dispatcher', 'DISPATCHER');
  }
}

initDb();

module.exports = db;
