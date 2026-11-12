const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');

const db = require('./database');
const {
  JWT_SECRET,
  POSITIONS,
  DEFAULT_ROLE_PERMISSIONS,
  getUserEffectivePermissions,
  hasPermission,
  writeAuditLog,
  requireAuth,
  requirePermission
} = require('./rbac');
const { extractDocumentOcr } = require('./ocr');

const app = express();
const PORT = process.env.PORT || 3000;

// Private storage directories (never exposed via static routes)
const PRIVATE_STAFF_DIR = path.join(__dirname, 'private_storage', 'staff_docs');
const PRIVATE_VEHICLE_DIR = path.join(__dirname, 'private_storage', 'vehicle_docs');
fs.mkdirSync(PRIVATE_STAFF_DIR, { recursive: true });
fs.mkdirSync(PRIVATE_VEHICLE_DIR, { recursive: true });

app.use(cors());
app.use(express.json({ limit: '5mb' }));

// Serve only explicit frontend files (never expose DB, server.js, or private_storage)
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/index.html', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/styles.css', (req, res) => res.sendFile(path.join(__dirname, 'styles.css')));
app.get('/app.js', (req, res) => res.sendFile(path.join(__dirname, 'app.js')));

// Multer in-memory upload (max 10 MB) with strict magic-byte validation
const ALLOWED_MIMES = {
  'image/jpeg': '.jpg',
  'image/png': '.png',
  'image/webp': '.webp',
  'application/pdf': '.pdf'
};

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (!ALLOWED_MIMES[file.mimetype]) {
      return cb(new Error('Unsupported file type. Allowed: JPEG, PNG, WebP, PDF.'));
    }
    cb(null, true);
  }
});

function verifyMagicBytes(buffer, mimeType) {
  if (!buffer || buffer.length < 4) return false;
  if (mimeType === 'application/pdf') {
    return buffer.slice(0, 4).toString('ascii') === '%PDF';
  }
  if (mimeType === 'image/jpeg') {
    return buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff;
  }
  if (mimeType === 'image/png') {
    return buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4e && buffer[3] === 0x47;
  }
  if (mimeType === 'image/webp') {
    return buffer.length >= 12 && buffer.slice(0, 4).toString('ascii') === 'RIFF' && buffer.slice(8, 12).toString('ascii') === 'WEBP';
  }
  return false;
}

function savePrivateFile(buffer, mimeType, targetDir) {
  if (!verifyMagicBytes(buffer, mimeType)) {
    throw new Error('File content does not match declared file type.');
  }
  const ext = ALLOWED_MIMES[mimeType] || '.bin';
  const storageFilename = `${crypto.randomUUID()}${ext}`;
  const fullPath = path.join(targetDir, storageFilename);
  fs.writeFileSync(fullPath, buffer);
  const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');
  return { storageFilename, sha256, fileSize: buffer.length };
}

function computeDocStatus(expiryDate, currentStatus) {
  if (currentStatus === 'Renewal submitted / awaiting verification') return currentStatus;
  if (!expiryDate) return 'Valid';
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const exp = new Date(expiryDate + 'T00:00:00');
  const diffDays = Math.ceil((exp - today) / 86400000);
  if (diffDays < 0) return 'Expired';
  if (diffDays <= 30) return 'Expiring soon';
  return 'Valid';
}

function daysUntil(dateStr) {
  if (!dateStr) return null;
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const target = new Date(dateStr + 'T00:00:00');
  return Math.ceil((target - today) / 86400000);
}

// ================= HEALTH =================
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', message: 'Bucks EMS Cloud Hub API + SQLite running securely.' });
});

// ================= AUTHENTICATION =================
function issueAuthResponse(user, req, methodLabel) {
  const token = jwt.sign(
    { id: user.id, role: user.role, username: user.username },
    JWT_SECRET,
    { expiresIn: '12h' }
  );
  const permissions = getUserEffectivePermissions(user);
  writeAuditLog({
    action: 'USER_LOGIN',
    detail: `${methodLabel} as ${user.full_name} (${POSITIONS[user.role] || user.role})`,
    role: user.role,
    userId: user.id,
    userName: user.full_name,
    ipAddress: req.ip
  });
  return {
    token,
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      full_name: user.full_name,
      role: user.role,
      position_title: user.position_title || POSITIONS[user.role] || user.role,
      fleet_management: !!user.fleet_management
    },
    permissions
  };
}

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }
  const user = db.prepare('SELECT * FROM users WHERE username = ? OR email = ?').get(username.trim(), username.trim());
  if (!user || !user.is_active || !bcrypt.compareSync(password, user.password_hash)) {
    writeAuditLog({
      action: 'LOGIN_FAILED',
      detail: `Failed login attempt for "${username}"`,
      role: 'ANONYMOUS',
      ipAddress: req.ip
    });
    return res.status(401).json({ error: 'Invalid credentials or inactive account.' });
  }
  res.json(issueAuthResponse(user, req, 'Password login'));
});

// Position-selector demo login (issues a real signed JWT for backend-enforced RBAC)
const DEMO_USERNAME_BY_KEY = {
  doctor: 'doctor',
  nurse: 'nurse',
  medic: 'medic',
  flight: 'flight',
  manager: 'manager',
  auditor: 'auditor',
  dispatcher: 'dispatcher',
  admin: 'admin'
};

app.post('/api/auth/demo-login', (req, res) => {
  const { positionKey } = req.body || {};
  const uname = DEMO_USERNAME_BY_KEY[positionKey];
  if (!uname) {
    return res.status(400).json({ error: 'Invalid EMS position selection.' });
  }
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(uname);
  if (!user || !user.is_active) {
    return res.status(403).json({ error: 'Selected position account is disabled.' });
  }
  res.json(issueAuthResponse(user, req, 'Position selector login'));
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({
    user: {
      ...req.user,
      position_title: req.user.position_title || POSITIONS[req.user.role] || req.user.role,
      fleet_management: !!req.user.fleet_management
    },
    permissions: getUserEffectivePermissions(req.user)
  });
});

// ================= INCIDENTS & EMERGENCY RESPONSE TIMELINE =================
app.get('/api/incidents', requireAuth, requirePermission('incidents', 'view'), (req, res) => {
  const incidents = db.prepare('SELECT * FROM incidents ORDER BY created_at DESC LIMIT 100').all();
  const eventsStmt = db.prepare('SELECT * FROM incident_timeline_events WHERE incident_id = ? ORDER BY occurred_at ASC');
  const enriched = incidents.map(inc => ({
    ...inc,
    timeline: eventsStmt.all(inc.id)
  }));
  res.json(enriched);
});

app.post('/api/incidents', requireAuth, requirePermission('incidents', 'create'), (req, res) => {
  const {
    caller_info,
    incident_type,
    location_address,
    location_lat,
    location_lng,
    priority,
    assigned_vehicle_id,
    assigned_crew,
    hospital_destination
  } = req.body || {};

  if (!incident_type || !priority) {
    return res.status(400).json({ error: 'Incident type and priority are required.' });
  }

  const now = new Date().toISOString();
  const incId = 'INC-' + new Date().toISOString().slice(0, 10).replace(/-/g, '') + '-' + Math.random().toString(36).substring(2, 6).toUpperCase();
  const status = assigned_vehicle_id ? 'DISPATCHED' : 'CALL_RECEIVED';

  db.prepare(`
    INSERT INTO incidents (id, call_received_at, caller_info, incident_type, location_address, location_lat, location_lng, priority, assigned_vehicle_id, assigned_crew, dispatcher_id, dispatcher_name, hospital_destination, status, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    incId, now, caller_info || null, incident_type, location_address || null,
    location_lat || null, location_lng || null, priority,
    assigned_vehicle_id || null, assigned_crew || null,
    req.user.id, req.user.position_title || req.user.full_name,
    hospital_destination || null, status, now, now
  );

  const insEv = db.prepare(`
    INSERT INTO incident_timeline_events (id, incident_id, event_type, event_label, occurred_at, recorded_by_id, recorded_by_name, recorded_by_role)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);
  insEv.run('ev-' + crypto.randomUUID().slice(0, 8), incId, 'CALL_RECEIVED', 'Emergency call received', now, req.user.id, req.user.position_title || req.user.full_name, req.user.role);

  if (assigned_vehicle_id) {
    insEv.run('ev-' + crypto.randomUUID().slice(0, 8), incId, 'AMBULANCE_DISPATCHED', `Ambulance dispatched (${assigned_vehicle_id}${assigned_crew ? ' • ' + assigned_crew : ''})`, now, req.user.id, req.user.position_title || req.user.full_name, req.user.role);
    db.prepare(`UPDATE vehicles SET status = 'Assigned', updated_at = ? WHERE id = ?`).run(now, assigned_vehicle_id);
  }

  writeAuditLog({
    action: 'INCIDENT_CREATED',
    detail: `Created incident ${incId} (${incident_type}, ${priority})`,
    role: req.user.role,
    userId: req.user.id,
    userName: req.user.full_name,
    recordRef: incId,
    ipAddress: req.ip
  });

  const created = db.prepare('SELECT * FROM incidents WHERE id = ?').get(incId);
  created.timeline = db.prepare('SELECT * FROM incident_timeline_events WHERE incident_id = ? ORDER BY occurred_at ASC').all(incId);
  res.status(201).json(created);
});

const EVENT_METADATA = {
  AMBULANCE_DISPATCHED: { label: 'Ambulance dispatched', status: 'DISPATCHED', perm: 'edit' },
  CREW_ASSIGNED: { label: 'Ambulance and crew assigned', status: 'DISPATCHED', perm: 'edit' },
  ARRIVED_SCENE: { label: 'Arrived at scene', status: 'ON_SCENE', perm: 'create' },
  PATIENT_PICKED_UP: { label: 'Patient picked up', status: 'PATIENT_PICKED_UP', perm: 'create' },
  ARRIVED_HOSPITAL: { label: 'Arrived at hospital', status: 'AT_HOSPITAL', perm: 'create' },
  PATIENT_HANDED_OVER: { label: 'Patient handed over', status: 'HANDED_OVER', perm: 'create' },
  AMBULANCE_AVAILABLE: { label: 'Ambulance available again', status: 'AVAILABLE', perm: 'edit' }
};

app.post('/api/incidents/:id/events', requireAuth, (req, res) => {
  const inc = db.prepare('SELECT * FROM incidents WHERE id = ?').get(req.params.id);
  if (!inc) return res.status(404).json({ error: 'Incident not found.' });

  const { event_type, assigned_vehicle_id, assigned_crew, gps_lat, gps_lng, gps_accuracy, gps_auto, offline_recorded, occurred_at, client_event_id, notes } = req.body || {};
  const meta = EVENT_METADATA[event_type];
  if (!meta) return res.status(400).json({ error: 'Invalid timeline event type.' });

  if (!hasPermission(req.user, 'incidents', meta.perm)) {
    return res.status(403).json({ error: `Forbidden: requires incidents:${meta.perm} to record ${event_type}` });
  }

  // Idempotent deduplication for offline sync
  if (client_event_id) {
    const existing = db.prepare('SELECT * FROM incident_timeline_events WHERE client_event_id = ?').get(client_event_id);
    if (existing) {
      return res.json({ deduplicated: true, event: existing });
    }
  }

  // Server automatically records actual time unless it was genuinely captured offline
  const eventTime = (offline_recorded && occurred_at) ? occurred_at : new Date().toISOString();
  const evId = 'ev-' + crypto.randomUUID().slice(0, 8);

  let label = meta.label;
  if (event_type === 'AMBULANCE_DISPATCHED' && assigned_vehicle_id) {
    label = `Ambulance dispatched (${assigned_vehicle_id}${assigned_crew ? ' • ' + assigned_crew : ''})`;
    db.prepare(`UPDATE incidents SET assigned_vehicle_id = ?, assigned_crew = COALESCE(?, assigned_crew) WHERE id = ?`)
      .run(assigned_vehicle_id, assigned_crew || null, inc.id);
    db.prepare(`UPDATE vehicles SET status = 'Assigned', updated_at = ? WHERE id = ?`).run(eventTime, assigned_vehicle_id);
  }
  if (event_type === 'AMBULANCE_AVAILABLE' && inc.assigned_vehicle_id) {
    db.prepare(`UPDATE vehicles SET status = 'Available', updated_at = ? WHERE id = ?`).run(eventTime, inc.assigned_vehicle_id);
  }

  db.prepare(`
    INSERT INTO incident_timeline_events (id, incident_id, event_type, event_label, occurred_at, recorded_by_id, recorded_by_name, recorded_by_role, gps_lat, gps_lng, gps_accuracy, gps_auto, offline_recorded, client_event_id, notes)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    evId, inc.id, event_type, label, eventTime,
    req.user.id, req.user.position_title || req.user.full_name, req.user.role,
    gps_lat || null, gps_lng || null, gps_accuracy || null,
    gps_auto ? 1 : 0, offline_recorded ? 1 : 0, client_event_id || null, notes || null
  );

  db.prepare('UPDATE incidents SET status = ?, updated_at = ? WHERE id = ?').run(meta.status, new Date().toISOString(), inc.id);

  writeAuditLog({
    action: 'TIMELINE_EVENT',
    detail: `Recorded ${event_type} for ${inc.id}${gps_auto ? ' (GPS-assisted)' : ''}${offline_recorded ? ' (Offline Sync)' : ''}`,
    role: req.user.role,
    userId: req.user.id,
    userName: req.user.full_name,
    recordRef: inc.id,
    ipAddress: req.ip
  });

  const updated = db.prepare('SELECT * FROM incidents WHERE id = ?').get(inc.id);
  updated.timeline = db.prepare('SELECT * FROM incident_timeline_events WHERE incident_id = ? ORDER BY occurred_at ASC').all(inc.id);
  res.status(201).json(updated);
});

app.post('/api/incidents/:id/handover', requireAuth, requirePermission('incidents', 'approve'), (req, res) => {
  const inc = db.prepare('SELECT * FROM incidents WHERE id = ?').get(req.params.id);
  if (!inc) return res.status(404).json({ error: 'Incident not found.' });

  const { handover_notes } = req.body || {};
  const now = new Date().toISOString();
  const confirmerName = req.user.position_title || req.user.full_name;

  db.prepare(`
    UPDATE incidents
    SET handover_confirmed_by = ?, handover_confirmed_role = ?, handover_confirmed_at = ?, handover_notes = ?, status = 'HANDED_OVER', updated_at = ?
    WHERE id = ?
  `).run(confirmerName, req.user.role, now, handover_notes || null, now, inc.id);

  db.prepare(`
    INSERT INTO incident_timeline_events (id, incident_id, event_type, event_label, occurred_at, recorded_by_id, recorded_by_name, recorded_by_role, notes)
    VALUES (?, ?, 'HANDOVER_CONFIRMED', ?, ?, ?, ?, ?, ?)
  `).run(
    'ev-' + crypto.randomUUID().slice(0, 8), inc.id,
    `Hospital handover confirmed by ${confirmerName}`,
    now, req.user.id, confirmerName, req.user.role, handover_notes || null
  );

  writeAuditLog({
    action: 'HANDOVER_CONFIRMED',
    detail: `Hospital handover confirmed for ${inc.id} by ${confirmerName}`,
    role: req.user.role,
    userId: req.user.id,
    userName: req.user.full_name,
    recordRef: inc.id,
    ipAddress: req.ip
  });

  const updated = db.prepare('SELECT * FROM incidents WHERE id = ?').get(inc.id);
  updated.timeline = db.prepare('SELECT * FROM incident_timeline_events WHERE incident_id = ? ORDER BY occurred_at ASC').all(inc.id);
  res.json(updated);
});

app.post('/api/incidents/:id/events/:eventId/correct', requireAuth, requirePermission('incidents', 'edit'), (req, res) => {
  const ev = db.prepare('SELECT * FROM incident_timeline_events WHERE id = ? AND incident_id = ?').get(req.params.eventId, req.params.id);
  if (!ev) return res.status(404).json({ error: 'Timeline event not found.' });

  const { new_occurred_at, reason } = req.body || {};
  if (!new_occurred_at || !reason || !reason.trim()) {
    return res.status(400).json({ error: 'Corrected timestamp and a documented reason are mandatory.' });
  }

  const now = new Date().toISOString();
  const original = ev.original_occurred_at || ev.occurred_at;

  db.prepare(`
    UPDATE incident_timeline_events
    SET occurred_at = ?, is_corrected = 1, correction_reason = ?, corrected_by = ?, corrected_at = ?, original_occurred_at = ?
    WHERE id = ?
  `).run(new_occurred_at, reason.trim(), req.user.position_title || req.user.full_name, now, original, ev.id);

  writeAuditLog({
    action: 'TIMELINE_CORRECTION',
    detail: `Corrected ${ev.event_type} on ${req.params.id} from ${original} to ${new_occurred_at}. Reason: ${reason.trim()}`,
    role: req.user.role,
    userId: req.user.id,
    userName: req.user.full_name,
    recordRef: req.params.id,
    ipAddress: req.ip
  });

  const updated = db.prepare('SELECT * FROM incidents WHERE id = ?').get(req.params.id);
  updated.timeline = db.prepare('SELECT * FROM incident_timeline_events WHERE incident_id = ? ORDER BY occurred_at ASC').all(req.params.id);
  res.json(updated);
});

// ================= ePCR (PATIENT CARE RECORDS) =================
app.get('/api/epcr', requireAuth, requirePermission('epcr', 'view'), (req, res) => {
  const rows = db.prepare('SELECT * FROM patient_records ORDER BY created_at DESC LIMIT 200').all();
  res.json(rows);
});

app.post('/api/epcr', requireAuth, requirePermission('epcr', 'create'), (req, res) => {
  const b = req.body || {};
  if (!b.patient_name || !b.primary_complaint) {
    return res.status(400).json({ error: 'Patient name/ID and primary chief complaint are required.' });
  }

  if (b.client_record_id) {
    const dup = db.prepare('SELECT * FROM patient_records WHERE client_record_id = ?').get(b.client_record_id);
    if (dup) return res.json({ deduplicated: true, record: dup });
  }

  const id = 'epcr-' + Date.now() + '-' + Math.random().toString(36).substring(2, 6);
  const now = new Date().toISOString();

  db.prepare(`
    INSERT INTO patient_records (
      id, incident_id, patient_name, patient_age, patient_gender, triage_priority,
      incident_type, primary_complaint, past_history, allergies, current_medications,
      bp, pulse, spo2, resp_rate, glucose, temp, gcs_score, pain_score,
      ecg_result, airway_support, meds_administered, iv_fluids, hospital,
      handover_doctor, treatment, disposition, is_returning, status, created_by, created_at, client_record_id
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Submitted', ?, ?, ?)
  `).run(
    id, b.incident_id || null, b.patient_name.trim(), b.patient_age || null, b.patient_gender || null,
    b.triage_priority || null, b.incident_type || 'Medical Emergency', b.primary_complaint.trim(),
    b.past_history || null, b.allergies || null, b.current_medications || null,
    b.bp || null, b.pulse || null, b.spo2 || null, b.resp_rate || null, b.glucose || null, b.temp || null,
    b.gcs_score || null, b.pain_score || null, b.ecg_result || null, b.airway_support || null,
    b.meds_administered || null, b.iv_fluids || null, b.hospital || null, b.handover_doctor || null,
    b.treatment || null, b.disposition || 'Admitted', b.is_returning ? 1 : 0,
    req.user.position_title || req.user.full_name, now, b.client_record_id || null
  );

  if (b.incident_id) {
    db.prepare('UPDATE incidents SET patient_record_id = ?, hospital_destination = COALESCE(?, hospital_destination), updated_at = ? WHERE id = ?')
      .run(id, b.hospital || null, now, b.incident_id);
  }

  writeAuditLog({
    action: 'EPCR_CREATED',
    detail: `Created ePCR ${id} for ${b.patient_name}${b.incident_id ? ' linked to ' + b.incident_id : ''}`,
    role: req.user.role,
    userId: req.user.id,
    userName: req.user.full_name,
    recordRef: id,
    ipAddress: req.ip
  });

  res.status(201).json(db.prepare('SELECT * FROM patient_records WHERE id = ?').get(id));
});

// ================= VEHICLE CHECKS =================
app.get('/api/vehicle-checks', requireAuth, requirePermission('vehicle_checks', 'view'), (req, res) => {
  res.json(db.prepare('SELECT * FROM vehicle_checks ORDER BY created_at DESC LIMIT 100').all());
});

app.post('/api/vehicle-checks', requireAuth, requirePermission('vehicle_checks', 'create'), (req, res) => {
  const { vehicle_id, completed_checks, proof, passed, mileage, notes } = req.body || {};
  if (!vehicle_id) return res.status(400).json({ error: 'Vehicle ID is required.' });

  const id = 'vehchk-' + Date.now() + '-' + Math.random().toString(36).substring(2, 6);
  const now = new Date().toISOString();
  const checksStr = Array.isArray(completed_checks) ? JSON.stringify(completed_checks) : String(completed_checks || '[]');

  db.prepare(`
    INSERT INTO vehicle_checks (id, vehicle_id, completed_checks, proof, passed, mileage, notes, created_by, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, vehicle_id.trim(), checksStr, proof || null, passed ? 1 : 0, mileage ? parseInt(mileage, 10) : null, notes || null, req.user.position_title || req.user.full_name, now);

  writeAuditLog({
    action: 'VEHICLE_CHECK_CREATED',
    detail: `Vehicle check ${id} for ${vehicle_id} (${passed ? 'Passed' : 'Attention Required'})`,
    role: req.user.role,
    userId: req.user.id,
    userName: req.user.full_name,
    recordRef: id,
    ipAddress: req.ip
  });

  res.status(201).json(db.prepare('SELECT * FROM vehicle_checks WHERE id = ?').get(id));
});

// ================= ASSET VERIFICATION =================
app.get('/api/assets', requireAuth, requirePermission('assets', 'view'), (req, res) => {
  res.json(db.prepare('SELECT * FROM asset_checks ORDER BY created_at DESC LIMIT 100').all());
});

app.post('/api/assets', requireAuth, requirePermission('assets', 'create'), (req, res) => {
  const { asset_name, category, status, notes } = req.body || {};
  if (!asset_name) return res.status(400).json({ error: 'Asset name is required.' });

  const id = 'ast-' + Date.now() + '-' + Math.random().toString(36).substring(2, 6);
  const now = new Date().toISOString();
  db.prepare(`
    INSERT INTO asset_checks (id, asset_name, category, status, notes, created_by, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(id, asset_name.trim(), category || 'Medical Equipment', status || 'Available', notes || null, req.user.position_title || req.user.full_name, now);

  writeAuditLog({
    action: 'ASSET_CHECK_CREATED',
    detail: `Asset check ${id}: ${asset_name} (${status})`,
    role: req.user.role,
    userId: req.user.id,
    userName: req.user.full_name,
    recordRef: id,
    ipAddress: req.ip
  });

  res.status(201).json(db.prepare('SELECT * FROM asset_checks WHERE id = ?').get(id));
});

// ================= CLINICAL AUDITS =================
app.get('/api/audits', requireAuth, requirePermission('audits', 'view'), (req, res) => {
  res.json(db.prepare('SELECT * FROM clinical_audits ORDER BY created_at DESC LIMIT 100').all());
});

app.post('/api/audits', requireAuth, requirePermission('audits', 'create'), (req, res) => {
  const { patient_record_id, outcome, notes } = req.body || {};
  if (!patient_record_id || !outcome) {
    return res.status(400).json({ error: 'Patient record and audit outcome are required.' });
  }
  const rec = db.prepare('SELECT id, patient_name, primary_complaint FROM patient_records WHERE id = ?').get(patient_record_id);
  if (!rec) return res.status(404).json({ error: 'Patient record not found.' });

  const id = 'aud-' + Date.now() + '-' + Math.random().toString(36).substring(2, 6);
  const now = new Date().toISOString();
  const label = `${rec.patient_name} - ${rec.primary_complaint}`;

  db.prepare(`
    INSERT INTO clinical_audits (id, patient_record_id, record_label, outcome, notes, created_by, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(id, rec.id, label, outcome, notes || null, req.user.position_title || req.user.full_name, now);

  writeAuditLog({
    action: 'CLINICAL_AUDIT_SUBMITTED',
    detail: `Submitted clinical audit ${id} for ${rec.id}: ${outcome}`,
    role: req.user.role,
    userId: req.user.id,
    userName: req.user.full_name,
    recordRef: id,
    ipAddress: req.ip
  });

  res.status(201).json(db.prepare('SELECT * FROM clinical_audits WHERE id = ?').get(id));
});

// ================= OCR EXTRACTION (REVIEW BEFORE SAVE) =================
app.post('/api/ocr/extract', requireAuth, upload.single('file'), async (req, res) => {
  const canStaff = hasPermission(req.user, 'staff_docs', 'create');
  const canFleet = hasPermission(req.user, 'fleet', 'create');
  if (!canStaff && !canFleet) {
    return res.status(403).json({ error: 'Forbidden: insufficient permissions for document OCR.' });
  }
  if (!req.file) {
    return res.status(400).json({ error: 'No document file uploaded for OCR.' });
  }
  if (!verifyMagicBytes(req.file.buffer, req.file.mimetype)) {
    return res.status(400).json({ error: 'Invalid or corrupted file header.' });
  }

  const result = await extractDocumentOcr(req.file.buffer, req.file.mimetype);
  res.json(result);
});

// ================= STAFF COMPLIANCE DOCUMENTS & EXPIRY =================
app.get('/api/staff-docs', requireAuth, requirePermission('staff_docs', 'view'), (req, res) => {
  let rows;
  if (req.permissionScope === 'own') {
    rows = db.prepare('SELECT * FROM staff_documents WHERE staff_user_id = ? ORDER BY created_at DESC').all(req.user.id);
  } else {
    rows = db.prepare('SELECT * FROM staff_documents ORDER BY created_at DESC').all();
  }
  // Dynamically refresh expiry status on read
  const updated = rows.map(r => ({
    ...r,
    status: computeDocStatus(r.expiry_date, r.status),
    days_remaining: daysUntil(r.expiry_date)
  }));
  res.json(updated);
});

app.post('/api/staff-docs', requireAuth, requirePermission('staff_docs', 'create'), upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Document file is required.' });

  const { staff_user_id, doc_type, doc_number, issue_date, expiry_date, is_renewal, ocr_raw_text, ocr_confidence } = req.body || {};
  const targetUserId = req.permissionScope === 'own' ? req.user.id : (staff_user_id || req.user.id);
  const staffUser = db.prepare('SELECT id, full_name, role, position_title FROM users WHERE id = ?').get(targetUserId);
  if (!staffUser) return res.status(404).json({ error: 'Target staff member not found.' });

  let saved;
  try {
    saved = savePrivateFile(req.file.buffer, req.file.mimetype, PRIVATE_STAFF_DIR);
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }

  const id = 'sdoc-' + crypto.randomUUID().slice(0, 10);
  const now = new Date().toISOString();
  const initialStatus = is_renewal === 'true' || is_renewal === true
    ? 'Renewal submitted / awaiting verification'
    : computeDocStatus(expiry_date, 'Valid');

  db.prepare(`
    INSERT INTO staff_documents (
      id, staff_user_id, staff_name, staff_role, doc_type, doc_number, issue_date, expiry_date,
      status, ocr_raw_text, ocr_confidence, ocr_verified, storage_filename, original_filename,
      mime_type, file_size, sha256_hash, uploaded_by, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id, staffUser.id, staffUser.position_title || staffUser.full_name, staffUser.role,
    doc_type || 'Professional Licence', doc_number || null, issue_date || null, expiry_date || null,
    initialStatus, ocr_raw_text || null, ocr_confidence ? Number(ocr_confidence) : null,
    saved.storageFilename, req.file.originalname, req.file.mimetype, saved.fileSize, saved.sha256,
    req.user.position_title || req.user.full_name, now, now
  );

  writeAuditLog({
    action: is_renewal === 'true' ? 'STAFF_DOC_RENEWAL_UPLOADED' : 'STAFF_DOC_UPLOADED',
    detail: `Uploaded ${doc_type || 'document'} (${id}) for ${staffUser.position_title || staffUser.full_name}`,
    role: req.user.role,
    userId: req.user.id,
    userName: req.user.full_name,
    recordRef: id,
    ipAddress: req.ip
  });

  res.status(201).json(db.prepare('SELECT * FROM staff_documents WHERE id = ?').get(id));
});

app.post('/api/staff-docs/:id/verify', requireAuth, requirePermission('staff_docs', 'approve'), (req, res) => {
  const doc = db.prepare('SELECT * FROM staff_documents WHERE id = ?').get(req.params.id);
  if (!doc) return res.status(404).json({ error: 'Staff document not found.' });

  const { expiry_date } = req.body || {};
  const finalExpiry = expiry_date || doc.expiry_date;
  const newStatus = computeDocStatus(finalExpiry, 'Valid');
  const now = new Date().toISOString();

  db.prepare(`
    UPDATE staff_documents SET expiry_date = ?, status = ?, verified_by = ?, verified_at = ?, updated_at = ? WHERE id = ?
  `).run(finalExpiry, newStatus, req.user.position_title || req.user.full_name, now, now, doc.id);

  writeAuditLog({
    action: 'STAFF_DOC_VERIFIED',
    detail: `Verified staff document ${doc.id} for ${doc.staff_name} (status: ${newStatus})`,
    role: req.user.role,
    userId: req.user.id,
    userName: req.user.full_name,
    recordRef: doc.id,
    ipAddress: req.ip
  });

  res.json(db.prepare('SELECT * FROM staff_documents WHERE id = ?').get(doc.id));
});

app.get('/api/staff-docs/:id/download', requireAuth, requirePermission('staff_docs', 'view'), (req, res) => {
  const doc = db.prepare('SELECT * FROM staff_documents WHERE id = ?').get(req.params.id);
  if (!doc) return res.status(404).json({ error: 'Document not found.' });
  if (req.permissionScope === 'own' && doc.staff_user_id !== req.user.id) {
    return res.status(403).json({ error: 'Forbidden: you can only access your own documents.' });
  }

  const filePath = path.join(PRIVATE_STAFF_DIR, path.basename(doc.storage_filename));
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Stored file not found.' });

  writeAuditLog({
    action: 'STAFF_DOC_DOWNLOAD',
    detail: `Accessed private staff document ${doc.id} (${doc.doc_type})`,
    role: req.user.role,
    userId: req.user.id,
    userName: req.user.full_name,
    recordRef: doc.id,
    ipAddress: req.ip
  });

  res.setHeader('Content-Type', doc.mime_type);
  res.setHeader('Content-Disposition', `inline; filename="${doc.original_filename.replace(/"/g, '')}"`);
  fs.createReadStream(filePath).pipe(res);
});

// ================= REMINDER SETTINGS & ACTIVE REMINDERS =================
app.get('/api/reminders/settings', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM reminder_settings').all();
  res.json(rows.map(r => ({ ...r, intervals_days: JSON.parse(r.intervals_days) })));
});

app.put('/api/reminders/settings', requireAuth, (req, res) => {
  if (!hasPermission(req.user, 'staff_docs', 'approve') && !hasPermission(req.user, 'fleet', 'edit') && !hasPermission(req.user, 'security', 'manage_permissions')) {
    return res.status(403).json({ error: 'Forbidden: management permissions required to configure reminders.' });
  }
  const { id, intervals_days, notify_after_expiry } = req.body || {};
  if (!id || !Array.isArray(intervals_days)) {
    return res.status(400).json({ error: 'Reminder id and intervals_days array are required.' });
  }
  const cleaned = intervals_days.map(n => parseInt(n, 10)).filter(n => !isNaN(n) && n >= 0).sort((a, b) => b - a);
  const now = new Date().toISOString();
  db.prepare(`
    INSERT INTO reminder_settings (id, intervals_days, notify_after_expiry, updated_by, updated_at)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET intervals_days = excluded.intervals_days, notify_after_expiry = excluded.notify_after_expiry, updated_by = excluded.updated_by, updated_at = excluded.updated_at
  `).run(id, JSON.stringify(cleaned), notify_after_expiry ? 1 : 0, req.user.position_title || req.user.full_name, now);

  writeAuditLog({
    action: 'REMINDER_SETTINGS_UPDATED',
    detail: `Updated ${id} reminder intervals to [${cleaned.join(', ')}] days`,
    role: req.user.role,
    userId: req.user.id,
    userName: req.user.full_name,
    recordRef: id,
    ipAddress: req.ip
  });

  res.json({ id, intervals_days: cleaned, notify_after_expiry: !!notify_after_expiry });
});

app.get('/api/reminders/active', requireAuth, (req, res) => {
  const settingsMap = {};
  db.prepare('SELECT * FROM reminder_settings').all().forEach(r => {
    settingsMap[r.id] = { intervals: JSON.parse(r.intervals_days), after: !!r.notify_after_expiry };
  });

  const reminders = [];
  const staffPerm = hasPermission(req.user, 'staff_docs', 'view');
  if (staffPerm) {
    const staffSet = settingsMap.staff_docs || { intervals: [30, 14, 7, 0], after: true };
    const maxWindow = Math.max(...staffSet.intervals, 30);
    const docs = staffPerm === 'own'
      ? db.prepare('SELECT * FROM staff_documents WHERE staff_user_id = ?').all(req.user.id)
      : db.prepare('SELECT * FROM staff_documents').all();

    docs.forEach(d => {
      const days = daysUntil(d.expiry_date);
      if (days === null) return;
      if ((days < 0 && staffSet.after) || (days >= 0 && days <= maxWindow)) {
        reminders.push({
          category: 'Staff Document',
          ref_id: d.id,
          title: `${d.staff_name} — ${d.doc_type}`,
          due_date: d.expiry_date,
          days_remaining: days,
          severity: days < 0 ? 'Expired' : days <= 7 ? 'Critical' : 'Expiring soon'
        });
      }
    });
  }

  if (hasPermission(req.user, 'fleet', 'view')) {
    const vehDocSet = settingsMap.vehicle_docs || { intervals: [30, 14, 7, 0], after: true };
    const vehSvcSet = settingsMap.vehicle_service || { intervals: [30, 14, 7, 0], after: true };
    const maxDocWin = Math.max(...vehDocSet.intervals, 30);
    const maxSvcWin = Math.max(...vehSvcSet.intervals, 30);

    db.prepare('SELECT * FROM vehicles').all().forEach(v => {
      [['Licence Disc', v.licence_disc_expiry], ['Roadworthiness', v.roadworthy_expiry]].forEach(([label, dt]) => {
        const days = daysUntil(dt);
        if (days !== null && ((days < 0 && vehDocSet.after) || (days >= 0 && days <= maxDocWin))) {
          reminders.push({
            category: 'Vehicle Compliance',
            ref_id: v.id,
            title: `${v.id} (${v.registration_number}) — ${label}`,
            due_date: dt,
            days_remaining: days,
            severity: days < 0 ? 'Expired' : days <= 7 ? 'Critical' : 'Expiring soon'
          });
        }
      });

      const svcDays = daysUntil(v.next_service_due_date);
      if (svcDays !== null && ((svcDays < 0 && vehSvcSet.after) || (svcDays >= 0 && svcDays <= maxSvcWin))) {
        reminders.push({
          category: 'Vehicle Service',
          ref_id: v.id,
          title: `${v.id} (${v.registration_number}) — Scheduled Service`,
          due_date: v.next_service_due_date,
          days_remaining: svcDays,
          severity: svcDays < 0 ? 'Overdue' : svcDays <= 7 ? 'Due Soon' : 'Upcoming'
        });
      }
    });
  }

  reminders.sort((a, b) => a.days_remaining - b.days_remaining);
  res.json(reminders);
});

// ================= FLEET, VEHICLE SERVICING & COMPLIANCE =================
app.get('/api/vehicles', requireAuth, (req, res) => {
  const canFleet = hasPermission(req.user, 'fleet', 'view');
  const canCheck = hasPermission(req.user, 'vehicle_checks', 'view');
  const canIncidents = hasPermission(req.user, 'incidents', 'view');
  if (!canFleet && !canCheck && !canIncidents) {
    return res.status(403).json({ error: 'Forbidden: cannot view vehicles.' });
  }
  const vehicles = db.prepare('SELECT * FROM vehicles ORDER BY id ASC').all();
  if (!canFleet) {
    // Non-fleet roles (e.g. Dispatcher, Medic) only receive operational availability info
    return res.json(vehicles.map(v => ({
      id: v.id,
      registration_number: v.registration_number,
      make_model: v.make_model,
      vehicle_type: v.vehicle_type,
      status: v.status
    })));
  }
  res.json(vehicles.map(v => ({
    ...v,
    licence_status: computeDocStatus(v.licence_disc_expiry),
    roadworthy_status: computeDocStatus(v.roadworthy_expiry),
    service_days_remaining: daysUntil(v.next_service_due_date)
  })));
});

app.post('/api/vehicles', requireAuth, requirePermission('fleet', 'create'), (req, res) => {
  const { id, registration_number, make_model, vehicle_type, status, service_interval_days, service_interval_km, licence_disc_expiry, roadworthy_expiry } = req.body || {};
  if (!id || !registration_number || !make_model) {
    return res.status(400).json({ error: 'Vehicle ID, registration number, and make/model are required.' });
  }
  const now = new Date().toISOString();
  db.prepare(`
    INSERT INTO vehicles (id, registration_number, make_model, vehicle_type, status, service_interval_days, service_interval_km, licence_disc_expiry, roadworthy_expiry, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id.trim().toUpperCase(), registration_number.trim(), make_model.trim(),
    vehicle_type || 'Ambulance', status || 'Available',
    service_interval_days ? parseInt(service_interval_days, 10) : null,
    service_interval_km ? parseInt(service_interval_km, 10) : null,
    licence_disc_expiry || null, roadworthy_expiry || null, now, now
  );
  writeAuditLog({
    action: 'VEHICLE_CREATED',
    detail: `Added vehicle ${id} (${registration_number})`,
    role: req.user.role,
    userId: req.user.id,
    userName: req.user.full_name,
    recordRef: id,
    ipAddress: req.ip
  });
  res.status(201).json(db.prepare('SELECT * FROM vehicles WHERE id = ?').get(id.trim().toUpperCase()));
});

app.get('/api/vehicles/:id', requireAuth, requirePermission('fleet', 'view'), (req, res) => {
  const v = db.prepare('SELECT * FROM vehicles WHERE id = ?').get(req.params.id);
  if (!v) return res.status(404).json({ error: 'Vehicle not found.' });
  const services = db.prepare('SELECT * FROM vehicle_services WHERE vehicle_id = ? ORDER BY service_date DESC, created_at DESC').all(v.id);
  const documents = db.prepare('SELECT * FROM vehicle_documents WHERE vehicle_id = ? ORDER BY created_at DESC').all(v.id);
  res.json({
    ...v,
    licence_status: computeDocStatus(v.licence_disc_expiry),
    roadworthy_status: computeDocStatus(v.roadworthy_expiry),
    services,
    documents
  });
});

app.post('/api/vehicles/:id/services', requireAuth, requirePermission('fleet', 'create'), (req, res) => {
  const v = db.prepare('SELECT * FROM vehicles WHERE id = ?').get(req.params.id);
  if (!v) return res.status(404).json({ error: 'Vehicle not found.' });

  const { service_date, recorded_mileage, work_performed, service_provider, cost, next_service_date, next_service_mileage } = req.body || {};
  if (!service_date || !work_performed) {
    return res.status(400).json({ error: 'Service date and description of work performed are required.' });
  }

  const svcId = 'svc-' + crypto.randomUUID().slice(0, 8);
  const now = new Date().toISOString();
  const mileageVal = (recorded_mileage !== undefined && recorded_mileage !== '' && recorded_mileage !== null) ? parseInt(recorded_mileage, 10) : null;
  const nextMileageVal = (next_service_mileage !== undefined && next_service_mileage !== '' && next_service_mileage !== null) ? parseInt(next_service_mileage, 10) : null;
  const costVal = (cost !== undefined && cost !== '' && cost !== null) ? parseFloat(cost) : null;

  db.prepare(`
    INSERT INTO vehicle_services (id, vehicle_id, service_date, recorded_mileage, work_performed, service_provider, cost, next_service_date, next_service_mileage, created_by, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(svcId, v.id, service_date, mileageVal, work_performed.trim(), service_provider || null, costVal, next_service_date || null, nextMileageVal, req.user.position_title || req.user.full_name, now);

  db.prepare(`
    UPDATE vehicles
    SET last_service_date = ?, last_service_mileage = COALESCE(?, last_service_mileage),
        next_service_due_date = COALESCE(?, next_service_due_date),
        next_service_due_mileage = COALESCE(?, next_service_due_mileage),
        updated_at = ?
    WHERE id = ?
  `).run(service_date, mileageVal, next_service_date || null, nextMileageVal, now, v.id);

  writeAuditLog({
    action: 'VEHICLE_SERVICE_LOGGED',
    detail: `Logged service ${svcId} for ${v.id} on ${service_date}`,
    role: req.user.role,
    userId: req.user.id,
    userName: req.user.full_name,
    recordRef: svcId,
    ipAddress: req.ip
  });

  res.status(201).json(db.prepare('SELECT * FROM vehicle_services WHERE id = ?').get(svcId));
});

app.post('/api/vehicles/:id/documents', requireAuth, requirePermission('fleet', 'create'), upload.single('file'), (req, res) => {
  const v = db.prepare('SELECT * FROM vehicles WHERE id = ?').get(req.params.id);
  if (!v) return res.status(404).json({ error: 'Vehicle not found.' });
  if (!req.file) return res.status(400).json({ error: 'Document file is required.' });

  const { doc_category, service_id, expiry_date, ocr_raw_text } = req.body || {};
  let saved;
  try {
    saved = savePrivateFile(req.file.buffer, req.file.mimetype, PRIVATE_VEHICLE_DIR);
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }

  const docId = 'vdoc-' + crypto.randomUUID().slice(0, 10);
  const now = new Date().toISOString();
  const category = doc_category || 'Service Receipt';

  db.prepare(`
    INSERT INTO vehicle_documents (id, vehicle_id, service_id, doc_category, expiry_date, ocr_raw_text, ocr_verified, storage_filename, original_filename, mime_type, file_size, sha256_hash, uploaded_by, created_at)
    VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)
  `).run(docId, v.id, service_id || null, category, expiry_date || null, ocr_raw_text || null, saved.storageFilename, req.file.originalname, req.file.mimetype, saved.fileSize, saved.sha256, req.user.position_title || req.user.full_name, now);

  if (expiry_date) {
    if (category === 'Licence Disc') {
      db.prepare('UPDATE vehicles SET licence_disc_expiry = ?, updated_at = ? WHERE id = ?').run(expiry_date, now, v.id);
    } else if (category === 'Roadworthiness Certificate') {
      db.prepare('UPDATE vehicles SET roadworthy_expiry = ?, updated_at = ? WHERE id = ?').run(expiry_date, now, v.id);
    }
  }

  writeAuditLog({
    action: 'VEHICLE_DOC_UPLOADED',
    detail: `Uploaded ${category} (${docId}) for vehicle ${v.id}`,
    role: req.user.role,
    userId: req.user.id,
    userName: req.user.full_name,
    recordRef: docId,
    ipAddress: req.ip
  });

  res.status(201).json(db.prepare('SELECT * FROM vehicle_documents WHERE id = ?').get(docId));
});

app.get('/api/vehicle-docs/:docId/download', requireAuth, requirePermission('fleet', 'view'), (req, res) => {
  const doc = db.prepare('SELECT * FROM vehicle_documents WHERE id = ?').get(req.params.docId);
  if (!doc) return res.status(404).json({ error: 'Vehicle document not found.' });

  const filePath = path.join(PRIVATE_VEHICLE_DIR, path.basename(doc.storage_filename));
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Stored file not found.' });

  writeAuditLog({
    action: 'VEHICLE_DOC_DOWNLOAD',
    detail: `Accessed private vehicle document ${doc.id} (${doc.doc_category}) for ${doc.vehicle_id}`,
    role: req.user.role,
    userId: req.user.id,
    userName: req.user.full_name,
    recordRef: doc.id,
    ipAddress: req.ip
  });

  res.setHeader('Content-Type', doc.mime_type);
  res.setHeader('Content-Disposition', `inline; filename="${doc.original_filename.replace(/"/g, '')}"`);
  fs.createReadStream(filePath).pipe(res);
});

// ================= OPERATIONAL ANALYTICS (AGGREGATED, NO PHI) =================
function computeAnalytics(fromDate, toDate) {
  const wherePatient = fromDate && toDate ? `WHERE substr(created_at, 1, 10) BETWEEN ? AND ?` : '';
  const params = fromDate && toDate ? [fromDate, toDate] : [];

  const patients = db.prepare(`SELECT patient_age, disposition, is_returning, created_at FROM patient_records ${wherePatient}`).all(...params);
  const now = Date.now();
  const dayMs = 86400000;
  let perDay = 0, perWeek = 0, perMonth = 0, returningCount = 0, newCount = 0;
  const dispositions = {};
  const ageBuckets = { '0-17': 0, '18-35': 0, '36-60': 0, '60+': 0, 'Unknown': 0 };

  patients.forEach(p => {
    const ageMs = now - new Date(p.created_at).getTime();
    if (ageMs <= dayMs) perDay++;
    if (ageMs <= 7 * dayMs) perWeek++;
    if (ageMs <= 30 * dayMs) perMonth++;
    if (p.is_returning) returningCount++; else newCount++;
    const disp = p.disposition || 'Recorded / Unspecified';
    dispositions[disp] = (dispositions[disp] || 0) + 1;
    const age = parseInt(p.patient_age, 10);
    if (isNaN(age)) ageBuckets.Unknown++;
    else if (age < 18) ageBuckets['0-17']++;
    else if (age <= 35) ageBuckets['18-35']++;
    else if (age <= 60) ageBuckets['36-60']++;
    else ageBuckets['60+']++;
  });

  // Staff stats
  const users = db.prepare('SELECT role, is_active FROM users WHERE is_active = 1').all();
  const staffByRole = {};
  users.forEach(u => {
    const label = POSITIONS[u.role] || u.role;
    staffByRole[label] = (staffByRole[label] || 0) + 1;
  });

  // Emergency response stats
  const whereInc = fromDate && toDate ? `WHERE substr(call_received_at, 1, 10) BETWEEN ? AND ?` : '';
  const incidents = db.prepare(`SELECT id, call_received_at, status FROM incidents ${whereInc}`).all(...params);
  let callsDay = 0, callsWeek = 0, callsMonth = 0, dispatchedCount = 0, incompleteCount = 0;
  const responseMins = [], sceneMins = [], transportMins = [], handoverMins = [];

  const evStmt = db.prepare('SELECT event_type, occurred_at FROM incident_timeline_events WHERE incident_id = ?');
  incidents.forEach(inc => {
    const ageMs = now - new Date(inc.call_received_at).getTime();
    if (ageMs <= dayMs) callsDay++;
    if (ageMs <= 7 * dayMs) callsWeek++;
    if (ageMs <= 30 * dayMs) callsMonth++;

    const evs = {};
    evStmt.all(inc.id).forEach(e => { evs[e.event_type] = new Date(e.occurred_at).getTime(); });
    if (evs.AMBULANCE_DISPATCHED) dispatchedCount++;

    const hasCore = evs.CALL_RECEIVED && evs.ARRIVED_SCENE && evs.PATIENT_HANDED_OVER;
    if (!hasCore) incompleteCount++;

    if (evs.CALL_RECEIVED && evs.ARRIVED_SCENE) responseMins.push((evs.ARRIVED_SCENE - evs.CALL_RECEIVED) / 60000);
    if (evs.ARRIVED_SCENE && evs.PATIENT_PICKED_UP) sceneMins.push((evs.PATIENT_PICKED_UP - evs.ARRIVED_SCENE) / 60000);
    if (evs.PATIENT_PICKED_UP && evs.ARRIVED_HOSPITAL) transportMins.push((evs.ARRIVED_HOSPITAL - evs.PATIENT_PICKED_UP) / 60000);
    if (evs.ARRIVED_HOSPITAL && evs.PATIENT_HANDED_OVER) handoverMins.push((evs.PATIENT_HANDED_OVER - evs.ARRIVED_HOSPITAL) / 60000);
  });

  const avg = arr => arr.length ? Math.round((arr.reduce((a, b) => a + b, 0) / arr.length) * 10) / 10 : null;

  // Fleet stats
  const vehicles = db.prepare('SELECT * FROM vehicles').all();
  const vehicleChecksCount = db.prepare('SELECT COUNT(*) as c FROM vehicle_checks').get().c;
  let availVeh = 0, assignedVeh = 0, unavailVeh = 0, upcomingSvc = 0, overdueSvc = 0, expiredVehDocs = 0;
  vehicles.forEach(v => {
    if (v.status === 'Available') availVeh++;
    else if (v.status === 'Assigned') assignedVeh++;
    else unavailVeh++;

    const svcDays = daysUntil(v.next_service_due_date);
    if (svcDays !== null) {
      if (svcDays < 0) overdueSvc++;
      else if (svcDays <= 30) upcomingSvc++;
    }
    if (computeDocStatus(v.licence_disc_expiry) === 'Expired') expiredVehDocs++;
    if (computeDocStatus(v.roadworthy_expiry) === 'Expired') expiredVehDocs++;
  });

  // Compliance stats
  const staffDocs = db.prepare('SELECT expiry_date, status FROM staff_documents').all();
  let validDocs = 0, expiringDocs = 0, expiredDocs = 0;
  staffDocs.forEach(d => {
    const st = computeDocStatus(d.expiry_date, d.status);
    if (st === 'Expired') expiredDocs++;
    else if (st === 'Expiring soon') expiringDocs++;
    else validDocs++;
  });

  return {
    filter: { from: fromDate || null, to: toDate || null },
    patientStats: {
      total: patients.length,
      perDay,
      perWeek,
      perMonth,
      newPatients: newCount,
      returningPatients: returningCount,
      dispositions,
      ageBuckets
    },
    staffStats: {
      totalEmployees: users.length,
      byRole: staffByRole,
      attendanceNote: 'Attendance / shift clock-in is not captured by this system; showing active registered staff.'
    },
    emergencyStats: {
      totalCalls: incidents.length,
      callsDay,
      callsWeek,
      callsMonth,
      dispatchedCount,
      avgResponseMinutes: avg(responseMins),
      avgSceneMinutes: avg(sceneMins),
      avgTransportMinutes: avg(transportMins),
      avgHandoverMinutes: avg(handoverMins),
      incompleteTimelines: incompleteCount
    },
    fleetStats: {
      totalAmbulances: vehicles.length,
      available: availVeh,
      assigned: assignedVeh,
      unavailable: unavailVeh,
      vehicleChecksCompleted: vehicleChecksCount,
      upcomingServices: upcomingSvc,
      overdueServices: overdueSvc,
      expiredVehicleDocs: expiredVehDocs
    },
    complianceStats: {
      validStaffDocs: validDocs,
      expiringSoonStaffDocs: expiringDocs,
      expiredStaffDocs: expiredDocs,
      expiredVehicleDocs: expiredVehDocs
    }
  };
}

app.get('/api/analytics', requireAuth, requirePermission('analytics', 'view'), (req, res) => {
  const { from, to } = req.query || {};
  res.json(computeAnalytics(from, to));
});

app.get('/api/analytics/export', requireAuth, requirePermission('analytics', 'export'), (req, res) => {
  const { from, to } = req.query || {};
  const data = computeAnalytics(from, to);
  const lines = [
    'Category,Metric,Value',
    `Patients,Total Patients,${data.patientStats.total}`,
    `Patients,Last 24h,${data.patientStats.perDay}`,
    `Patients,Last 7 Days,${data.patientStats.perWeek}`,
    `Patients,Last 30 Days,${data.patientStats.perMonth}`,
    `Staff,Total Active Employees,${data.staffStats.totalEmployees}`,
    `Emergency,Total Calls,${data.emergencyStats.totalCalls}`,
    `Emergency,Avg Response (min),${data.emergencyStats.avgResponseMinutes ?? 'Insufficient data'}`,
    `Emergency,Avg Scene Time (min),${data.emergencyStats.avgSceneMinutes ?? 'Insufficient data'}`,
    `Emergency,Avg Transport (min),${data.emergencyStats.avgTransportMinutes ?? 'Insufficient data'}`,
    `Emergency,Avg Handover (min),${data.emergencyStats.avgHandoverMinutes ?? 'Insufficient data'}`,
    `Emergency,Incomplete Timelines,${data.emergencyStats.incompleteTimelines}`,
    `Fleet,Total Vehicles,${data.fleetStats.totalAmbulances}`,
    `Fleet,Available,${data.fleetStats.available}`,
    `Fleet,Overdue Services,${data.fleetStats.overdueServices}`,
    `Compliance,Valid Staff Docs,${data.complianceStats.validStaffDocs}`,
    `Compliance,Expiring Soon Staff Docs,${data.complianceStats.expiringSoonStaffDocs}`,
    `Compliance,Expired Staff Docs,${data.complianceStats.expiredStaffDocs}`
  ];

  writeAuditLog({
    action: 'ANALYTICS_EXPORTED',
    detail: `Exported aggregated operational analytics CSV`,
    role: req.user.role,
    userId: req.user.id,
    userName: req.user.full_name,
    ipAddress: req.ip
  });

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="bucks_ems_analytics.csv"');
  res.send(lines.join('\n'));
});

// ================= IT SECURITY, USERS, PERMISSIONS & AUDIT LOGS =================
app.get('/api/users', requireAuth, (req, res) => {
  const canSecurity = hasPermission(req.user, 'security', 'view');
  const canStaffDocs = hasPermission(req.user, 'staff_docs', 'view') === 'all';
  if (!canSecurity && !canStaffDocs) {
    return res.status(403).json({ error: 'Forbidden: cannot list staff users.' });
  }
  const users = db.prepare('SELECT id, username, email, full_name, role, position_title, fleet_management, is_active, created_at FROM users ORDER BY created_at ASC').all();
  res.json(users);
});

app.post('/api/users', requireAuth, requirePermission('security', 'create'), (req, res) => {
  const { username, email, password, full_name, role, fleet_management } = req.body || {};
  if (!username || !email || !password || !full_name || !POSITIONS[role]) {
    return res.status(400).json({ error: 'Valid username, email, password, full name, and official role are required.' });
  }
  const hash = bcrypt.hashSync(password, 10);
  const id = 'usr-' + crypto.randomUUID().slice(0, 8);
  const now = new Date().toISOString();
  try {
    db.prepare(`
      INSERT INTO users (id, username, email, password_hash, full_name, role, position_title, fleet_management, is_active, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
    `).run(id, username.trim(), email.trim(), hash, full_name.trim(), role, POSITIONS[role], fleet_management ? 1 : 0, now);
  } catch {
    return res.status(409).json({ error: 'Username or email already exists.' });
  }

  writeAuditLog({
    action: 'USER_CREATED',
    detail: `IT Admin created user ${username} (${POSITIONS[role]}, fleet_management=${!!fleet_management})`,
    role: req.user.role,
    userId: req.user.id,
    userName: req.user.full_name,
    recordRef: id,
    ipAddress: req.ip
  });

  res.status(201).json(db.prepare('SELECT id, username, email, full_name, role, position_title, fleet_management, is_active, created_at FROM users WHERE id = ?').get(id));
});

app.patch('/api/users/:id', requireAuth, requirePermission('security', 'manage_permissions'), (req, res) => {
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!target) return res.status(404).json({ error: 'User not found.' });

  const { fleet_management, is_active, role } = req.body || {};
  const newFleet = fleet_management !== undefined ? (fleet_management ? 1 : 0) : target.fleet_management;
  const newActive = is_active !== undefined ? (is_active ? 1 : 0) : target.is_active;
  const newRole = (role && POSITIONS[role]) ? role : target.role;

  db.prepare('UPDATE users SET fleet_management = ?, is_active = ?, role = ?, position_title = ? WHERE id = ?')
    .run(newFleet, newActive, newRole, POSITIONS[newRole], target.id);

  writeAuditLog({
    action: 'PERMISSION_CHANGED',
    detail: `Updated permissions for ${target.username}: role=${newRole}, fleet_management=${!!newFleet}, active=${!!newActive}`,
    role: req.user.role,
    userId: req.user.id,
    userName: req.user.full_name,
    recordRef: target.id,
    ipAddress: req.ip
  });

  res.json(db.prepare('SELECT id, username, email, full_name, role, position_title, fleet_management, is_active FROM users WHERE id = ?').get(target.id));
});

app.get('/api/roles/permissions', requireAuth, requirePermission('security', 'view'), (req, res) => {
  res.json({ positions: POSITIONS, defaults: DEFAULT_ROLE_PERMISSIONS });
});

app.get('/api/audit-logs', requireAuth, requirePermission('security', 'view'), (req, res) => {
  res.json(db.prepare('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 200').all());
});

// ================= OFFLINE BATCH SYNCHRONISATION =================
app.post('/api/sync', requireAuth, (req, res) => {
  const { items } = req.body || {};
  if (!Array.isArray(items)) return res.status(400).json({ error: 'items array is required.' });

  const results = [];
  for (const entry of items) {
    try {
      if (entry.type === 'TIMELINE_EVENT' && hasPermission(req.user, 'incidents', 'create')) {
        const p = entry.payload;
        const dup = p.client_event_id ? db.prepare('SELECT id FROM incident_timeline_events WHERE client_event_id = ?').get(p.client_event_id) : null;
        if (!dup && p.incident_id && EVENT_METADATA[p.event_type]) {
          const evId = 'ev-' + crypto.randomUUID().slice(0, 8);
          const meta = EVENT_METADATA[p.event_type];
          db.prepare(`
            INSERT INTO incident_timeline_events (id, incident_id, event_type, event_label, occurred_at, recorded_by_id, recorded_by_name, recorded_by_role, gps_lat, gps_lng, gps_accuracy, gps_auto, offline_recorded, client_event_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
          `).run(evId, p.incident_id, p.event_type, meta.label, p.occurred_at, req.user.id, req.user.position_title || req.user.full_name, req.user.role, p.gps_lat || null, p.gps_lng || null, p.gps_accuracy || null, p.gps_auto ? 1 : 0, p.client_event_id || null);
          db.prepare('UPDATE incidents SET status = ?, updated_at = ? WHERE id = ?').run(meta.status, new Date().toISOString(), p.incident_id);
        }
        results.push({ clientId: entry.clientId, status: 'synced' });
      } else if (entry.type === 'PATIENT_RECORD' && hasPermission(req.user, 'epcr', 'create')) {
        const b = entry.payload;
        const dup = b.client_record_id ? db.prepare('SELECT id FROM patient_records WHERE client_record_id = ?').get(b.client_record_id) : null;
        if (!dup) {
          const id = 'epcr-' + Date.now() + '-' + Math.random().toString(36).substring(2, 6);
          db.prepare(`
            INSERT INTO patient_records (id, incident_id, patient_name, patient_age, patient_gender, triage_priority, incident_type, primary_complaint, past_history, allergies, current_medications, bp, pulse, spo2, resp_rate, glucose, temp, gcs_score, pain_score, ecg_result, airway_support, meds_administered, iv_fluids, hospital, handover_doctor, treatment, status, created_by, created_at, client_record_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Submitted', ?, ?, ?)
          `).run(id, b.incident_id || null, b.patient_name, b.patient_age || null, b.patient_gender || null, b.triage_priority || null, b.incident_type || 'Medical Emergency', b.primary_complaint, b.past_history || null, b.allergies || null, b.current_medications || null, b.bp || null, b.pulse || null, b.spo2 || null, b.resp_rate || null, b.glucose || null, b.temp || null, b.gcs_score || null, b.pain_score || null, b.ecg_result || null, b.airway_support || null, b.meds_administered || null, b.iv_fluids || null, b.hospital || null, b.handover_doctor || null, b.treatment || null, req.user.position_title || req.user.full_name, b.created_at || new Date().toISOString(), b.client_record_id || null);
        }
        results.push({ clientId: entry.clientId, status: 'synced' });
      } else if (entry.type === 'VEHICLE_CHECK' && hasPermission(req.user, 'vehicle_checks', 'create')) {
        const v = entry.payload;
        const id = 'vehchk-' + Date.now() + '-' + Math.random().toString(36).substring(2, 6);
        db.prepare(`INSERT INTO vehicle_checks (id, vehicle_id, completed_checks, proof, passed, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`)
          .run(id, v.vehicle_id, JSON.stringify(v.completed_checks || []), v.proof || null, v.passed ? 1 : 0, req.user.position_title || req.user.full_name, v.created_at || new Date().toISOString());
        results.push({ clientId: entry.clientId, status: 'synced' });
      } else if (entry.type === 'ASSET_CHECK' && hasPermission(req.user, 'assets', 'create')) {
        const a = entry.payload;
        const id = 'ast-' + Date.now() + '-' + Math.random().toString(36).substring(2, 6);
        db.prepare(`INSERT INTO asset_checks (id, asset_name, category, status, notes, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`)
          .run(id, a.asset_name, a.category || 'Medical Equipment', a.status || 'Available', a.notes || null, req.user.position_title || req.user.full_name, a.created_at || new Date().toISOString());
        results.push({ clientId: entry.clientId, status: 'synced' });
      } else {
        results.push({ clientId: entry.clientId, status: 'rejected_permission' });
      }
    } catch {
      results.push({ clientId: entry.clientId, status: 'error' });
    }
  }

  writeAuditLog({
    action: 'OFFLINE_SYNC',
    detail: `Synchronised ${results.filter(r => r.status === 'synced').length}/${items.length} offline queued item(s)`,
    role: req.user.role,
    userId: req.user.id,
    userName: req.user.full_name,
    ipAddress: req.ip
  });

  res.json({ results });
});

// Safe global error handler (no stack traces leaked)
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError || (err && err.message && err.message.includes('Unsupported file'))) {
    return res.status(400).json({ error: err.message });
  }
  console.error('Unhandled error:', err ? err.message : err);
  res.status(500).json({ error: 'An internal server error occurred.' });
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`====================================================`);
    console.log(` 🚑 Bucks EMS Cloud Hub Server is running!`);
    console.log(` 🌐 URL: http://localhost:${PORT}`);
    console.log(` 🔒 Mode: SQLite + Backend RBAC + Private Doc Storage`);
    console.log(`====================================================`);
  });
}

module.exports = app;
