const QUEUE_KEY = 'bucksEmsOfflineQueue_v1';

const POSITION_PREVIEWS = {
  doctor: { title: 'Doctor / Medical Director', desc: 'Medical oversight, ePCR review, clinical analytics, handover confirmation, and QA sign-off.' },
  nurse: { title: 'Emergency / Training Nurse', desc: 'ED triage, nursing assessments, hospital handover confirmation, and staff compliance verification.' },
  medic: { title: 'Field Medic', desc: 'Patient care records, one-tap emergency response timeline events, and daily ambulance checks.' },
  flight: { title: 'Flight Paramedic', desc: 'Specialist aeromedical patient records, flight response tracking, and helicopter checks.' },
  manager: { title: 'Station Manager', desc: 'Station operations, fleet servicing & compliance, staff document expiry, and operational analytics.' },
  auditor: { title: 'QA Clinical / Clinical Audit', desc: 'Clinical documentation review, outcome audits, and clinical quality analytics.' },
  dispatcher: { title: 'EMS Dispatcher', desc: 'Record emergency calls, assign ambulances & crews, and monitor live response timelines.' },
  admin: { title: 'IT Admin', desc: 'User account creation, role & Fleet Management permissions, and immutable security audit logs.' }
};

let authToken = null;
let currentUser = null;
let permissions = {};
let online = true;
let offlineQueue = JSON.parse(localStorage.getItem(QUEUE_KEY) || '[]');

let cachedIncidents = [];
let cachedVehicles = [];
let cachedEpcr = [];
let selectedFleetVehicleId = null;

// ================= API HELPER =================
async function apiFetch(url, options = {}) {
  const headers = options.headers ? { ...options.headers } : {};
  if (authToken) headers['Authorization'] = `Bearer ${authToken}`;
  if (!(options.body instanceof FormData) && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json';
  }
  const res = await fetch(url, { ...options, headers });
  const contentType = res.headers.get('content-type') || '';
  const data = contentType.includes('application/json') ? await res.json() : await res.text();
  if (!res.ok) {
    throw new Error((data && data.error) ? data.error : `Request failed (${res.status})`);
  }
  return data;
}

function esc(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 3000);
}

function saveQueue() {
  localStorage.setItem(QUEUE_KEY, JSON.stringify(offlineQueue));
  renderQueue();
}

function can(resource, action) {
  const list = permissions[resource] || [];
  if (list.includes(action)) return true;
  if (action === 'view' && list.includes('view_own')) return true;
  if (action === 'create' && list.includes('create_own')) return true;
  return false;
}

// ================= AUTHENTICATION =================
const accountSelect = document.getElementById('accountSelect');
function updatePreview() {
  const p = POSITION_PREVIEWS[accountSelect.value];
  if (p) {
    document.getElementById('previewRoleTag').textContent = p.title.toUpperCase();
    document.getElementById('previewDesc').textContent = p.desc;
  }
}
accountSelect.addEventListener('change', updatePreview);
updatePreview();

async function handleAuthSuccess(data) {
  authToken = data.token;
  currentUser = data.user;
  permissions = data.permissions;

  document.getElementById('userFullName').textContent = currentUser.position_title || currentUser.full_name;
  document.getElementById('userRoleBadge').textContent = currentUser.role;
  document.getElementById('userFleetBadge').classList.toggle('hidden', !currentUser.fleet_management);

  document.getElementById('authContainer').classList.add('hidden');
  document.getElementById('appShell').classList.remove('hidden');

  applyRoleVisibility();
  await refreshAllModules();
  switchPage('dashboard');
  showToast(`Signed in as ${currentUser.position_title}`);
}

document.getElementById('accountLoginForm').addEventListener('submit', async e => {
  e.preventDefault();
  try {
    const data = await apiFetch('/api/auth/demo-login', {
      method: 'POST',
      body: JSON.stringify({ positionKey: accountSelect.value })
    });
    await handleAuthSuccess(data);
  } catch (err) {
    showToast(err.message);
  }
});

document.getElementById('shortcutBypassBtn').addEventListener('click', async () => {
  try {
    const data = await apiFetch('/api/auth/demo-login', {
      method: 'POST',
      body: JSON.stringify({ positionKey: 'doctor' })
    });
    await handleAuthSuccess(data);
  } catch (err) {
    showToast(err.message);
  }
});

document.getElementById('passwordLoginForm').addEventListener('submit', async e => {
  e.preventDefault();
  try {
    const data = await apiFetch('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({
        username: document.getElementById('loginUsername').value.trim(),
        password: document.getElementById('loginPassword').value
      })
    });
    e.target.reset();
    await handleAuthSuccess(data);
  } catch (err) {
    showToast(err.message);
  }
});

document.getElementById('logoutBtn').addEventListener('click', () => {
  authToken = null;
  currentUser = null;
  permissions = {};
  document.getElementById('appShell').classList.add('hidden');
  document.getElementById('authContainer').classList.remove('hidden');
  showToast('Logged out.');
});

// ================= NAVIGATION & ROLE VISIBILITY =================
const PAGE_RESOURCE_MAP = {
  dashboard: 'dashboard',
  incidents: 'incidents',
  epcr: 'epcr',
  vehicle: 'vehicle_checks',
  fleet: 'fleet',
  staffdocs: 'staff_docs',
  assets: 'assets',
  audits: 'audits',
  analytics: 'analytics',
  security: 'security'
};

function applyRoleVisibility() {
  document.getElementById('roleDescription').textContent =
    (POSITION_PREVIEWS[Object.keys(POSITION_PREVIEWS).find(k => POSITION_PREVIEWS[k].title === currentUser.position_title)] || {}).desc ||
    'Role-based access enforced.';

  document.querySelectorAll('.nav-btn').forEach(btn => {
    const res = PAGE_RESOURCE_MAP[btn.dataset.page];
    const allowed = res ? can(res, 'view') : false;
    btn.classList.toggle('hidden', !allowed);
  });

  // Granular action visibility inside Dispatch & Timeline
  document.getElementById('dispatchCreateCard').classList.toggle('hidden', !can('incidents', 'create') || !can('incidents', 'edit'));
  document.getElementById('dispatcherActionBar').classList.toggle('hidden', !can('incidents', 'edit'));
  document.getElementById('handoverConfirmBox').classList.toggle('hidden', !can('incidents', 'approve'));
  document.getElementById('reminderConfigPanel').classList.toggle('hidden', !can('staff_docs', 'approve'));
}

function setMobileDrawer(open) {
  const sidebar = document.getElementById('appSidebar');
  const backdrop = document.getElementById('sidebarBackdrop');
  if (sidebar) sidebar.classList.toggle('open', open);
  if (backdrop) backdrop.classList.toggle('hidden', !open);
}

const mobileMenuBtn = document.getElementById('mobileMenuBtn');
if (mobileMenuBtn) mobileMenuBtn.addEventListener('click', () => setMobileDrawer(true));
const sidebarBackdrop = document.getElementById('sidebarBackdrop');
if (sidebarBackdrop) sidebarBackdrop.addEventListener('click', () => setMobileDrawer(false));

function switchPage(pageId) {
  const res = PAGE_RESOURCE_MAP[pageId];
  if (res && !can(res, 'view')) {
    showToast('Access denied for your assigned position.');
    return;
  }
  setMobileDrawer(false);
  document.querySelectorAll('.page').forEach(p => p.classList.toggle('active', p.id === pageId));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.toggle('active', b.dataset.page === pageId));
  const btn = document.querySelector(`.nav-btn[data-page="${pageId}"]`);
  if (btn) document.getElementById('pageTitle').textContent = btn.textContent;

  if (pageId === 'analytics') loadAnalytics();
  if (pageId === 'fleet') loadFleetVehicles();
  if (pageId === 'staffdocs') loadStaffDocs();
  if (pageId === 'security') loadSecurityModule();
}

document.querySelectorAll('.nav-btn').forEach(btn => {
  btn.addEventListener('click', () => switchPage(btn.dataset.page));
});

// ePCR Section Tabs
const formTabs = document.querySelectorAll('.form-tab');
const formSections = document.querySelectorAll('.form-section');
formTabs.forEach(tab => {
  tab.addEventListener('click', () => {
    formTabs.forEach(t => t.classList.toggle('active', t === tab));
    formSections.forEach(s => s.classList.toggle('active', s.id === tab.dataset.tab));
  });
});

// ================= OFFLINE / ONLINE & SYNC =================
document.getElementById('networkToggle').addEventListener('click', () => {
  online = !online;
  document.getElementById('networkToggle').textContent = online ? 'Go Offline' : 'Go Online';
  document.getElementById('connLabel').textContent = online ? 'Online' : 'Offline Mode';
  document.getElementById('connDot').className = online ? 'dot green' : 'dot red';
  showToast(online ? 'Connected — ready to sync.' : 'Offline mode active — supported actions will queue locally.');
});

function renderQueue() {
  document.getElementById('queueCountBadge').textContent = offlineQueue.length;
  const el = document.getElementById('queueList');
  el.innerHTML = offlineQueue.length
    ? offlineQueue.map(q => `
      <div class="queue-item">
        <strong>${esc(q.type)}</strong>
        <p><small>Queued: ${new Date(q.queuedAt).toLocaleString()}</small></p>
      </div>
    `).join('')
    : '<p class="muted">No offline records waiting to sync.</p>';
}

document.getElementById('syncBtn').addEventListener('click', async () => {
  if (!online) return showToast('Go online first to synchronise.');
  if (!offlineQueue.length) return showToast('Offline queue is empty.');

  try {
    const resp = await apiFetch('/api/sync', {
      method: 'POST',
      body: JSON.stringify({ items: offlineQueue })
    });
    const syncedCount = resp.results.filter(r => r.status === 'synced').length;
    offlineQueue = [];
    saveQueue();
    await refreshAllModules();
    showToast(`Synchronised ${syncedCount} queued item(s).`);
  } catch (err) {
    showToast('Sync failed: ' + err.message);
  }
});

// ================= REFRESH ALL PERMITTED MODULES =================
async function refreshAllModules() {
  renderQueue();
  const tasks = [];
  tasks.push(loadReminders());
  if (can('incidents', 'view')) tasks.push(loadIncidents(), loadVehiclesForDispatch());
  if (can('epcr', 'view')) tasks.push(loadEpcr());
  if (can('vehicle_checks', 'view')) tasks.push(loadVehicleChecks());
  if (can('assets', 'view')) tasks.push(loadAssets());
  if (can('audits', 'view')) tasks.push(loadAudits());
  await Promise.allSettled(tasks);
}

async function loadReminders() {
  try {
    const reminders = await apiFetch('/api/reminders/active');
    document.getElementById('reminderCount').textContent = reminders.length;
    const el = document.getElementById('dashboardReminders');
    el.innerHTML = reminders.length
      ? reminders.map(r => `
        <div class="record-item">
          <div class="record-header-row">
            <strong>${esc(r.title)}</strong>
            <span class="badge ${r.days_remaining < 0 ? 'danger' : 'warn'}">${esc(r.severity)}</span>
          </div>
          <p><small>${esc(r.category)} • Due: ${esc(r.due_date)} (${r.days_remaining < 0 ? Math.abs(r.days_remaining) + 'd overdue' : r.days_remaining + 'd left'})</small></p>
        </div>
      `).join('')
      : '<p class="muted">All visible licences, compliance docs, and vehicle services are up to date.</p>';
  } catch {
    document.getElementById('reminderCount').textContent = '0';
  }
}

// ================= INCIDENTS & EMERGENCY RESPONSE TIMELINE =================
async function loadVehiclesForDispatch() {
  try {
    cachedVehicles = await apiFetch('/api/vehicles');
    const sel = document.getElementById('incVehicleSelect');
    const avail = cachedVehicles.filter(v => v.status === 'Available');
    sel.innerHTML = '<option value="">-- Hold (Call Received Only) --</option>' +
      avail.map(v => `<option value="${esc(v.id)}">${esc(v.id)} (${esc(v.vehicle_type)} - ${esc(v.registration_number)})</option>`).join('');
  } catch { /* non-permitted roles skip */ }
}

async function loadIncidents() {
  cachedIncidents = await apiFetch('/api/incidents');
  document.getElementById('incidentCount').textContent = cachedIncidents.length;

  const sel = document.getElementById('activeIncidentSelect');
  const prev = sel.value;
  sel.innerHTML = cachedIncidents.map(i =>
    `<option value="${esc(i.id)}">${esc(i.id)} • ${esc(i.incident_type)} [${esc(i.status)}]</option>`
  ).join('');
  if (prev && cachedIncidents.some(i => i.id === prev)) sel.value = prev;

  const epcrInc = document.getElementById('epcrIncidentId');
  epcrInc.innerHTML = '<option value="">-- Standalone ePCR --</option>' +
    cachedIncidents.map(i => `<option value="${esc(i.id)}">${esc(i.id)} (${esc(i.incident_type)})</option>`).join('');

  renderSelectedIncident();
}

function renderSelectedIncident() {
  const incId = document.getElementById('activeIncidentSelect').value;
  const inc = cachedIncidents.find(i => i.id === incId);
  const headerEl = document.getElementById('incidentDetailHeader');
  const listEl = document.getElementById('incidentTimelineList');

  if (!inc) {
    headerEl.innerHTML = '<p class="muted">No incidents recorded.</p>';
    listEl.innerHTML = '';
    return;
  }

  headerEl.innerHTML = `
    <strong>${esc(inc.id)}</strong> — <span class="badge good">${esc(inc.status)}</span><br/>
    <small>Vehicle: <b>${esc(inc.assigned_vehicle_id || 'Unassigned')}</b> | Crew: ${esc(inc.assigned_crew || '-')} | Hospital: ${esc(inc.hospital_destination || '-')}</small>
    ${inc.handover_confirmed_by ? `<br/><small>✅ Handover confirmed by ${esc(inc.handover_confirmed_by)} at ${new Date(inc.handover_confirmed_at).toLocaleTimeString()}</small>` : ''}
  `;

  listEl.innerHTML = (inc.timeline || []).map(ev => {
    const timeStr = new Date(ev.occurred_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    const canCorrect = can('incidents', 'edit');
    return `
      <div class="timeline-entry ${ev.is_corrected ? 'timeline-corrected' : ''}">
        <div>
          <span class="timeline-time">${esc(timeStr)}</span>
          <strong>${esc(ev.event_label)}</strong>
          ${ev.gps_auto ? '<span class="badge good">GPS Verified</span>' : ''}
          ${ev.offline_recorded ? '<span class="badge warn">Offline Sync</span>' : ''}
          ${ev.is_corrected ? `<span class="badge warn">Corrected</span>` : ''}
          <div class="timeline-meta">
            Recorded by ${esc(ev.recorded_by_name)}
            ${ev.gps_lat ? ` • GPS (${Number(ev.gps_lat).toFixed(4)}, ${Number(ev.gps_lng).toFixed(4)} ±${Math.round(ev.gps_accuracy || 0)}m)` : ''}
            ${ev.is_corrected ? `<br/>Correction by ${esc(ev.corrected_by)}: "${esc(ev.correction_reason)}" (Original: ${new Date(ev.original_occurred_at).toLocaleTimeString()})` : ''}
          </div>
        </div>
        ${canCorrect ? `<button type="button" class="secondary" onclick="openCorrectionModal('${esc(inc.id)}','${esc(ev.id)}')">Correct</button>` : ''}
      </div>
    `;
  }).join('');
}

document.getElementById('activeIncidentSelect').addEventListener('change', renderSelectedIncident);

document.getElementById('incidentForm').addEventListener('submit', async e => {
  e.preventDefault();
  try {
    await apiFetch('/api/incidents', {
      method: 'POST',
      body: JSON.stringify({
        incident_type: document.getElementById('incType').value,
        priority: document.getElementById('incPriority').value,
        location_address: document.getElementById('incLocation').value.trim(),
        caller_info: document.getElementById('incCaller').value.trim(),
        assigned_vehicle_id: document.getElementById('incVehicleSelect').value || null,
        assigned_crew: document.getElementById('incCrew').value.trim(),
        hospital_destination: document.getElementById('incHospital').value.trim()
      })
    });
    e.target.reset();
    await loadIncidents();
    await loadVehiclesForDispatch();
    showToast('Emergency call recorded with automatic timestamp.');
  } catch (err) {
    showToast(err.message);
  }
});

async function getOptionalGps() {
  if (!document.getElementById('gpsAssistToggle').checked || !navigator.geolocation) {
    return null;
  }
  document.getElementById('gpsStatusText').textContent = 'Requesting GPS coordinates...';
  return new Promise(resolve => {
    navigator.geolocation.getCurrentPosition(
      pos => {
        document.getElementById('gpsStatusText').textContent = `GPS locked (±${Math.round(pos.coords.accuracy)}m)`;
        resolve({ lat: pos.coords.latitude, lng: pos.coords.longitude, accuracy: pos.coords.accuracy });
      },
      () => {
        document.getElementById('gpsStatusText').textContent = 'GPS unavailable — recorded manually';
        resolve(null);
      },
      { enableHighAccuracy: true, timeout: 4000 }
    );
  });
}

async function recordTimelineEvent(eventType) {
  const incId = document.getElementById('activeIncidentSelect').value;
  if (!incId) return showToast('Select an incident first.');

  const gps = (eventType === 'ARRIVED_SCENE' || eventType === 'ARRIVED_HOSPITAL') ? await getOptionalGps() : null;
  const payload = {
    incident_id: incId,
    event_type: eventType,
    occurred_at: new Date().toISOString(),
    gps_lat: gps ? gps.lat : null,
    gps_lng: gps ? gps.lng : null,
    gps_accuracy: gps ? gps.accuracy : null,
    gps_auto: !!gps,
    offline_recorded: !online,
    client_event_id: 'ce-' + Date.now() + '-' + Math.random().toString(36).slice(2, 7)
  };

  if (!online) {
    offlineQueue.push({ clientId: payload.client_event_id, type: 'TIMELINE_EVENT', payload, queuedAt: payload.occurred_at });
    saveQueue();
    return showToast('Offline: Timeline event queued with exact timestamp.');
  }

  try {
    await apiFetch(`/api/incidents/${incId}/events`, { method: 'POST', body: JSON.stringify(payload) });
    await loadIncidents();
    await loadVehiclesForDispatch();
    showToast(`Recorded ${eventType.replace(/_/g, ' ')}.`);
  } catch (err) {
    showToast(err.message);
  }
}

document.querySelectorAll('.timeline-btn').forEach(btn => {
  btn.addEventListener('click', () => recordTimelineEvent(btn.dataset.event));
});
document.getElementById('markAvailableBtn').addEventListener('click', () => recordTimelineEvent('AMBULANCE_AVAILABLE'));

document.getElementById('confirmHandoverBtn').addEventListener('click', async () => {
  const incId = document.getElementById('activeIncidentSelect').value;
  if (!incId) return showToast('Select an incident first.');
  try {
    await apiFetch(`/api/incidents/${incId}/handover`, {
      method: 'POST',
      body: JSON.stringify({ handover_notes: document.getElementById('handoverConfirmNotes').value.trim() })
    });
    document.getElementById('handoverConfirmNotes').value = '';
    await loadIncidents();
    showToast('Hospital handover confirmed.');
  } catch (err) {
    showToast(err.message);
  }
});

// Correction Modal
window.openCorrectionModal = function (incId, evId) {
  document.getElementById('corrIncidentId').value = incId;
  document.getElementById('corrEventId').value = evId;
  document.getElementById('correctionModal').classList.remove('hidden');
};
document.getElementById('closeCorrectionModal').addEventListener('click', () => {
  document.getElementById('correctionModal').classList.add('hidden');
});
document.getElementById('correctionForm').addEventListener('submit', async e => {
  e.preventDefault();
  const incId = document.getElementById('corrIncidentId').value;
  const evId = document.getElementById('corrEventId').value;
  try {
    await apiFetch(`/api/incidents/${incId}/events/${evId}/correct`, {
      method: 'POST',
      body: JSON.stringify({
        new_occurred_at: new Date(document.getElementById('corrTimestamp').value).toISOString(),
        reason: document.getElementById('corrReason').value.trim()
      })
    });
    document.getElementById('correctionModal').classList.add('hidden');
    e.target.reset();
    await loadIncidents();
    showToast('Timestamp correction logged.');
  } catch (err) {
    showToast(err.message);
  }
});

// ================= ePCR =================
async function loadEpcr() {
  cachedEpcr = await apiFetch('/api/epcr');
  document.getElementById('recordCount').textContent = cachedEpcr.length;

  const list = document.getElementById('recordsList');
  list.innerHTML = cachedEpcr.length
    ? cachedEpcr.map(r => `
      <div class="record-card-detailed">
        <div class="record-header-row">
          <h4>${esc(r.patient_name)} ${r.patient_age ? `(${esc(r.patient_age)}y ${esc(r.patient_gender || '')})` : ''}</h4>
          <span class="triage-tag">${esc(r.triage_priority || 'Green')}</span>
        </div>
        ${r.incident_id ? `<p><strong>Incident:</strong> ${esc(r.incident_id)} (${esc(r.incident_type)})</p>` : `<p><strong>Incident:</strong> ${esc(r.incident_type)}</p>`}
        <p><strong>Chief Complaint:</strong> ${esc(r.primary_complaint)}</p>
        ${r.allergies ? `<p><strong>Allergies:</strong> ⚠️ ${esc(r.allergies)}</p>` : ''}
        <div class="vitals-strip">
          <span class="vitals-pill">BP: ${esc(r.bp || '-')}</span>
          <span class="vitals-pill">HR: ${esc(r.pulse || '-')}</span>
          <span class="vitals-pill">SpO₂: ${esc(r.spo2 || '-')}</span>
          <span class="vitals-pill">RR: ${esc(r.resp_rate || '-')}</span>
          <span class="vitals-pill">BSL: ${esc(r.glucose || '-')}</span>
          <span class="vitals-pill">Temp: ${esc(r.temp || '-')}</span>
        </div>
        <p><strong>ECG:</strong> ${esc(r.ecg_result || '-')} • <strong>GCS:</strong> ${esc(r.gcs_score || '-')} • <strong>Disposition:</strong> ${esc(r.disposition || '-')}</p>
        <p><strong>Hospital:</strong> ${esc(r.hospital || '-')} ${r.handover_doctor ? `(${esc(r.handover_doctor)})` : ''}</p>
        <p><small>${new Date(r.created_at).toLocaleString()} • ${esc(r.created_by)}</small></p>
      </div>
    `).join('')
    : '<p class="muted">No clinical patient records captured yet.</p>';

  const auditSel = document.getElementById('auditRecordSelect');
  if (auditSel) {
    auditSel.innerHTML = cachedEpcr.map(r => `<option value="${esc(r.id)}">${esc(r.patient_name)} - ${esc(r.primary_complaint)}</option>`).join('');
  }
}

document.getElementById('epcrForm').addEventListener('submit', async e => {
  e.preventDefault();
  const payload = {
    incident_id: document.getElementById('epcrIncidentId').value || null,
    is_returning: document.getElementById('isReturning').checked,
    patient_name: document.getElementById('patientName').value.trim(),
    patient_age: document.getElementById('patientAge').value.trim(),
    patient_gender: document.getElementById('patientGender').value,
    triage_priority: document.getElementById('triagePriority').value,
    incident_type: document.getElementById('incidentType').value,
    primary_complaint: document.getElementById('primaryComplaint').value.trim(),
    past_history: document.getElementById('pastHistory').value.trim(),
    allergies: document.getElementById('allergies').value.trim(),
    current_medications: document.getElementById('currentMedications').value.trim(),
    bp: document.getElementById('bp').value.trim(),
    pulse: document.getElementById('pulse').value.trim(),
    spo2: document.getElementById('spo2').value.trim(),
    resp_rate: document.getElementById('respRate').value.trim(),
    glucose: document.getElementById('glucose').value.trim(),
    temp: document.getElementById('temp').value.trim(),
    gcs_score: document.getElementById('gcsScore').value,
    pain_score: document.getElementById('painScore').value.trim(),
    ecg_result: document.getElementById('ecgResult').value,
    airway_support: document.getElementById('airwaySupport').value.trim(),
    meds_administered: document.getElementById('medsAdministered').value.trim(),
    iv_fluids: document.getElementById('ivFluids').value.trim(),
    hospital: document.getElementById('hospital').value.trim(),
    handover_doctor: document.getElementById('handoverDoctor').value.trim(),
    disposition: document.getElementById('epcrDisposition').value,
    treatment: document.getElementById('treatment').value.trim(),
    client_record_id: 'cr-' + Date.now() + '-' + Math.random().toString(36).slice(2, 7)
  };

  if (!online) {
    offlineQueue.push({ clientId: payload.client_record_id, type: 'PATIENT_RECORD', payload, queuedAt: new Date().toISOString() });
    saveQueue();
    e.target.reset();
    formTabs[0].click();
    return showToast('Offline: ePCR saved to sync queue.');
  }

  try {
    await apiFetch('/api/epcr', { method: 'POST', body: JSON.stringify(payload) });
    e.target.reset();
    formTabs[0].click();
    await loadEpcr();
    showToast('ePCR saved to SQLite database.');
  } catch (err) {
    showToast(err.message);
  }
});

// ================= VEHICLE CHECKS =================
async function loadVehicleChecks() {
  const rows = await apiFetch('/api/vehicle-checks');
  document.getElementById('vehicleCount').textContent = rows.length;
  document.getElementById('vehicleList').innerHTML = rows.length
    ? rows.map(v => {
      const checks = typeof v.completed_checks === 'string' && v.completed_checks.startsWith('[')
        ? JSON.parse(v.completed_checks) : [v.completed_checks];
      return `
        <div class="record-item">
          <h4>${esc(v.vehicle_id)}</h4>
          <span class="badge ${v.passed ? 'good' : 'warn'}">${v.passed ? 'Passed' : 'Attention Required'}</span>
          <p><strong>Checks:</strong> ${esc(checks.join(', ') || 'None')}</p>
          <p><strong>Proof:</strong> ${esc(v.proof || '-')}</p>
          <p><small>${new Date(v.created_at).toLocaleString()} • ${esc(v.created_by)}</small></p>
        </div>
      `;
    }).join('')
    : '<p class="muted">No vehicle checks submitted yet.</p>';
}

document.getElementById('vehicleForm').addEventListener('submit', async e => {
  e.preventDefault();
  const checks = [['lights', 'Lights'], ['sirens', 'Sirens'], ['fuel', 'Fuel'], ['tyres', 'Tyres'], ['oxygen', 'Oxygen']];
  const completed = checks.filter(([id]) => document.getElementById(id).checked).map(([, lbl]) => lbl);
  const payload = {
    vehicle_id: document.getElementById('vehicleId').value.trim(),
    completed_checks: completed,
    proof: document.getElementById('vehicleProof').value.trim(),
    passed: completed.length === checks.length
  };
  if (!online) {
    offlineQueue.push({ clientId: 'vc-' + Date.now(), type: 'VEHICLE_CHECK', payload, queuedAt: new Date().toISOString() });
    saveQueue();
    e.target.reset();
    return showToast('Offline: Vehicle check queued.');
  }
  try {
    await apiFetch('/api/vehicle-checks', { method: 'POST', body: JSON.stringify(payload) });
    e.target.reset();
    await loadVehicleChecks();
    showToast('Vehicle check submitted.');
  } catch (err) {
    showToast(err.message);
  }
});

// ================= FLEET, SERVICING & COMPLIANCE =================
async function loadFleetVehicles() {
  const vehicles = await apiFetch('/api/vehicles');
  const container = document.getElementById('fleetVehicleCards');
  container.innerHTML = vehicles.map(v => `
    <div class="record-item fleet-vehicle-card ${v.id === selectedFleetVehicleId ? 'selected' : ''}" onclick="selectFleetVehicle('${esc(v.id)}')">
      <div class="record-header-row">
        <h4>${esc(v.id)} — ${esc(v.registration_number)}</h4>
        <span class="badge ${v.status === 'Available' ? 'good' : 'warn'}">${esc(v.status)}</span>
      </div>
      <p>${esc(v.make_model)} (${esc(v.vehicle_type)})</p>
      <p><small>Licence Disc: <span class="badge ${v.licence_status === 'Expired' ? 'danger' : v.licence_status === 'Expiring soon' ? 'warn' : 'good'}">${esc(v.licence_status || 'N/A')}</span>
      • Roadworthy: <span class="badge ${v.roadworthy_status === 'Expired' ? 'danger' : v.roadworthy_status === 'Expiring soon' ? 'warn' : 'good'}">${esc(v.roadworthy_status || 'N/A')}</span></small></p>
    </div>
  `).join('');

  if (!selectedFleetVehicleId && vehicles.length) {
    await selectFleetVehicle(vehicles[0].id);
  }
}

window.selectFleetVehicle = async function (vehId) {
  selectedFleetVehicleId = vehId;
  const profile = await apiFetch(`/api/vehicles/${vehId}`);
  document.getElementById('selectedFleetVehTitle').textContent = `${profile.id} (${profile.registration_number})`;
  document.getElementById('selectedFleetSummary').innerHTML = `
    <p><strong>${esc(profile.make_model)}</strong> • Status: <b>${esc(profile.status)}</b></p>
    <p>Last Service: ${esc(profile.last_service_date || 'None')} ${profile.last_service_mileage ? `(${profile.last_service_mileage} km)` : ''}</p>
    <p>Next Service Due: ${esc(profile.next_service_due_date || 'Not set')} ${profile.next_service_due_mileage ? `or ${profile.next_service_due_mileage} km` : ''}</p>
    <p>Licence Disc Expiry: <b>${esc(profile.licence_disc_expiry || 'Not set')}</b> • Roadworthiness Expiry: <b>${esc(profile.roadworthy_expiry || 'Not set')}</b></p>
  `;
  document.getElementById('addServiceForm').classList.remove('hidden');
  document.getElementById('uploadVehDocForm').classList.remove('hidden');

  document.getElementById('fleetServiceHistory').innerHTML = '<h4>Service History</h4>' + (profile.services.length
    ? profile.services.map(s => `
      <div class="record-item">
        <strong>${esc(s.service_date)}</strong> ${s.recorded_mileage ? `• ${s.recorded_mileage} km` : ''} ${s.cost ? `• Cost: ${s.cost}` : ''}
        <p>${esc(s.work_performed)}</p>
        <p><small>Provider: ${esc(s.service_provider || '-')} • Logged by ${esc(s.created_by)}</small></p>
      </div>
    `).join('')
    : '<p class="muted">No service entries logged yet.</p>');

  document.getElementById('fleetDocHistory').innerHTML = '<h4>Attached Service &amp; Compliance Documents</h4>' + (profile.documents.length
    ? profile.documents.map(d => `
      <div class="record-item">
        <div class="record-header-row">
          <strong>${esc(d.doc_category)}</strong>
          <a href="/api/vehicle-docs/${esc(d.id)}/download?token=${encodeURIComponent(authToken)}" target="_blank" class="badge good">View Private Doc</a>
        </div>
        <p><small>${esc(d.original_filename)} ${d.expiry_date ? `• Expiry: ${esc(d.expiry_date)}` : ''}</small></p>
      </div>
    `).join('')
    : '<p class="muted">No documents attached to this vehicle yet.</p>');
};

document.getElementById('addVehicleForm').addEventListener('submit', async e => {
  e.preventDefault();
  try {
    await apiFetch('/api/vehicles', {
      method: 'POST',
      body: JSON.stringify({
        id: document.getElementById('newVehId').value.trim(),
        registration_number: document.getElementById('newVehReg').value.trim(),
        make_model: document.getElementById('newVehModel').value.trim(),
        vehicle_type: document.getElementById('newVehType').value,
        licence_disc_expiry: document.getElementById('newVehLicenceExp').value || null,
        roadworthy_expiry: document.getElementById('newVehRoadExp').value || null
      })
    });
    e.target.reset();
    await loadFleetVehicles();
    showToast('Vehicle profile created.');
  } catch (err) {
    showToast(err.message);
  }
});

document.getElementById('addServiceForm').addEventListener('submit', async e => {
  e.preventDefault();
  if (!selectedFleetVehicleId) return;
  try {
    await apiFetch(`/api/vehicles/${selectedFleetVehicleId}/services`, {
      method: 'POST',
      body: JSON.stringify({
        service_date: document.getElementById('svcDate').value,
        recorded_mileage: document.getElementById('svcMileage').value || null,
        work_performed: document.getElementById('svcWork').value.trim(),
        service_provider: document.getElementById('svcProvider').value.trim(),
        cost: document.getElementById('svcCost').value || null,
        next_service_date: document.getElementById('svcNextDate').value || null,
        next_service_mileage: document.getElementById('svcNextMileage').value || null
      })
    });
    e.target.reset();
    await selectFleetVehicle(selectedFleetVehicleId);
    await loadFleetVehicles();
    showToast('Service entry logged.');
  } catch (err) {
    showToast(err.message);
  }
});

let capturedVehFile = null;
let capturedStaffFile = null;

document.getElementById('vehOcrBtn').addEventListener('click', async () => {
  const file = capturedVehFile || document.getElementById('vehDocFile').files[0];
  if (!file) return showToast('Select or capture a document image first.');
  const fd = new FormData();
  fd.append('file', file);
  document.getElementById('vehOcrStatus').textContent = 'Running OCR extraction...';
  try {
    const res = await apiFetch('/api/ocr/extract', { method: 'POST', body: fd });
    if (res.extracted.expiryDate) document.getElementById('vehDocExpiry').value = res.extracted.expiryDate;
    document.getElementById('vehOcrStatus').textContent = `${res.warning} (Confidence: ${res.confidence}%)`;
  } catch (err) {
    document.getElementById('vehOcrStatus').textContent = err.message;
  }
});

document.getElementById('uploadVehDocForm').addEventListener('submit', async e => {
  e.preventDefault();
  if (!selectedFleetVehicleId) return;
  const file = capturedVehFile || document.getElementById('vehDocFile').files[0];
  if (!file) return showToast('Please select or photograph a document.');
  const fd = new FormData();
  fd.append('file', file);
  fd.append('doc_category', document.getElementById('vehDocCategory').value);
  if (document.getElementById('vehDocExpiry').value) fd.append('expiry_date', document.getElementById('vehDocExpiry').value);
  try {
    await apiFetch(`/api/vehicles/${selectedFleetVehicleId}/documents`, { method: 'POST', body: fd });
    capturedVehFile = null;
    e.target.reset();
    document.getElementById('vehOcrStatus').textContent = '';
    await selectFleetVehicle(selectedFleetVehicleId);
    await loadFleetVehicles();
    showToast('Vehicle document saved to private storage.');
  } catch (err) {
    showToast(err.message);
  }
});

// ================= STAFF COMPLIANCE DOCUMENTS & OCR =================
let lastStaffOcrMeta = { rawText: '', confidence: 0 };

async function loadStaffDocs() {
  try {
    const users = await apiFetch('/api/users');
    document.getElementById('staffDocUserSelect').innerHTML = users.map(u =>
      `<option value="${esc(u.id)}">${esc(u.position_title || u.full_name)} (${esc(u.username)})</option>`
    ).join('');
  } catch {
    document.getElementById('staffDocUserSelect').innerHTML = `<option value="${esc(currentUser.id)}">${esc(currentUser.position_title)}</option>`;
  }

  const docs = await apiFetch('/api/staff-docs');
  const canVerify = can('staff_docs', 'approve');
  document.getElementById('staffDocsList').innerHTML = docs.length
    ? docs.map(d => `
      <div class="record-item">
        <div class="record-header-row">
          <h4>${esc(d.staff_name)} — ${esc(d.doc_type)}</h4>
          <span class="badge ${d.status === 'Expired' ? 'danger' : d.status === 'Valid' ? 'good' : 'warn'}">${esc(d.status)}</span>
        </div>
        <p>Cert/Licence #: ${esc(d.doc_number || '-')} • Issue: ${esc(d.issue_date || '-')} • Expiry: <b>${esc(d.expiry_date || '-')}</b></p>
        <div class="action-buttons-row">
          <a href="/api/staff-docs/${esc(d.id)}/download?token=${encodeURIComponent(authToken)}" target="_blank" class="badge good">View Private Doc</a>
          ${canVerify && d.status === 'Renewal submitted / awaiting verification'
            ? `<button type="button" class="secondary" onclick="verifyStaffDoc('${esc(d.id)}')">✔ Verify Renewal</button>` : ''}
        </div>
      </div>
    `).join('')
    : '<p class="muted">No staff compliance documents uploaded yet.</p>';
}

window.verifyStaffDoc = async function (docId) {
  try {
    await apiFetch(`/api/staff-docs/${docId}/verify`, { method: 'POST', body: JSON.stringify({}) });
    await loadStaffDocs();
    await loadReminders();
    showToast('Staff document verified and status updated.');
  } catch (err) {
    showToast(err.message);
  }
};

document.getElementById('staffOcrBtn').addEventListener('click', async () => {
  const file = capturedStaffFile || document.getElementById('staffDocFile').files[0];
  if (!file) return showToast('Select or photograph a document first.');
  const fd = new FormData();
  fd.append('file', file);
  const banner = document.getElementById('staffOcrBanner');
  banner.classList.remove('hidden');
  banner.textContent = 'Running Tesseract OCR extraction...';
  try {
    const res = await apiFetch('/api/ocr/extract', { method: 'POST', body: fd });
    lastStaffOcrMeta = { rawText: res.rawText, confidence: res.confidence };
    if (res.extracted.docType) document.getElementById('staffDocType').value = res.extracted.docType;
    if (res.extracted.docNumber) document.getElementById('staffDocNumber').value = res.extracted.docNumber;
    if (res.extracted.issueDate) document.getElementById('staffDocIssueDate').value = res.extracted.issueDate;
    if (res.extracted.expiryDate) document.getElementById('staffDocExpiryDate').value = res.extracted.expiryDate;
    banner.textContent = `${res.warning} (Confidence: ${res.confidence}%). Review & correct fields below before saving.`;
  } catch (err) {
    banner.textContent = err.message;
  }
});

document.getElementById('staffDocForm').addEventListener('submit', async e => {
  e.preventDefault();
  const file = capturedStaffFile || document.getElementById('staffDocFile').files[0];
  if (!file) return showToast('Please select or photograph a document.');
  const fd = new FormData();
  fd.append('file', file);
  fd.append('staff_user_id', document.getElementById('staffDocUserSelect').value);
  fd.append('doc_type', document.getElementById('staffDocType').value);
  fd.append('doc_number', document.getElementById('staffDocNumber').value.trim());
  fd.append('issue_date', document.getElementById('staffDocIssueDate').value);
  fd.append('expiry_date', document.getElementById('staffDocExpiryDate').value);
  fd.append('is_renewal', document.getElementById('staffDocIsRenewal').checked);
  fd.append('ocr_raw_text', lastStaffOcrMeta.rawText);
  fd.append('ocr_confidence', String(lastStaffOcrMeta.confidence));
  try {
    await apiFetch('/api/staff-docs', { method: 'POST', body: fd });
    capturedStaffFile = null;
    e.target.reset();
    document.getElementById('staffOcrBanner').classList.add('hidden');
    await loadStaffDocs();
    await loadReminders();
    showToast('Staff document saved in private storage.');
  } catch (err) {
    showToast(err.message);
  }
});

document.getElementById('saveReminderSettingsBtn').addEventListener('click', async () => {
  const arr = document.getElementById('reminderIntervalsInput').value.split(',').map(s => parseInt(s.trim(), 10)).filter(n => !isNaN(n));
  try {
    await apiFetch('/api/reminders/settings', {
      method: 'PUT',
      body: JSON.stringify({ id: 'staff_docs', intervals_days: arr, notify_after_expiry: true })
    });
    await loadReminders();
    showToast('Reminder intervals updated.');
  } catch (err) {
    showToast(err.message);
  }
});

// ================= CAMERA CAPTURE MODAL (PREVIEW, RETAKE, ROTATE, CROP, MULTI-PAGE) =================
let cameraStream = null;
let cameraTarget = 'staff'; // 'staff' or 'vehicle'
let capturedPages = [];
let currentRotation = 0;

async function openCameraModal(target) {
  cameraTarget = target;
  capturedPages = [];
  currentRotation = 0;
  document.getElementById('capturedPageCount').textContent = '0';
  document.getElementById('cameraModal').classList.remove('hidden');
  resetCameraStage();
  try {
    cameraStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
    document.getElementById('cameraVideo').srcObject = cameraStream;
  } catch (err) {
    showToast('Camera unavailable: ' + err.message);
    closeCameraModal();
  }
}

function resetCameraStage() {
  document.getElementById('cameraVideo').classList.remove('hidden');
  document.getElementById('cameraCanvas').classList.add('hidden');
  document.getElementById('capturePhotoBtn').classList.remove('hidden');
  ['retakePhotoBtn', 'rotatePhotoBtn', 'cropPhotoBtn', 'addPageBtn', 'submitCameraDocBtn'].forEach(id => {
    document.getElementById(id).classList.add('hidden');
  });
}

function closeCameraModal() {
  if (cameraStream) {
    cameraStream.getTracks().forEach(t => t.stop());
    cameraStream = null;
  }
  document.getElementById('cameraModal').classList.add('hidden');
}

document.getElementById('staffCameraBtn').addEventListener('click', () => openCameraModal('staff'));
document.getElementById('vehCameraBtn').addEventListener('click', () => openCameraModal('vehicle'));
document.getElementById('closeCameraModal').addEventListener('click', closeCameraModal);

document.getElementById('capturePhotoBtn').addEventListener('click', () => {
  const video = document.getElementById('cameraVideo');
  const canvas = document.getElementById('cameraCanvas');
  canvas.width = video.videoWidth || 800;
  canvas.height = video.videoHeight || 600;
  canvas.getContext('2d').drawImage(video, 0, 0, canvas.width, canvas.height);

  video.classList.add('hidden');
  canvas.classList.remove('hidden');
  document.getElementById('capturePhotoBtn').classList.add('hidden');
  ['retakePhotoBtn', 'rotatePhotoBtn', 'cropPhotoBtn', 'addPageBtn', 'submitCameraDocBtn'].forEach(id => {
    document.getElementById(id).classList.remove('hidden');
  });
});

document.getElementById('retakePhotoBtn').addEventListener('click', resetCameraStage);

document.getElementById('rotatePhotoBtn').addEventListener('click', () => {
  const canvas = document.getElementById('cameraCanvas');
  const tmp = document.createElement('canvas');
  tmp.width = canvas.height;
  tmp.height = canvas.width;
  const ctx = tmp.getContext('2d');
  ctx.translate(tmp.width / 2, tmp.height / 2);
  ctx.rotate(Math.PI / 2);
  ctx.drawImage(canvas, -canvas.width / 2, -canvas.height / 2);
  canvas.width = tmp.width;
  canvas.height = tmp.height;
  canvas.getContext('2d').drawImage(tmp, 0, 0);
});

document.getElementById('cropPhotoBtn').addEventListener('click', () => {
  const canvas = document.getElementById('cameraCanvas');
  const w = Math.round(canvas.width * 0.8);
  const h = Math.round(canvas.height * 0.8);
  const sx = Math.round((canvas.width - w) / 2);
  const sy = Math.round((canvas.height - h) / 2);
  const tmp = document.createElement('canvas');
  tmp.width = w;
  tmp.height = h;
  tmp.getContext('2d').drawImage(canvas, sx, sy, w, h, 0, 0, w, h);
  canvas.width = w;
  canvas.height = h;
  canvas.getContext('2d').drawImage(tmp, 0, 0);
});

document.getElementById('addPageBtn').addEventListener('click', () => {
  const canvas = document.getElementById('cameraCanvas');
  const copy = document.createElement('canvas');
  copy.width = canvas.width;
  copy.height = canvas.height;
  copy.getContext('2d').drawImage(canvas, 0, 0);
  capturedPages.push(copy);
  document.getElementById('capturedPageCount').textContent = String(capturedPages.length);
  resetCameraStage();
  showToast(`Page ${capturedPages.length} added. Capture next page or submit.`);
});

document.getElementById('submitCameraDocBtn').addEventListener('click', () => {
  const canvas = document.getElementById('cameraCanvas');
  if (!canvas.classList.contains('hidden')) {
    const copy = document.createElement('canvas');
    copy.width = canvas.width;
    copy.height = canvas.height;
    copy.getContext('2d').drawImage(canvas, 0, 0);
    capturedPages.push(copy);
  }
  if (!capturedPages.length) return;

  // Stitch multi-page captures vertically into one high-clarity PNG
  const totalHeight = capturedPages.reduce((s, c) => s + c.height, 0);
  const maxWidth = Math.max(...capturedPages.map(c => c.width));
  const out = document.createElement('canvas');
  out.width = maxWidth;
  out.height = totalHeight;
  const ctx = out.getContext('2d');
  let y = 0;
  capturedPages.forEach(c => {
    ctx.drawImage(c, 0, y);
    y += c.height;
  });

  out.toBlob(blob => {
    const file = new File([blob], `camera_capture_${Date.now()}.png`, { type: 'image/png' });
    if (cameraTarget === 'staff') {
      capturedStaffFile = file;
      showToast(`Captured ${capturedPages.length} page(s) ready for OCR & upload.`);
    } else {
      capturedVehFile = file;
      showToast(`Captured ${capturedPages.length} page(s) ready for vehicle upload.`);
    }
    closeCameraModal();
  }, 'image/png');
});

// ================= ASSETS & AUDITS =================
async function loadAssets() {
  const rows = await apiFetch('/api/assets');
  document.getElementById('assetList').innerHTML = rows.length
    ? rows.map(a => `
      <div class="record-item">
        <h4>${esc(a.asset_name)}</h4>
        <span class="badge ${a.status === 'Available' ? 'good' : 'warn'}">${esc(a.status)}</span>
        <p><strong>Category:</strong> ${esc(a.category)} • <strong>Notes:</strong> ${esc(a.notes || '-')}</p>
        <p><small>${new Date(a.created_at).toLocaleString()} • ${esc(a.created_by)}</small></p>
      </div>
    `).join('')
    : '<p class="muted">No asset checks captured yet.</p>';
}

document.getElementById('assetForm').addEventListener('submit', async e => {
  e.preventDefault();
  const payload = {
    asset_name: document.getElementById('assetName').value.trim(),
    category: document.getElementById('assetCategory').value,
    status: document.getElementById('assetStatus').value,
    notes: document.getElementById('assetNotes').value.trim()
  };
  if (!online) {
    offlineQueue.push({ clientId: 'ast-' + Date.now(), type: 'ASSET_CHECK', payload, queuedAt: new Date().toISOString() });
    saveQueue();
    e.target.reset();
    return showToast('Offline: Asset check queued.');
  }
  try {
    await apiFetch('/api/assets', { method: 'POST', body: JSON.stringify(payload) });
    e.target.reset();
    await loadAssets();
    showToast('Asset check saved.');
  } catch (err) {
    showToast(err.message);
  }
});

async function loadAudits() {
  const rows = await apiFetch('/api/audits');
  document.getElementById('clinicalAuditList').innerHTML = rows.length
    ? rows.map(a => `
      <div class="record-item">
        <h4>${esc(a.record_label)}</h4>
        <span class="badge ${a.outcome.includes('Approved') ? 'good' : 'warn'}">${esc(a.outcome)}</span>
        <p>${esc(a.notes || '-')}</p>
        <p><small>${new Date(a.created_at).toLocaleString()} • ${esc(a.created_by)}</small></p>
      </div>
    `).join('')
    : '<p class="muted">No clinical audits submitted yet.</p>';
}

document.getElementById('auditForm').addEventListener('submit', async e => {
  e.preventDefault();
  try {
    await apiFetch('/api/audits', {
      method: 'POST',
      body: JSON.stringify({
        patient_record_id: document.getElementById('auditRecordSelect').value,
        outcome: document.getElementById('auditOutcome').value,
        notes: document.getElementById('auditNotes').value.trim()
      })
    });
    e.target.reset();
    await loadAudits();
    showToast('Clinical audit submitted.');
  } catch (err) {
    showToast(err.message);
  }
});

// ================= OPERATIONAL ANALYTICS =================
function renderBarGroup(obj) {
  const entries = Object.entries(obj || {});
  const max = Math.max(1, ...entries.map(([, v]) => v));
  return entries.map(([k, v]) => `
    <div class="chart-bar-row">
      <span class="chart-bar-label" title="${esc(k)}">${esc(k)}</span>
      <div class="chart-bar-track"><div class="chart-bar-fill" style="width:${Math.round((v / max) * 100)}%"></div></div>
      <span class="chart-bar-val">${v}</span>
    </div>
  `).join('');
}

async function loadAnalytics() {
  const from = document.getElementById('analyticsFrom').value;
  const to = document.getElementById('analyticsTo').value;
  const qs = (from && to) ? `?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}` : '';
  const data = await apiFetch('/api/analytics' + qs);

  document.getElementById('analyticsContent').innerHTML = `
    <div class="card">
      <h3>Patient Statistics (Aggregated)</h3>
      <p>Total: <b>${data.patientStats.total}</b> • 24h: <b>${data.patientStats.perDay}</b> • 7d: <b>${data.patientStats.perWeek}</b> • 30d: <b>${data.patientStats.perMonth}</b></p>
      <p>New: <b>${data.patientStats.newPatients}</b> • Returning: <b>${data.patientStats.returningPatients}</b></p>
      <h4>Age Distribution</h4>
      ${renderBarGroup(data.patientStats.ageBuckets)}
      <h4>Dispositions</h4>
      ${renderBarGroup(data.patientStats.dispositions)}
    </div>

    <div class="card">
      <h3>Emergency Response Statistics</h3>
      <p>Total Calls: <b>${data.emergencyStats.totalCalls}</b> • Dispatched: <b>${data.emergencyStats.dispatchedCount}</b> • Incomplete Timelines: <b>${data.emergencyStats.incompleteTimelines}</b></p>
      <p>Avg Response Time: <b>${data.emergencyStats.avgResponseMinutes ?? 'Insufficient data'}</b> ${data.emergencyStats.avgResponseMinutes !== null ? 'min' : ''}</p>
      <p>Avg Scene Time: <b>${data.emergencyStats.avgSceneMinutes ?? 'Insufficient data'}</b> ${data.emergencyStats.avgSceneMinutes !== null ? 'min' : ''}</p>
      <p>Avg Transport Time: <b>${data.emergencyStats.avgTransportMinutes ?? 'Insufficient data'}</b> ${data.emergencyStats.avgTransportMinutes !== null ? 'min' : ''}</p>
      <p>Avg Handover Time: <b>${data.emergencyStats.avgHandoverMinutes ?? 'Insufficient data'}</b> ${data.emergencyStats.avgHandoverMinutes !== null ? 'min' : ''}</p>
    </div>

    <div class="card">
      <h3>Staff Statistics</h3>
      <p>Total Active Employees: <b>${data.staffStats.totalEmployees}</b></p>
      <p><small class="muted">${esc(data.staffStats.attendanceNote)}</small></p>
      ${renderBarGroup(data.staffStats.byRole)}
    </div>

    <div class="card">
      <h3>Fleet &amp; Compliance Statistics</h3>
      <p>Vehicles: <b>${data.fleetStats.totalAmbulances}</b> (Available: ${data.fleetStats.available}, Assigned: ${data.fleetStats.assigned}, Unavailable: ${data.fleetStats.unavailable})</p>
      <p>Vehicle Checks Completed: <b>${data.fleetStats.vehicleChecksCompleted}</b> • Upcoming Services: <b>${data.fleetStats.upcomingServices}</b> • Overdue Services: <b>${data.fleetStats.overdueServices}</b></p>
      <h4>Compliance Breakdown</h4>
      ${renderBarGroup({
        'Valid Staff Docs': data.complianceStats.validStaffDocs,
        'Expiring Soon Staff Docs': data.complianceStats.expiringSoonStaffDocs,
        'Expired Staff Docs': data.complianceStats.expiredStaffDocs,
        'Expired Vehicle Docs': data.complianceStats.expiredVehicleDocs
      })}
    </div>
  `;
}

document.getElementById('refreshAnalyticsBtn').addEventListener('click', loadAnalytics);
document.getElementById('exportAnalyticsBtn').addEventListener('click', () => {
  const from = document.getElementById('analyticsFrom').value;
  const to = document.getElementById('analyticsTo').value;
  const qs = (from && to) ? `&from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}` : '';
  window.open(`/api/analytics/export?token=${encodeURIComponent(authToken)}${qs}`, '_blank');
});

// ================= IT SECURITY, USERS & AUDIT LOGS =================
async function loadSecurityModule() {
  const [users, logs] = await Promise.all([apiFetch('/api/users'), apiFetch('/api/audit-logs')]);

  document.getElementById('usersManagementList').innerHTML = users.map(u => `
    <div class="record-item">
      <div class="record-header-row">
        <strong>${esc(u.full_name)} (${esc(u.username)})</strong>
        <span class="badge ${u.is_active ? 'good' : 'danger'}">${u.is_active ? 'Active' : 'Disabled'}</span>
      </div>
      <p><small>Position: ${esc(u.position_title || u.role)} • Fleet Management Profile: <b>${u.fleet_management ? 'Enabled' : 'Disabled'}</b></small></p>
      <div class="action-buttons-row">
        <button type="button" class="secondary" onclick="toggleFleetProfile('${esc(u.id)}', ${u.fleet_management ? 'false' : 'true'})">
          ${u.fleet_management ? 'Revoke Fleet Profile' : 'Grant Fleet Profile'}
        </button>
      </div>
    </div>
  `).join('');

  document.getElementById('auditLogs').innerHTML = logs.map(l => `
    <div class="log-item">
      <strong>${esc(l.action)}</strong> ${l.record_ref ? `<span class="badge warn">${esc(l.record_ref)}</span>` : ''}
      <p>${esc(l.detail)}</p>
      <p><small>${esc(l.user_name || l.role)} (${esc(l.role)}) • ${new Date(l.timestamp).toLocaleString()}</small></p>
    </div>
  `).join('');
}

window.toggleFleetProfile = async function (userId, enable) {
  try {
    await apiFetch(`/api/users/${userId}`, {
      method: 'PATCH',
      body: JSON.stringify({ fleet_management: enable })
    });
    await loadSecurityModule();
    showToast(`Fleet Management profile ${enable ? 'granted' : 'revoked'}.`);
  } catch (err) {
    showToast(err.message);
  }
};

document.getElementById('createUserForm').addEventListener('submit', async e => {
  e.preventDefault();
  try {
    await apiFetch('/api/users', {
      method: 'POST',
      body: JSON.stringify({
        username: document.getElementById('newUserUsername').value.trim(),
        email: document.getElementById('newUserEmail').value.trim(),
        full_name: document.getElementById('newUserFullName').value.trim(),
        password: document.getElementById('newUserPassword').value,
        role: document.getElementById('newUserRole').value,
        fleet_management: document.getElementById('newUserFleet').checked
      })
    });
    e.target.reset();
    await loadSecurityModule();
    showToast('Staff account created.');
  } catch (err) {
    showToast(err.message);
  }
});
