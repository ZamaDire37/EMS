const jwt = require('jsonwebtoken');
const db = require('./database');

const JWT_SECRET = process.env.JWT_SECRET || 'bucks-ems-cloud-hub-secret-key-2026';

const POSITIONS = {
  MEDICAL_DIRECTOR: 'Doctor / Medical Director',
  TRIAGE_NURSE: 'Emergency / Training Nurse',
  FIELD_MEDIC: 'Field Medic',
  FLIGHT_MEDIC: 'Flight Paramedic',
  STATION_MANAGER: 'Station Manager',
  QA_AUDITOR: 'QA Clinical / Clinical Audit',
  DISPATCHER: 'EMS Dispatcher',
  IT_ADMIN: 'IT Admin'
};

/**
 * Default granular permissions per role.
 * Actions: view, create, edit, delete, approve, export, manage_permissions, view_own, create_own
 */
const DEFAULT_ROLE_PERMISSIONS = {
  MEDICAL_DIRECTOR: {
    dashboard: ['view'],
    analytics: ['view', 'export'],
    incidents: ['view', 'approve', 'edit'],
    epcr: ['view', 'create', 'edit', 'approve', 'export'],
    vehicle_checks: ['view'],
    fleet: [],
    assets: ['view'],
    staff_docs: ['view'],
    audits: ['view', 'create', 'approve', 'export'],
    security: []
  },
  TRIAGE_NURSE: {
    dashboard: ['view'],
    analytics: ['view'],
    incidents: ['view', 'approve'],
    epcr: ['view', 'create', 'edit'],
    vehicle_checks: [],
    fleet: [],
    assets: ['view'],
    staff_docs: ['view', 'create', 'approve'],
    audits: ['view'],
    security: []
  },
  FIELD_MEDIC: {
    dashboard: ['view'],
    analytics: [],
    incidents: ['view', 'create'],
    epcr: ['view', 'create', 'edit'],
    vehicle_checks: ['view', 'create'],
    fleet: [],
    assets: ['view', 'create'],
    staff_docs: ['view_own', 'create_own'],
    audits: [],
    security: []
  },
  FLIGHT_MEDIC: {
    dashboard: ['view'],
    analytics: [],
    incidents: ['view', 'create'],
    epcr: ['view', 'create', 'edit'],
    vehicle_checks: ['view', 'create'],
    fleet: [],
    assets: ['view', 'create'],
    staff_docs: ['view_own', 'create_own'],
    audits: [],
    security: []
  },
  STATION_MANAGER: {
    dashboard: ['view'],
    analytics: ['view', 'export'],
    incidents: ['view', 'edit'],
    epcr: [],
    vehicle_checks: ['view', 'create'],
    fleet: ['view', 'create', 'edit', 'export'],
    assets: ['view', 'create', 'edit'],
    staff_docs: ['view', 'create', 'approve'],
    audits: [],
    security: []
  },
  QA_AUDITOR: {
    dashboard: ['view'],
    analytics: ['view', 'export'],
    incidents: ['view'],
    epcr: ['view', 'export'],
    vehicle_checks: [],
    fleet: [],
    assets: [],
    staff_docs: [],
    audits: ['view', 'create', 'approve', 'export'],
    security: []
  },
  DISPATCHER: {
    dashboard: ['view'],
    analytics: [],
    incidents: ['view', 'create', 'edit'],
    epcr: ['view', 'create'],
    vehicle_checks: ['view'],
    fleet: [],
    assets: [],
    staff_docs: ['view_own', 'create_own'],
    audits: [],
    security: []
  },
  IT_ADMIN: {
    dashboard: ['view'],
    analytics: ['view', 'export'],
    incidents: [],
    epcr: [], // Least privilege: IT Admin has no unrestricted access to patient records
    vehicle_checks: [],
    fleet: [],
    assets: [],
    staff_docs: [], // Least privilege: IT Admin has no unrestricted access to staff medical documents
    audits: [],
    security: ['view', 'create', 'edit', 'manage_permissions']
  }
};

const FLEET_MANAGEMENT_PERMISSIONS = ['view', 'create', 'edit', 'export'];

function getRolePermissions(role) {
  const base = JSON.parse(JSON.stringify(DEFAULT_ROLE_PERMISSIONS[role] || {}));
  const row = db.prepare('SELECT permissions_json FROM role_permissions WHERE role = ?').get(role);
  if (row && row.permissions_json) {
    try {
      const overrides = JSON.parse(row.permissions_json);
      for (const [res, actions] of Object.entries(overrides)) {
        if (Array.isArray(actions)) {
          base[res] = actions;
        }
      }
    } catch {
      // ignore malformed override
    }
  }
  return base;
}

function getUserEffectivePermissions(user) {
  const perms = getRolePermissions(user.role);
  // Configurable Fleet Management permission profile (no 9th role required)
  if (user.fleet_management === 1 || user.fleet_management === true) {
    const existing = new Set(perms.fleet || []);
    FLEET_MANAGEMENT_PERMISSIONS.forEach(a => existing.add(a));
    perms.fleet = Array.from(existing);
  }
  return perms;
}

function hasPermission(user, resource, action) {
  if (!user || !user.is_active) return false;
  const perms = getUserEffectivePermissions(user);
  const actions = perms[resource] || [];
  if (actions.includes(action)) return true;
  // Support view_own / create_own checks when caller checks general 'view' or 'create'
  if (action === 'view' && actions.includes('view_own')) return 'own';
  if (action === 'create' && actions.includes('create_own')) return 'own';
  return false;
}

function writeAuditLog({ action, detail, role, userId, userName, recordRef, ipAddress }) {
  try {
    const id = 'log-' + Date.now() + '-' + Math.random().toString(36).substring(2, 8);
    db.prepare(`
      INSERT INTO audit_logs (id, action, detail, role, user_id, user_name, record_ref, ip_address, timestamp)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      action,
      detail,
      role || 'SYSTEM',
      userId || null,
      userName || null,
      recordRef || null,
      ipAddress || null,
      new Date().toISOString()
    );
  } catch (err) {
    console.error('Failed to write audit log:', err.message);
  }
}

function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || '';
  let token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token && req.query && req.query.token) {
    token = req.query.token;
  }
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = db.prepare('SELECT id, username, email, full_name, role, position_title, fleet_management, is_active FROM users WHERE id = ?').get(decoded.id);
    if (!user || !user.is_active) {
      return res.status(401).json({ error: 'Account is inactive or not found' });
    }
    req.user = user;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired session token' });
  }
}

function requirePermission(resource, action) {
  return (req, res, next) => {
    const perm = hasPermission(req.user, resource, action);
    if (!perm) {
      writeAuditLog({
        action: 'ACCESS_DENIED',
        detail: `Denied ${req.method} ${req.originalUrl} (required ${resource}:${action})`,
        role: req.user ? req.user.role : 'UNKNOWN',
        userId: req.user ? req.user.id : null,
        userName: req.user ? req.user.full_name : null,
        ipAddress: req.ip
      });
      return res.status(403).json({ error: `Forbidden: requires ${resource}:${action} permission` });
    }
    req.permissionScope = perm === 'own' ? 'own' : 'all';
    next();
  };
}

module.exports = {
  JWT_SECRET,
  POSITIONS,
  DEFAULT_ROLE_PERMISSIONS,
  getRolePermissions,
  getUserEffectivePermissions,
  hasPermission,
  writeAuditLog,
  requireAuth,
  requirePermission
};
