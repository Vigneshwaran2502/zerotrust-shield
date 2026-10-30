import crypto from 'node:crypto';

export async function getUserById(db, id) {
  if (!id) return null;
  return await db.prepare('SELECT id, name, email, password, role FROM users WHERE id = ?').bind(id).first();
}

export async function getUserByEmail(db, email) {
  if (!email) return null;
  return await db.prepare('SELECT id, name, email, password, role FROM users WHERE LOWER(email) = LOWER(?)').bind(email.trim()).first();
}

export async function createUser(db, { id, name, email, passwordHash, role }) {
  await db.prepare(
    'INSERT INTO users (id, name, email, password, role) VALUES (?, ?, ?, ?, ?)'
  ).bind(id, name, email.trim().toLowerCase(), passwordHash, role).run();
  return { id, name, email: email.trim().toLowerCase(), role };
}

export async function updateUserRole(db, email, role) {
  await db.prepare('UPDATE users SET role = ? WHERE LOWER(email) = LOWER(?)').bind(role, email.trim()).run();
}

export async function updateUserPassword(db, userId, newPasswordHash) {
  await db.prepare('UPDATE users SET password = ? WHERE id = ?').bind(newPasswordHash, userId).run();
}

export async function createSession(db, { id, userId, expiresAt, createdAt }) {
  await db.prepare(
    'INSERT INTO sessions (id, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)'
  ).bind(id, userId, expiresAt, createdAt).run();
  return id;
}

export async function getSession(db, sessionId) {
  if (!sessionId) return null;
  return await db.prepare(`
    SELECT users.id, users.name, users.email, users.role, sessions.expires_at
    FROM sessions
    JOIN users ON sessions.user_id = users.id
    WHERE sessions.id = ?
  `).bind(sessionId).first();
}

export async function deleteSession(db, sessionId) {
  if (!sessionId) return;
  await db.prepare('DELETE FROM sessions WHERE id = ?').bind(sessionId).run();
}

export async function logAuditEvent(db, { eventType, outcome, endpoint, method, userId = null, ipAddress = null, reason = null }) {
  if (!db) return;
  const id = `AUD-${Date.now()}-${crypto.randomInt(10000, 99999)}`;
  const timestamp = new Date().toISOString();

  // Sanitize reason to prevent log injection
  const sanitizedReason = reason ? String(reason).replace(/[\r\n\x00-\x1F]/g, ' ').slice(0, 255) : null;
  const sanitizedUserId = userId ? String(userId).slice(0, 64) : null;

  try {
    await db.prepare(`
      INSERT INTO audit_logs (id, timestamp, event_type, outcome, endpoint, method, user_id, ip_address, reason)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      id,
      timestamp,
      eventType,
      outcome,
      endpoint,
      method,
      sanitizedUserId,
      ipAddress,
      sanitizedReason
    ).run();
  } catch (err) {
    console.error('Failed to write audit log to D1:', err);
  }
}

export async function getAuditLogs(db, { limit = 50, offset = 0 } = {}) {
  const safeLimit = Math.min(Math.max(parseInt(limit, 10) || 50, 1), 100);
  const safeOffset = Math.max(parseInt(offset, 10) || 0, 0);

  const { results } = await db.prepare(`
    SELECT id, timestamp, event_type, outcome, endpoint, method, user_id, ip_address, reason
    FROM audit_logs
    ORDER BY timestamp DESC
    LIMIT ? OFFSET ?
  `).bind(safeLimit, safeOffset).all();

  return results || [];
}

export async function getDashboardMetrics(db) {
  const now = Date.now();
  const [usersRow, sessionsRow, logsResult] = await Promise.all([
    db.prepare('SELECT COUNT(*) AS total_users FROM users').first(),
    db.prepare('SELECT COUNT(*) AS active_sessions FROM sessions WHERE expires_at > ?').bind(now).first(),
    db.prepare(`
      SELECT id, timestamp, event_type, outcome, endpoint, method, user_id, ip_address, reason
      FROM audit_logs
      ORDER BY timestamp DESC
      LIMIT 10
    `).all()
  ]);

  return {
    totalUsers: usersRow ? usersRow.total_users : 0,
    activeSessions: sessionsRow ? sessionsRow.active_sessions : 0,
    activeApplications: 8,
    protectedEndpoints: 4,
    recentEvents: logsResult?.results || []
  };
}

export async function getDemoStudents(db) {
  const countRow = await db.prepare('SELECT COUNT(*) AS total FROM demo_students').first();
  const total = countRow ? countRow.total : 0;
  const maxLimit = 5;
  const remaining = Math.max(0, maxLimit - total);

  const { results } = await db.prepare(`
    SELECT u.id, u.name, u.email, u.role, ds.created_at AS createdAt, ds.created_by AS createdBy
    FROM demo_students ds
    JOIN users u ON ds.user_id = u.id
    ORDER BY ds.created_at DESC
  `).all();

  return {
    total,
    maxLimit,
    remaining,
    students: results || []
  };
}

export async function createDemoStudent(db, { id, name, email, passwordHash, createdBy }) {
  const now = Date.now();
  await db.batch([
    db.prepare('INSERT INTO users (id, name, email, password, role) VALUES (?, ?, ?, ?, ?)').bind(id, name, email.trim().toLowerCase(), passwordHash, 'Student'),
    db.prepare('INSERT INTO demo_students (user_id, created_at, created_by) VALUES (?, ?, ?)').bind(id, now, createdBy)
  ]);
  return { id, name, email: email.trim().toLowerCase(), role: 'Student', createdAt: now };
}
