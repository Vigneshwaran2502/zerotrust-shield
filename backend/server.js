require('dotenv').config();
const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const { verifyCloudflareAccessJwt, validateCloudflareEnvironment } = require('./cloudflareAccess');

const app = express();
const PORT = process.env.PORT || 3001;
const SALT_ROUNDS = 12;
const SESSION_EXPIRY_MS = 24 * 60 * 60 * 1000; // 24 hours

// Validate environment on startup
try {
  validateCloudflareEnvironment();
} catch (envErr) {
  if (process.env.NODE_ENV === 'production') {
    console.error(envErr.message);
    process.exit(1);
  }
}

// Session secret: load from environment variable or generate cryptographically secure random secret
const SESSION_SECRET = process.env.SESSION_SECRET || (
  process.env.NODE_ENV === 'test'
    ? 'test-session-secret-key-1234567890'
    : crypto.randomBytes(32).toString('hex')
);

// Cookie security configuration
const isHttpsMode = process.env.NODE_ENV === 'production' || process.env.CLOUDFLARE_ACCESS_ENFORCE === 'true';
const cookieOptions = {
  signed: true,
  httpOnly: true,
  secure: isHttpsMode,
  sameSite: 'lax',
  maxAge: SESSION_EXPIRY_MS,
  path: '/'
};

// Security Headers Middleware
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '0');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  next();
});

// ── Enforcement helper ─────────────────────────────────────────────────────
// Returns true when the backend must require a Cloudflare Access JWT.
// This is the case in production, OR when CLOUDFLARE_ACCESS_ENFORCE=true AND
// ALLOW_LOCAL_AUTH is not explicitly enabled (used by the tunnel startup script).
function isCfAccessEnforced() {
  const isProduction = process.env.NODE_ENV === 'production';
  const enforceCfAccess = process.env.CLOUDFLARE_ACCESS_ENFORCE === 'true';
  const allowLocalAuth = process.env.ALLOW_LOCAL_AUTH === 'true';
  return isProduction || (enforceCfAccess && !allowLocalAuth);
}

// CORS configuration supporting credentials (cookies)
const isProductionMode = process.env.NODE_ENV === 'production';
const allowedOrigins = isProductionMode
  ? [process.env.CLIENT_URL, process.env.FRONTEND_ORIGIN].filter(Boolean)
  : [
      'http://localhost:5173',
      'http://127.0.0.1:5173',
      process.env.CLIENT_URL,
      process.env.FRONTEND_ORIGIN
    ].filter(Boolean);

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(null, false);
  },
  credentials: true
}));

// CSRF Origin Protection Middleware for state-changing requests
app.use((req, res, next) => {
  if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
    const origin = req.headers['origin'];
    if (origin && !allowedOrigins.includes(origin)) {
      logAuditEvent({
        eventType: 'CSRF_BLOCKED',
        outcome: 'DENY',
        endpoint: req.originalUrl,
        method: req.method,
        req,
        reason: `Untrusted Origin header: ${origin}`
      });
      return res.status(403).json({ error: 'Cross-origin request blocked by CSRF policy' });
    }
  }
  next();
});

// Request size limit to prevent Denial of Service
app.use(express.json({ limit: '100kb' }));
app.use(cookieParser(SESSION_SECRET));

// Initialize SQLite DB (support custom DB path for testing)
const dbPath = process.env.TEST_DB_PATH || path.resolve(__dirname, 'database.sqlite');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) console.error('Database connection error:', err);
  else if (process.env.NODE_ENV !== 'test') console.log(`Connected to SQLite database: ${path.basename(dbPath)}`);
});

// Enable foreign keys
db.run('PRAGMA foreign_keys = ON');

// Create tables: users, server-managed sessions, and security audit logs
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      created_at INTEGER NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  db.run('CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)');

  db.run(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      timestamp TEXT NOT NULL,
      event_type TEXT NOT NULL,
      outcome TEXT NOT NULL,
      endpoint TEXT NOT NULL,
      method TEXT NOT NULL,
      user_id TEXT,
      ip_address TEXT,
      reason TEXT
    )
  `);

  db.run('CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp DESC)');
  db.run('CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id)');

  db.run(`
    CREATE TABLE IF NOT EXISTS demo_students (
      user_id TEXT PRIMARY KEY,
      created_at INTEGER NOT NULL,
      created_by TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  db.run('CREATE INDEX IF NOT EXISTS idx_demo_students_created_at ON demo_students(created_at DESC)');
});

// -------------------------------------------------------------
// Security Audit Logging Engine
// -------------------------------------------------------------
function logAuditEvent({ eventType, outcome, endpoint, method, userId = null, req = null, reason = null }) {
  try {
    const id = `AUD-${Date.now()}-${crypto.randomInt(10000, 99999)}`;
    const timestamp = new Date().toISOString();

    // Sanitize string fields against log injection (remove newlines, truncate length)
    const safeEventType = String(eventType || 'UNKNOWN').replace(/[\r\n]/g, '').substring(0, 50);
    const safeOutcome = String(outcome || 'UNKNOWN').replace(/[\r\n]/g, '').substring(0, 20);
    const safeEndpoint = String(endpoint || req?.originalUrl || req?.url || 'UNKNOWN').replace(/[\r\n]/g, '').substring(0, 100);
    const safeMethod = String(method || req?.method || 'UNKNOWN').replace(/[\r\n]/g, '').substring(0, 10);
    const safeUserId = userId ? String(userId).replace(/[\r\n]/g, '').substring(0, 50) : null;
    const safeIp = req ? String(req.ip || req.socket?.remoteAddress || 'unknown').replace(/[\r\n]/g, '').substring(0, 45) : 'system';
    const safeReason = reason ? String(reason).replace(/[\r\n]/g, ' ').substring(0, 255) : null;

    db.run(
      `INSERT INTO audit_logs (id, timestamp, event_type, outcome, endpoint, method, user_id, ip_address, reason)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [id, timestamp, safeEventType, safeOutcome, safeEndpoint, safeMethod, safeUserId, safeIp, safeReason],
      (err) => {
        if (err && process.env.NODE_ENV !== 'test') {
          console.error('Audit logging write failed (non-fatal):', err.message);
        }
      }
    );
  } catch (err) {
    if (process.env.NODE_ENV !== 'test') {
      console.error('Audit log serialization error:', err);
    }
  }
}

// Input validation helpers
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function validateRegistrationInput(name, email, password) {
  if (!name || typeof name !== 'string' || name.trim().length < 2 || name.trim().length > 100) {
    return 'Name must be between 2 and 100 characters';
  }
  if (!email || typeof email !== 'string' || !EMAIL_REGEX.test(email.trim()) || email.trim().length > 255) {
    return 'A valid email address is required';
  }
  if (!password || typeof password !== 'string' || password.length < 8 || password.length > 128) {
    return 'Password must be between 8 and 128 characters long';
  }
  return null;
}

// Strong temporary password generator for demo student accounts
function generateSecureTempPassword() {
  const upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  const lower = 'abcdefghijkmnpqrstuvwxyz';
  const digits = '23456789';
  const special = '!@#$%^&*';
  const all = upper + lower + digits + special;

  const chars = [
    upper[crypto.randomInt(0, upper.length)],
    lower[crypto.randomInt(0, lower.length)],
    digits[crypto.randomInt(0, digits.length)],
    special[crypto.randomInt(0, special.length)]
  ];

  for (let i = 4; i < 14; i++) {
    chars.push(all[crypto.randomInt(0, all.length)]);
  }

  for (let i = chars.length - 1; i > 0; i--) {
    const j = crypto.randomInt(0, i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }

  return chars.join('');
}

// Session Creation Helper
function createSession(userId, callback) {
  const sessionId = crypto.randomBytes(32).toString('hex');
  const now = Date.now();
  const expiresAt = now + SESSION_EXPIRY_MS;

  db.run(
    'INSERT INTO sessions (id, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)',
    [sessionId, userId, expiresAt, now],
    function (err) {
      if (err) return callback(err);
      callback(null, sessionId);
    }
  );
}

// -------------------------------------------------------------
// Authentication Middleware (Dual-Layer: Cloudflare Access Outer Gate + Campus Session Inner Gate)
// -------------------------------------------------------------
async function requireAuth(req, res, next) {
  let verifiedCfEmail = null;
  const cfJwt = req.headers['cf-access-jwt-assertion'];

  // ── Layer 1: Outer Perimeter Gate (Cloudflare Access Verification) ─────────
  if (cfJwt) {
    try {
      const verifiedPayload = await verifyCloudflareAccessJwt(cfJwt);
      verifiedCfEmail = (verifiedPayload.email || verifiedPayload.sub || '').trim().toLowerCase();
    } catch (cfErr) {
      let logReason = 'Cloudflare Access JWT verification failed';
      if (cfErr.name === 'TokenExpiredError') {
        logReason = 'Cloudflare Access JWT expired';
      } else if (cfErr.name === 'JsonWebTokenError') {
        logReason = `Cloudflare Access JWT invalid: ${cfErr.message}`;
      } else if (cfErr.message) {
        logReason = cfErr.message;
      }

      logAuditEvent({
        eventType: 'CF_ACCESS_INVALID',
        outcome: 'DENY',
        endpoint: req.originalUrl,
        method: req.method,
        req,
        reason: logReason
      });

      const isProd = process.env.NODE_ENV === 'production';
      const clientReason = isProd ? 'Invalid or expired Cloudflare Access assertion' : logReason;
      return res.status(401).json({ error: 'Invalid Cloudflare Access assertion', reason: clientReason });
    }
  } else if (isCfAccessEnforced()) {
    // Cloudflare Access assertion is strictly required when enforced (tunnel or production mode)
    logAuditEvent({
      eventType: 'CF_ACCESS_MISSING',
      outcome: 'DENY',
      endpoint: req.originalUrl,
      method: req.method,
      req,
      reason: 'Cloudflare Access assertion required'
    });
    return res.status(401).json({ error: 'Cloudflare Access assertion required' });
  }

  // ── Layer 2: Inner Campus Application Session & Identity ───────────────────
  const sessionId = req.signedCookies?.sessionId;

  // Case 2A: Active campus application session exists in SQLite
  if (sessionId) {
    const sessionQuery = `
      SELECT users.id, users.name, users.email, users.role, sessions.expires_at
      FROM sessions
      JOIN users ON sessions.user_id = users.id
      WHERE sessions.id = ?
    `;

    db.get(sessionQuery, [sessionId], (err, row) => {
      if (err) {
        return res.status(500).json({ error: 'Database error occurred' });
      }
      if (!row) {
        logAuditEvent({
          eventType: 'SESSION_INVALID',
          outcome: 'DENY',
          endpoint: req.originalUrl,
          method: req.method,
          req,
          reason: 'Unrecognized or forged session identifier'
        });
        res.clearCookie('sessionId', cookieOptions);
        return res.status(401).json({ error: 'Invalid or expired session' });
      }

      if (Date.now() > row.expires_at) {
        logAuditEvent({
          eventType: 'SESSION_EXPIRED',
          outcome: 'DENY',
          endpoint: req.originalUrl,
          method: req.method,
          userId: row.id,
          req,
          reason: 'Session validity period elapsed'
        });
        db.run('DELETE FROM sessions WHERE id = ?', [sessionId]);
        res.clearCookie('sessionId', cookieOptions);
        return res.status(401).json({ error: 'Session expired' });
      }

      // Campus identity is derived from verified application session
      req.user = {
        id: row.id,
        name: row.name,
        email: row.email,
        role: row.role,
        authMethod: 'campus-session',
        cfIdentity: verifiedCfEmail
      };
      req.sessionId = sessionId;

      logAuditEvent({
        eventType: 'SESSION_VERIFIED',
        outcome: 'ALLOW',
        endpoint: req.originalUrl,
        method: req.method,
        userId: row.id,
        req,
        reason: `Authenticated as '${row.role}' via campus session (Outer CF: ${verifiedCfEmail || 'local'})`
      });

      return next();
    });
    return;
  }

  // Case 2B: No campus session cookie, but verified via Cloudflare Access at outer gate
  if (verifiedCfEmail) {
    const configuredAdmins = (process.env.ADMIN_EMAILS || process.env.ADMIN_EMAIL || '')
      .split(',')
      .map((e) => e.trim().toLowerCase())
      .filter(Boolean);

    db.get('SELECT id, name, email, role FROM users WHERE email = ?', [verifiedCfEmail], (err, row) => {
      if (err) {
        return res.status(500).json({ error: 'Database error occurred' });
      }
      if (!row) {
        if (configuredAdmins.includes(verifiedCfEmail)) {
          const adminId = `ADM-${Date.now().toString().slice(-4)}-${crypto.randomInt(1000, 9999)}`;
          const adminName = verifiedCfEmail.split('@')[0];
          db.run(
            'INSERT INTO users (id, name, email, password, role) VALUES (?, ?, ?, ?, ?)',
            [adminId, adminName, verifiedCfEmail, 'CF_ACCESS_PROVISIONED', 'Administrator'],
            (insErr) => {
              if (insErr) {
                return res.status(500).json({ error: 'Failed to provision admin user' });
              }
              req.user = {
                id: adminId,
                name: adminName,
                email: verifiedCfEmail,
                role: 'Administrator',
                authMethod: 'cloudflare-access',
                cfIdentity: verifiedCfEmail
              };
              logAuditEvent({
                eventType: 'CF_ACCESS_VERIFIED',
                outcome: 'ALLOW',
                endpoint: req.originalUrl,
                method: req.method,
                userId: adminId,
                req,
                reason: "Cloudflare Access JWT verified for role 'Administrator'"
              });
              return next();
            }
          );
          return;
        }

        logAuditEvent({
          eventType: 'CF_ACCESS_UNAUTHORIZED_USER',
          outcome: 'DENY',
          endpoint: req.originalUrl,
          method: req.method,
          req,
          reason: `Cloudflare Access authenticated '${verifiedCfEmail}', but user is not provisioned in campus directory`
        });
        return res.status(401).json({ error: 'User identity not provisioned in campus directory' });
      }

      let role = row.role;
      if (configuredAdmins.includes(verifiedCfEmail) && role !== 'Administrator') {
        role = 'Administrator';
        db.run('UPDATE users SET role = ? WHERE email = ?', ['Administrator', verifiedCfEmail], () => {});
      }

      req.user = {
        id: row.id,
        name: row.name,
        email: row.email,
        role: role,
        authMethod: 'cloudflare-access',
        cfIdentity: verifiedCfEmail
      };

      logAuditEvent({
        eventType: 'CF_ACCESS_VERIFIED',
        outcome: 'ALLOW',
        endpoint: req.originalUrl,
        method: req.method,
        userId: row.id,
        req,
        reason: `Cloudflare Access JWT verified for default role '${role}'`
      });

      return next();
    });
    return;
  }

  // Case 2C: Unauthenticated in local mode
  logAuditEvent({
    eventType: 'SESSION_MISSING',
    outcome: 'DENY',
    endpoint: req.originalUrl,
    method: req.method,
    req,
    reason: 'Authentication required'
  });
  return res.status(401).json({ error: 'Authentication required' });
}

// -------------------------------------------------------------
// Role-Based Access Control (RBAC) Middleware
// -------------------------------------------------------------
function requireRole(allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    if (!allowedRoles.includes(req.user.role)) {
      logAuditEvent({
        eventType: 'ACCESS_DENIED',
        outcome: 'DENY',
        endpoint: req.originalUrl,
        method: req.method,
        userId: req.user.id,
        req,
        reason: `Role '${req.user.role}' lacks permission for this endpoint`
      });
      return res.status(403).json({ error: 'Insufficient privileges' });
    }

    logAuditEvent({
      eventType: 'ACCESS_GRANTED',
      outcome: 'ALLOW',
      endpoint: req.originalUrl,
      method: req.method,
      userId: req.user.id,
      req,
      reason: `Role '${req.user.role}' authorized (${req.user.authMethod || 'local'})`
    });

    next();
  };
}

// -------------------------------------------------------------
// Public Endpoints
// -------------------------------------------------------------

// 1. User Registration (Public endpoint: strictly assigns 'Student' role)
app.post('/api/register', async (req, res) => {
  // Blocked in production AND when CF Access enforcement is active (tunnel mode)
  if (isCfAccessEnforced()) {
    logAuditEvent({
      eventType: 'REGISTER_BLOCKED',
      outcome: 'DENY',
      endpoint: '/api/register',
      method: 'POST',
      req,
      reason: 'Public user registration disabled in production environment'
    });
    return res.status(403).json({
      error: 'Public user registration is disabled in production. Accounts must be provisioned via campus identity provider.'
    });
  }

  try {
    const { name, email, password } = req.body;

    const validationError = validateRegistrationInput(name, email, password);
    if (validationError) {
      logAuditEvent({
        eventType: 'REGISTER_FAILURE',
        outcome: 'DENY',
        endpoint: '/api/register',
        method: 'POST',
        req,
        reason: `Validation failed: ${validationError}`
      });
      return res.status(400).json({ error: validationError });
    }

    const trimmedName = name.trim();
    const normalizedEmail = email.trim().toLowerCase();

    // Prevent privilege escalation: role is strictly determined by server
    const assignedRole = 'Student';

    // Generate unique ID with CSPRNG
    const randomSuffix = crypto.randomInt(1000, 9999);
    const userId = `STU-${new Date().getFullYear()}-${randomSuffix}`;

    // Hash password with bcrypt
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    db.run(
      'INSERT INTO users (id, name, email, password, role) VALUES (?, ?, ?, ?, ?)',
      [userId, trimmedName, normalizedEmail, hashedPassword, assignedRole],
      function (err) {
        if (err) {
          if (err.message && err.message.includes('UNIQUE constraint failed')) {
            logAuditEvent({
              eventType: 'REGISTER_FAILURE',
              outcome: 'DENY',
              endpoint: '/api/register',
              method: 'POST',
              req,
              reason: 'Email already registered'
            });
            return res.status(400).json({ error: 'Email already registered' });
          }
          return res.status(500).json({ error: 'Database error occurred' });
        }

        logAuditEvent({
          eventType: 'REGISTER_SUCCESS',
          outcome: 'ALLOW',
          endpoint: '/api/register',
          method: 'POST',
          userId,
          req,
          reason: 'Account successfully registered with Student role'
        });

        // Establish session and attach secure cookie
        createSession(userId, (sessionErr, sessionId) => {
          if (!sessionErr && sessionId) {
            res.cookie('sessionId', sessionId, cookieOptions);
          }

          // Return sanitized user context
          return res.status(201).json({
            id: userId,
            name: trimmedName,
            email: normalizedEmail,
            role: assignedRole,
            department: 'Self-Registered',
            status: 'Active',
            mfa: true,
            deviceTrusted: true
          });
        });
      }
    );
  } catch (error) {
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// 2. User Login (Campus Application Authentication)
app.post('/api/login', async (req, res) => {
  // Layer 1: Outer Gate Guard
  // In tunnel or production mode, direct requests without a valid Cloudflare Access assertion are strictly rejected.
  let verifiedCfEmail = null;
  if (isCfAccessEnforced()) {
    const cfJwt = req.headers['cf-access-jwt-assertion'];
    if (!cfJwt) {
      logAuditEvent({
        eventType: 'LOCAL_LOGIN_BLOCKED',
        outcome: 'DENY',
        endpoint: '/api/login',
        method: 'POST',
        req,
        reason: 'Direct tunnel request blocked: Cloudflare Access assertion required'
      });
      return res.status(401).json({ error: 'Cloudflare Access assertion required before campus login' });
    }
    try {
      const verifiedPayload = await verifyCloudflareAccessJwt(cfJwt);
      verifiedCfEmail = (verifiedPayload.email || verifiedPayload.sub || '').trim().toLowerCase();
    } catch (cfErr) {
      logAuditEvent({
        eventType: 'CF_ACCESS_INVALID',
        outcome: 'DENY',
        endpoint: '/api/login',
        method: 'POST',
        req,
        reason: `Outer gate rejection on login: ${cfErr.message}`
      });
      return res.status(401).json({ error: 'Invalid Cloudflare Access assertion' });
    }
  }

  const { email, password } = req.body;

  if (!email || !password || typeof email !== 'string' || typeof password !== 'string') {
    logAuditEvent({
      eventType: 'LOGIN_FAILURE',
      outcome: 'DENY',
      endpoint: '/api/login',
      method: 'POST',
      req,
      reason: 'Missing email or password'
    });
    return res.status(400).json({ error: 'Email and password are required' });
  }

  const normalizedEmail = email.trim().toLowerCase();

  db.get('SELECT * FROM users WHERE email = ?', [normalizedEmail], async (err, row) => {
    if (err) {
      return res.status(500).json({ error: 'Database error occurred' });
    }
    if (!row) {
      logAuditEvent({
        eventType: 'LOGIN_FAILURE',
        outcome: 'DENY',
        endpoint: '/api/login',
        method: 'POST',
        req,
        reason: 'Account not found'
      });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    try {
      let isPasswordValid = false;
      const storedPassword = row.password;

      // Check if stored password is a bcrypt hash
      const isBcryptHash = storedPassword && (
        storedPassword.startsWith('$2a$') ||
        storedPassword.startsWith('$2b$') ||
        storedPassword.startsWith('$2y$')
      );

      if (isBcryptHash) {
        isPasswordValid = await bcrypt.compare(password, storedPassword);
      } else {
        // Safe lazy migration: Handle legacy plaintext password
        isPasswordValid = (password === storedPassword);

        if (isPasswordValid) {
          const upgradedHash = await bcrypt.hash(password, SALT_ROUNDS);
          db.run('UPDATE users SET password = ? WHERE id = ?', [upgradedHash, row.id], (updateErr) => {
            if (updateErr) console.error('Failed to upgrade legacy password hash:', updateErr);
          });
        }
      }

      if (!isPasswordValid) {
        logAuditEvent({
          eventType: 'LOGIN_FAILURE',
          outcome: 'DENY',
          endpoint: '/api/login',
          method: 'POST',
          userId: row.id,
          req,
          reason: 'Incorrect password provided'
        });
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      logAuditEvent({
        eventType: 'LOGIN_SUCCESS',
        outcome: 'ALLOW',
        endpoint: '/api/login',
        method: 'POST',
        userId: row.id,
        req,
        reason: 'Credentials verified'
      });

      // Invalidate any prior session for this client
      const prevSessionId = req.signedCookies?.sessionId;
      if (prevSessionId) {
        db.run('DELETE FROM sessions WHERE id = ?', [prevSessionId], () => {});
      }

      // Establish session and issue secure signed cookie
      createSession(row.id, (sessionErr, sessionId) => {
        if (!sessionErr && sessionId) {
          res.cookie('sessionId', sessionId, cookieOptions);
        }

        return res.json({
          id: row.id,
          name: row.name,
          email: row.email,
          role: row.role,
          department: row.role === 'Administrator' ? 'IT Security' : 'Computer Science',
          status: 'Active',
          mfa: true,
          deviceTrusted: true
        });
      });
    } catch (authError) {
      return res.status(500).json({ error: 'Authentication failed' });
    }
  });
});

// 3. User Logout
app.post('/api/logout', (req, res) => {
  const sessionId = req.signedCookies?.sessionId;
  if (sessionId) {
    db.run('DELETE FROM sessions WHERE id = ?', [sessionId], () => {});
  }
  logAuditEvent({
    eventType: 'LOGOUT',
    outcome: 'ALLOW',
    endpoint: '/api/logout',
    method: 'POST',
    userId: req.user?.id || null,
    req,
    reason: 'User session terminated'
  });
  res.clearCookie('sessionId', cookieOptions);
  return res.json({ message: 'Logged out successfully' });
});

// -------------------------------------------------------------
// Protected Endpoints
// -------------------------------------------------------------

// 4. Authenticated User Profile & Role Verification
app.get('/api/me', requireAuth, (req, res) => {
  res.json({
    id: req.user.id,
    name: req.user.name,
    email: req.user.email,
    role: req.user.role,
    authMethod: req.user.authMethod || 'session',
    department: req.user.role === 'Administrator' ? 'IT Security' : 'Computer Science',
    status: 'Active',
    mfa: true,
    deviceTrusted: true
  });
});

// 5. Student Dashboard Endpoint (Restricted to Student role)
app.get('/api/student/dashboard', requireAuth, requireRole(['Student']), (req, res) => {
  res.json({
    portal: 'Student Portal',
    user: {
      id: req.user.id,
      name: req.user.name,
      role: req.user.role,
      authMethod: req.user.authMethod
    },
    metrics: {
      attendance: '87%',
      currentCourses: 5,
      assignmentsPending: 3,
      notifications: 4
    },
    courses: [
      { id: 'CS301', name: 'Computer Networks', progress: 75 },
      { id: 'CS302', name: 'Cloud Computing', progress: 60 },
      { id: 'CS303', name: 'Cyber Security', progress: 90 },
      { id: 'CS304', name: 'Database Management', progress: 85 },
      { id: 'CS305', name: 'Operating Systems', progress: 40 }
    ]
  });
});

// 6. Faculty Dashboard Endpoint (Restricted to Faculty role)
app.get('/api/faculty/dashboard', requireAuth, requireRole(['Faculty']), (req, res) => {
  res.json({
    portal: 'Faculty Portal',
    user: {
      id: req.user.id,
      name: req.user.name,
      role: req.user.role,
      authMethod: req.user.authMethod
    },
    metrics: {
      coursesTeaching: 2,
      totalStudents: 75,
      pendingEvaluations: 12,
      notifications: 2
    },
    courses: [
      { id: 'CS301', name: 'Computer Networks', students: 45, nextClass: '10:00 AM Today' },
      { id: 'CS401', name: 'Advanced Cryptography', students: 30, nextClass: '2:00 PM Tomorrow' }
    ]
  });
});

// 7. Administrator Dashboard Endpoint (Restricted to Administrator role only)
app.get('/api/admin/dashboard', requireAuth, requireRole(['Administrator']), (req, res) => {
  db.get('SELECT COUNT(*) AS total_users FROM users', [], (errUsers, userRow) => {
    db.get('SELECT COUNT(*) AS active_sessions FROM sessions WHERE expires_at > ?', [Date.now()], (errSess, sessRow) => {
      db.all(
        `SELECT id, timestamp, event_type, outcome, endpoint, user_id, ip_address, reason
         FROM audit_logs
         ORDER BY timestamp DESC
         LIMIT 10`,
        [],
        (errLogs, logRows) => {
          res.json({
            portal: 'Admin Portal',
            user: {
              id: req.user.id,
              name: req.user.name,
              role: req.user.role,
              authMethod: req.user.authMethod
            },
            metrics: {
              totalUsers: userRow ? userRow.total_users : 0,
              activeSessions: sessRow ? sessRow.active_sessions : 0,
              activeApplications: 8,
              protectedEndpoints: 4
            },
            securityEvents: (logRows || []).map(row => ({
              id: row.id,
              time: new Date(row.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
              timestamp: row.timestamp,
              eventType: row.event_type,
              user: row.user_id || 'Anonymous',
              outcome: row.outcome,
              endpoint: row.endpoint,
              reason: row.reason || 'None'
            }))
          });
        }
      );
    });
  });
});

// 8. Dedicated Administrator Audit Logs Endpoint (Paginated query restricted to Administrator)
app.get('/api/admin/audit-logs', requireAuth, requireRole(['Administrator']), (req, res) => {
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 100);
  const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);

  db.all(
    `SELECT id, timestamp, event_type, outcome, endpoint, method, user_id, ip_address, reason
     FROM audit_logs
     ORDER BY timestamp DESC
     LIMIT ? OFFSET ?`,
    [limit, offset],
    (err, rows) => {
      if (err) {
        return res.status(500).json({ error: 'Failed to retrieve audit logs' });
      }
      res.json({
        total: rows.length,
        limit,
        offset,
        auditLogs: rows
      });
    }
  );
});

// 9. Administrator: List Created Demo Student Accounts
app.get('/api/admin/students', requireAuth, requireRole(['Administrator']), (req, res) => {
  db.get('SELECT COUNT(*) AS total FROM demo_students', [], (errCount, countRow) => {
    if (errCount) {
      return res.status(500).json({ error: 'Database error retrieving student count' });
    }
    const total = countRow ? countRow.total : 0;
    const maxLimit = 5;
    const remaining = Math.max(0, maxLimit - total);

    db.all(
      `SELECT u.id, u.name, u.email, u.role, ds.created_at AS createdAt, ds.created_by AS createdBy
       FROM demo_students ds
       JOIN users u ON ds.user_id = u.id
       ORDER BY ds.created_at DESC`,
      [],
      (errStudents, rows) => {
        if (errStudents) {
          return res.status(500).json({ error: 'Database error retrieving demo students' });
        }
        res.json({
          total,
          maxLimit,
          remaining,
          students: (rows || []).map(r => ({
            id: r.id,
            name: r.name,
            email: r.email,
            role: r.role,
            createdAt: r.createdAt,
            createdBy: r.createdBy
          }))
        });
      }
    );
  });
});

// 10. Administrator: Create Demo Student Account (Maximum 5 accounts)
app.post('/api/admin/students', requireAuth, requireRole(['Administrator']), async (req, res) => {
  try {
    // 1. Verify limit of 5 demo accounts
    db.get('SELECT COUNT(*) AS count FROM demo_students', [], async (errCount, countRow) => {
      if (errCount) {
        return res.status(500).json({ error: 'Database error checking account count' });
      }
      const count = countRow ? countRow.count : 0;
      const MAX_DEMO_STUDENTS = 5;
      if (count >= MAX_DEMO_STUDENTS) {
        logAuditEvent({
          eventType: 'STUDENT_ACCOUNT_CREATE_FAILED',
          outcome: 'DENY',
          endpoint: '/api/admin/students',
          method: 'POST',
          userId: req.user.id,
          req,
          reason: 'Maximum demo student account limit (5) reached'
        });
        return res.status(400).json({
          error: `Maximum limit of ${MAX_DEMO_STUDENTS} demo student accounts has been reached.`
        });
      }

      // 2. Validate input
      const { name, email, studentId } = req.body;
      if (!name || typeof name !== 'string' || name.trim().length < 2 || name.trim().length > 100) {
        return res.status(400).json({ error: 'Student name must be between 2 and 100 characters.' });
      }
      if (!email || typeof email !== 'string' || !EMAIL_REGEX.test(email.trim()) || email.trim().length > 255) {
        return res.status(400).json({ error: 'Valid student email address is required.' });
      }

      const trimmedName = name.trim();
      const normalizedEmail = email.trim().toLowerCase();

      // Custom student ID validation if provided, or generate one
      let finalStudentId;
      if (studentId && typeof studentId === 'string' && studentId.trim().length > 0) {
        const trimmedId = studentId.trim();
        if (!/^[A-Za-z0-9-]{3,32}$/.test(trimmedId)) {
          return res.status(400).json({ error: 'Student ID must be 3-32 alphanumeric characters or hyphens.' });
        }
        finalStudentId = trimmedId;
      } else {
        const randomSuffix = crypto.randomInt(1000, 9999);
        finalStudentId = `STU-${new Date().getFullYear()}-${randomSuffix}`;
      }

      // 3. Check for duplicates in users table (email or student ID)
      db.get('SELECT id, email FROM users WHERE id = ? OR email = ?', [finalStudentId, normalizedEmail], async (errDup, dupRow) => {
        if (errDup) {
          return res.status(500).json({ error: 'Database error checking duplicates' });
        }
        if (dupRow) {
          const isEmailDup = dupRow.email.toLowerCase() === normalizedEmail;
          const reason = isEmailDup ? 'Email address already exists' : 'Student ID already exists';
          logAuditEvent({
            eventType: 'STUDENT_ACCOUNT_CREATE_FAILED',
            outcome: 'DENY',
            endpoint: '/api/admin/students',
            method: 'POST',
            userId: req.user.id,
            req,
            reason
          });
          return res.status(400).json({
            error: isEmailDup
              ? 'An account with this email address already exists.'
              : 'An account with this student ID already exists.'
          });
        }

        // 4. Generate strong temporary password and hash with bcrypt
        const tempPassword = generateSecureTempPassword();
        const hashedPassword = await bcrypt.hash(tempPassword, SALT_ROUNDS);
        const now = Date.now();
        const assignedRole = 'Student'; // Strictly assigned on server

        // 5. Insert into users and demo_students
        db.run(
          'INSERT INTO users (id, name, email, password, role) VALUES (?, ?, ?, ?, ?)',
          [finalStudentId, trimmedName, normalizedEmail, hashedPassword, assignedRole],
          function (errInsertUser) {
            if (errInsertUser) {
              return res.status(500).json({ error: 'Failed to create student user record' });
            }

            db.run(
              'INSERT INTO demo_students (user_id, created_at, created_by) VALUES (?, ?, ?)',
              [finalStudentId, now, req.user.id || 'admin'],
              function (errInsertDemo) {
                if (errInsertDemo) {
                  // Rollback user if demo_students insert fails
                  db.run('DELETE FROM users WHERE id = ?', [finalStudentId]);
                  return res.status(500).json({ error: 'Failed to record demo student metadata' });
                }

                logAuditEvent({
                  eventType: 'STUDENT_ACCOUNT_CREATED',
                  outcome: 'SUCCESS',
                  endpoint: '/api/admin/students',
                  method: 'POST',
                  userId: req.user.id,
                  req,
                  reason: `Created demo student ${finalStudentId} (${normalizedEmail})`
                });

                const newTotal = count + 1;
                res.status(201).json({
                  message: 'Demo Student account created successfully.',
                  student: {
                    id: finalStudentId,
                    name: trimmedName,
                    email: normalizedEmail,
                    role: assignedRole,
                    temporaryPassword: tempPassword,
                    createdAt: now
                  },
                  total: newTotal,
                  maxLimit: MAX_DEMO_STUDENTS,
                  remaining: Math.max(0, MAX_DEMO_STUDENTS - newTotal)
                });
              }
            );
          }
        );
      });
    });
  } catch (error) {
    console.error('Error creating demo student account:', error);
    res.status(500).json({ error: 'Internal server error creating demo student account' });
  }
});

// 11. User: Authenticated Password Change
app.post('/api/user/change-password', requireAuth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Current password and new password are required.' });
    }
    if (typeof newPassword !== 'string' || newPassword.length < 8 || newPassword.length > 128) {
      return res.status(400).json({ error: 'New password must be between 8 and 128 characters long.' });
    }

    db.get('SELECT password FROM users WHERE id = ?', [req.user.id], async (err, row) => {
      if (err || !row) {
        return res.status(500).json({ error: 'Failed to retrieve account details.' });
      }

      const match = await bcrypt.compare(currentPassword, row.password);
      if (!match) {
        logAuditEvent({
          eventType: 'PASSWORD_CHANGE_FAILED',
          outcome: 'DENY',
          endpoint: '/api/user/change-password',
          method: 'POST',
          userId: req.user.id,
          req,
          reason: 'Incorrect current password'
        });
        return res.status(400).json({ error: 'Current password is incorrect.' });
      }

      const hashedPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);
      db.run('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, req.user.id], function (errUpdate) {
        if (errUpdate) {
          return res.status(500).json({ error: 'Failed to update password' });
        }

        logAuditEvent({
          eventType: 'PASSWORD_CHANGED',
          outcome: 'SUCCESS',
          endpoint: '/api/user/change-password',
          method: 'POST',
          userId: req.user.id,
          req,
          reason: 'Password successfully changed'
        });

        res.json({ message: 'Password updated successfully.' });
      });
    });
  } catch (err) {
    console.error('Error changing password:', err);
    res.status(500).json({ error: 'Internal server error changing password' });
  }
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Backend server running on http://localhost:${PORT}`);
  });
}

module.exports = { app, db, requireAuth, requireRole, logAuditEvent, generateSecureTempPassword };
