import crypto from 'node:crypto';
import { hashPassword, verifyPassword, signCookie, unsignCookie, parseCookies, generateSecureTempPassword } from './crypto.js';
import { verifyCloudflareAccessJwt } from './cloudflareAccess.js';
import * as db from './db.js';

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const SESSION_EXPIRY_MS = 24 * 60 * 60 * 1000;

export function jsonResponse(data, status = 200, customHeaders = {}) {
  const headers = new Headers({
    'Content-Type': 'application/json',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '0',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
    ...customHeaders
  });
  return new Response(JSON.stringify(data), { status, headers });
}

function getClientIp(request) {
  return request.headers.get('cf-connecting-ip') || request.headers.get('x-forwarded-for') || '127.0.0.1';
}

function isCfAccessEnforced(env) {
  const allowLocal = (env.ALLOW_LOCAL_AUTH === 'true' || env.ALLOW_LOCAL_AUTH === true);
  return !allowLocal;
}

export function validateCsrf(request, env) {
  const method = request.method.toUpperCase();
  if (!['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
    return null;
  }

  const origin = request.headers.get('origin');
  if (!origin) return null; // Non-browser / same-origin requests

  const url = new URL(request.url);
  const allowed = [
    url.origin,
    'http://localhost:5173',
    'http://127.0.0.1:5173',
    env.CLIENT_URL,
    env.FRONTEND_ORIGIN
  ].filter(Boolean);

  if (!allowed.includes(origin)) {
    return jsonResponse({ error: 'Cross-origin request blocked by CSRF policy' }, 403);
  }

  return null;
}

export async function resolveAuth(request, env) {
  const database = env.zerotrust_shield_db;
  const cfJwt = request.headers.get('cf-access-jwt-assertion');
  let verifiedCfEmail = null;

  // 1. Outer Gate: Cloudflare Access JWT validation
  if (cfJwt) {
    try {
      const verified = await verifyCloudflareAccessJwt(cfJwt, { env });
      verifiedCfEmail = (verified.email || verified.sub || '').trim().toLowerCase();
    } catch (cfErr) {
      const reason = cfErr.message || 'Invalid Cloudflare Access assertion';
      await db.logAuditEvent(database, {
        eventType: 'CF_ACCESS_INVALID',
        outcome: 'DENY',
        endpoint: new URL(request.url).pathname,
        method: request.method,
        ipAddress: getClientIp(request),
        reason
      });
      return { error: 'Invalid or expired Cloudflare Access assertion', status: 401 };
    }
  } else if (isCfAccessEnforced(env)) {
    await db.logAuditEvent(database, {
      eventType: 'CF_ACCESS_MISSING',
      outcome: 'DENY',
      endpoint: new URL(request.url).pathname,
      method: request.method,
      ipAddress: getClientIp(request),
      reason: 'Cloudflare Access assertion required'
    });
    return { error: 'Cloudflare Access assertion required', status: 401 };
  }

  // 2. Inner Gate: Campus Session validation from signed cookie
  const sessionSecret = env.SESSION_SECRET;
  if (!sessionSecret || typeof sessionSecret !== 'string' || sessionSecret.trim() === '') {
    return { error: 'Server configuration error', status: 500 };
  }

  const cookieHeader = request.headers.get('cookie');
  const cookies = parseCookies(cookieHeader);
  const rawSessionCookie = cookies.sessionId;

  if (rawSessionCookie) {
    const sessionId = unsignCookie(rawSessionCookie, sessionSecret);
    if (sessionId) {
      const session = await db.getSession(database, sessionId);
      if (session) {
        if (Date.now() > session.expires_at) {
          await db.deleteSession(database, sessionId);
          await db.logAuditEvent(database, {
            eventType: 'SESSION_EXPIRED',
            outcome: 'DENY',
            endpoint: new URL(request.url).pathname,
            method: request.method,
            userId: session.id,
            ipAddress: getClientIp(request),
            reason: 'Session expired'
          });
          return { error: 'Session expired', status: 401, clearSession: true };
        }

        const user = {
          id: session.id,
          name: session.name,
          email: session.email,
          role: session.role,
          authMethod: 'campus-session',
          cfIdentity: verifiedCfEmail
        };

        return { user, sessionId };
      }
    }
    // Invalid signature or session not found in D1
    return { error: 'Invalid or expired session', status: 401, clearSession: true };
  }

  // 3. Fallback: Authenticated via Cloudflare Access at outer gate without an inner campus session
  if (verifiedCfEmail) {
    const configuredAdmins = (env.ADMIN_EMAILS || '')
      .split(',')
      .map(e => e.trim().toLowerCase())
      .filter(Boolean);

    let userRecord = await db.getUserByEmail(database, verifiedCfEmail);

    if (!userRecord) {
      if (configuredAdmins.includes(verifiedCfEmail)) {
        // Auto-provision configured administrator
        const adminId = `ADM-${Date.now().toString().slice(-4)}-${crypto.randomInt(1000, 9999)}`;
        const adminName = verifiedCfEmail.split('@')[0];
        userRecord = await db.createUser(database, {
          id: adminId,
          name: adminName,
          email: verifiedCfEmail,
          passwordHash: 'CF_ACCESS_PROVISIONED',
          role: 'Administrator'
        });
      } else {
        await db.logAuditEvent(database, {
          eventType: 'CF_ACCESS_UNAUTHORIZED_USER',
          outcome: 'DENY',
          endpoint: new URL(request.url).pathname,
          method: request.method,
          ipAddress: getClientIp(request),
          reason: `Cloudflare Access user '${verifiedCfEmail}' not provisioned in campus directory`
        });
        return { error: 'User identity not provisioned in campus directory', status: 401 };
      }
    }

    let role = userRecord.role;
    if (configuredAdmins.includes(verifiedCfEmail) && role !== 'Administrator') {
      role = 'Administrator';
      await db.updateUserRole(database, verifiedCfEmail, 'Administrator');
    }

    const user = {
      id: userRecord.id,
      name: userRecord.name,
      email: userRecord.email,
      role,
      authMethod: 'cloudflare-access',
      cfIdentity: verifiedCfEmail
    };

    return { user };
  }

  return { error: 'Authentication required', status: 401 };
}

export async function handleApiRequest(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method.toUpperCase();
  const database = env.zerotrust_shield_db;
  const sessionSecret = env.SESSION_SECRET;
  if (!sessionSecret || typeof sessionSecret !== 'string' || sessionSecret.trim() === '') {
    return jsonResponse({ error: 'Server configuration error' }, 500);
  }
  const isHttps = url.protocol === 'https:';

  // 1. CSRF Protection
  const csrfError = validateCsrf(request, env);
  if (csrfError) return csrfError;

  // -------------------------------------------------------------
  // POST /api/register
  // -------------------------------------------------------------
  if (path === '/api/register' && method === 'POST') {
    if (isCfAccessEnforced(env)) {
      await db.logAuditEvent(database, {
        eventType: 'REGISTER_BLOCKED',
        outcome: 'DENY',
        endpoint: path,
        method,
        ipAddress: getClientIp(request),
        reason: 'Public registration disabled in production'
      });
      return jsonResponse({
        error: 'Public user registration is disabled in production. Accounts must be provisioned via campus identity provider.'
      }, 403);
    }

    try {
      const body = await request.json().catch(() => ({}));
      const { name, email, password } = body;
      if (!name || typeof name !== 'string' || name.trim().length < 2) {
        return jsonResponse({ error: 'Name must be at least 2 characters long' }, 400);
      }
      if (!email || typeof email !== 'string' || !EMAIL_REGEX.test(email.trim())) {
        return jsonResponse({ error: 'Invalid email address format' }, 400);
      }
      if (!password || typeof password !== 'string' || password.length < 8) {
        return jsonResponse({ error: 'Password must be between 8 and 128 characters long' }, 400);
      }

      const existing = await db.getUserByEmail(database, email);
      if (existing) {
        return jsonResponse({ error: 'Email already registered' }, 400);
      }

      const userId = `STU-${new Date().getFullYear()}-${crypto.randomInt(1000, 9999)}`;
      const passwordHash = await hashPassword(password);
      await db.createUser(database, {
        id: userId,
        name: name.trim(),
        email: email.trim().toLowerCase(),
        passwordHash,
        role: 'Student'
      });

      await db.logAuditEvent(database, {
        eventType: 'REGISTER_SUCCESS',
        outcome: 'ALLOW',
        endpoint: path,
        method,
        userId,
        ipAddress: getClientIp(request),
        reason: 'User registered successfully as Student'
      });

      return jsonResponse({ message: 'User registered successfully', userId }, 201);
    } catch (err) {
      return jsonResponse({ error: 'Registration failed' }, 500);
    }
  }

  // -------------------------------------------------------------
  // POST /api/login
  // -------------------------------------------------------------
  if (path === '/api/login' && method === 'POST') {
    // Outer Gate Verification
    if (isCfAccessEnforced(env)) {
      const cfJwt = request.headers.get('cf-access-jwt-assertion');
      if (!cfJwt) {
        await db.logAuditEvent(database, {
          eventType: 'LOCAL_LOGIN_BLOCKED',
          outcome: 'DENY',
          endpoint: path,
          method,
          ipAddress: getClientIp(request),
          reason: 'Direct tunnel/outer request blocked: Cloudflare Access assertion required'
        });
        return jsonResponse({ error: 'Cloudflare Access assertion required before campus login' }, 401);
      }
      try {
        await verifyCloudflareAccessJwt(cfJwt, { env });
      } catch (cfErr) {
        await db.logAuditEvent(database, {
          eventType: 'CF_ACCESS_INVALID',
          outcome: 'DENY',
          endpoint: path,
          method,
          ipAddress: getClientIp(request),
          reason: cfErr.message || 'Invalid Cloudflare Access assertion on login'
        });
        return jsonResponse({ error: 'Invalid or expired Cloudflare Access assertion' }, 401);
      }
    }

    try {
      const body = await request.json().catch(() => ({}));
      const { email, password } = body;

      if (!email || !password || typeof email !== 'string' || typeof password !== 'string') {
        return jsonResponse({ error: 'Email and password are required' }, 400);
      }

      const user = await db.getUserByEmail(database, email);
      if (!user) {
        await db.logAuditEvent(database, {
          eventType: 'LOGIN_FAILURE',
          outcome: 'DENY',
          endpoint: path,
          method,
          ipAddress: getClientIp(request),
          reason: `No account for '${email.trim().toLowerCase()}'`
        });
        return jsonResponse({ error: 'Invalid email or password' }, 401);
      }

      const match = await verifyPassword(password, user.password);
      if (!match) {
        await db.logAuditEvent(database, {
          eventType: 'LOGIN_FAILURE',
          outcome: 'DENY',
          endpoint: path,
          method,
          userId: user.id,
          ipAddress: getClientIp(request),
          reason: 'Incorrect password supplied'
        });
        return jsonResponse({ error: 'Invalid email or password' }, 401);
      }

      // Create session in D1
      const sessionId = crypto.randomUUID();
      const now = Date.now();
      const expiresAt = now + SESSION_EXPIRY_MS;
      await db.createSession(database, {
        id: sessionId,
        userId: user.id,
        expiresAt,
        createdAt: now
      });

      await db.logAuditEvent(database, {
        eventType: 'LOGIN_SUCCESS',
        outcome: 'ALLOW',
        endpoint: path,
        method,
        userId: user.id,
        ipAddress: getClientIp(request),
        reason: `Campus login successful as role '${user.role}'`
      });

      const signedCookie = signCookie(sessionId, sessionSecret);
      const cookieVal = `sessionId=${encodeURIComponent(signedCookie)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400; ${isHttps ? 'Secure;' : ''}`;

      return jsonResponse({
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      }, 200, { 'Set-Cookie': cookieVal });
    } catch (err) {
      console.error('Login error:', err);
      return jsonResponse({ error: 'Login service error' }, 500);
    }
  }

  // -------------------------------------------------------------
  // POST /api/logout
  // -------------------------------------------------------------
  if (path === '/api/logout' && method === 'POST') {
    const cookieHeader = request.headers.get('cookie');
    const cookies = parseCookies(cookieHeader);
    const rawSession = cookies.sessionId;
    if (rawSession) {
      const sessionId = unsignCookie(rawSession, sessionSecret);
      if (sessionId) {
        await db.deleteSession(database, sessionId);
      }
    }

    const clearCookie = `sessionId=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; ${isHttps ? 'Secure;' : ''}`;
    return jsonResponse({ message: 'Logged out successfully' }, 200, { 'Set-Cookie': clearCookie });
  }

  // -------------------------------------------------------------
  // Protected Routes - Authentication Required
  // -------------------------------------------------------------
  const auth = await resolveAuth(request, env);
  if (auth.error) {
    const headers = {};
    if (auth.clearSession) {
      headers['Set-Cookie'] = `sessionId=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; ${isHttps ? 'Secure;' : ''}`;
    }
    return jsonResponse({ error: auth.error }, auth.status || 401, headers);
  }

  const { user } = auth;

  // -------------------------------------------------------------
  // GET /api/me
  // -------------------------------------------------------------
  if (path === '/api/me' && method === 'GET') {
    return jsonResponse({
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      authMethod: user.authMethod,
      cfIdentity: user.cfIdentity
    });
  }

  // -------------------------------------------------------------
  // GET /api/student/dashboard
  // -------------------------------------------------------------
  if (path === '/api/student/dashboard' && method === 'GET') {
    if (user.role !== 'Student') {
      await db.logAuditEvent(database, {
        eventType: 'ACCESS_DENIED',
        outcome: 'DENY',
        endpoint: path,
        method,
        userId: user.id,
        ipAddress: getClientIp(request),
        reason: `Role '${user.role}' lacks permission for Student Portal`
      });
      return jsonResponse({ error: 'Insufficient privileges' }, 403);
    }

    return jsonResponse({
      portal: 'Student Portal',
      user: {
        id: user.id,
        name: user.name,
        role: user.role,
        authMethod: user.authMethod
      },
      courses: [
        { id: 'CS101', name: 'Introduction to Computer Science', grade: 'A', instructor: 'Dr. Turing' },
        { id: 'SEC201', name: 'Network Security Fundamentals', grade: 'A-', instructor: 'Prof. Lovelace' },
        { id: 'CRYPTO301', name: 'Applied Cryptography', grade: 'B+', instructor: 'Dr. Shannon' }
      ]
    });
  }

  // -------------------------------------------------------------
  // GET /api/faculty/dashboard
  // -------------------------------------------------------------
  if (path === '/api/faculty/dashboard' && method === 'GET') {
    if (user.role !== 'Faculty') {
      await db.logAuditEvent(database, {
        eventType: 'ACCESS_DENIED',
        outcome: 'DENY',
        endpoint: path,
        method,
        userId: user.id,
        ipAddress: getClientIp(request),
        reason: `Role '${user.role}' lacks permission for Faculty Portal`
      });
      return jsonResponse({ error: 'Insufficient privileges' }, 403);
    }

    return jsonResponse({
      portal: 'Faculty Portal',
      user: {
        id: user.id,
        name: user.name,
        role: user.role,
        authMethod: user.authMethod
      },
      coursesTeaching: [
        { id: 'CS301', name: 'Cloud Computing & Zero Trust', students: 45, nextClass: '10:00 AM Tomorrow' },
        { id: 'CS401', name: 'Advanced Cryptography', students: 30, nextClass: '2:00 PM Tomorrow' }
      ]
    });
  }

  // -------------------------------------------------------------
  // GET /api/admin/dashboard
  // -------------------------------------------------------------
  if (path === '/api/admin/dashboard' && method === 'GET') {
    if (user.role !== 'Administrator') {
      await db.logAuditEvent(database, {
        eventType: 'ACCESS_DENIED',
        outcome: 'DENY',
        endpoint: path,
        method,
        userId: user.id,
        ipAddress: getClientIp(request),
        reason: `Role '${user.role}' lacks permission for Admin Portal`
      });
      return jsonResponse({ error: 'Insufficient privileges' }, 403);
    }

    const metricsData = await db.getDashboardMetrics(database);

    return jsonResponse({
      portal: 'Admin Portal',
      user: {
        id: user.id,
        name: user.name,
        role: user.role,
        authMethod: user.authMethod
      },
      metrics: {
        totalUsers: metricsData.totalUsers,
        activeSessions: metricsData.activeSessions,
        activeApplications: 8,
        protectedEndpoints: 4
      },
      securityEvents: (metricsData.recentEvents || []).map(row => ({
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

  // -------------------------------------------------------------
  // GET /api/admin/audit-logs
  // -------------------------------------------------------------
  if (path === '/api/admin/audit-logs' && method === 'GET') {
    if (user.role !== 'Administrator') {
      return jsonResponse({ error: 'Insufficient privileges' }, 403);
    }

    const limit = url.searchParams.get('limit') || '50';
    const offset = url.searchParams.get('offset') || '0';
    const logs = await db.getAuditLogs(database, { limit, offset });

    return jsonResponse({
      total: logs.length,
      limit: parseInt(limit, 10) || 50,
      offset: parseInt(offset, 10) || 0,
      auditLogs: logs
    });
  }

  // -------------------------------------------------------------
  // GET /api/admin/students
  // -------------------------------------------------------------
  if (path === '/api/admin/students' && method === 'GET') {
    if (user.role !== 'Administrator') {
      return jsonResponse({ error: 'Insufficient privileges' }, 403);
    }

    const studentData = await db.getDemoStudents(database);
    return jsonResponse({
      total: studentData.total,
      maxLimit: studentData.maxLimit,
      remaining: studentData.remaining,
      students: (studentData.students || []).map(r => ({
        id: r.id,
        name: r.name,
        email: r.email,
        role: r.role,
        createdAt: r.createdAt,
        createdBy: r.createdBy
      }))
    });
  }

  // -------------------------------------------------------------
  // POST /api/admin/students
  // -------------------------------------------------------------
  if (path === '/api/admin/students' && method === 'POST') {
    if (user.role !== 'Administrator') {
      return jsonResponse({ error: 'Insufficient privileges' }, 403);
    }

    try {
      const currentData = await db.getDemoStudents(database);
      const MAX_LIMIT = 5;

      if (currentData.total >= MAX_LIMIT) {
        await db.logAuditEvent(database, {
          eventType: 'STUDENT_ACCOUNT_CREATE_FAILED',
          outcome: 'DENY',
          endpoint: path,
          method,
          userId: user.id,
          ipAddress: getClientIp(request),
          reason: 'Maximum demo student account limit (5) reached'
        });
        return jsonResponse({
          error: `Maximum limit of ${MAX_LIMIT} demo student accounts has been reached.`
        }, 400);
      }

      const body = await request.json().catch(() => ({}));
      const { name, email, studentId } = body;

      if (!name || typeof name !== 'string' || name.trim().length < 2 || name.trim().length > 100) {
        return jsonResponse({ error: 'Student name must be between 2 and 100 characters.' }, 400);
      }
      if (!email || typeof email !== 'string' || !EMAIL_REGEX.test(email.trim()) || email.trim().length > 255) {
        return jsonResponse({ error: 'Valid student email address is required.' }, 400);
      }

      const trimmedName = name.trim();
      const normalizedEmail = email.trim().toLowerCase();

      let finalStudentId;
      if (studentId && typeof studentId === 'string' && studentId.trim().length > 0) {
        const trimmedId = studentId.trim();
        if (!/^[A-Za-z0-9-]{3,32}$/.test(trimmedId)) {
          return jsonResponse({ error: 'Student ID must be 3-32 alphanumeric characters or hyphens.' }, 400);
        }
        finalStudentId = trimmedId;
      } else {
        finalStudentId = `STU-${new Date().getFullYear()}-${crypto.randomInt(1000, 9999)}`;
      }

      // Check duplicates
      const dupEmail = await db.getUserByEmail(database, normalizedEmail);
      if (dupEmail) {
        return jsonResponse({ error: 'An account with this email address already exists.' }, 400);
      }
      const dupId = await db.getUserById(database, finalStudentId);
      if (dupId) {
        return jsonResponse({ error: 'An account with this student ID already exists.' }, 400);
      }

      const tempPassword = generateSecureTempPassword();
      const passwordHash = await hashPassword(tempPassword);

      const created = await db.createDemoStudent(database, {
        id: finalStudentId,
        name: trimmedName,
        email: normalizedEmail,
        passwordHash,
        createdBy: user.id
      });

      await db.logAuditEvent(database, {
        eventType: 'STUDENT_ACCOUNT_CREATED',
        outcome: 'SUCCESS',
        endpoint: path,
        method,
        userId: user.id,
        ipAddress: getClientIp(request),
        reason: `Created demo student ${finalStudentId} (${normalizedEmail})`
      });

      const newTotal = currentData.total + 1;
      return jsonResponse({
        message: 'Demo Student account created successfully.',
        student: {
          id: created.id,
          name: created.name,
          email: created.email,
          role: 'Student',
          temporaryPassword: tempPassword,
          createdAt: created.createdAt
        },
        total: newTotal,
        maxLimit: MAX_LIMIT,
        remaining: Math.max(0, MAX_LIMIT - newTotal)
      }, 201);
    } catch (err) {
      console.error('Create student error:', err);
      return jsonResponse({ error: 'Internal server error creating demo student account' }, 500);
    }
  }

  // -------------------------------------------------------------
  // POST /api/user/change-password
  // -------------------------------------------------------------
  if (path === '/api/user/change-password' && method === 'POST') {
    try {
      const body = await request.json().catch(() => ({}));
      const { currentPassword, newPassword } = body;

      if (!currentPassword || !newPassword) {
        return jsonResponse({ error: 'Current password and new password are required.' }, 400);
      }
      if (typeof newPassword !== 'string' || newPassword.length < 8 || newPassword.length > 128) {
        return jsonResponse({ error: 'New password must be between 8 and 128 characters long.' }, 400);
      }

      const userRecord = await db.getUserById(database, user.id);
      if (!userRecord) {
        return jsonResponse({ error: 'Failed to verify account' }, 500);
      }

      const match = await verifyPassword(currentPassword, userRecord.password);
      if (!match) {
        await db.logAuditEvent(database, {
          eventType: 'PASSWORD_CHANGE_FAILED',
          outcome: 'DENY',
          endpoint: path,
          method,
          userId: user.id,
          ipAddress: getClientIp(request),
          reason: 'Incorrect current password'
        });
        return jsonResponse({ error: 'Current password is incorrect.' }, 400);
      }

      const newHash = await hashPassword(newPassword);
      await db.updateUserPassword(database, user.id, newHash);

      await db.logAuditEvent(database, {
        eventType: 'PASSWORD_CHANGED',
        outcome: 'SUCCESS',
        endpoint: path,
        method,
        userId: user.id,
        ipAddress: getClientIp(request),
        reason: 'Password updated successfully'
      });

      return jsonResponse({ message: 'Password updated successfully.' }, 200);
    } catch (err) {
      return jsonResponse({ error: 'Internal server error changing password' }, 500);
    }
  }

  return jsonResponse({ error: `Not Found: ${method} ${path}` }, 404);
}
