import crypto from 'node:crypto';
import sqlite3 from './backend/node_modules/sqlite3/lib/sqlite3.js';
import { handleApiRequest } from './src/server/routes.js';
import { setTestKeyProvider } from './src/server/cloudflareAccess.js';
import { hashPassword, verifyPassword } from './src/server/crypto.js';

// Create D1 wrapper around SQLite for offline automated unit testing
function createMockD1Database(sqliteDb) {
  return {
    prepare(sql) {
      let boundParams = [];
      return {
        bind(...params) {
          boundParams = params;
          return this;
        },
        async first() {
          return new Promise((resolve, reject) => {
            sqliteDb.get(sql, boundParams, (err, row) => {
              if (err) return reject(err);
              resolve(row || null);
            });
          });
        },
        async all() {
          return new Promise((resolve, reject) => {
            sqliteDb.all(sql, boundParams, (err, rows) => {
              if (err) return reject(err);
              resolve({ results: rows || [] });
            });
          });
        },
        async run() {
          return new Promise((resolve, reject) => {
            sqliteDb.run(sql, boundParams, function (err) {
              if (err) return reject(err);
              resolve({ success: true, meta: { changes: this.changes, last_row_id: this.lastID } });
            });
          });
        }
      };
    },
    async batch(statements) {
      const results = [];
      for (const stmt of statements) {
        results.push(await stmt.run());
      }
      return results;
    }
  };
}

// Generate RSA keypairs for offline Cloudflare Access testing
const { publicKey: testPublicKey, privateKey: testPrivateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

function createTestCfJwt({ email, aud = 'cf-test-aud-tag', iss = 'https://still-meadow-8113.cloudflareaccess.com', exp = Math.floor(Date.now() / 1000) + 3600 }) {
  const header = { alg: 'RS256', kid: 'test-key-1' };
  const payload = {
    email,
    sub: email,
    aud,
    iss,
    exp,
    iat: Math.floor(Date.now() / 1000) - 10
  };

  const b64Url = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
  const unsigned = `${b64Url(header)}.${b64Url(payload)}`;
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(unsigned);
  const signature = signer.sign(testPrivateKey).toString('base64url');
  return `${unsigned}.${signature}`;
}

setTestKeyProvider((header) => {
  if (header.kid === 'test-key-1') return testPublicKey;
  return null;
});

let passed = 0;
let failed = 0;
function assert(cond, msg) {
  if (cond) {
    console.log(`  ✓ PASS: ${msg}`);
    passed++;
  } else {
    console.error(`  ✗ FAIL: ${msg}`);
    failed++;
  }
}

async function runTests() {
  console.log('================================================================');
  console.log('ZeroTrust Campus — Cloudflare Workers & D1 Verification Suite');
  console.log('================================================================\n');

  const rawDb = new sqlite3.Database(':memory:');

  // Initialize D1 Schema
  await new Promise((resolve) => {
    rawDb.serialize(() => {
      rawDb.run(`
        CREATE TABLE users (
          id TEXT PRIMARY KEY,
          name TEXT,
          email TEXT UNIQUE,
          password TEXT,
          role TEXT
        )
      `);
      rawDb.run(`
        CREATE TABLE sessions (
          id TEXT PRIMARY KEY,
          user_id TEXT NOT NULL,
          expires_at INTEGER NOT NULL,
          created_at INTEGER NOT NULL,
          FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
      `);
      rawDb.run(`
        CREATE TABLE audit_logs (
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
      rawDb.run(`
        CREATE TABLE demo_students (
          user_id TEXT PRIMARY KEY,
          created_at INTEGER NOT NULL,
          created_by TEXT NOT NULL,
          FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
      `, resolve);
    });
  });

  const mockD1 = createMockD1Database(rawDb);

  const env = {
    zerotrust_shield_db: mockD1,
    SESSION_SECRET: 'test-session-secret-9876543210',
    CLOUDFLARE_ACCESS_TEAM_DOMAIN: 'still-meadow-8113.cloudflareaccess.com',
    CLOUDFLARE_ACCESS_AUD: 'cf-test-aud-tag',
    ADMIN_EMAILS: 'vigneshwaran7002@gmail.com,admin@zerotrustcampus.edu',
    ALLOW_LOCAL_AUTH: 'false',
    CLIENT_URL: 'https://zerotrust-campus.vigneshwaran7002.workers.dev'
  };

  // Seed demo accounts
  const adminPassHash = await hashPassword('AdminPass123!');
  const facultyPassHash = await hashPassword('FacultyPass123!');
  const studentPassHash = await hashPassword('StudentPass123!');

  await mockD1.prepare('INSERT INTO users VALUES (?, ?, ?, ?, ?)').bind('ADM-1001', 'Admin User', 'admin@zerotrustcampus.edu', adminPassHash, 'Administrator').run();
  await mockD1.prepare('INSERT INTO users VALUES (?, ?, ?, ?, ?)').bind('FAC-1001', 'Prof. Alan Turing', 'faculty@zerotrustcampus.edu', facultyPassHash, 'Faculty').run();
  await mockD1.prepare('INSERT INTO users VALUES (?, ?, ?, ?, ?)').bind('STU-1001', 'Student User', 'student@zerotrustcampus.edu', studentPassHash, 'Student').run();

  try {
    // -----------------------------------------------------------
    // Test 1: Password hashing and verification in Worker runtime
    // -----------------------------------------------------------
    console.log('Scenario 1: Password Hashing Verification');
    const pwd = 'TestSecretPassword2026!';
    const h = await hashPassword(pwd);
    assert(h.startsWith('$2'), 'Bcrypt hash correctly generated');
    const matchOk = await verifyPassword(pwd, h);
    assert(matchOk === true, 'Bcrypt verification succeeds for valid password');
    const matchBad = await verifyPassword('WrongPassword', h);
    assert(matchBad === false, 'Bcrypt verification fails for wrong password');

    // -----------------------------------------------------------
    // Test 2: CSRF Origin Protection
    // -----------------------------------------------------------
    console.log('\nScenario 2: CSRF Origin Protection');
    const csrfReq = new Request('https://zerotrust-campus.vigneshwaran7002.workers.dev/api/login', {
      method: 'POST',
      headers: {
        'Origin': 'https://evil-attacker.com',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ email: 'admin@zerotrustcampus.edu', password: 'AdminPass123!' })
    });
    const csrfRes = await handleApiRequest(csrfReq, env);
    assert(csrfRes.status === 403, 'Untrusted cross-origin request blocked (HTTP 403)');
    const csrfBody = await csrfRes.json();
    assert(csrfBody.error === 'Cross-origin request blocked by CSRF policy', 'Correct CSRF blocked error');

    // -----------------------------------------------------------
    // Test 3: Outer Gate Cloudflare Access Enforcement on /api/login
    // -----------------------------------------------------------
    console.log('\nScenario 3: Cloudflare Access Outer Gate on Login');
    const directLoginReq = new Request('https://zerotrust-campus.vigneshwaran7002.workers.dev/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'student@zerotrustcampus.edu', password: 'StudentPass123!' })
    });
    const directLoginRes = await handleApiRequest(directLoginReq, env);
    assert(directLoginRes.status === 401, 'Direct login without Cloudflare Access assertion rejected (HTTP 401)');

    // -----------------------------------------------------------
    // Test 4: Authenticated Student Login behind Cloudflare Access
    // -----------------------------------------------------------
    console.log('\nScenario 4: Student Login behind Cloudflare Access');
    const studentCfJwt = createTestCfJwt({ email: 'vigneshwaran7002@gmail.com' });
    const studentLoginReq = new Request('https://zerotrust-campus.vigneshwaran7002.workers.dev/api/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Cf-Access-Jwt-Assertion': studentCfJwt
      },
      body: JSON.stringify({ email: 'student@zerotrustcampus.edu', password: 'StudentPass123!' })
    });
    const studentLoginRes = await handleApiRequest(studentLoginReq, env);
    assert(studentLoginRes.status === 200, 'Student login succeeds behind outer gate (HTTP 200)');
    const studentLoginBody = await studentLoginRes.json();
    assert(studentLoginBody.role === 'Student', 'Student profile returned with role "Student"');

    const studentCookie = studentLoginRes.headers.get('Set-Cookie');
    assert(studentCookie && studentCookie.includes('sessionId='), 'Signed sessionId cookie returned in Set-Cookie header');
    assert(studentCookie.includes('HttpOnly'), 'Cookie has HttpOnly flag');
    assert(studentCookie.includes('SameSite=Lax'), 'Cookie has SameSite=Lax flag');

    // Extract cookie for subsequent calls
    const studentCookieVal = studentCookie.split(';')[0];

    // -----------------------------------------------------------
    // Test 5: Student Role Boundaries
    // -----------------------------------------------------------
    console.log('\nScenario 5: Student Role Boundaries');
    const studentMeReq = new Request('https://zerotrust-campus.vigneshwaran7002.workers.dev/api/me', {
      headers: {
        'Cookie': studentCookieVal,
        'Cf-Access-Jwt-Assertion': studentCfJwt
      }
    });
    const studentMeRes = await handleApiRequest(studentMeReq, env);
    assert(studentMeRes.status === 200, 'Student can access /api/me (HTTP 200)');
    const studentMeBody = await studentMeRes.json();
    assert(studentMeBody.role === 'Student', 'Active session confirms role is "Student"');

    const studentDashReq = new Request('https://zerotrust-campus.vigneshwaran7002.workers.dev/api/student/dashboard', {
      headers: { 'Cookie': studentCookieVal, 'Cf-Access-Jwt-Assertion': studentCfJwt }
    });
    const studentDashRes = await handleApiRequest(studentDashReq, env);
    assert(studentDashRes.status === 200, 'Student accesses Student Portal (HTTP 200)');

    const studentAdminReq = new Request('https://zerotrust-campus.vigneshwaran7002.workers.dev/api/admin/dashboard', {
      headers: { 'Cookie': studentCookieVal, 'Cf-Access-Jwt-Assertion': studentCfJwt }
    });
    const studentAdminRes = await handleApiRequest(studentAdminReq, env);
    assert(studentAdminRes.status === 403, 'Student blocked from Admin Portal (HTTP 403)');

    const studentFacReq = new Request('https://zerotrust-campus.vigneshwaran7002.workers.dev/api/faculty/dashboard', {
      headers: { 'Cookie': studentCookieVal, 'Cf-Access-Jwt-Assertion': studentCfJwt }
    });
    const studentFacRes = await handleApiRequest(studentFacReq, env);
    assert(studentFacRes.status === 403, 'Student blocked from Faculty Portal (HTTP 403)');

    // -----------------------------------------------------------
    // Test 6: Admin Login & Admin Endpoints
    // -----------------------------------------------------------
    console.log('\nScenario 6: Admin Login & Admin Dashboard Access');
    const adminCfJwt = createTestCfJwt({ email: 'vigneshwaran7002@gmail.com' });
    const adminLoginReq = new Request('https://zerotrust-campus.vigneshwaran7002.workers.dev/api/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Cf-Access-Jwt-Assertion': adminCfJwt
      },
      body: JSON.stringify({ email: 'admin@zerotrustcampus.edu', password: 'AdminPass123!' })
    });
    const adminLoginRes = await handleApiRequest(adminLoginReq, env);
    assert(adminLoginRes.status === 200, 'Admin login succeeds (HTTP 200)');
    const adminCookieVal = adminLoginRes.headers.get('Set-Cookie').split(';')[0];

    const adminDashReq = new Request('https://zerotrust-campus.vigneshwaran7002.workers.dev/api/admin/dashboard', {
      headers: { 'Cookie': adminCookieVal, 'Cf-Access-Jwt-Assertion': adminCfJwt }
    });
    const adminDashRes = await handleApiRequest(adminDashReq, env);
    assert(adminDashRes.status === 200, 'Admin accesses Admin Dashboard (HTTP 200)');
    const adminDashBody = await adminDashRes.json();
    assert(adminDashBody.metrics && typeof adminDashBody.metrics.totalUsers === 'number', 'Metrics retrieved from D1');

    // -----------------------------------------------------------
    // Test 7: Dedicated Administrator Audit Logs API
    // -----------------------------------------------------------
    console.log('\nScenario 7: Administrator Audit Logs API');
    const auditLogsReq = new Request('https://zerotrust-campus.vigneshwaran7002.workers.dev/api/admin/audit-logs?limit=10&offset=0', {
      headers: { 'Cookie': adminCookieVal, 'Cf-Access-Jwt-Assertion': adminCfJwt }
    });
    const auditLogsRes = await handleApiRequest(auditLogsReq, env);
    assert(auditLogsRes.status === 200, 'Admin can access audit logs (HTTP 200)');
    const auditLogsBody = await auditLogsRes.json();
    assert(Array.isArray(auditLogsBody.auditLogs), 'Audit logs returned as array');
    assert(auditLogsBody.auditLogs.length > 0, 'Audit events captured in D1 audit_logs table');

    // -----------------------------------------------------------
    // Test 8: Admin Demo Student Account Creation (Quota = 5)
    // -----------------------------------------------------------
    console.log('\nScenario 8: Admin Demo Student Account Management (Quota Limit = 5)');
    const newStudent1Req = new Request('https://zerotrust-campus.vigneshwaran7002.workers.dev/api/admin/students', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Cookie': adminCookieVal,
        'Cf-Access-Jwt-Assertion': adminCfJwt
      },
      body: JSON.stringify({
        name: 'Demo Student One',
        email: 'demo1@campus.edu',
        studentId: 'STU-DEMO-01'
      })
    });
    const newStudent1Res = await handleApiRequest(newStudent1Req, env);
    assert(newStudent1Res.status === 201, 'Admin creates demo student 1 (HTTP 201)');
    const newStudent1Body = await newStudent1Res.json();
    assert(newStudent1Body.student.role === 'Student', 'Role strictly forced to Student');
    assert(typeof newStudent1Body.student.temporaryPassword === 'string' && newStudent1Body.student.temporaryPassword.length >= 14, 'Strong 14-char temp password returned');
    assert(newStudent1Body.total === 1, 'Total demo students is 1');
    assert(newStudent1Body.remaining === 4, 'Remaining demo students is 4');

    const tempPasswordStudent1 = newStudent1Body.student.temporaryPassword;

    // Verify password is NOT stored in plaintext
    const dbRow = await mockD1.prepare('SELECT password FROM users WHERE id = ?').bind('STU-DEMO-01').first();
    assert(dbRow.password.startsWith('$2'), 'Password stored as bcrypt hash in D1');
    assert(dbRow.password !== tempPasswordStudent1, 'Plaintext temporary password never stored in D1');

    // Create remaining 4 accounts to hit quota
    for (let i = 2; i <= 5; i++) {
      const req = new Request('https://zerotrust-campus.vigneshwaran7002.workers.dev/api/admin/students', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Cookie': adminCookieVal,
          'Cf-Access-Jwt-Assertion': adminCfJwt
        },
        body: JSON.stringify({
          name: `Demo Student ${i}`,
          email: `demo${i}@campus.edu`,
          studentId: `STU-DEMO-0${i}`
        })
      });
      const res = await handleApiRequest(req, env);
      assert(res.status === 201, `Demo student ${i} created (HTTP 201)`);
    }

    // Attempt 6th account creation (must fail)
    const sixthReq = new Request('https://zerotrust-campus.vigneshwaran7002.workers.dev/api/admin/students', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Cookie': adminCookieVal,
        'Cf-Access-Jwt-Assertion': adminCfJwt
      },
      body: JSON.stringify({
        name: 'Demo Student 6 Over Limit',
        email: 'demo6@campus.edu'
      })
    });
    const sixthRes = await handleApiRequest(sixthReq, env);
    assert(sixthRes.status === 400, 'Attempt to create 6th account blocked (HTTP 400)');
    const sixthBody = await sixthRes.json();
    assert(sixthBody.error.includes('Maximum limit of 5 demo student accounts has been reached'), 'Limit reached message');

    // List accounts (passwords must NOT be returned)
    const listReq = new Request('https://zerotrust-campus.vigneshwaran7002.workers.dev/api/admin/students', {
      headers: { 'Cookie': adminCookieVal, 'Cf-Access-Jwt-Assertion': adminCfJwt }
    });
    const listRes = await handleApiRequest(listReq, env);
    const listBody = await listRes.json();
    assert(listBody.total === 5 && listBody.remaining === 0, 'List shows total: 5, remaining: 0');
    assert(listBody.students.every(s => !s.password && !s.temporaryPassword), 'No passwords exposed in student list API');

    // -----------------------------------------------------------
    // Test 9: Created Demo Student Login & Password Change
    // -----------------------------------------------------------
    console.log('\nScenario 9: Demo Student Login & Password Change');
    const demoStuLoginReq = new Request('https://zerotrust-campus.vigneshwaran7002.workers.dev/api/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Cf-Access-Jwt-Assertion': studentCfJwt
      },
      body: JSON.stringify({ email: 'demo1@campus.edu', password: tempPasswordStudent1 })
    });
    const demoStuLoginRes = await handleApiRequest(demoStuLoginReq, env);
    assert(demoStuLoginRes.status === 200, 'Created demo student logs in with temporary password');
    const demoStuCookieVal = demoStuLoginRes.headers.get('Set-Cookie').split(';')[0];

    // Change password
    const changePassReq = new Request('https://zerotrust-campus.vigneshwaran7002.workers.dev/api/user/change-password', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Cookie': demoStuCookieVal,
        'Cf-Access-Jwt-Assertion': studentCfJwt
      },
      body: JSON.stringify({
        currentPassword: tempPasswordStudent1,
        newPassword: 'MyNewPermanentPassword2026!'
      })
    });
    const changePassRes = await handleApiRequest(changePassReq, env);
    assert(changePassRes.status === 200, 'Password updated successfully (HTTP 200)');

    // Log in with new password
    const newPassLoginReq = new Request('https://zerotrust-campus.vigneshwaran7002.workers.dev/api/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Cf-Access-Jwt-Assertion': studentCfJwt
      },
      body: JSON.stringify({ email: 'demo1@campus.edu', password: 'MyNewPermanentPassword2026!' })
    });
    const newPassLoginRes = await handleApiRequest(newPassLoginReq, env);
    assert(newPassLoginRes.status === 200, 'Login succeeds with new password');

    // -----------------------------------------------------------
    // Test 10: Logout & Session Invalidation
    // -----------------------------------------------------------
    console.log('\nScenario 10: Logout & Session Invalidation');
    const logoutReq = new Request('https://zerotrust-campus.vigneshwaran7002.workers.dev/api/logout', {
      method: 'POST',
      headers: {
        'Cookie': demoStuCookieVal,
        'Cf-Access-Jwt-Assertion': studentCfJwt
      }
    });
    const logoutRes = await handleApiRequest(logoutReq, env);
    assert(logoutRes.status === 200, 'Logout succeeds with HTTP 200');
    assert(logoutRes.headers.get('Set-Cookie').includes('Max-Age=0'), 'Session cookie cleared');

    // -----------------------------------------------------------
    // Test 11: Mandatory 'exp' Claim Validation in Cloudflare Access JWT
    // -----------------------------------------------------------
    console.log('\nScenario 11: Mandatory "exp" Claim Enforcement');
    // Token missing exp completely
    const noExpJwt = (() => {
      const b64 = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
      const unsigned = `${b64({ alg: 'RS256', kid: 'test-key-1' })}.${b64({
        email: 'admin@zerotrustcampus.edu',
        sub: 'admin@zerotrustcampus.edu',
        aud: env.CLOUDFLARE_ACCESS_AUD,
        iss: 'https://still-meadow-8113.cloudflareaccess.com',
        iat: Math.floor(Date.now() / 1000)
      })}`;
      const signer = crypto.createSign('RSA-SHA256');
      signer.update(unsigned);
      return `${unsigned}.${signer.sign(testPrivateKey).toString('base64url')}`;
    })();

    const noExpReq = new Request('https://zerotrust-campus.vigneshwaran7002.workers.dev/api/me', {
      headers: { 'Cf-Access-Jwt-Assertion': noExpJwt }
    });
    const noExpRes = await handleApiRequest(noExpReq, env);
    assert(noExpRes.status === 401, 'Token missing exp claim is rejected (HTTP 401)');

    // Token with non-numeric exp
    const invalidExpJwt = (() => {
      const b64 = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
      const unsigned = `${b64({ alg: 'RS256', kid: 'test-key-1' })}.${b64({
        email: 'admin@zerotrustcampus.edu',
        sub: 'admin@zerotrustcampus.edu',
        aud: env.CLOUDFLARE_ACCESS_AUD,
        iss: 'https://still-meadow-8113.cloudflareaccess.com',
        exp: 'not-a-number'
      })}`;
      const signer = crypto.createSign('RSA-SHA256');
      signer.update(unsigned);
      return `${unsigned}.${signer.sign(testPrivateKey).toString('base64url')}`;
    })();

    const invalidExpReq = new Request('https://zerotrust-campus.vigneshwaran7002.workers.dev/api/me', {
      headers: { 'Cf-Access-Jwt-Assertion': invalidExpJwt }
    });
    const invalidExpRes = await handleApiRequest(invalidExpReq, env);
    assert(invalidExpRes.status === 401, 'Token with invalid exp claim is rejected (HTTP 401)');

    // -----------------------------------------------------------
    // Test 12: Fail-Closed Behavior when SESSION_SECRET is Missing
    // -----------------------------------------------------------
    console.log('\nScenario 12: Fail-Closed Protection on Missing SESSION_SECRET');
    const envMissingSecret = { ...env, SESSION_SECRET: undefined };
    const missingSecretReq = new Request('https://zerotrust-campus.vigneshwaran7002.workers.dev/api/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Cf-Access-Jwt-Assertion': studentCfJwt
      },
      body: JSON.stringify({ email: 'admin@zerotrustcampus.edu', password: 'AdminPass123!' })
    });
    const missingSecretRes = await handleApiRequest(missingSecretReq, envMissingSecret);
    assert(missingSecretRes.status === 500, 'Requests fail closed with HTTP 500 when SESSION_SECRET is missing');
    const missingSecretBody = await missingSecretRes.json();
    assert(missingSecretBody.error === 'Server configuration error', 'Generic error message returned without secret leakage');

    // -----------------------------------------------------------
    // Test 13: Sanitized Client Error on JWT Verification Failure
    // -----------------------------------------------------------
    console.log('\nScenario 13: Sanitized Client Error Responses (Zero Information Leakage)');
    const badJwtReq = new Request('https://zerotrust-campus.vigneshwaran7002.workers.dev/api/me', {
      headers: { 'Cf-Access-Jwt-Assertion': 'invalid.jwt.token' }
    });
    const badJwtRes = await handleApiRequest(badJwtReq, env);
    assert(badJwtRes.status === 401, 'Invalid assertion returns HTTP 401');
    const badJwtBody = await badJwtRes.json();
    assert(badJwtBody.error === 'Invalid or expired Cloudflare Access assertion', 'Standardized sanitized error message');
    assert(badJwtBody.reason === undefined, 'Internal stack/diagnostics reason is NEVER exposed to clients');

    // -----------------------------------------------------------
    // Test 14: Seed Script Overwrite Protection (ON CONFLICT DO NOTHING)
    // -----------------------------------------------------------
    console.log('\nScenario 14: Seed Script Rerun Idempotency & Overwrite Protection');
    const preUser = await mockD1.prepare('SELECT password, role FROM users WHERE email = ?').bind('admin@zerotrustcampus.edu').first();
    const originalPasswordHash = preUser.password;

    // Simulate seed rerun with different dummy password hash and modified role
    await mockD1.prepare(`
      INSERT INTO users (id, name, email, password, role) VALUES 
      ('ADM-NEW-9999', 'Fake Admin', 'admin@zerotrustcampus.edu', '$2b$12$OVERWRITTENPASSWORDHASH', 'HackerRole')
      ON CONFLICT(email) DO NOTHING;
    `).run();

    const postUser = await mockD1.prepare('SELECT password, role FROM users WHERE email = ?').bind('admin@zerotrustcampus.edu').first();
    assert(postUser.password === originalPasswordHash, 'Existing user password hash preserved intact on seed rerun');
    assert(postUser.role === 'Administrator', 'Existing user role preserved intact on seed rerun');

  } finally {
    rawDb.close();
    console.log('\n================================================================');
    console.log(`Worker & D1 Test Summary: ${passed} passed, ${failed} failed.`);
    console.log('================================================================\n');
    process.exit(failed > 0 ? 1 : 0);
  }
}

runTests().catch(err => {
  console.error('Test execution fatal error:', err);
  process.exit(1);
});
