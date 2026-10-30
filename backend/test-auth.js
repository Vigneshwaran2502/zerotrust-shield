/**
 * Automated Security & Authorization Test Suite for ZeroTrust Campus
 * Phases 1, 2, 3 & 4:
 * - Phase 1: Authentication, Password Hashing, Privilege Escalation Prevention, Input Validation
 * - Phase 2: Server-Managed Sessions in SQLite, RBAC Middleware, Endpoint Protection
 * - Phase 3: Security Audit Logging Engine, Zero Secret Leakage, Telemetry
 * - Phase 4: Cloudflare Zero Trust Access JWT Verification (RS256), Key Rotation, Boundary Enforcement, Prod Guards
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const request = require('supertest');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Configure isolated test database environment variable before loading server
const TEST_DB_PATH = path.resolve(__dirname, 'database.test.sqlite');
process.env.TEST_DB_PATH = TEST_DB_PATH;
process.env.NODE_ENV = 'test';
process.env.SESSION_SECRET = 'test-session-secret-key-1234567890';
process.env.CLOUDFLARE_ACCESS_TEAM_DOMAIN = 'zerotrustcampus.cloudflareaccess.com';
process.env.CLOUDFLARE_ACCESS_AUD = 'cf-test-audience-tag-2026';
process.env.ALLOW_LOCAL_AUTH = 'true';

// Remove any lingering test database from previous runs
if (fs.existsSync(TEST_DB_PATH)) {
  try {
    fs.unlinkSync(TEST_DB_PATH);
  } catch (e) {}
}

// -------------------------------------------------------------
// Generate Offline RSA Keypairs for Cryptographic JWT Testing
// -------------------------------------------------------------
const { publicKey: testPublicKey, privateKey: testPrivateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

const { publicKey: untrustedPublicKey, privateKey: untrustedPrivateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

const { setTestKeyProvider, verifyCloudflareAccessJwt } = require('./cloudflareAccess');
setTestKeyProvider((header) => {
  if (header.kid === 'test-cloudflare-key-1') {
    return testPublicKey;
  }
  throw new Error(`Signing key not found for kid: ${header.kid}`);
});

const { app, db } = require('./server');

let passedTests = 0;
let failedTests = 0;

function assert(condition, testName) {
  if (condition) {
    console.log(`  ✓ PASS: ${testName}`);
    passedTests++;
  } else {
    console.error(`  ✗ FAIL: ${testName}`);
    failedTests++;
  }
}

// Helper to create Cloudflare Access test tokens
function createTestCfJwt({
  email = 'student.test@zerotrustcampus.edu',
  aud = process.env.CLOUDFLARE_ACCESS_AUD,
  iss = `https://${process.env.CLOUDFLARE_ACCESS_TEAM_DOMAIN}`,
  expiresIn = '1h',
  privateKey = testPrivateKey,
  kid = 'test-cloudflare-key-1'
} = {}) {
  return jwt.sign(
    {
      email,
      sub: email,
      type: 'app',
      identity_nonce: crypto.randomBytes(16).toString('hex')
    },
    privateKey,
    {
      algorithm: 'RS256',
      keyid: kid,
      audience: aud,
      issuer: iss,
      expiresIn
    }
  );
}

async function runTests() {
  console.log('\n================================================================');
  console.log('ZeroTrust Campus — Full Security, RBAC & Cloudflare Access Suite');
  console.log('================================================================\n');

  try {
    // ===========================================================
    // PHASE 1 TESTS
    // ===========================================================

    // -----------------------------------------------------------
    // Test 1: Password hashing and response sanitization
    // -----------------------------------------------------------
    console.log('Scenario 1: Secure Registration & Password Hashing');
    const userPayload = {
      name: 'Security Test Student',
      email: 'student.test@zerotrustcampus.edu',
      password: 'StrongP@ssw0rd2026!'
    };

    const regRes = await request(app)
      .post('/api/register')
      .send(userPayload);

    assert(regRes.status === 201, 'Registration returns HTTP 201 Created');
    assert(regRes.body.role === 'Student', 'Registered account has role "Student"');
    assert(!regRes.body.password && !regRes.body.passwordHash, 'Registration response does not leak password or passwordHash');

    await new Promise((resolve) => {
      db.get('SELECT * FROM users WHERE email = ?', [userPayload.email], (err, row) => {
        assert(!err, 'Database query succeeds');
        assert(row && row.password !== userPayload.password, 'Stored password is NOT stored as plaintext');
        const isBcrypt = row && (row.password.startsWith('$2a$') || row.password.startsWith('$2b$') || row.password.startsWith('$2y$'));
        assert(isBcrypt, 'Stored password matches bcrypt hash pattern ($2a$/$2b$/$2y$)');
        resolve();
      });
    });

    // -----------------------------------------------------------
    // Test 2: Authentication with correct and incorrect credentials
    // -----------------------------------------------------------
    console.log('\nScenario 2: Authentication Verification');
    const goodLogin = await request(app)
      .post('/api/login')
      .send({
        email: userPayload.email,
        password: userPayload.password
      });

    assert(goodLogin.status === 200, 'Valid credentials authenticate successfully (HTTP 200)');
    assert(goodLogin.body.id && goodLogin.body.email === userPayload.email, 'Login returns verified user context');
    assert(!goodLogin.body.password && !goodLogin.body.passwordHash, 'Login response does not leak password or passwordHash');

    const badLogin = await request(app)
      .post('/api/login')
      .send({
        email: userPayload.email,
        password: 'IncorrectPassword123!'
      });

    assert(badLogin.status === 401, 'Incorrect password is rejected with HTTP 401 Unauthorized');
    assert(badLogin.body.error === 'Invalid credentials', 'Login failure returns safe generic error message');

    // -----------------------------------------------------------
    // Test 3: Privilege Escalation Prevention on Registration
    // -----------------------------------------------------------
    console.log('\nScenario 3: Privilege Escalation Prevention');
    const exploitPayload = {
      name: 'Malicious Actor',
      email: 'attacker@zerotrustcampus.edu',
      password: 'HackerPassword999!',
      role: 'Administrator'
    };

    const exploitRes = await request(app)
      .post('/api/register')
      .send(exploitPayload);

    assert(exploitRes.status === 201, 'Registration completes');
    assert(exploitRes.body.role === 'Student', 'Client-supplied "Administrator" role is ignored and overridden to "Student"');

    await new Promise((resolve) => {
      db.get('SELECT role FROM users WHERE email = ?', [exploitPayload.email], (err, row) => {
        assert(row && row.role === 'Student', 'Database record confirms role is strictly "Student"');
        resolve();
      });
    });

    // -----------------------------------------------------------
    // Test 4: Duplicate Email Rejection
    // -----------------------------------------------------------
    console.log('\nScenario 4: Duplicate Email Rejection');
    const duplicateRes = await request(app)
      .post('/api/register')
      .send({
        name: 'Duplicate User',
        email: userPayload.email,
        password: 'AnotherPassword123!'
      });

    assert(duplicateRes.status === 400, 'Duplicate email registration is rejected with HTTP 400');
    assert(duplicateRes.body.error === 'Email already registered', 'Safe duplicate registration message returned');

    // -----------------------------------------------------------
    // Test 5: Input Validation & Sanitization
    // -----------------------------------------------------------
    console.log('\nScenario 5: Input Validation');
    const shortPasswordRes = await request(app)
      .post('/api/register')
      .send({
        name: 'Valid Name',
        email: 'shortpass@zerotrustcampus.edu',
        password: '123'
      });
    assert(shortPasswordRes.status === 400, 'Short password (< 8 chars) rejected with HTTP 400');

    const invalidEmailRes = await request(app)
      .post('/api/register')
      .send({
        name: 'Valid Name',
        email: 'not-an-email',
        password: 'ValidPassword123!'
      });
    assert(invalidEmailRes.status === 400, 'Invalid email syntax rejected with HTTP 400');

    const missingNameRes = await request(app)
      .post('/api/register')
      .send({
        name: '',
        email: 'noname@zerotrustcampus.edu',
        password: 'ValidPassword123!'
      });
    assert(missingNameRes.status === 400, 'Empty name rejected with HTTP 400');

    // -----------------------------------------------------------
    // Test 6: Legacy Plaintext Password Migration Test
    // -----------------------------------------------------------
    console.log('\nScenario 6: Legacy Plaintext Password Migration');
    const legacyEmail = 'legacy.user@zerotrustcampus.edu';
    const legacyPassword = 'OldPlaintextPassword2024!';

    await new Promise((resolve) => {
      db.run(
        'INSERT INTO users (id, name, email, password, role) VALUES (?, ?, ?, ?, ?)',
        ['STU-2024-9999', 'Legacy User', legacyEmail, legacyPassword, 'Student'],
        resolve
      );
    });

    const legacyLogin = await request(app)
      .post('/api/login')
      .send({ email: legacyEmail, password: legacyPassword });

    assert(legacyLogin.status === 200, 'Legacy user authenticates with plaintext password on first login');

    await new Promise((r) => setTimeout(r, 100));

    await new Promise((resolve) => {
      db.get('SELECT password FROM users WHERE email = ?', [legacyEmail], (err, row) => {
        assert(row && row.password !== legacyPassword, 'Legacy plaintext password was replaced');
        const isUpgradedBcrypt = row && (row.password.startsWith('$2a$') || row.password.startsWith('$2b$') || row.password.startsWith('$2y$'));
        assert(isUpgradedBcrypt, 'Legacy account was automatically migrated to bcrypt hash');
        resolve();
      });
    });

    const secondLegacyLogin = await request(app)
      .post('/api/login')
      .send({ email: legacyEmail, password: legacyPassword });
    assert(secondLegacyLogin.status === 200, 'Migrated legacy account continues to authenticate normally');

    // ===========================================================
    // PHASE 2 TESTS: SESSIONS & SERVER-SIDE RBAC
    // ===========================================================

    // -----------------------------------------------------------
    // Test 7: Anonymous requests to protected endpoints return 401
    // -----------------------------------------------------------
    console.log('\nScenario 7: Anonymous Access Rejection (HTTP 401)');
    const anonMe = await request(app).get('/api/me');
    assert(anonMe.status === 401, 'Anonymous GET /api/me returns 401 Unauthorized');
    assert(anonMe.body.error === 'Authentication required', 'Returns correct auth required error');

    const anonStudent = await request(app).get('/api/student/dashboard');
    assert(anonStudent.status === 401, 'Anonymous GET /api/student/dashboard returns 401 Unauthorized');

    const anonFaculty = await request(app).get('/api/faculty/dashboard');
    assert(anonFaculty.status === 401, 'Anonymous GET /api/faculty/dashboard returns 401 Unauthorized');

    const anonAdmin = await request(app).get('/api/admin/dashboard');
    assert(anonAdmin.status === 401, 'Anonymous GET /api/admin/dashboard returns 401 Unauthorized');

    // -----------------------------------------------------------
    // Test 8: Student Role Access & Boundaries (Least Privilege)
    // -----------------------------------------------------------
    console.log('\nScenario 8: Student Role Authorization & Boundary Check');
    const studentAgent = request.agent(app);
    const studentLogin = await studentAgent
      .post('/api/login')
      .send({
        email: userPayload.email,
        password: userPayload.password
      });

    assert(studentLogin.status === 200, 'Student logs in and receives signed session cookie');

    const studentMe = await studentAgent.get('/api/me');
    assert(studentMe.status === 200, 'Student can access /api/me');
    assert(studentMe.body.role === 'Student', 'Profile confirms role is "Student"');

    const studentDash = await studentAgent.get('/api/student/dashboard');
    assert(studentDash.status === 200, 'Student can access /api/student/dashboard (HTTP 200)');
    assert(studentDash.body.portal === 'Student Portal', 'Student receives Student Portal payload');

    const studentFacultyDash = await studentAgent.get('/api/faculty/dashboard');
    assert(studentFacultyDash.status === 403, 'Student is denied from /api/faculty/dashboard with HTTP 403 Forbidden');
    assert(studentFacultyDash.body.error === 'Insufficient privileges', 'Returns "Insufficient privileges" error message');

    const studentAdminDash = await studentAgent.get('/api/admin/dashboard');
    assert(studentAdminDash.status === 403, 'Student is denied from /api/admin/dashboard with HTTP 403 Forbidden');
    assert(studentAdminDash.body.error === 'Insufficient privileges', 'Returns "Insufficient privileges" error message');

    // -----------------------------------------------------------
    // Test 9: Faculty Role Authorization & Boundaries
    // -----------------------------------------------------------
    console.log('\nScenario 9: Faculty Role Authorization & Boundary Check');
    const facultyEmail = 'faculty.test@zerotrustcampus.edu';
    const facultyPassword = 'FacultySecretPass2026!';
    const hashedFacultyPass = await bcrypt.hash(facultyPassword, 10);

    await new Promise((resolve) => {
      db.run(
        'INSERT INTO users (id, name, email, password, role) VALUES (?, ?, ?, ?, ?)',
        ['FAC-2026-1001', 'Prof. Alan Turing', facultyEmail, hashedFacultyPass, 'Faculty'],
        resolve
      );
    });

    const facultyAgent = request.agent(app);
    await facultyAgent
      .post('/api/login')
      .send({ email: facultyEmail, password: facultyPassword });

    const facultyDash = await facultyAgent.get('/api/faculty/dashboard');
    assert(facultyDash.status === 200, 'Faculty can access /api/faculty/dashboard (HTTP 200)');
    assert(facultyDash.body.portal === 'Faculty Portal', 'Faculty receives Faculty Portal payload');

    const facultyAdminDash = await facultyAgent.get('/api/admin/dashboard');
    assert(facultyAdminDash.status === 403, 'Faculty is denied from /api/admin/dashboard with HTTP 403 Forbidden');

    // -----------------------------------------------------------
    // Test 10: Administrator Role Authorization
    // -----------------------------------------------------------
    console.log('\nScenario 10: Administrator Role Authorization');
    const adminEmail = 'admin.test@zerotrustcampus.edu';
    const adminPassword = 'AdminSecretPass2026!';
    const hashedAdminPass = await bcrypt.hash(adminPassword, 10);

    await new Promise((resolve) => {
      db.run(
        'INSERT INTO users (id, name, email, password, role) VALUES (?, ?, ?, ?, ?)',
        ['ADM-2026-0001', 'Chief Security Officer', adminEmail, hashedAdminPass, 'Administrator'],
        resolve
      );
    });

    const adminAgent = request.agent(app);
    await adminAgent
      .post('/api/login')
      .send({ email: adminEmail, password: adminPassword });

    const adminDash = await adminAgent.get('/api/admin/dashboard');
    assert(adminDash.status === 200, 'Administrator can access /api/admin/dashboard (HTTP 200)');
    assert(adminDash.body.portal === 'Admin Portal', 'Admin receives Admin Portal payload with security events');

    // -----------------------------------------------------------
    // Test 11: Tamper Resistance — Role in Request Cannot Elevate Privileges
    // -----------------------------------------------------------
    console.log('\nScenario 11: Tamper Resistance (Server-Side Authorization Invariance)');
    const spoofedHeaderRes = await studentAgent
      .get('/api/admin/dashboard')
      .set('X-User-Role', 'Administrator')
      .set('Role', 'Administrator');
    assert(spoofedHeaderRes.status === 403, 'Spoofed request headers cannot elevate privileges (HTTP 403)');

    const spoofedQueryRes = await studentAgent
      .get('/api/admin/dashboard?role=Administrator');
    assert(spoofedQueryRes.status === 403, 'Spoofed query parameters cannot elevate privileges (HTTP 403)');

    // -----------------------------------------------------------
    // Test 12: Session Invalidation on Logout
    // -----------------------------------------------------------
    console.log('\nScenario 12: Session Invalidation on Logout');
    const logoutRes = await studentAgent.post('/api/logout');
    assert(logoutRes.status === 200, 'Logout succeeds with HTTP 200');
    assert(logoutRes.body.message === 'Logged out successfully', 'Logout confirmation message received');

    const postLogoutMe = await studentAgent.get('/api/me');
    assert(postLogoutMe.status === 401, 'Accessing /api/me after logout returns 401 Unauthorized');

    const postLogoutDash = await studentAgent.get('/api/student/dashboard');
    assert(postLogoutDash.status === 401, 'Accessing /api/student/dashboard after logout returns 401 Unauthorized');

    // -----------------------------------------------------------
    // Test 13: Invalid & Expired Sessions Rejected
    // -----------------------------------------------------------
    console.log('\nScenario 13: Invalid & Expired Sessions Rejection');
    const forgedSessionRes = await request(app)
      .get('/api/me')
      .set('Cookie', 'sessionId=s%3Aforged_invalid_session_token.fakeSignature');
    assert(forgedSessionRes.status === 401, 'Forged/tampered session cookie returns 401 Unauthorized');

    const expiredSessionId = 'expired_session_test_token_12345';
    await new Promise((resolve) => {
      db.run(
        'INSERT INTO sessions (id, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)',
        [expiredSessionId, 'STU-2024-9999', Date.now() - 10000, Date.now() - 50000],
        resolve
      );
    });

    const cookieSignature = require('cookie-signature');
    const signedExpiredCookie = 's:' + cookieSignature.sign(expiredSessionId, process.env.SESSION_SECRET);

    const expiredRes = await request(app)
      .get('/api/me')
      .set('Cookie', `sessionId=${encodeURIComponent(signedExpiredCookie)}`);
    assert(expiredRes.status === 401, 'Expired session is detected and rejected with HTTP 401');

    // ===========================================================
    // PHASE 3 TESTS: SECURITY AUDIT LOGGING & TELEMETRY
    // ===========================================================

    // -----------------------------------------------------------
    // Test 14: Audit Logging — Ingestion Verification
    // -----------------------------------------------------------
    console.log('\nScenario 14: Security Audit Log Ingestion');
    await new Promise(r => setTimeout(r, 100));

    await new Promise((resolve) => {
      db.all('SELECT * FROM audit_logs', [], (err, rows) => {
        assert(!err, 'Audit logs query succeeds');
        assert(rows && rows.length > 0, `Audit logs recorded in database (Total records: ${rows.length})`);

        const loginSuccessLog = rows.find(r => r.event_type === 'LOGIN_SUCCESS');
        assert(loginSuccessLog && loginSuccessLog.outcome === 'ALLOW', 'LOGIN_SUCCESS event accurately recorded with outcome ALLOW');

        const loginFailLog = rows.find(r => r.event_type === 'LOGIN_FAILURE');
        assert(loginFailLog && loginFailLog.outcome === 'DENY', 'LOGIN_FAILURE event accurately recorded with outcome DENY');

        const accessGrantedLog = rows.find(r => r.event_type === 'ACCESS_GRANTED');
        assert(accessGrantedLog && accessGrantedLog.outcome === 'ALLOW', 'ACCESS_GRANTED event recorded for authorized endpoint');

        const accessDeniedLog = rows.find(r => r.event_type === 'ACCESS_DENIED');
        assert(accessDeniedLog && accessDeniedLog.outcome === 'DENY', 'ACCESS_DENIED event recorded when Student attempted Admin dashboard');

        const sessionMissingLog = rows.find(r => r.event_type === 'SESSION_MISSING' || r.event_type === 'SESSION_INVALID');
        assert(sessionMissingLog && sessionMissingLog.outcome === 'DENY', 'Unauthenticated request logged with outcome DENY');

        resolve();
      });
    });

    // -----------------------------------------------------------
    // Test 15: Audit Logging — Zero Secret Leakage Sweep
    // -----------------------------------------------------------
    console.log('\nScenario 15: Zero Secret Leakage in Audit Logs');
    await new Promise((resolve) => {
      db.all('SELECT * FROM audit_logs', [], (err, rows) => {
        assert(!err, 'Audit table query succeeds for leakage check');

        let leakedSecretsCount = 0;
        const testPasswordStrings = [
          'StrongP@ssw0rd2026!',
          'IncorrectPassword123!',
          'HackerPassword999!',
          'OldPlaintextPassword2024!',
          'FacultySecretPass2026!',
          'AdminSecretPass2026!'
        ];

        rows.forEach((row) => {
          const rowDump = JSON.stringify(row);

          testPasswordStrings.forEach((pwd) => {
            if (rowDump.includes(pwd)) leakedSecretsCount++;
          });

          if (rowDump.includes('$2a$') || rowDump.includes('$2b$') || rowDump.includes('$2y$')) {
            leakedSecretsCount++;
          }

          if (rowDump.includes('s%3A') || rowDump.includes('sessionId')) {
            leakedSecretsCount++;
          }
        });

        assert(leakedSecretsCount === 0, 'Audit logs contain ZERO passwords, password hashes, or session tokens');
        resolve();
      });
    });

    // -----------------------------------------------------------
    // Test 16: Audit Logging Failure Resiliency
    // -----------------------------------------------------------
    console.log('\nScenario 16: Authorization Enforcement Invariance (Logging Resiliency)');
    const brokenReq = {
      originalUrl: '/api/admin/dashboard',
      method: 'GET',
      user: { id: 'STU-123', role: 'Student' }
    };

    let deniedCalled = false;
    const mockRes = {
      status: (code) => {
        if (code === 403) deniedCalled = true;
        return { json: (data) => data };
      }
    };

    const { requireRole } = require('./server');
    const adminOnlyMiddleware = requireRole(['Administrator']);
    adminOnlyMiddleware(brokenReq, mockRes, () => {});

    assert(deniedCalled, 'requireRole strictly returns 403 Forbidden regardless of logging outcome');

    // -----------------------------------------------------------
    // Test 17: Live Admin Dashboard Telemetry
    // -----------------------------------------------------------
    console.log('\nScenario 17: Admin Dashboard Live Audit Telemetry');
    const liveAdminRes = await adminAgent.get('/api/admin/dashboard');
    assert(liveAdminRes.status === 200, 'Admin can fetch live dashboard (HTTP 200)');
    assert(Array.isArray(liveAdminRes.body.securityEvents), 'Dashboard contains securityEvents array');
    assert(liveAdminRes.body.securityEvents.length > 0, `Live security events returned from database (Count: ${liveAdminRes.body.securityEvents.length})`);
    assert(liveAdminRes.body.metrics.totalUsers > 0, 'Live totalUsers metric accurately reflects database user count');

    // ===========================================================
    // PHASE 4 TESTS: CLOUDFLARE ZERO TRUST ACCESS INTEGRATION
    // ===========================================================

    // -----------------------------------------------------------
    // Test 18: Valid Cloudflare Access JWT Authentication
    // -----------------------------------------------------------
    console.log('\nScenario 18: Valid Cloudflare Access JWT Authentication');
    const validStudentJwt = createTestCfJwt({ email: userPayload.email });

    const cfMeRes = await request(app)
      .get('/api/me')
      .set('Cf-Access-Jwt-Assertion', validStudentJwt);

    assert(cfMeRes.status === 200, 'Valid Cloudflare Access JWT grants access (HTTP 200)');
    assert(cfMeRes.body.email === userPayload.email, 'Profile reflects verified Cloudflare Access email claim');
    assert(cfMeRes.body.role === 'Student', 'Profile maps verified email to database role "Student"');
    assert(cfMeRes.body.authMethod === 'cloudflare-access', 'Context confirms authMethod is "cloudflare-access"');

    const cfStudentDash = await request(app)
      .get('/api/student/dashboard')
      .set('Cf-Access-Jwt-Assertion', validStudentJwt);
    assert(cfStudentDash.status === 200, 'Student with valid Access JWT accesses /api/student/dashboard (HTTP 200)');
    assert(cfStudentDash.body.portal === 'Student Portal', 'Correct portal returned');

    // -----------------------------------------------------------
    // Test 19: Role Boundary Enforcement with Cloudflare Access JWT
    // -----------------------------------------------------------
    console.log('\nScenario 19: Cloudflare Access Role Boundary Enforcement');
    // Student Access JWT attempts Admin endpoint
    const cfStudentToAdmin = await request(app)
      .get('/api/admin/dashboard')
      .set('Cf-Access-Jwt-Assertion', validStudentJwt);
    assert(cfStudentToAdmin.status === 403, 'Student with valid Access JWT is DENIED from Admin endpoint (HTTP 403)');

    // Faculty Access JWT
    const validFacultyJwt = createTestCfJwt({ email: facultyEmail });
    const cfFacultyDash = await request(app)
      .get('/api/faculty/dashboard')
      .set('Cf-Access-Jwt-Assertion', validFacultyJwt);
    assert(cfFacultyDash.status === 200, 'Faculty with valid Access JWT accesses /api/faculty/dashboard (HTTP 200)');

    const cfFacultyToAdmin = await request(app)
      .get('/api/admin/dashboard')
      .set('Cf-Access-Jwt-Assertion', validFacultyJwt);
    assert(cfFacultyToAdmin.status === 403, 'Faculty with valid Access JWT is DENIED from Admin endpoint (HTTP 403)');

    // Administrator Access JWT
    const validAdminJwt = createTestCfJwt({ email: adminEmail });
    const cfAdminDash = await request(app)
      .get('/api/admin/dashboard')
      .set('Cf-Access-Jwt-Assertion', validAdminJwt);
    assert(cfAdminDash.status === 200, 'Administrator with valid Access JWT accesses /api/admin/dashboard (HTTP 200)');

    // -----------------------------------------------------------
    // Test 20: Malformed Cloudflare Access JWT Rejection
    // -----------------------------------------------------------
    console.log('\nScenario 20: Malformed Cloudflare Access JWT Rejection');
    const malformedRes = await request(app)
      .get('/api/me')
      .set('Cf-Access-Jwt-Assertion', 'this-is-not-a-valid-jwt-token');
    assert(malformedRes.status === 401, 'Malformed JWT string rejected with HTTP 401');
    assert(malformedRes.body.error === 'Invalid Cloudflare Access assertion', 'Safe error message returned');

    // -----------------------------------------------------------
    // Test 21: Expired Cloudflare Access JWT Rejection
    // -----------------------------------------------------------
    console.log('\nScenario 21: Expired Cloudflare Access JWT Rejection');
    const expiredCfJwt = createTestCfJwt({
      email: userPayload.email,
      expiresIn: '-10s' // Expired in the past
    });

    const expiredCfRes = await request(app)
      .get('/api/me')
      .set('Cf-Access-Jwt-Assertion', expiredCfJwt);
    assert(expiredCfRes.status === 401, 'Expired Cloudflare Access JWT rejected with HTTP 401');
    assert(expiredCfRes.body.reason && expiredCfRes.body.reason.includes('expired'), 'Reason explains token expiration');

    // -----------------------------------------------------------
    // Test 22: Untrusted / Invalid Signature Rejection
    // -----------------------------------------------------------
    console.log('\nScenario 22: Untrusted Signature Rejection');
    const untrustedSignedJwt = createTestCfJwt({
      email: userPayload.email,
      privateKey: untrustedPrivateKey // Signed with rogue private key not in test JWKS
    });

    const untrustedRes = await request(app)
      .get('/api/me')
      .set('Cf-Access-Jwt-Assertion', untrustedSignedJwt);
    assert(untrustedRes.status === 401, 'JWT signed with untrusted/invalid key rejected with HTTP 401');

    // -----------------------------------------------------------
    // Test 23: Incorrect Audience (AUD) Rejection
    // -----------------------------------------------------------
    console.log('\nScenario 23: Incorrect Audience (AUD) Rejection');
    const wrongAudJwt = createTestCfJwt({
      email: userPayload.email,
      aud: 'malicious-or-wrong-application-aud-tag'
    });

    const wrongAudRes = await request(app)
      .get('/api/me')
      .set('Cf-Access-Jwt-Assertion', wrongAudJwt);
    assert(wrongAudRes.status === 401, 'JWT with incorrect Audience rejected with HTTP 401');

    // -----------------------------------------------------------
    // Test 24: Incorrect Issuer (ISS) Rejection
    // -----------------------------------------------------------
    console.log('\nScenario 24: Incorrect Issuer (ISS) Rejection');
    const wrongIssJwt = createTestCfJwt({
      email: userPayload.email,
      iss: 'https://attacker-controlled-team.cloudflareaccess.com'
    });

    const wrongIssRes = await request(app)
      .get('/api/me')
      .set('Cf-Access-Jwt-Assertion', wrongIssJwt);
    assert(wrongIssRes.status === 401, 'JWT with untrusted Issuer rejected with HTTP 401');

    // -----------------------------------------------------------
    // Test 25: Unknown or Unauthorized User in Campus Directory
    // -----------------------------------------------------------
    console.log('\nScenario 25: Unprovisioned User Rejection');
    const unknownUserJwt = createTestCfJwt({
      email: 'external.visitor@outside-university.org'
    });

    const unknownUserRes = await request(app)
      .get('/api/me')
      .set('Cf-Access-Jwt-Assertion', unknownUserJwt);
    assert(unknownUserRes.status === 401, 'Verified JWT with unknown campus email rejected with HTTP 401');
    assert(unknownUserRes.body.error === 'User identity not provisioned in campus directory', 'Unprovisioned error returned');

    // -----------------------------------------------------------
    // Test 26: Production Mode Rejection of Unauthenticated Requests
    // -----------------------------------------------------------
    console.log('\nScenario 26: Production Mode Strict Enforcement');
    const originalEnv = process.env.NODE_ENV;
    const originalAllowLocal = process.env.ALLOW_LOCAL_AUTH;

    try {
      // Simulate production mode with no local auth bypass
      process.env.NODE_ENV = 'production';
      process.env.ALLOW_LOCAL_AUTH = 'false';

      // Request to protected endpoint without Cf-Access-Jwt-Assertion must fail
      const prodMissingCfRes = await request(app)
        .get('/api/student/dashboard')
        .set('Cookie', 'sessionId=some_local_cookie');

      assert(prodMissingCfRes.status === 401, 'Production mode strictly rejects requests missing Cloudflare Access header (HTTP 401)');
      assert(prodMissingCfRes.body.error === 'Cloudflare Access assertion required', 'Strict production message returned');

      // Direct login request missing Cloudflare Access assertion MUST be rejected with HTTP 401
      const prodLocalLoginRes = await request(app)
        .post('/api/login')
        .send({ email: userPayload.email, password: userPayload.password });
      assert(prodLocalLoginRes.status === 401, 'Direct tunnel request to /api/login without Cloudflare Access is rejected (HTTP 401)');
    } finally {
      process.env.NODE_ENV = originalEnv;
      process.env.ALLOW_LOCAL_AUTH = originalAllowLocal;
    }

    // -----------------------------------------------------------
    // Test 27: Audit Ingestion of Cloudflare Access Events
    // -----------------------------------------------------------
    console.log('\nScenario 27: Cloudflare Access Audit Trail Verification');
    await new Promise(r => setTimeout(r, 100));

    await new Promise((resolve) => {
      db.all('SELECT * FROM audit_logs WHERE event_type LIKE "CF_ACCESS%"', [], (err, rows) => {
        assert(!err, 'Query for CF_ACCESS audit events succeeds');
        assert(rows && rows.length > 0, `Recorded Cloudflare Access audit events (Count: ${rows.length})`);

        const verifiedEvent = rows.find(r => r.event_type === 'CF_ACCESS_VERIFIED');
        assert(verifiedEvent && verifiedEvent.outcome === 'ALLOW', 'CF_ACCESS_VERIFIED event recorded with outcome ALLOW');

        const invalidEvent = rows.find(r => r.event_type === 'CF_ACCESS_INVALID');
        assert(invalidEvent && invalidEvent.outcome === 'DENY', 'CF_ACCESS_INVALID event recorded with outcome DENY');

        const unprovEvent = rows.find(r => r.event_type === 'CF_ACCESS_UNAUTHORIZED_USER');
        assert(unprovEvent && unprovEvent.outcome === 'DENY', 'CF_ACCESS_UNAUTHORIZED_USER event recorded with outcome DENY');

        // Verify zero JWT leakage in audit logs
        let leakedJwt = false;
        rows.forEach(r => {
          if (r.reason && (r.reason.includes('eyJ') || r.reason.length > 300)) {
            leakedJwt = true;
          }
        });
        assert(!leakedJwt, 'Audit logs do not store complete JWT assertions or raw signatures');

        resolve();
      });
    });

    // -----------------------------------------------------------
    // Test 28: Test Key Provider Production Lockout Guard
    // -----------------------------------------------------------
    console.log('\nScenario 28: Test Key Provider Production Lockout Guard');
    const prevEnv28 = process.env.NODE_ENV;
    try {
      process.env.NODE_ENV = 'production';
      let threwOnRegister = false;
      try {
        setTestKeyProvider(() => testPublicKey);
      } catch (err) {
        threwOnRegister = true;
        assert(err.message.includes('Security Violation'), 'setTestKeyProvider throws in production');
      }
      assert(threwOnRegister, 'Registering test key provider in production is strictly blocked');

      let threwOnVerify = false;
      const validJwtSample = createTestCfJwt();
      try {
        await verifyCloudflareAccessJwt(validJwtSample);
      } catch (verifyErr) {
        threwOnVerify = true;
        assert(verifyErr.message.includes('FATAL') || verifyErr.message.includes('Custom test key provider'), 'Active custom key provider is rejected in production mode');
      }
      assert(threwOnVerify, 'verifyCloudflareAccessJwt rejects test key provider under production');
    } finally {
      process.env.NODE_ENV = prevEnv28;
    }

    // -----------------------------------------------------------
    // Test 29: Production Registration Lockout
    // -----------------------------------------------------------
    console.log('\nScenario 29: Production Registration Lockout');
    const prevEnv29 = process.env.NODE_ENV;
    try {
      process.env.NODE_ENV = 'production';
      const prodRegRes = await request(app)
        .post('/api/register')
        .send({
          name: 'Unauthorized External',
          email: 'unauth.user@example.edu',
          password: 'Password123!'
        });
      assert(prodRegRes.status === 403, 'Public registration returns 403 Forbidden in production');
      assert(prodRegRes.body.error.includes('disabled in production'), 'Safe directory provisioning message returned');
    } finally {
      process.env.NODE_ENV = prevEnv29;
    }

    // -----------------------------------------------------------
    // Test 30: Production Local Login Bypass Prevention
    // -----------------------------------------------------------
    console.log('\nScenario 30: Production Local Login Bypass Prevention');
    const prevEnv30 = process.env.NODE_ENV;
    const prevAllow30 = process.env.ALLOW_LOCAL_AUTH;
    try {
      process.env.NODE_ENV = 'production';
      process.env.ALLOW_LOCAL_AUTH = 'true'; // Attempt to bypass via flag

      const bypassAttemptRes = await request(app)
        .post('/api/login')
        .send({ email: userPayload.email, password: userPayload.password });
      assert(bypassAttemptRes.status === 401, 'Direct login to tunnel without Cloudflare Access assertion strictly rejected (HTTP 401)');
    } finally {
      process.env.NODE_ENV = prevEnv30;
      process.env.ALLOW_LOCAL_AUTH = prevAllow30;
    }

    // -----------------------------------------------------------
    // Test 31: Mandatory Audience and Issuer Enforcement
    // -----------------------------------------------------------
    console.log('\nScenario 31: Mandatory Audience and Issuer Enforcement');
    const sampleJwt31 = createTestCfJwt();
    let threwAud = false;
    try {
      await verifyCloudflareAccessJwt(sampleJwt31, { expectedAud: '' });
    } catch (audErr) {
      threwAud = true;
      assert(audErr.message.includes('Audience (AUD) configuration is required'), 'Missing expectedAud fails closed');
    }
    assert(threwAud, 'verifyCloudflareAccessJwt strictly enforces audience presence');

    let threwIss = false;
    try {
      await verifyCloudflareAccessJwt(sampleJwt31, { teamDomain: '', expectedIss: '' });
    } catch (issErr) {
      threwIss = true;
      assert(issErr.message.includes('Issuer (team domain) is required'), 'Missing expectedIss fails closed');
    }
    assert(threwIss, 'verifyCloudflareAccessJwt strictly enforces issuer presence');

    // -----------------------------------------------------------
    // Test 32: Dedicated Administrator Audit Logs API Endpoint
    // -----------------------------------------------------------
    console.log('\nScenario 32: Dedicated Administrator Audit Logs API');
    const adminJwt32 = createTestCfJwt({ email: adminEmail });
    const studentJwt32 = createTestCfJwt({ email: userPayload.email });

    const adminLogsRes = await request(app)
      .get('/api/admin/audit-logs?limit=5&offset=0')
      .set('Cf-Access-Jwt-Assertion', adminJwt32);
    assert(adminLogsRes.status === 200, 'Administrator can access /api/admin/audit-logs (HTTP 200)');
    assert(Array.isArray(adminLogsRes.body.auditLogs), 'Audit logs returned in array');
    assert(adminLogsRes.body.limit === 5, 'Pagination limit parameter respected');

    const studentLogsRes = await request(app)
      .get('/api/admin/audit-logs')
      .set('Cf-Access-Jwt-Assertion', studentJwt32);
    assert(studentLogsRes.status === 403, 'Student cannot access /api/admin/audit-logs (HTTP 403)');

    const anonLogsRes = await request(app)
      .get('/api/admin/audit-logs');
    assert(anonLogsRes.status === 401, 'Anonymous request to /api/admin/audit-logs rejected (HTTP 401)');

    // -----------------------------------------------------------
    // Test 33: Production Verification Response Sanitization
    // -----------------------------------------------------------
    console.log('\nScenario 33: Production Verification Response Sanitization');
    const prevEnv33 = process.env.NODE_ENV;
    try {
      process.env.NODE_ENV = 'production';
      const malformedRes33 = await request(app)
        .get('/api/me')
        .set('Cf-Access-Jwt-Assertion', 'completely.invalid.token');
      assert(malformedRes33.status === 401, 'Invalid token returns 401 in production');
      assert(malformedRes33.body.reason === 'Invalid or expired Cloudflare Access assertion', 'Generic sanitized reason returned to client in production');
    } finally {
      process.env.NODE_ENV = prevEnv33;
    }

    // -----------------------------------------------------------
    // Test 34: Admin Refresh & Role Persistence via Cloudflare Access JWT
    // -----------------------------------------------------------
    console.log('\nScenario 34: Admin Session Refresh & Role Persistence');
    const adminRefreshJwt = createTestCfJwt({ email: adminEmail });

    // Initial page load /api/me
    const adminInitialMe = await request(app)
      .get('/api/me')
      .set('Cf-Access-Jwt-Assertion', adminRefreshJwt);
    assert(adminInitialMe.status === 200, 'Admin initial GET /api/me returns 200');
    assert(adminInitialMe.body.role === 'Administrator', 'Admin role confirmed as "Administrator"');

    // Simulated browser refresh 1
    const adminRefresh1 = await request(app)
      .get('/api/me')
      .set('Cf-Access-Jwt-Assertion', adminRefreshJwt);
    assert(adminRefresh1.status === 200, 'Admin refresh 1 GET /api/me returns 200');
    assert(adminRefresh1.body.role === 'Administrator', 'Admin role persists as "Administrator" after refresh 1');

    // Simulated browser refresh 2
    const adminRefresh2 = await request(app)
      .get('/api/me')
      .set('Cf-Access-Jwt-Assertion', adminRefreshJwt);
    assert(adminRefresh2.status === 200, 'Admin refresh 2 GET /api/me returns 200');
    assert(adminRefresh2.body.role === 'Administrator', 'Admin role persists as "Administrator" after refresh 2');

    // Access to admin dashboard & audit logs after refresh
    const adminDashAfterRefresh = await request(app)
      .get('/api/admin/dashboard')
      .set('Cf-Access-Jwt-Assertion', adminRefreshJwt);
    assert(adminDashAfterRefresh.status === 200, 'Admin accesses /api/admin/dashboard after refresh (HTTP 200)');

    const adminLogsAfterRefresh = await request(app)
      .get('/api/admin/audit-logs?limit=10&offset=0')
      .set('Cf-Access-Jwt-Assertion', adminRefreshJwt);
    assert(adminLogsAfterRefresh.status === 200, 'Admin accesses /api/admin/audit-logs after refresh (HTTP 200)');
    assert(Array.isArray(adminLogsAfterRefresh.body.auditLogs), 'Audit logs payload received as array');

    // -----------------------------------------------------------
    // Test 35: Student Denial Invariance on Refresh & Audit Logs
    // -----------------------------------------------------------
    console.log('\nScenario 35: Student Denial Invariance on Refresh & Audit Logs');
    const studentRefreshJwt = createTestCfJwt({ email: userPayload.email });

    // Student /api/me
    const studentRefreshMe = await request(app)
      .get('/api/me')
      .set('Cf-Access-Jwt-Assertion', studentRefreshJwt);
    assert(studentRefreshMe.status === 200, 'Student GET /api/me returns 200');
    assert(studentRefreshMe.body.role === 'Student', 'Student role is strictly "Student"');

    // Student denied from Admin Dashboard
    const studentDeniedDash = await request(app)
      .get('/api/admin/dashboard')
      .set('Cf-Access-Jwt-Assertion', studentRefreshJwt);
    assert(studentDeniedDash.status === 403, 'Student is denied /api/admin/dashboard (HTTP 403)');
    assert(studentDeniedDash.body.error === 'Insufficient privileges', 'Returns "Insufficient privileges"');

    // Student denied from Admin Audit Logs
    const studentDeniedLogs = await request(app)
      .get('/api/admin/audit-logs')
      .set('Cf-Access-Jwt-Assertion', studentRefreshJwt);
    assert(studentDeniedLogs.status === 403, 'Student is denied /api/admin/audit-logs (HTTP 403)');
    assert(studentDeniedLogs.body.error === 'Insufficient privileges', 'Returns "Insufficient privileges"');

    // -----------------------------------------------------------
    // Test 36: Dynamic Admin Configuration via ADMIN_EMAILS
    // -----------------------------------------------------------
    console.log('\nScenario 36: Dynamic Admin Configuration via ADMIN_EMAILS');
    const dynamicAdminEmail = 'delegated.admin@zerotrustcampus.edu';
    process.env.ADMIN_EMAILS = `admin@zerotrustcampus.edu,${dynamicAdminEmail}`;

    const dynamicAdminJwt = createTestCfJwt({ email: dynamicAdminEmail });

    const dynamicAdminMe = await request(app)
      .get('/api/me')
      .set('Cf-Access-Jwt-Assertion', dynamicAdminJwt);
    assert(dynamicAdminMe.status === 200, 'Configured admin via ADMIN_EMAILS is provisioned (HTTP 200)');
    assert(dynamicAdminMe.body.role === 'Administrator', 'Configured admin role is "Administrator"');

    const dynamicAdminLogs = await request(app)
      .get('/api/admin/audit-logs')
      .set('Cf-Access-Jwt-Assertion', dynamicAdminJwt);
    assert(dynamicAdminLogs.status === 200, 'Configured admin accesses /api/admin/audit-logs (HTTP 200)');

    // -----------------------------------------------------------
    // Test 37: Dual-Layer Auth — Deployed Student Campus Login behind Cloudflare Access
    // -----------------------------------------------------------
    console.log('\nScenario 37: Dual-Layer Auth — Deployed Student Campus Login behind Cloudflare Access');
    const prevEnforce37 = process.env.CLOUDFLARE_ACCESS_ENFORCE;
    const prevAllow37 = process.env.ALLOW_LOCAL_AUTH;
    try {
      process.env.CLOUDFLARE_ACCESS_ENFORCE = 'true';
      process.env.ALLOW_LOCAL_AUTH = 'false';

      // Outer gate: Valid Cloudflare Access JWT (even if outer identity is Admin)
      const outerGateJwt = createTestCfJwt({ email: 'admin@zerotrustcampus.edu' });

      // 1. Direct login without Cloudflare Access assertion MUST be rejected
      const directTunnelLogin = await request(app)
        .post('/api/login')
        .send({ email: userPayload.email, password: userPayload.password });
      assert(directTunnelLogin.status === 401, 'Direct tunnel request to /api/login without CF JWT is rejected (HTTP 401)');

      // 2. Login with valid Cloudflare Access assertion + Student credentials MUST succeed
      const deployedStudentLogin = await request(app)
        .post('/api/login')
        .set('Cf-Access-Jwt-Assertion', outerGateJwt)
        .send({ email: userPayload.email, password: userPayload.password });

      assert(deployedStudentLogin.status === 200, 'Student login succeeds behind Cloudflare Access gate (HTTP 200)');
      assert(deployedStudentLogin.body.role === 'Student', 'Student account profile returned with role "Student"');

      // Extract signed session cookie
      const rawCookie = deployedStudentLogin.headers['set-cookie'];
      assert(rawCookie && rawCookie.length > 0, 'Signed session cookie issued by backend');
      const studentSessionCookie = rawCookie[0].split(';')[0];

      // 3. Page Refresh: GET /api/me with CF JWT + Student Session Cookie
      // Campus session takes precedence over outer CF Access email!
      const studentRefreshedMe = await request(app)
        .get('/api/me')
        .set('Cf-Access-Jwt-Assertion', outerGateJwt)
        .set('Cookie', studentSessionCookie);

      assert(studentRefreshedMe.status === 200, 'Refreshed /api/me returns HTTP 200');
      assert(studentRefreshedMe.body.role === 'Student', 'Refreshed role strictly remains "Student" from active session');
      assert(studentRefreshedMe.body.authMethod === 'campus-session', 'Auth method confirmed as "campus-session"');

      // 4. Student can access Student Portal
      const studentPortalRes = await request(app)
        .get('/api/student/dashboard')
        .set('Cf-Access-Jwt-Assertion', outerGateJwt)
        .set('Cookie', studentSessionCookie);
      assert(studentPortalRes.status === 200, 'Student accesses /api/student/dashboard (HTTP 200)');

      // 5. Student is strictly rejected from Admin endpoints (HTTP 403)
      const studentBlockedAdminDash = await request(app)
        .get('/api/admin/dashboard')
        .set('Cf-Access-Jwt-Assertion', outerGateJwt)
        .set('Cookie', studentSessionCookie);
      assert(studentBlockedAdminDash.status === 403, 'Student is denied /api/admin/dashboard (HTTP 403)');

      const studentBlockedAuditLogs = await request(app)
        .get('/api/admin/audit-logs')
        .set('Cf-Access-Jwt-Assertion', outerGateJwt)
        .set('Cookie', studentSessionCookie);
      assert(studentBlockedAuditLogs.status === 403, 'Student is denied /api/admin/audit-logs (HTTP 403)');

      // 6. Direct request to Quick Tunnel with valid session cookie but WITHOUT CF JWT must be rejected (HTTP 401)
      const tunnelDirectWithCookie = await request(app)
        .get('/api/me')
        .set('Cookie', studentSessionCookie);
      assert(tunnelDirectWithCookie.status === 401, 'Direct tunnel request with valid session cookie but without CF JWT is rejected (HTTP 401)');
      assert(tunnelDirectWithCookie.body.error === 'Cloudflare Access assertion required', 'Safe error message returned');

      const tunnelDirectStudentDash = await request(app)
        .get('/api/student/dashboard')
        .set('Cookie', studentSessionCookie);
      assert(tunnelDirectStudentDash.status === 401, 'Direct tunnel request to /api/student/dashboard with cookie but without CF JWT is rejected (HTTP 401)');

    } finally {
      process.env.CLOUDFLARE_ACCESS_ENFORCE = prevEnforce37;
      process.env.ALLOW_LOCAL_AUTH = prevAllow37;
    }

    // -----------------------------------------------------------
    // Test 38: Dual-Layer Auth — Deployed Admin Campus Login behind Cloudflare Access
    // -----------------------------------------------------------
    console.log('\nScenario 38: Dual-Layer Auth — Deployed Admin Campus Login behind Cloudflare Access');
    try {
      process.env.CLOUDFLARE_ACCESS_ENFORCE = 'true';
      process.env.ALLOW_LOCAL_AUTH = 'false';

      const outerGateJwt = createTestCfJwt({ email: 'vigneshwaran7002@gmail.com' });

      // Login as Admin
      const deployedAdminLogin = await request(app)
        .post('/api/login')
        .set('Cf-Access-Jwt-Assertion', outerGateJwt)
        .send({ email: adminEmail, password: adminPassword });

      assert(deployedAdminLogin.status === 200, 'Admin login succeeds behind Cloudflare Access gate (HTTP 200)');
      assert(deployedAdminLogin.body.role === 'Administrator', 'Admin profile returned with role "Administrator"');

      const adminSessionCookie = deployedAdminLogin.headers['set-cookie'][0].split(';')[0];

      // Page refresh for Admin
      const adminRefreshedMe = await request(app)
        .get('/api/me')
        .set('Cf-Access-Jwt-Assertion', outerGateJwt)
        .set('Cookie', adminSessionCookie);

      assert(adminRefreshedMe.status === 200, 'Admin refreshed /api/me returns HTTP 200');
      assert(adminRefreshedMe.body.role === 'Administrator', 'Admin role strictly persists as "Administrator" on refresh');

      // Admin accesses Admin endpoints
      const adminDashRes = await request(app)
        .get('/api/admin/dashboard')
        .set('Cf-Access-Jwt-Assertion', outerGateJwt)
        .set('Cookie', adminSessionCookie);
      assert(adminDashRes.status === 200, 'Admin accesses /api/admin/dashboard (HTTP 200)');

      const adminLogsRes38 = await request(app)
        .get('/api/admin/audit-logs?limit=5&offset=0')
        .set('Cf-Access-Jwt-Assertion', outerGateJwt)
        .set('Cookie', adminSessionCookie);
      assert(adminLogsRes38.status === 200, 'Admin accesses /api/admin/audit-logs (HTTP 200)');

      // -----------------------------------------------------------
      // Test 39: Logout & Session Invalidation behind Cloudflare Access
      // -----------------------------------------------------------
      console.log('\nScenario 39: Logout & Session Invalidation behind Cloudflare Access');
      const logoutRes = await request(app)
        .post('/api/logout')
        .set('Cf-Access-Jwt-Assertion', outerGateJwt)
        .set('Cookie', adminSessionCookie);

      assert(logoutRes.status === 200, 'Logout succeeds with HTTP 200');
      assert(logoutRes.body.message === 'Logged out successfully', 'Logout confirmation received');

    } finally {
      process.env.CLOUDFLARE_ACCESS_ENFORCE = prevEnforce37;
      process.env.ALLOW_LOCAL_AUTH = prevAllow37;
    }

    // -----------------------------------------------------------
    // Test 40: CSRF Origin Protection Middleware
    // -----------------------------------------------------------
    console.log('\nScenario 40: CSRF Origin Protection Middleware');
    const csrfAttackRes = await request(app)
      .post('/api/login')
      .set('Origin', 'https://malicious-attacker-website.com')
      .send({ email: userPayload.email, password: userPayload.password });

    assert(csrfAttackRes.status === 403, 'Cross-origin request from untrusted origin blocked (HTTP 403)');
    assert(csrfAttackRes.body.error === 'Cross-origin request blocked by CSRF policy', 'Safe CSRF blocked message returned');

    // -----------------------------------------------------------
    // Test 41: Admin Creates Demo Student Account with Strong One-Time Temporary Password
    // -----------------------------------------------------------
    console.log('\nScenario 41: Admin Creates Demo Student Account with Strong One-Time Temporary Password');
    const demoAdminAgent = request.agent(app);
    const adminLoginRes = await demoAdminAgent
      .post('/api/login')
      .send({ email: adminEmail, password: adminPassword });
    assert(adminLoginRes.status === 200, 'Admin logs in successfully');

    const demoStudent1 = {
      name: 'Alice Demo Student',
      email: 'alice.demo@zerotrustcampus.edu',
      studentId: 'STU-DEMO-001'
    };

    const createRes1 = await demoAdminAgent
      .post('/api/admin/students')
      .send(demoStudent1);

    assert(createRes1.status === 201, 'Admin creates demo student account with HTTP 201');
    assert(createRes1.body.student.role === 'Student', 'Student role is strictly assigned on server as "Student"');
    assert(createRes1.body.student.id === demoStudent1.studentId, 'Student ID matches requested ID');
    assert(createRes1.body.student.email === demoStudent1.email, 'Email matches requested email');
    assert(typeof createRes1.body.student.temporaryPassword === 'string', 'Temporary password returned in creation response');
    assert(createRes1.body.student.temporaryPassword.length >= 14, 'Temporary password is strong (at least 14 chars)');
    assert(createRes1.body.total === 1, 'Total demo students count is 1');
    assert(createRes1.body.maxLimit === 5, 'Max limit is 5');
    assert(createRes1.body.remaining === 4, 'Remaining demo student accounts is 4');

    const demo1TempPassword = createRes1.body.student.temporaryPassword;

    // -----------------------------------------------------------
    // Test 42: Password Security & Database Hash Verification (No Plaintext Leaks)
    // -----------------------------------------------------------
    console.log('\nScenario 42: Password Security & Database Hash Verification (No Plaintext Leaks)');
    const dbStudentRow = await new Promise((resolve) => {
      db.get('SELECT password FROM users WHERE id = ?', [demoStudent1.studentId], (err, row) => resolve(row));
    });
    assert(dbStudentRow && dbStudentRow.password.startsWith('$2'), 'Password is stored as a bcrypt hash');
    assert(dbStudentRow.password !== demo1TempPassword, 'Plaintext temporary password is NEVER stored in database');
    const hashMatches = await bcrypt.compare(demo1TempPassword, dbStudentRow.password);
    assert(hashMatches === true, 'Bcrypt hash correctly validates temporary password');

    // Verify GET /api/admin/students does NOT return passwords
    const listRes = await demoAdminAgent.get('/api/admin/students');
    assert(listRes.status === 200, 'Admin can list demo students');
    assert(listRes.body.total === 1, 'List shows total: 1');
    assert(listRes.body.students.length === 1, 'List contains 1 student');
    assert(listRes.body.students[0].password === undefined, 'No password field in student list');
    assert(listRes.body.students[0].temporaryPassword === undefined, 'No temporaryPassword field in student list');

    // Verify audit logs do NOT leak password
    const auditLogRow = await new Promise((resolve) => {
      db.get("SELECT reason FROM audit_logs WHERE event_type = 'STUDENT_ACCOUNT_CREATED' ORDER BY timestamp DESC LIMIT 1", [], (err, row) => resolve(row));
    });
    assert(auditLogRow && !auditLogRow.reason.includes(demo1TempPassword), 'Audit logs do not leak temporary password');

    // -----------------------------------------------------------
    // Test 43: Non-Admin Access Rejection (RBAC Enforcement)
    // -----------------------------------------------------------
    console.log('\nScenario 43: Non-Admin Access Rejection (RBAC Enforcement)');
    // Student attempt (authenticated as student)
    const activeStudentAgent = request.agent(app);
    await activeStudentAgent
      .post('/api/login')
      .send({ email: userPayload.email, password: userPayload.password });

    const studentCreateAttempt = await activeStudentAgent
      .post('/api/admin/students')
      .send({ name: 'Hacker Student', email: 'hacker@campus.edu' });
    assert(studentCreateAttempt.status === 403, 'Student cannot create accounts (HTTP 403 Forbidden)');

    const studentListAttempt = await activeStudentAgent.get('/api/admin/students');
    assert(studentListAttempt.status === 403, 'Student cannot list demo accounts (HTTP 403 Forbidden)');

    // Faculty attempt
    const facultyCreateAttempt = await facultyAgent
      .post('/api/admin/students')
      .send({ name: 'Faculty Student', email: 'facstu@campus.edu' });
    assert(facultyCreateAttempt.status === 403, 'Faculty cannot create accounts (HTTP 403 Forbidden)');

    const facultyListAttempt = await facultyAgent.get('/api/admin/students');
    assert(facultyListAttempt.status === 403, 'Faculty cannot list demo accounts (HTTP 403 Forbidden)');

    // Unauthenticated attempt
    const anonCreateAttempt = await request(app)
      .post('/api/admin/students')
      .send({ name: 'Anon Student', email: 'anon@campus.edu' });
    assert(anonCreateAttempt.status === 401, 'Unauthenticated user cannot create accounts (HTTP 401 Unauthorized)');

    const anonListAttempt = await request(app).get('/api/admin/students');
    assert(anonListAttempt.status === 401, 'Unauthenticated user cannot list demo accounts (HTTP 401 Unauthorized)');

    // -----------------------------------------------------------
    // Test 44: Direct Quick Tunnel Request Without Outer Gate Cloudflare JWT Rejected
    // -----------------------------------------------------------
    console.log('\nScenario 44: Direct Quick Tunnel Request Without Outer Gate Cloudflare JWT Rejected');
    const prevEnforce44 = process.env.CLOUDFLARE_ACCESS_ENFORCE;
    const prevAllow44 = process.env.ALLOW_LOCAL_AUTH;
    try {
      process.env.CLOUDFLARE_ACCESS_ENFORCE = 'true';
      process.env.ALLOW_LOCAL_AUTH = 'false';

      // Direct tunnel request with admin session cookie but NO CF JWT
      const directTunnelRes = await demoAdminAgent.post('/api/admin/students').send({
        name: 'Direct Tunnel Test',
        email: 'direct@campus.edu'
      });
      assert(directTunnelRes.status === 401, 'Direct tunnel request without Cloudflare JWT is rejected (HTTP 401)');

      // Valid CF JWT + Admin Session succeeds
      const validAdminCfJwt = createTestCfJwt({ email: 'vigneshwaran7002@gmail.com' });
      const authenticatedTunnelRes = await demoAdminAgent
        .get('/api/admin/students')
        .set('Cf-Access-Jwt-Assertion', validAdminCfJwt);
      assert(authenticatedTunnelRes.status === 200, 'Admin request with valid CF JWT succeeds in tunnel mode (HTTP 200)');
    } finally {
      process.env.CLOUDFLARE_ACCESS_ENFORCE = prevEnforce44;
      process.env.ALLOW_LOCAL_AUTH = prevAllow44;
    }

    // -----------------------------------------------------------
    // Test 45: Duplicate Email, Duplicate Student ID, & Input Validation
    // -----------------------------------------------------------
    console.log('\nScenario 45: Duplicate Email, Duplicate Student ID, & Input Validation');
    // Duplicate email
    const dupEmailRes = await demoAdminAgent
      .post('/api/admin/students')
      .send({ name: 'Duplicate Email Test', email: demoStudent1.email, studentId: 'STU-DEMO-999' });
    assert(dupEmailRes.status === 400, 'Duplicate email rejected with HTTP 400');
    assert(dupEmailRes.body.error === 'An account with this email address already exists.', 'Correct duplicate email error message');

    // Duplicate student ID
    const dupIdRes = await demoAdminAgent
      .post('/api/admin/students')
      .send({ name: 'Duplicate ID Test', email: 'unique.email@campus.edu', studentId: demoStudent1.studentId });
    assert(dupIdRes.status === 400, 'Duplicate student ID rejected with HTTP 400');
    assert(dupIdRes.body.error === 'An account with this student ID already exists.', 'Correct duplicate student ID error message');

    // Invalid email format
    const invalidEmailRes45 = await demoAdminAgent
      .post('/api/admin/students')
      .send({ name: 'Invalid Email Test', email: 'not-an-email' });
    assert(invalidEmailRes45.status === 400, 'Invalid email rejected with HTTP 400');

    // Short name
    const shortNameRes = await demoAdminAgent
      .post('/api/admin/students')
      .send({ name: 'A', email: 'valid@campus.edu' });
    assert(shortNameRes.status === 400, 'Short name rejected with HTTP 400');

    // -----------------------------------------------------------
    // Test 46: Strict 5-Account Quota Limit Enforcement
    // -----------------------------------------------------------
    console.log('\nScenario 46: Strict 5-Account Quota Limit Enforcement');
    // We already created 1 account (total: 1, remaining: 4)
    // Create accounts 2, 3, 4, 5
    for (let i = 2; i <= 5; i++) {
      const res = await demoAdminAgent
        .post('/api/admin/students')
        .send({
          name: `Demo Student ${i}`,
          email: `student${i}.demo@zerotrustcampus.edu`,
          studentId: `STU-DEMO-00${i}`
        });
      assert(res.status === 201, `Demo student account #${i} created successfully (HTTP 201)`);
      assert(res.body.total === i, `Total is now ${i}`);
      assert(res.body.remaining === 5 - i, `Remaining is now ${5 - i}`);
    }

    // Verify limit is reached
    const quotaCheck = await demoAdminAgent.get('/api/admin/students');
    assert(quotaCheck.body.total === 5, 'Quota reached: total is 5');
    assert(quotaCheck.body.remaining === 0, 'Quota reached: remaining is 0');
    assert(quotaCheck.body.students.length === 5, 'List contains exactly 5 demo students');

    // Attempt to create 6th account
    const sixthRes = await demoAdminAgent
      .post('/api/admin/students')
      .send({
        name: 'Sixth Student Over Limit',
        email: 'sixth@zerotrustcampus.edu',
        studentId: 'STU-DEMO-006'
      });
    assert(sixthRes.status === 400, 'Attempt to create 6th account rejected with HTTP 400');
    assert(sixthRes.body.error.includes('Maximum limit of 5 demo student accounts has been reached'), 'Limit reached error message');

    // Database check: count in demo_students is still exactly 5
    const finalDemoCount = await new Promise((resolve) => {
      db.get('SELECT COUNT(*) AS count FROM demo_students', [], (err, row) => resolve(row.count));
    });
    assert(finalDemoCount === 5, 'Database confirms exactly 5 accounts in demo_students table');

    // -----------------------------------------------------------
    // Test 47: Created Demo Student Login & Authenticated Password Change
    // -----------------------------------------------------------
    console.log('\nScenario 47: Created Demo Student Login & Authenticated Password Change');
    const demoStudentAgent = request.agent(app);
    const demoStudentLogin = await demoStudentAgent
      .post('/api/login')
      .send({
        email: demoStudent1.email,
        password: demo1TempPassword
      });

    assert(demoStudentLogin.status === 200, 'Created demo student logs in successfully with temporary password');
    assert(demoStudentLogin.body.role === 'Student', 'Logged in role is "Student"');

    // Demo student accesses Student Portal
    const demoStudentDash = await demoStudentAgent.get('/api/student/dashboard');
    assert(demoStudentDash.status === 200, 'Created demo student accesses student dashboard');
    assert(demoStudentDash.body.portal === 'Student Portal', 'Receives Student Portal data');

    // Demo student denied from Admin Portal
    const demoStudentAdminAttempt = await demoStudentAgent.get('/api/admin/dashboard');
    assert(demoStudentAdminAttempt.status === 403, 'Created demo student denied from Admin dashboard (HTTP 403)');

    // Demo student changes password
    const changePassRes = await demoStudentAgent
      .post('/api/user/change-password')
      .send({
        currentPassword: demo1TempPassword,
        newPassword: 'NewPermanentPassword!2026'
      });
    assert(changePassRes.status === 200, 'Demo student successfully changes password (HTTP 200)');

    // Log in with new password
    const newLoginRes = await request(app)
      .post('/api/login')
      .send({
        email: demoStudent1.email,
        password: 'NewPermanentPassword!2026'
      });
    assert(newLoginRes.status === 200, 'Demo student successfully logs in with updated password');

  } catch (err) {
    console.error('Unexpected test execution error:', err);
    failedTests++;
  } finally {
    // Close database connection and clean up test file
    await new Promise((resolve) => db.close(resolve));
    if (fs.existsSync(TEST_DB_PATH)) {
      try {
        fs.unlinkSync(TEST_DB_PATH);
      } catch (cleanupErr) {}
    }

    console.log('\n----------------------------------------------------------------');
    console.log(`Test Execution Summary: ${passedTests} passed, ${failedTests} failed.`);
    console.log('----------------------------------------------------------------\n');

    process.exit(failedTests > 0 ? 1 : 0);
  }
}

runTests();
