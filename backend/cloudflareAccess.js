/**
 * Cloudflare Zero Trust Access Authentication Module
 * Validates 'Cf-Access-Jwt-Assertion' headers using RS256 public key verification,
 * JWKS key retrieval with caching, and strict audience & issuer validation.
 */
const jwt = require('jsonwebtoken');
const jwksRsa = require('jwks-rsa');

let customKeyProvider = null; // For offline automated test key injection

// Cache the JWKS client by team domain
let jwksClientInstance = null;
let currentTeamDomain = null;

function getJwksClient(teamDomain, certsUrlOverride) {
  const cleanDomain = (teamDomain || '').replace(/^https?:\/\//, '').replace(/\/$/, '');
  const normalizedDomain = cleanDomain.includes('.') ? cleanDomain : `${cleanDomain}.cloudflareaccess.com`;
  const jwksUri = certsUrlOverride || `https://${normalizedDomain}/cdn-cgi/access/certs`;

  if (!jwksClientInstance || currentTeamDomain !== normalizedDomain || certsUrlOverride) {
    currentTeamDomain = normalizedDomain;
    jwksClientInstance = jwksRsa({
      jwksUri,
      cache: true,
      cacheMaxEntries: 5,
      cacheMaxAge: 10 * 60 * 1000,
      rateLimit: true,
      jwksRequestsPerMinute: 10,
      timeout: 10000 // 10 second timeout to prevent hanging connections
    });
  }

  return jwksClientInstance;
}

/**
 * Allows injecting a test key provider during offline automated unit/integration tests.
 * STRICT SECURITY GUARD: Never permitted in production environment.
 */
function setTestKeyProvider(fn) {
  if (process.env.NODE_ENV === 'production') {
    throw new Error('Security Violation: Test key provider cannot be registered in production environment.');
  }
  customKeyProvider = fn;
}

/**
 * Retrieves the signing key for a given JWT header kid.
 */
function getSigningKey(header, teamDomain, certsUrl) {
  return new Promise((resolve, reject) => {
    // Check if test key provider is active
    if (customKeyProvider) {
      if (process.env.NODE_ENV === 'production') {
        return reject(new Error('FATAL: Custom test key provider cannot be used in production mode.'));
      }
      try {
        const key = customKeyProvider(header);
        if (!key) return reject(new Error('Custom test key provider returned null or undefined key'));
        return resolve(key);
      } catch (err) {
        return reject(err);
      }
    }

    if (!header || !header.kid) {
      return reject(new Error('JWT header missing key identifier (kid)'));
    }

    if (!teamDomain && !certsUrl) {
      return reject(new Error('Cloudflare Access team domain or certs URL required to retrieve signing keys'));
    }

    const client = getJwksClient(teamDomain, certsUrl);
    client.getSigningKey(header.kid, (err, key) => {
      if (err) return reject(err);
      if (!key) return reject(new Error(`Signing key not found in JWKS for kid: ${header.kid}`));
      const signingKey = key.getPublicKey ? key.getPublicKey() : key.rsaPublicKey;
      if (!signingKey) return reject(new Error('Unable to extract public key from JWKS certificate'));
      resolve(signingKey);
    });
  });
}

/**
 * Cryptographically verifies a Cloudflare Access JWT.
 * Validates RS256 signature, exp, nbf, iss, and aud claims.
 */
async function verifyCloudflareAccessJwt(token, options = {}) {
  if (!token || typeof token !== 'string') {
    throw new Error('Token must be a non-empty string');
  }

  // 1. Decode header to extract kid and alg
  const decodedComplete = jwt.decode(token, { complete: true });
  if (!decodedComplete || !decodedComplete.header) {
    throw new Error('Malformed token structure');
  }

  const { header } = decodedComplete;
  if (header.alg !== 'RS256') {
    throw new Error(`Invalid signing algorithm: ${header.alg}. Cloudflare Access requires RS256`);
  }

  const teamDomain = options.teamDomain !== undefined ? options.teamDomain : process.env.CLOUDFLARE_ACCESS_TEAM_DOMAIN;
  const expectedAud = options.expectedAud !== undefined ? options.expectedAud : process.env.CLOUDFLARE_ACCESS_AUD;
  const certsUrl = options.certsUrl !== undefined ? options.certsUrl : process.env.CLOUDFLARE_ACCESS_CERTS_URL;

  // Expected audience is mandatory to prevent cross-app token reuse
  if (!expectedAud) {
    throw new Error('Cloudflare Access Audience (AUD) configuration is required for token verification');
  }

  // Expected issuer: https://<team>.cloudflareaccess.com
  let expectedIss = null;
  if (teamDomain) {
    const cleanDomain = teamDomain.replace(/^https?:\/\//, '').replace(/\/$/, '');
    const normalizedDomain = cleanDomain.includes('.') ? cleanDomain : `${cleanDomain}.cloudflareaccess.com`;
    expectedIss = `https://${normalizedDomain}`;
  }
  if (options.expectedIss !== undefined) {
    expectedIss = options.expectedIss;
  }

  if (!expectedIss) {
    throw new Error('Cloudflare Access Issuer (team domain) is required for token verification');
  }

  // 2. Fetch public key (supports rotation, caching & timeouts)
  const signingKey = await getSigningKey(header, teamDomain, certsUrl);

  // 3. Verify signature, audience, issuer, expiration, and not-before
  const verifyOptions = {
    algorithms: ['RS256'],
    audience: expectedAud,
    issuer: expectedIss,
    clockTolerance: 10 // 10-second tolerance for minor clock skew
  };

  return new Promise((resolve, reject) => {
    jwt.verify(token, signingKey, verifyOptions, (err, verifiedPayload) => {
      if (err) {
        return reject(err);
      }

      // Check required identity claim
      const email = verifiedPayload.email || verifiedPayload.sub;
      if (!email || typeof email !== 'string') {
        return reject(new Error('Token missing email/sub identity claim'));
      }

      resolve(verifiedPayload);
    });
  });
}

/**
 * Validates environment configuration on startup
 */
function validateCloudflareEnvironment() {
  const isProd = process.env.NODE_ENV === 'production';
  const teamDomain = process.env.CLOUDFLARE_ACCESS_TEAM_DOMAIN;
  const aud = process.env.CLOUDFLARE_ACCESS_AUD;

  if (isProd) {
    if (!teamDomain || !aud) {
      throw new Error(
        'FATAL: Production mode requires CLOUDFLARE_ACCESS_TEAM_DOMAIN and CLOUDFLARE_ACCESS_AUD to be configured.'
      );
    }
  }
}

module.exports = {
  verifyCloudflareAccessJwt,
  setTestKeyProvider,
  validateCloudflareEnvironment,
  getJwksClient
};
