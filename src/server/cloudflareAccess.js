import crypto from 'node:crypto';

let customKeyProvider = null;
let jwksCache = {
  keys: [],
  timestamp: 0,
  teamDomain: null
};

export function setTestKeyProvider(fn) {
  customKeyProvider = fn;
}

function base64UrlDecode(str) {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  return Buffer.from(base64, 'base64');
}

async function fetchJwks(teamDomain, certsUrlOverride) {
  const cleanDomain = (teamDomain || '').replace(/^https?:\/\//, '').replace(/\/$/, '');
  const normalizedDomain = cleanDomain.includes('.') ? cleanDomain : `${cleanDomain}.cloudflareaccess.com`;
  const jwksUri = certsUrlOverride || `https://${normalizedDomain}/cdn-cgi/access/certs`;

  const now = Date.now();
  if (jwksCache.teamDomain === normalizedDomain && (now - jwksCache.timestamp < 10 * 60 * 1000) && jwksCache.keys.length > 0) {
    return jwksCache.keys;
  }

  const res = await fetch(jwksUri, {
    headers: { 'User-Agent': 'ZeroTrustCampus-Worker' },
    cf: { cacheTtl: 600, cacheEverything: true }
  });

  if (!res.ok) {
    throw new Error(`Failed to fetch Cloudflare Access JWKS: HTTP ${res.status}`);
  }

  const data = await res.json();
  const keys = Array.isArray(data.keys) ? data.keys : [];
  jwksCache = {
    keys,
    timestamp: now,
    teamDomain: normalizedDomain
  };
  return keys;
}

export async function verifyCloudflareAccessJwt(token, options = {}) {
  if (!token || typeof token !== 'string') {
    throw new Error('Token must be a non-empty string');
  }

  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Malformed token structure');
  }

  let header;
  let payload;
  try {
    header = JSON.parse(base64UrlDecode(parts[0]).toString('utf-8'));
    payload = JSON.parse(base64UrlDecode(parts[1]).toString('utf-8'));
  } catch {
    throw new Error('Malformed token structure');
  }

  if (header.alg !== 'RS256') {
    throw new Error(`Invalid signing algorithm: ${header.alg}. Cloudflare Access requires RS256`);
  }

  const teamDomain = options.teamDomain !== undefined ? options.teamDomain : options.env?.CLOUDFLARE_ACCESS_TEAM_DOMAIN;
  const expectedAud = options.expectedAud !== undefined ? options.expectedAud : options.env?.CLOUDFLARE_ACCESS_AUD;
  const certsUrl = options.certsUrl !== undefined ? options.certsUrl : options.env?.CLOUDFLARE_ACCESS_CERTS_URL;

  if (!expectedAud) {
    throw new Error('Cloudflare Access Audience (AUD) configuration is required for token verification');
  }

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

  // Validate audience
  const audArray = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!audArray.includes(expectedAud)) {
    throw new Error(`Audience mismatch: expected ${expectedAud}`);
  }

  // Validate issuer
  if (payload.iss !== expectedIss) {
    throw new Error(`Issuer mismatch: expected ${expectedIss}, got ${payload.iss}`);
  }

  // Validate expiration and not-before with 30s leeway
  const nowSec = Math.floor(Date.now() / 1000);
  if (!payload.exp || typeof payload.exp !== 'number' || !Number.isFinite(payload.exp) || payload.exp <= 0) {
    throw new Error('Cloudflare Access JWT missing or invalid expiration (exp) timestamp');
  }
  if (nowSec > payload.exp + 30) {
    const err = new Error('Cloudflare Access JWT expired');
    err.name = 'TokenExpiredError';
    throw err;
  }
  if (payload.nbf && (typeof payload.nbf !== 'number' || nowSec < payload.nbf - 30)) {
    throw new Error('Cloudflare Access JWT not active yet');
  }

  // Verify signature
  const data = Buffer.from(`${parts[0]}.${parts[1]}`, 'utf-8');
  const signature = base64UrlDecode(parts[2]);

  if (customKeyProvider) {
    const key = customKeyProvider(header);
    if (!key) throw new Error('Custom test key provider returned null key');
    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(data);
    if (!verifier.verify(key, signature)) {
      throw new Error('Invalid signature');
    }
  } else {
    if (!header.kid) {
      throw new Error('JWT header missing key identifier (kid)');
    }
    const keys = await fetchJwks(teamDomain, certsUrl);
    const jwk = keys.find(k => k.kid === header.kid);
    if (!jwk) {
      throw new Error(`Signing key not found in JWKS for kid: ${header.kid}`);
    }

    const cryptoKey = await crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify']
    );

    const isValid = await crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5',
      cryptoKey,
      signature,
      data
    );

    if (!isValid) {
      throw new Error('Invalid signature');
    }
  }

  const email = (payload.email || payload.sub || '').trim().toLowerCase();
  if (!email) {
    throw new Error('Token missing email/sub identity claim');
  }

  return payload;
}
