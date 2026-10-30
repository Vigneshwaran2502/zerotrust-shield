# ZeroTrust Campus — Cloudflare Zero Trust Security Integration

[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare_Workers-Live_Deployment-F38020?logo=cloudflare&logoColor=white)](https://zerotrust-campus.vigneshwaran7002.workers.dev/)
[![Cloudflare D1](https://img.shields.io/badge/Cloudflare_D1-Serverless_SQL-F38020?logo=cloudflare&logoColor=white)](https://zerotrust-campus.vigneshwaran7002.workers.dev/)
[![Zero Trust Access](https://img.shields.io/badge/Zero_Trust-Access_Enforced-2F80ED?logo=cloudflare&logoColor=white)](https://zerotrust-campus.vigneshwaran7002.workers.dev/)

> 🌐 **Live Production URL:**  
> **[https://zerotrust-campus.vigneshwaran7002.workers.dev/](https://zerotrust-campus.vigneshwaran7002.workers.dev/)**

**ZeroTrust Campus** is an enterprise-grade university portal demonstrating practical Zero Trust security architecture, multi-layer identity verification, server-side role-based access control (RBAC), and tamper-resistant security audit logging.

---

## 1. Architectural Overview

Traditional campus networks rely on castle-and-moat perimeter security (VPNs or campus network subnets). Once inside, attackers or compromised accounts can move laterally across internal services.

**ZeroTrust Campus** eliminates perimeter trust by enforcing:
1. **Never Trust, Always Verify:** Every incoming request must provide cryptographically verified identity assertions from Cloudflare Access.
2. **Dual-Layer Identity & Authorization:** Cloudflare Access handles edge authentication, MFA, and device posture. The application layer independently validates assertions and strictly enforces server-side campus RBAC. Cloudflare Access alone never determines application privileges.
3. **Private Ingress via Cloudflare Tunnel (`cloudflared`):** The backend origin has no public IP address, open inbound firewall ports, or direct internet exposure. Traffic reaches the service exclusively via an encrypted outbound tunnel to Cloudflare's edge.
4. **Complete Audit Telemetry:** Every authentication attempt, authorization decision, privilege denial, and token failure is captured in a persistent SQLite audit log without leaking sensitive credentials or raw tokens.

```
                              ┌──────────────────────────────────┐
                              │     Cloudflare Edge Network      │
                              │  - Identity Provider (IdP) / SSO │
                              │  - Cloudflare Access Policies    │
                              │  - Signs RS256 Access JWT        │
                              └─────────────────┬────────────────┘
                                                │ Encrypted Ingress
                                                ▼ (Cloudflare Tunnel)
                              ┌──────────────────────────────────┐
                              │       cloudflared Daemon         │
                              │   (No inbound ports open)        │
                              └─────────────────┬────────────────┘
                                                │ Local Proxy
                                                ▼
     ┌────────────────────────────────────────────────────────────────────────┐
     │                     ZeroTrust Campus Backend (Node/Express)            │
     │                                                                        │
     │  1. Security Headers & Request Limit Middleware (100kb)                │
     │  2. Cloudflare Access JWT Verification Middleware                      │
     │     - Validates RS256 signature using JWKS public keys                 │
     │     - Validates Issuer (teamDomain) and Audience (AUD)                 │
     │     - Validates Expiration (exp) and token integrity                   │
     │  3. Campus Identity & Directory Mapping                                │
     │     - Maps verified claim (email) to SQLite User record                │
     │     - Rejects unprovisioned/unknown identities (401)                   │
     │  4. Server-Side RBAC Middleware (Student / Faculty / Administrator)   │
     │  5. Security Audit Logger (ALLOW / DENY events recorded to SQLite)     │
     └────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Role-Based Access Control (RBAC) Matrix

| Endpoint | Role Required | Student | Faculty | Administrator | Anonymous |
| :--- | :--- | :---: | :---: | :---: | :---: |
| `GET /api/me` | Authenticated | ✅ | ✅ | ✅ | ❌ (401) |
| `GET /api/student/dashboard` | `Student` | ✅ | ❌ (403) | ❌ (403) | ❌ (401) |
| `GET /api/faculty/dashboard` | `Faculty` | ❌ (403) | ✅ | ❌ (403) | ❌ (401) |
| `GET /api/admin/dashboard` | `Administrator` | ❌ (403) | ❌ (403) | ✅ | ❌ (401) |
| `GET /api/admin/audit-logs` | `Administrator` | ❌ (403) | ❌ (403) | ✅ | ❌ (401) |

*Note: Roles are strictly derived from the verified database record on the server. Client-submitted roles, request headers, or query parameters cannot alter permissions.*

---

## 3. Cloudflare Access JWT Verification Engine

The verification module (`backend/cloudflareAccess.js`) integrates directly with Cloudflare Access:
- **Header:** Reads the JWT assertion passed in `Cf-Access-Jwt-Assertion`.
- **JWKS Endpoint:** Fetches and caches Cloudflare's signing certificates from `https://<teamDomain>.cloudflareaccess.com/cdn-cgi/access/certs`.
- **Key Rotation & Caching:** Uses `jwks-rsa` with safe caching (`cache: true`, `rateLimit: true`, 10-minute cache max age).
- **Cryptographic Validation:** Verifies RS256 signature, audience (`AUD`), issuer (`ISS`), and expiration (`exp`).
- **Identity Mapping:** Rejects any user whose email is not explicitly provisioned in the campus database (`CF_ACCESS_UNAUTHORIZED_USER`).
- **Audit Logging:** Every verification outcome (`CF_ACCESS_VERIFIED`, `CF_ACCESS_INVALID`, `CF_ACCESS_UNAUTHORIZED_USER`, `CF_ACCESS_MISSING`) is persisted in `audit_logs`.

---

## 4. Environment Configuration

Copy the example environment configuration:
```bash
cp backend/.env.example backend/.env
```

### Configuration Variables (`backend/.env`)

| Variable | Description | Default / Example |
| :--- | :--- | :--- |
| `PORT` | Local port for Express API | `3001` |
| `NODE_ENV` | Environment mode (`development` or `production`) | `development` |
| `SESSION_SECRET` | Secret key used to sign session cookies | Secure random 64-character string |
| `CLOUDFLARE_ACCESS_TEAM_DOMAIN` | Your Cloudflare Zero Trust team domain | `your-team-domain` (without `.cloudflareaccess.com`) |
| `CLOUDFLARE_ACCESS_AUD` | Application Audience Tag from Cloudflare Access | `your-cloudflare-access-application-aud` |
| `ALLOW_LOCAL_AUTH` | Enables password fallback for offline development | `true` (dev only, auto-disabled in production) |
| `CLOUDFLARE_ACCESS_ENFORCE` | Force Access JWT validation even in development | `false` (set `true` to test Access locally) |
| `FRONTEND_ORIGIN` | Explicit CORS allowed origin | `http://localhost:5173` |

> **Security Rule:** In `production` mode (`NODE_ENV=production`), `ALLOW_LOCAL_AUTH` is permanently locked out. The server automatically rejects local password logins with `403 Forbidden` and demands a valid `Cf-Access-Jwt-Assertion` on all protected endpoints.

---

## 5. Local Development & Testing

### Prerequisites
- Node.js v18+ (tested on Node v20/v22)
- npm v9+

### Installation
```bash
# 1. Install frontend dependencies
npm install

# 2. Install backend dependencies
cd backend
npm install
cd ..
```

### Running Backend Tests
The automated test suite runs 33 scenarios (110 assertions) verifying local auth, password hashing, session cookies, RBAC boundaries, Cloudflare Access JWT validation (with ephemeral RSA keys), tamper-resistance, production lockouts, and audit logging.

```bash
cd backend
npm test
```

### Running Frontend Production Build
```bash
npm run build
```

### Running the Full Application Locally
```bash
# Terminal 1: Start Backend API
cd backend
npm run dev

# Terminal 2: Start Frontend Application
npm run dev
```

Frontend runs at `http://localhost:5173`, proxying API requests to `http://localhost:3001`.

---

## 6. Production Deployment Options

### Option A: Cloudflare Workers + D1 Serverless Edge (Live Deployment)

The portal can run fully serverless on Cloudflare's global edge network using Cloudflare Workers, Static Assets, and Cloudflare D1 (serverless SQLite):

- **Live URL:** [https://zerotrust-campus.vigneshwaran7002.workers.dev/](https://zerotrust-campus.vigneshwaran7002.workers.dev/)
- **Worker Configuration:** [wrangler.jsonc](file:///d:/Cloudflare/wrangler.jsonc)
- **API Entrypoint:** [src/worker.js](file:///d:/Cloudflare/src/worker.js)
- **Database:** Cloudflare D1 (`zerotrust_shield_db` / `zerotrust-shield-db`)
- **Static Assets:** React SPA served directly from `dist/` via Workers Assets

#### Deploying with Wrangler:
```bash
# 1. Build frontend bundle
npm run build

# 2. Deploy to Cloudflare Workers
npx wrangler deploy
```

---

### Option B: Private Origin behind Cloudflare Tunnel (`cloudflared`)

For environments hosting a traditional Node.js/Express service, the backend can remain private on an internal host behind **Cloudflare Tunnel (`cloudflared`)**:
- Zero public ingress ports on the host.
- Encrypted outbound tunnel to Cloudflare's edge with Access policies enforced.
- Complete edge DDoS protection and Cloudflare Access authentication at the edge.

### Step 1: Create a Cloudflare Tunnel
1. Install `cloudflared` on your production host:
   ```bash
   # Linux / Debian / Ubuntu
   sudo apt-get install cloudflared
   ```
2. Authenticate `cloudflared`:
   ```bash
   cloudflared tunnel login
   ```
3. Create your tunnel:
   ```bash
   cloudflared tunnel create zerotrust-campus-tunnel
   ```
4. Note your Tunnel ID and credentials file path (`<UUID>.json`).

### Step 2: Configure Tunnel Ingress (`cloudflared/config.yml`)
Use the template provided in [cloudflared/config.example.yml](file:///d:/Cloudflare/cloudflared/config.example.yml):

```yaml
tunnel: <YOUR-TUNNEL-UUID>
credentials-file: /etc/cloudflared/<YOUR-TUNNEL-UUID>.json

ingress:
  # Route API traffic to local Express server
  - hostname: api.campus.yourdomain.edu
    service: http://localhost:3001
  # Route Frontend traffic to local web server
  - hostname: campus.yourdomain.edu
    service: http://localhost:5173
  # Catch-all rule
  - service: http_status:404
```

Route your DNS to the tunnel:
```bash
cloudflared tunnel route dns zerotrust-campus-tunnel api.campus.yourdomain.edu
cloudflared tunnel route dns zerotrust-campus-tunnel campus.yourdomain.edu
```

### Step 3: Configure Cloudflare Access
1. Open the **Cloudflare One / Zero Trust Dashboard** (`https://one.dash.cloudflare.com`).
2. Navigate to **Access** > **Applications** > **Add an Application**.
3. Select **Self-Hosted**.
4. Configure Application Settings:
   - **Application Name:** `ZeroTrust Campus Portal`
   - **Application Domain:** `campus.yourdomain.edu` and `api.campus.yourdomain.edu`
   - **Session Duration:** `15 minutes` (or per your university policy)
5. Configure Access Policies:
   - **Policy Name:** `Campus Community Only`
   - **Action:** `Allow`
   - **Rule Type:** Include
   - **Selector:** `Email Domain` (`yourdomain.edu`) or `Identity Provider` (e.g. Google Workspace, Okta, Azure AD with student/faculty groups).
6. Save the application and go to the **Overview** tab.
7. Copy the **Application Audience (AUD) Tag**.
8. Set the AUD tag in your production environment:
   ```bash
   CLOUDFLARE_ACCESS_TEAM_DOMAIN="your-university"
   CLOUDFLARE_ACCESS_AUD="<COPIED-AUDIENCE-TAG>"
   NODE_ENV="production"
   ALLOW_LOCAL_AUTH="false"
   ```

### Step 4: Run the Tunnel Service
```bash
sudo cloudflared service install
sudo systemctl start cloudflared
```

---

## 7. Security Hardening & Threat Mitigations

| Threat | Mitigation in ZeroTrust Campus |
| :--- | :--- |
| **Token Forgery / Tampering** | RS256 signature verification against Cloudflare's JWKS certificates. Rejects malformed or untrusted signatures. |
| **Token Replay Across Apps** | Strict `aud` (Audience) claim validation ensuring token was minted specifically for this campus app. |
| **Token Expiration Bypass** | Expiration (`exp`) claim checked on every request. Expired assertions rejected immediately. |
| **Identity Header Spoofing** | Identity is derived **only** from verified cryptographic JWT claims (`email`/`sub`), never from unverified `Cf-Access-Authenticated-User-Email` headers. |
| **Lateral Privilege Escalation** | Campus role is looked up from local SQLite database using verified email; client headers or parameters cannot override server RBAC. |
| **Unprovisioned Account Access** | Users authenticated by Cloudflare Access who lack a valid campus database record are rejected (`401 Unauthorized`). |
| **Public Origin Attacks** | Cloudflare Tunnel keeps origin behind firewall; direct IP probing is impossible. |
| **Sensitive Data Exposure** | Passwords, hashes, raw JWT assertions, and session tokens are stripped from all API responses and audit logs. |
| **Request Flooding / Payload Attacks** | Request body size strictly capped at `100kb`. Security headers (`nosniff`, `DENY`, `no-referrer`) applied globally. |

---

## 8. License

Internal Educational & Demonstrative Project — ZeroTrust Campus Architecture.
