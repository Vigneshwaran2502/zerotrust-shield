/**
 * ZeroTrust Campus — Cloudflare Worker
 *
 * Responsibilities:
 *  1. Direct D1 Edge API handling for all /api/* requests.
 *  2. Serverless authentication, Cloudflare Access JWT validation, and RBAC.
 *  3. Serve static React SPA assets from the bound ASSETS binding.
 */
import { handleApiRequest } from './server/routes.js';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // ── Direct D1 API Handler ───────────────────────────────────────────────
    if (url.pathname.startsWith('/api/')) {
      return await handleApiRequest(request, env);
    }

    // ── Static assets (React SPA) ───────────────────────────────────────────
    return env.ASSETS.fetch(request);
  },
};
