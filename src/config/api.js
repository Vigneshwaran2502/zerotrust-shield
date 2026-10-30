/**
 * ZeroTrust Shield — Centralized Frontend API Configuration
 *
 * In production (workers.dev), the Cloudflare Worker proxies /api/* to the backend.
 * So the base URL must be empty (same-origin relative calls like `/api/me`).
 *
 * In local development:
 *   - If VITE_API_BASE_URL is set, use it.
 *   - Otherwise fall back to http://localhost:3001.
 *
 * The MODE variable is injected by Vite at build time.
 */

const isProduction = import.meta.env.MODE === 'production';
const rawBaseUrl = import.meta.env.VITE_API_BASE_URL;

export const API_BASE_URL = isProduction
  ? ''  // Same-origin: Cloudflare Worker proxies /api/* to the backend
  : (typeof rawBaseUrl === 'string' && rawBaseUrl.trim() !== '')
    ? rawBaseUrl.trim().replace(/\/+$/, '')
    : 'http://localhost:3001';

/**
 * Builds a complete URL for a given backend API path.
 *
 * @param {string} endpoint - The relative endpoint path (e.g. '/api/me' or 'api/login')
 * @returns {string} Fully resolved API URL
 */
export function apiUrl(endpoint) {
  const cleanEndpoint = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
  return `${API_BASE_URL}${cleanEndpoint}`;
}

export default {
  API_BASE_URL,
  apiUrl
};
