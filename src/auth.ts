import { fetch } from "undici";
import { randomUUID } from "node:crypto";

import { AFFINE_CLIENT_VERSION } from "./config.js";

const AUTH_FETCH_TIMEOUT_MS = 30_000;

function extractCookiePairs(setCookies: string[]): string {
  const pairs: string[] = [];
  for (const sc of setCookies) {
    const first = sc.split(";")[0];
    if (first) pairs.push(first.trim());
  }
  return pairs.join("; ");
}

/** Reject cookie values containing CR/LF to prevent header injection. */
function assertNoCRLF(value: string, label: string): void {
  if (/[\r\n]/.test(value)) {
    throw new Error(`${label} contains illegal CR/LF characters`);
  }
}

/**
 * Drop authentication headers a sign-in must never carry — it establishes the
 * session cookie itself, so any inherited `Authorization`/`Cookie` is stale.
 */
function sanitizeSignInHeaders(headers?: Record<string, string>): Record<string, string> {
  if (!headers) return {};
  return Object.fromEntries(
    Object.entries(headers).filter(([name]) => !/^(authorization|cookie)$/i.test(name)),
  );
}

/** Case-insensitive presence check — HTTP header names are case-insensitive. */
function hasHeader(headers: Record<string, string>, name: string): boolean {
  const lower = name.toLowerCase();
  return Object.keys(headers).some((key) => key.toLowerCase() === lower);
}

export type NativeAuthSession = {
  accessToken: string;
  refreshToken: string;
  accessTokenExpiresAt: number;
  refreshExpiresAt?: string;
  installationId: string;
};

/** Signals that the server predates refreshable native sessions and may use cookie auth instead. */
export class NativeAuthUnavailableError extends Error {
  readonly cookieHeader?: string;

  constructor(message: string, cookieHeader?: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "NativeAuthUnavailableError";
    this.cookieHeader = cookieHeader;
  }
}

function nativeAuthHeaders(configuredHeaders?: Record<string, string>): Record<string, string> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "x-affine-client-kind": "native",
    Origin: "https://localhost",
    ...sanitizeSignInHeaders(configuredHeaders),
  };
  if (!hasHeader(headers, "x-affine-version")) {
    headers["x-affine-version"] = AFFINE_CLIENT_VERSION;
  }
  return headers;
}

async function postAuthJson(
  baseUrl: string,
  path: string,
  body: Record<string, unknown>,
  configuredHeaders?: Record<string, string>,
): Promise<{ json: any; cookieHeader?: string }> {
  const url = `${baseUrl.replace(/\/$/, "")}${path}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), AUTH_FETCH_TIMEOUT_MS);
  let response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: nativeAuthHeaders(configuredHeaders),
      body: JSON.stringify(body),
      signal: controller.signal,
    });
  } catch (err: any) {
    if (err.name === "AbortError") {
      throw new Error(`Authentication request timed out after ${AUTH_FETCH_TIMEOUT_MS / 1000}s`);
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }

  const raw = await response.text();
  let json: any = {};
  if (raw) {
    try {
      json = JSON.parse(raw);
    } catch {
      json = {};
    }
  }
  if (!response.ok) {
    const sanitized = raw.replace(/<[^>]*>/g, "").replace(/\s+/g, " ").trim();
    const truncated = sanitized.length > 200 ? sanitized.slice(0, 200) + "..." : sanitized;
    throw new Error(`Authentication failed: ${response.status} ${truncated}`);
  }
  const anyHeaders = response.headers as any;
  let setCookies: string[] = [];
  if (typeof anyHeaders.getSetCookie === "function") {
    setCookies = anyHeaders.getSetCookie();
  } else {
    const setCookie = response.headers.get("set-cookie");
    if (setCookie) setCookies = [setCookie];
  }
  const cookieHeader = setCookies.length ? extractCookiePairs(setCookies) : undefined;
  if (cookieHeader) assertNoCRLF(cookieHeader, "Cookie header from sign-in");
  return { json, cookieHeader };
}

function parseNativeSession(
  json: any,
  installationId: string,
): NativeAuthSession {
  if (
    typeof json?.accessToken !== "string"
    || typeof json?.refreshToken !== "string"
    || typeof json?.expiresIn !== "number"
  ) {
    throw new Error("AFFiNE returned an invalid native auth-session response");
  }
  return {
    accessToken: json.accessToken,
    refreshToken: json.refreshToken,
    accessTokenExpiresAt: Date.now() + Math.max(0, json.expiresIn) * 1000,
    refreshExpiresAt: typeof json.refreshExpiresAt === "string" ? json.refreshExpiresAt : undefined,
    installationId,
  };
}

/**
 * Sign in as a native client and exchange the one-time code for a refreshable
 * AFFiNE 0.27+ auth session.
 */
export async function loginWithPasswordSession(
  baseUrl: string,
  email: string,
  password: string,
  configuredHeaders?: Record<string, string>,
  installationId = randomUUID(),
): Promise<NativeAuthSession> {
  const signInResponse = await postAuthJson(
    baseUrl,
    "/api/auth/sign-in",
    { email, password },
    configuredHeaders,
  );
  const signIn = signInResponse.json;
  if (typeof signIn?.exchangeCode !== "string" || !signIn.exchangeCode) {
    throw new NativeAuthUnavailableError(
      "AFFiNE sign-in did not return a native session exchange code",
      signInResponse.cookieHeader,
    );
  }
  const exchanged = await postAuthJson(
    baseUrl,
    "/api/auth/session/exchange",
    {
      code: signIn.exchangeCode,
      installationId,
      platform: "electron",
      deviceName: "AFFiNE MCP",
    },
    configuredHeaders,
  );
  return parseNativeSession(exchanged.json, installationId);
}

/** Rotate an AFFiNE 0.27+ refresh token and return the replacement token pair. */
export async function refreshPasswordSession(
  baseUrl: string,
  session: NativeAuthSession,
  configuredHeaders?: Record<string, string>,
): Promise<NativeAuthSession> {
  const response = await postAuthJson(
    baseUrl,
    "/api/auth/session/refresh",
    { refreshToken: session.refreshToken },
    configuredHeaders,
  );
  return parseNativeSession(response.json, session.installationId);
}

/**
 * Exchange email/password for a session cookie.
 *
 * `configuredHeaders` (typically `config.headers` from `AFFINE_HEADERS_JSON`)
 * is merged after the defaults so an explicit `x-affine-version` override wins,
 * matching how the GraphQL/REST paths honor the same override.
 */
export async function loginWithPassword(
  baseUrl: string,
  email: string,
  password: string,
  configuredHeaders?: Record<string, string>,
): Promise<{ cookieHeader: string }> {
  const url = `${baseUrl.replace(/\/$/, "")}/api/auth/sign-in`;
  // Configured headers first so an explicit override wins; only supply the
  // default version when the caller did not set one in any casing, so Fetch
  // can't coalesce two `x-affine-version` casings into one comma-joined value.
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...sanitizeSignInHeaders(configuredHeaders),
  };
  if (!hasHeader(headers, "x-affine-version")) {
    headers["x-affine-version"] = AFFINE_CLIENT_VERSION;
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), AUTH_FETCH_TIMEOUT_MS);
  let res;
  try {
    res = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify({ email, password }),
      signal: controller.signal,
    });
  } catch (err: any) {
    if (err.name === "AbortError") throw new Error(`Sign-in request timed out after ${AUTH_FETCH_TIMEOUT_MS / 1000}s`);
    throw err;
  } finally {
    clearTimeout(timer);
  }
  if (!res.ok) {
    const raw = await res.text().catch(() => "");
    const sanitized = raw.replace(/<[^>]*>/g, "").replace(/\s+/g, " ").trim();
    const truncated = sanitized.length > 200 ? sanitized.slice(0, 200) + "..." : sanitized;
    throw new Error(`Sign-in failed: ${res.status} ${truncated}`);
  }
  const anyHeaders = res.headers as any;
  let setCookies: string[] = [];
  if (typeof anyHeaders.getSetCookie === "function") {
    setCookies = anyHeaders.getSetCookie();
  } else {
    const sc = res.headers.get("set-cookie");
    if (sc) setCookies = [sc];
  }
  if (!setCookies.length) {
    throw new Error("Sign-in succeeded but no Set-Cookie received");
  }
  const cookieHeader = extractCookiePairs(setCookies);
  assertNoCRLF(cookieHeader, "Cookie header from sign-in");
  return { cookieHeader };
}

