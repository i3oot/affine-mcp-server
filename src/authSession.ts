import {
  loginWithPassword,
  loginWithPasswordSession,
  NativeAuthUnavailableError,
  refreshPasswordSession,
  type NativeAuthSession,
} from "./auth.js";

export type AuthSnapshot =
  | { kind: "none" }
  | { kind: "bearer"; token: string }
  | { kind: "cookie"; cookie: string };

export type LoginMode = "async" | "sync";

type LoginFunction = typeof loginWithPassword;
type NativeLoginFunction = typeof loginWithPasswordSession;
type NativeRefreshFunction = typeof refreshPasswordSession;

type AuthSessionOptions = {
  baseUrl: string;
  bearer?: string;
  cookie?: string;
  email?: string;
  password?: string;
  /** Extra headers (e.g. from AFFINE_HEADERS_JSON) forwarded to email/password sign-in. */
  headers?: Record<string, string>;
  login?: LoginFunction;
  nativeLogin?: NativeLoginFunction;
  nativeRefresh?: NativeRefreshFunction;
};

const ACCESS_TOKEN_REFRESH_SKEW_MS = 60_000;

export function parseLoginMode(raw: string | undefined): LoginMode {
  if (raw === undefined || raw.trim() === "") return "async";
  const normalized = raw.trim().toLowerCase();
  if (normalized === "async" || normalized === "sync") return normalized;
  throw new Error(`AFFINE_LOGIN_AT_START must be "async" or "sync". Received: ${raw}`);
}

/** Process-scoped authentication state shared by every MCP transport session. */
export class AuthSession {
  private readonly baseUrl: string;
  private readonly login: LoginFunction;
  private readonly nativeLogin: NativeLoginFunction;
  private readonly nativeRefresh: NativeRefreshFunction;
  private readonly useNativeLogin: boolean;
  private readonly headers?: Record<string, string>;
  private email?: string;
  private password?: string;
  private immediate: AuthSnapshot;
  private pending?: Promise<AuthSnapshot>;
  private nativeSession?: NativeAuthSession;

  constructor(options: AuthSessionOptions) {
    const hasImmediateAuth = Boolean(options.bearer || options.cookie);
    if (!hasImmediateAuth && Boolean(options.email) !== Boolean(options.password)) {
      throw new Error("AFFINE_EMAIL and AFFINE_PASSWORD must be configured together.");
    }

    this.baseUrl = options.baseUrl;
    this.login = options.login || loginWithPassword;
    this.nativeLogin = options.nativeLogin || loginWithPasswordSession;
    this.nativeRefresh = options.nativeRefresh || refreshPasswordSession;
    this.useNativeLogin = Boolean(options.nativeLogin || !options.login);
    this.headers = options.headers;
    this.email = hasImmediateAuth ? undefined : options.email;
    this.password = hasImmediateAuth ? undefined : options.password;

    if (options.bearer) {
      this.immediate = { kind: "bearer", token: options.bearer };
    } else if (options.cookie) {
      this.immediate = { kind: "cookie", cookie: options.cookie };
    } else {
      this.immediate = { kind: "none" };
    }
  }

  get hasConfiguredAuth(): boolean {
    return this.immediate.kind !== "none" || this.requiresLogin;
  }

  get requiresLogin(): boolean {
    return this.immediate.kind === "none" && Boolean(this.pending || (this.email && this.password));
  }

  get source(): "bearer" | "cookie" | "email-password" | "none" {
    if (this.immediate.kind === "bearer") return "bearer";
    if (this.immediate.kind === "cookie") return "cookie";
    return this.requiresLogin ? "email-password" : "none";
  }

  /** Begin authentication without delaying transport startup. */
  start(): void {
    void this.ready().catch(() => {
      // The shared promise remains rejected so every backend consumer receives the failure.
    });
  }

  private nativeSnapshot(): AuthSnapshot | undefined {
    if (!this.nativeSession) return undefined;
    return { kind: "bearer", token: this.nativeSession.accessToken };
  }

  private nativeSessionNeedsRefresh(): boolean {
    return Boolean(
      this.nativeSession
      && this.nativeSession.accessTokenExpiresAt - Date.now() <= ACCESS_TOKEN_REFRESH_SKEW_MS,
    );
  }

  /** Resolve one shared login/refresh attempt. Rejections are never downgraded to anonymous access. */
  ready(): Promise<AuthSnapshot> {
    if (this.pending) return this.pending;
    if (this.nativeSession && !this.nativeSessionNeedsRefresh()) {
      return Promise.resolve(this.nativeSnapshot()!);
    }
    if (this.nativeSession) {
      console.error("[affine-mcp] Refreshing AFFiNE auth session...");
      this.pending = this.nativeRefresh(this.baseUrl, this.nativeSession, this.headers)
        .then((session) => {
          this.nativeSession = session;
          this.immediate = this.nativeSnapshot()!;
          console.error("[affine-mcp] AFFiNE auth session refreshed");
          return this.immediate;
        })
        .catch((error) => {
          const message = error instanceof Error ? error.message : String(error);
          console.error(`[affine-mcp] AFFiNE auth-session refresh failed: ${message}`);
          throw new Error(`AFFiNE auth-session refresh failed: ${message}`, { cause: error });
        });
      this.pending.then(() => {
          this.pending = undefined;
        }, () => {
          // Preserve the rejected promise so concurrent and later consumers see one shared failure.
        });
      void this.pending.catch(() => {});
      return this.pending;
    }
    if (this.immediate.kind !== "none" || !this.requiresLogin) {
      return Promise.resolve(this.immediate);
    }

    const email = this.email!;
    const password = this.password!;
    console.error("[affine-mcp] Authenticating with an AFFiNE auth session...");

    const nativeAttempt = this.useNativeLogin
      ? Promise.resolve().then(() => this.nativeLogin(this.baseUrl, email, password, this.headers))
      : Promise.reject(new NativeAuthUnavailableError("native login disabled by custom cookie login"));

    this.pending = nativeAttempt
      .then((session) => {
        this.nativeSession = session;
        this.immediate = this.nativeSnapshot()!;
        console.error("[affine-mcp] Refreshable AFFiNE auth session established");
        return this.immediate;
      })
      .catch(async (nativeError) => {
        if (!(nativeError instanceof NativeAuthUnavailableError)) {
          const message = nativeError instanceof Error ? nativeError.message : String(nativeError);
          console.error(`[affine-mcp] Native authentication failed: ${message}`);
          throw new Error(`Email/password authentication failed: ${message}`, {
            cause: nativeError,
          });
        }
        if (nativeError.cookieHeader) {
          this.immediate = { kind: "cookie", cookie: nativeError.cookieHeader };
          console.error("[affine-mcp] AFFiNE returned a compatible session cookie");
          return this.immediate;
        }
        const nativeMessage = nativeError instanceof Error ? nativeError.message : String(nativeError);
        console.error(
          `[affine-mcp] Native auth session unavailable (${nativeMessage}); trying cookie compatibility mode...`,
        );
        try {
          const { cookieHeader } = await this.login(
            this.baseUrl,
            email,
            password,
            this.headers,
          );
          this.immediate = { kind: "cookie", cookie: cookieHeader };
          console.error("[affine-mcp] Email/password cookie authentication succeeded");
          return this.immediate;
        } catch (cookieError) {
          const message = cookieError instanceof Error ? cookieError.message : String(cookieError);
          console.error(`[affine-mcp] Email/password authentication failed: ${message}`);
          throw new Error(`Email/password authentication failed: ${message}`, {
            cause: cookieError,
          });
        }
      });
    this.pending.then(() => {
        this.pending = undefined;
      }, () => {
        // Preserve the rejected promise so every backend consumer receives the same failure.
      });

    // Attach a handler immediately so an asynchronously started login cannot emit an unhandled rejection.
    void this.pending.catch(() => {});
    return this.pending;
  }
}
