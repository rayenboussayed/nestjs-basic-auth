import { Buffer } from "node:buffer";
import { timingSafeEqual } from "node:crypto";
import type { IncomingHttpHeaders, IncomingMessage } from "node:http";
import { Injectable, UnauthorizedException } from "@nestjs/common";
import type { CanActivate, ExecutionContext } from "@nestjs/common";
import { z } from "zod";
import { parse } from "basic-auth";
import type { Credentials } from "basic-auth";
import { isEmptyString } from "jutilities/is";
import { toArray } from "jutilities/to";
import { environment } from "./environment.js";

/**
 * Options for {@link BasicAuthGuard}.
 */
export interface BasicAuthOptions {
  /**
   * Realm included in the `WWW-Authenticate: Basic realm="..."` challenge.
   * Defaults to the `AUTH_REALM` environment variable, then `"Secure Area"`.
   */
  realm?: string;
  /**
   * Name of the request header carrying the `Authorization: Basic ...` credentials.
   * Defaults to `"authorization"` (Node headers are case-insensitive).
   */
  header?: string;
  /**
   * Credentials accepted by this guard: one `Credentials` pair or a list of pairs.
   * Defaults to the `AUTH_USERNAME`/`AUTH_PASSWORD` environment pair when omitted.
   */
  credentials?: Credentials | Credentials[];
  /**
   * Header names for the fallback credentials: both `username` and `password`
   * must be present as string values.
   * Defaults to `{ username: "x-auth-username", password: "x-auth-password" }`.
   */
  headerNames?: { username: string; password: string };
  /**
   * Accept credentials from `body.auth.username` / `body.auth.password` when the
   * header yields no credentials. Defaults to false.
   */
  body?: boolean;
}

interface AuthenticatedRequest extends IncomingMessage {
  body?: unknown;
  user?: Credentials;
}

interface GuardResponse {
  setHeader?: (name: string, value: string) => void;
  header?: (name: string, value: string) => void;
}

/**
 * A credential source: returns the credentials it found, or `undefined` when it has none.
 */
type CredentialSource = (request: AuthenticatedRequest) => Credentials | undefined;

const DEFAULT_REALM = "Secure Area";
const DEFAULT_CUSTOM_HEADER_NAMES = {
  username: "x-auth-username",
  password: "x-auth-password",
};

const CredentialsPairSchema = z.object({ name: z.string(), pass: z.string() });
const CredentialsListSchema = z.union([CredentialsPairSchema, z.array(CredentialsPairSchema)]);

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && !isEmptyString(value);
}

/**
 * Read a header by name: Node normalizes names to lowercase, so try the name as
 * given and fall back to its lowercase form. Non-string and non-string-array
 * values count as absent.
 */
function readHeader(headers: IncomingHttpHeaders, name: string): string | undefined {
  const value = headers[name] ?? headers[name.toLowerCase()];
  if (typeof value === "string") return value;
  const first = Array.isArray(value) ? value[0] : undefined;
  return typeof first === "string" ? first : undefined;
}

/**
 * Credentials from the custom headers: returned only when both `username` and
 * `password` are non-empty strings (absent/non-string/empty means "not provided").
 */
function customHeaderCredentials(headers: IncomingHttpHeaders, names: { username: string; password: string }): Credentials | undefined {
  const username = readHeader(headers, names.username);
  const password = readHeader(headers, names.password);
  return isNonEmptyString(username) && isNonEmptyString(password) ? { name: username, pass: password } : undefined;
}

/**
 * Credentials from a parsed request body: `body.auth.username` / `body.auth.password`,
 * read with own-property checks only (a crafted body with inherited `auth` is not trusted).
 */
function bodyCredentials(body: unknown): Credentials | undefined {
  if (typeof body !== "object" || body === null) return undefined;
  const record = body as Record<string, unknown>;
  const auth = Object.hasOwn(record, "auth") ? record.auth : undefined;
  if (typeof auth !== "object" || auth === null) return undefined;
  const authRecord = auth as Record<string, unknown>;
  const username = Object.hasOwn(authRecord, "username") ? authRecord.username : undefined;
  const password = Object.hasOwn(authRecord, "password") ? authRecord.password : undefined;
  return isNonEmptyString(username) && isNonEmptyString(password) ? { name: username, pass: password } : undefined;
}

/**
 * Compare two strings in constant time. Both buffers are padded to the same
 * length so `timingSafeEqual` runs unconditionally — it neither throws nor
 * short-circuits, so timing reveals neither the lengths nor the value.
 */
function timingSafeCompare(expected: Buffer, provided: Buffer): boolean {
  const length = expected.length > provided.length ? expected.length : provided.length;
  const paddedExpected = expected.length === length ? expected : Buffer.concat([expected, Buffer.alloc(length - expected.length)]);
  const paddedProvided = provided.length === length ? provided : Buffer.concat([provided, Buffer.alloc(length - provided.length)]);
  return timingSafeEqual(paddedExpected, paddedProvided);
}

/**
 * Guards a route with the HTTP Basic authentication scheme (RFC 7617), wrapping
 * the [`basic-auth`](https://www.npmjs.com/package/basic-auth) package (`parse`).
 *
 * Credentials are resolved in order (first source that yields credentials wins):
 *
 * 1. the standard `Authorization` header via `parse()` — when the header is
 *    present it is authoritative (an empty value falls through, a malformed one
 *    rejects the request);
 * 2. the custom `headerNames` headers (`x-auth-username`/`x-auth-password` by
 *    default) when both values are non-empty strings;
 * 3. the request body `auth.username`/`auth.password` when `body: true` is set.
 *
 * On success: sets `req.user` to the validated credentials.
 * On failure: sets `WWW-Authenticate` on the response and throws `UnauthorizedException`.
 */
@Injectable()
export class BasicAuthGuard implements CanActivate {
  private expectedCache?: Array<{ name: Buffer; pass: Buffer }>;

  /**
   * @param options - Guard options; omitted values fall back to the environment/defaults.
   *   Invalid `credentials` entries throw at construction.
   */
  constructor(private readonly options?: BasicAuthOptions) {
    // Fail fast on misconfigured `credentials` (a bad entry used to throw a 500 on the first request).
    if (options?.credentials !== undefined) CredentialsListSchema.parse(options.credentials);
  }

  /**
   * NestJS guard entry point: resolves and validates credentials from the request.
   * @param context - The NestJS execution context (HTTP request/response).
   * @returns `true` when authenticated; throws `UnauthorizedException` (401) with a
   *   `WWW-Authenticate` challenge otherwise.
   */
  canActivate(context: ExecutionContext): boolean {
    const http = context.switchToHttp();
    const request = http.getRequest<AuthenticatedRequest>();
    const credentials = this.resolveCredentials(request);
    if (credentials === undefined || !this.isValidCredentials(credentials)) {
      this.reject(http.getResponse() as GuardResponse);
    }
    request.user = credentials;
    return true;
  }

  /**
   * Resolve credentials in order:
   *
   * 1. the standard `Authorization` header — when present it is authoritative
   *    (a present-but-unparseable value rejects the request, no fallback);
   * 2. the custom `headerNames` headers, when both values are non-empty strings;
   * 3. the request body pair, when `body: true` is set.
   */
  private resolveCredentials(request: AuthenticatedRequest): Credentials | undefined {
    const header = readHeader(request.headers, this.standardHeaderName);
    if (header !== undefined && !isEmptyString(header)) return parse(header);

    for (const source of this.fallbackSources()) {
      const credentials = source(request);
      if (credentials !== undefined) return credentials;
    }
    return undefined;
  }

  /** Fallback credential sources, consulted in order after the standard header. */
  private fallbackSources(): CredentialSource[] {
    return [
      (request) => customHeaderCredentials(request.headers, this.customHeaderNames),
      (request) => (this.options?.body === true ? bodyCredentials(request.body) : undefined),
    ];
  }

  /** Sets the `WWW-Authenticate: Basic realm="..."` challenge (realm escaped per RFC 7617) and throws a 401. */
  private reject(response: GuardResponse): never {
    const challenge = this.challenge();
    if (typeof response.setHeader === "function") {
      response.setHeader("WWW-Authenticate", challenge);
    } else if (typeof response.header === "function") {
      response.header("WWW-Authenticate", challenge);
    }
    throw new UnauthorizedException();
  }

  /** The `WWW-Authenticate` challenge string with the realm escaped per RFC 7617. */
  private challenge(): string {
    return `Basic realm="${this.realm.replace(/["\\]/g, "\\$&")}"`;
  }

  private get standardHeaderName(): string {
    return this.options?.header ?? "authorization";
  }

  private get customHeaderNames(): { username: string; password: string } {
    return this.options?.headerNames ?? DEFAULT_CUSTOM_HEADER_NAMES;
  }

  private get realm(): string {
    return this.options?.realm ?? environment.AUTH_REALM ?? DEFAULT_REALM;
  }

  /** Expected credentials as buffers, cached on first use (options/environment are fixed after construction). */
  private get expectedPairs(): Array<{ name: Buffer; pass: Buffer }> {
    this.expectedCache ??= this.resolveExpectedPairs();
    return this.expectedCache;
  }

  private resolveExpectedPairs(): Array<{ name: Buffer; pass: Buffer }> {
    const configured = this.options?.credentials;
    const pairs = configured !== undefined ? toArray<Credentials>(configured) : this.envPairs();
    return pairs.map((pair) => ({ name: Buffer.from(pair.name, "utf8"), pass: Buffer.from(pair.pass, "utf8") }));
  }

  private envPairs(): Credentials[] {
    const { AUTH_USERNAME, AUTH_PASSWORD } = environment;
    return AUTH_USERNAME && AUTH_PASSWORD ? [{ name: AUTH_USERNAME, pass: AUTH_PASSWORD }] : [];
  }

  /**
   * Constant-time check of the provided credentials against every expected pair.
   * Both comparisons always run and are length-padded, so a mismatch in username
   * does not skip the password check (no timing oracle on the username or on the
   * expected password length).
   */
  private isValidCredentials(provided: Credentials): boolean {
    const providedName = Buffer.from(provided.name, "utf8");
    const providedPass = Buffer.from(provided.pass, "utf8");
    let authenticated = false;
    for (const { name, pass } of this.expectedPairs) {
      if (timingSafeCompare(name, providedName) && timingSafeCompare(pass, providedPass)) {
        authenticated = true;
      }
    }
    return authenticated;
  }
}
