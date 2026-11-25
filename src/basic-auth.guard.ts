import { timingSafeEqual } from "node:crypto";
import type { IncomingHttpHeaders, IncomingMessage } from "node:http";
import {
  Inject,
  Injectable,
  Optional,
  UnauthorizedException,
} from "@nestjs/common";
import type { CanActivate, ExecutionContext } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { parse } from "basic-auth";
import type { Credentials } from "basic-auth";
import { isEmptyString } from "jutilities/is";
import { sha256 } from "jutilities/node/hash";
import { toArray } from "jutilities/to";
import { environment } from "./environment.js";
import { SKIP_BASIC_AUTH_KEY } from "./skip-basic-auth.decorator.js";
import { BasicAuthBodySchema } from "./schema.js";

/** Injection token for {@link BasicAuthOptions} (provided by `BasicAuthModule.forRoot()`). */
export const BASIC_AUTH_OPTIONS = "nestjs-basic-auth:options";

export interface BasicAuthOptions {
  /** Realm in the `WWW-Authenticate` challenge. Defaults to `AUTH_REALM`, then `"Secure Area"`. */
  realm?: string;
  /** Header carrying `Basic ...` credentials. Defaults to `"authorization"`. */
  header?: string;
  /** Accepted credentials. Defaults to the `AUTH_NAME`/`AUTH_PASS` pair. */
  credentials?: Credentials | Credentials[];
  /** Fallback headers for the pair. Defaults to `x-auth-name` / `x-auth-pass`. */
  headerNames?: { name: string; pass: string };
  /** Also accept `body.auth.name` / `body.auth.pass`. Defaults to `false`. */
  body?: boolean;
}

interface AuthenticatedRequest extends IncomingMessage {
  body?: unknown;
  user?: Credentials;
}

/** Express exposes `setHeader`, Fastify's reply exposes `header`. */
interface GuardResponse {
  setHeader?: (name: string, value: string) => void;
  header?: (name: string, value: string) => void;
}

const DEFAULT_REALM = "Secure Area";
const DEFAULT_HEADER_NAMES = {
  name: "x-auth-name",
  pass: "x-auth-pass",
};

/** SHA-256 digest: fixed length, so `timingSafeEqual` never throws and lengths never leak. */
const digest = (value: string) => sha256.buffer({ value });

/** Node lowercases header names; only `set-cookie` is ever an array. */
function readHeader(headers: IncomingHttpHeaders, name: string) {
  const value = headers[name.toLowerCase()];
  return typeof value === "string" ? value : value?.[0];
}

/**
 * HTTP Basic authentication guard (RFC 7617).
 *
 * Credentials are taken from the first source that has them:
 * 1. the `Authorization` header, which is authoritative when non-empty
 *    (a malformed value is rejected, with no fallback);
 * 2. the `headerNames` header pair;
 * 3. `body.auth`, when `body: true`.
 *
 * Routes marked `@SkipBasicAuth()` pass without checks. On success `req.user` is
 * set to the credentials; on failure a `WWW-Authenticate` challenge is set and a
 * 401 is thrown.
 *
 * Works as `new BasicAuthGuard(options)`, `@UseGuards(BasicAuthGuard)`, or via
 * `BasicAuthModule.forRoot(options)`.
 */
@Injectable()
export class BasicAuthGuard implements CanActivate {
  private readonly expected: ReadonlyArray<{ name: Buffer; pass: Buffer }>;
  private readonly challenge: string;

  /** Hashes the configured credentials once; `AUTH_*` pairs are appended when both are set. */
  constructor(
    @Optional()
    @Inject(BASIC_AUTH_OPTIONS)
    private readonly options: BasicAuthOptions = {},
    @Optional() private readonly reflector: Reflector = new Reflector(),
  ) {
    const credentials = options.credentials ? toArray(options.credentials) : [];
    if (environment.AUTH_NAME && environment.AUTH_PASS) {
      credentials.push({
        name: environment.AUTH_NAME,
        pass: environment.AUTH_PASS,
      });
    }

    this.expected = credentials.map(({ name, pass }) => ({
      name: digest(name),
      pass: digest(pass),
    }));
    const realm = options.realm ?? environment.AUTH_REALM ?? DEFAULT_REALM;
    this.challenge = `Basic realm="${realm.replace(/["\\]/g, "\\$&")}"`;
  }

  canActivate(context: ExecutionContext) {
    if (this.isPublic(context)) return true;

    const http = context.switchToHttp();
    const request = http.getRequest<AuthenticatedRequest>();
    const credentials = this.resolveCredentials(request);
    if (!credentials || !this.matches(credentials)) {
      this.reject(http.getResponse<GuardResponse>());
    }
    request.user = credentials;
    return true;
  }

  private isPublic(context: ExecutionContext) {
    const handler = typeof context.getHandler === "function" ? context.getHandler() : undefined;
    const controller = typeof context.getClass === "function" ? context.getClass() : undefined;
    const targets = [handler, controller].filter(
      (target): target is NonNullable<typeof target> => target !== undefined,
    );
    return this.reflector.getAllAndOverride<boolean>(SKIP_BASIC_AUTH_KEY, targets) === true;
  }

  private resolveCredentials({ headers, body }: AuthenticatedRequest) {
    const authorization = readHeader(
      headers,
      this.options.header ?? "authorization",
    );
    if (authorization !== undefined && !isEmptyString(authorization))
      return parse(authorization);

    const names = this.options.headerNames ?? DEFAULT_HEADER_NAMES;
    const headerName = readHeader(headers, names.name);
    const headerPass = readHeader(headers, names.pass);
    if (headerName && headerPass)
      return {
        name: headerName,
        pass: headerPass,
      } satisfies Credentials;

    if (this.options.body !== true) return undefined;
    const safeParsedBody = BasicAuthBodySchema.safeParse(body);
    return safeParsedBody.data ? safeParsedBody.data.auth : undefined;
  }

  /** Constant-time check against every expected pair; both comparisons always run. */
  private matches(provided: Credentials) {
    const name = digest(provided.name);
    const pass = digest(provided.pass);
    let matched = false;
    for (const expected of this.expected) {
      const nameMatches = timingSafeEqual(expected.name, name);
      const passMatches = timingSafeEqual(expected.pass, pass);
      if (nameMatches && passMatches) matched = true;
    }
    return matched;
  }

  private reject(response: GuardResponse): never {
    response.setHeader?.("WWW-Authenticate", this.challenge);
    response.header?.("WWW-Authenticate", this.challenge);
    throw new UnauthorizedException();
  }
}
