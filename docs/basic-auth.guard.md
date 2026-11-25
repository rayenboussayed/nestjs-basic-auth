## Members

<dl>
<dt><a href="#BasicAuthGuard">BasicAuthGuard</a></dt>
<dd><p>Guards a route with the HTTP Basic authentication scheme (RFC 7617), wrapping
the <a href="https://www.npmjs.com/package/basic-auth"><code>basic-auth</code></a> package (<code>parse</code>).</p>
<p>Credentials are resolved in order (first source that yields credentials wins):</p>
<ol>
<li>the standard <code>Authorization</code> header via <code>parse()</code> — when the header is
present it is authoritative (an empty value falls through, a malformed one
rejects the request);</li>
<li>the custom <code>headerNames</code> headers (<code>x-auth-username</code>/<code>x-auth-password</code> by
default) when both values are non-empty strings;</li>
<li>the request body <code>auth.username</code>/<code>auth.password</code> when <code>body: true</code> is set.</li>
</ol>
<p>On success: sets <code>req.user</code> to the validated credentials.
On failure: sets <code>WWW-Authenticate</code> on the response and throws <code>UnauthorizedException</code>.</p>
</dd>
</dl>

## Functions

<dl>
<dt><a href="#readHeader">readHeader()</a> ⇒ <code>string</code></dt>
<dd><p>Read a header by name: Node normalizes names to lowercase, so try the name as
given and fall back to its lowercase form. Non-string and non-string-array
values count as absent.</p>
</dd>
<dt><a href="#customHeaderCredentials">customHeaderCredentials()</a> ⇒ <code>Credentials</code></dt>
<dd><p>Credentials from the custom headers: returned only when both <code>username</code> and
<code>password</code> are non-empty strings (absent/non-string/empty means &quot;not provided&quot;).</p>
</dd>
<dt><a href="#bodyCredentials">bodyCredentials()</a> ⇒ <code>Credentials</code></dt>
<dd><p>Credentials from a parsed request body: <code>body.auth.username</code> / <code>body.auth.password</code>,
read with own-property checks only (a crafted body with inherited <code>auth</code> is not trusted).</p>
</dd>
<dt><a href="#timingSafeCompare">timingSafeCompare()</a> ⇒ <code>boolean</code></dt>
<dd><p>Compare two strings in constant time. Both buffers are padded to the same
length so <code>timingSafeEqual</code> runs unconditionally — it neither throws nor
short-circuits, so timing reveals neither the lengths nor the value.</p>
</dd>
</dl>

<a name="BasicAuthGuard"></a>

## BasicAuthGuard
Guards a route with the HTTP Basic authentication scheme (RFC 7617), wrapping
the [`basic-auth`](https://www.npmjs.com/package/basic-auth) package (`parse`).

Credentials are resolved in order (first source that yields credentials wins):

1. the standard `Authorization` header via `parse()` — when the header is
   present it is authoritative (an empty value falls through, a malformed one
   rejects the request);
2. the custom `headerNames` headers (`x-auth-username`/`x-auth-password` by
   default) when both values are non-empty strings;
3. the request body `auth.username`/`auth.password` when `body: true` is set.

On success: sets `req.user` to the validated credentials.
On failure: sets `WWW-Authenticate` on the response and throws `UnauthorizedException`.

**Kind**: global variable  
src: src/basic-auth.guard.ts:139  
dist: dist/basic-auth.guard.js:89

* [BasicAuthGuard](#BasicAuthGuard)
    * [.expectedPairs](#BasicAuthGuard+expectedPairs) ⇒ <code>{ name: Buffer; pass: Buffer; }[]</code>
    * [.canActivate(context)](#BasicAuthGuard+canActivate) ⇒ <code>boolean</code>
    * [.resolveCredentials()](#BasicAuthGuard+resolveCredentials) ⇒ <code>Credentials</code>
    * [.fallbackSources()](#BasicAuthGuard+fallbackSources) ⇒ <code>CredentialSource[]</code>
    * [.reject()](#BasicAuthGuard+reject) ⇒ <code>never</code>
    * [.challenge()](#BasicAuthGuard+challenge) ⇒ <code>string</code>
    * [.isValidCredentials()](#BasicAuthGuard+isValidCredentials) ⇒ <code>boolean</code>

<a name="BasicAuthGuard+expectedPairs"></a>

### basicAuthGuard.expectedPairs ⇒ <code>{ name: Buffer; pass: Buffer; }[]</code>
Expected credentials as buffers, cached on first use (options/environment are fixed after construction).

**Kind**: instance property of [<code>BasicAuthGuard</code>](#BasicAuthGuard)  
src: src/basic-auth.guard.ts:224  
dist: dist/basic-auth.guard.js:169
<a name="BasicAuthGuard+canActivate"></a>

### basicAuthGuard.canActivate(context) ⇒ <code>boolean</code>
NestJS guard entry point: resolves and validates credentials from the request.

**Kind**: instance method of [<code>BasicAuthGuard</code>](#BasicAuthGuard)  
**Returns**: <code>boolean</code> - `true` when authenticated; throws `UnauthorizedException` (401) with a
  `WWW-Authenticate` challenge otherwise.  

| Param | Type | Description |
| --- | --- | --- |
| context | <code>ExecutionContext</code> | The NestJS execution context (HTTP request/response). |

src: src/basic-auth.guard.ts:157  
dist: dist/basic-auth.guard.js:108
<a name="BasicAuthGuard+resolveCredentials"></a>

### basicAuthGuard.resolveCredentials() ⇒ <code>Credentials</code>
Resolve credentials in order:

1. the standard `Authorization` header — when present it is authoritative
   (a present-but-unparseable value rejects the request, no fallback);
2. the custom `headerNames` headers, when both values are non-empty strings;
3. the request body pair, when `body: true` is set.

**Kind**: instance method of [<code>BasicAuthGuard</code>](#BasicAuthGuard)  
src: src/basic-auth.guard.ts:176  
dist: dist/basic-auth.guard.js:126
<a name="BasicAuthGuard+fallbackSources"></a>

### basicAuthGuard.fallbackSources() ⇒ <code>CredentialSource[]</code>
Fallback credential sources, consulted in order after the standard header.

**Kind**: instance method of [<code>BasicAuthGuard</code>](#BasicAuthGuard)  
src: src/basic-auth.guard.ts:188  
dist: dist/basic-auth.guard.js:138
<a name="BasicAuthGuard+reject"></a>

### basicAuthGuard.reject() ⇒ <code>never</code>
Sets the `WWW-Authenticate: Basic realm="..."` challenge (realm escaped per RFC 7617) and throws a 401.

**Kind**: instance method of [<code>BasicAuthGuard</code>](#BasicAuthGuard)  
src: src/basic-auth.guard.ts:196  
dist: dist/basic-auth.guard.js:145
<a name="BasicAuthGuard+challenge"></a>

### basicAuthGuard.challenge() ⇒ <code>string</code>
The `WWW-Authenticate` challenge string with the realm escaped per RFC 7617.

**Kind**: instance method of [<code>BasicAuthGuard</code>](#BasicAuthGuard)  
src: src/basic-auth.guard.ts:207  
dist: dist/basic-auth.guard.js:156
<a name="BasicAuthGuard+isValidCredentials"></a>

### basicAuthGuard.isValidCredentials() ⇒ <code>boolean</code>
Constant-time check of the provided credentials against every expected pair.
Both comparisons always run and are length-padded, so a mismatch in username
does not skip the password check (no timing oracle on the username or on the
expected password length).

**Kind**: instance method of [<code>BasicAuthGuard</code>](#BasicAuthGuard)  
src: src/basic-auth.guard.ts:246  
dist: dist/basic-auth.guard.js:188
<a name="readHeader"></a>

## readHeader() ⇒ <code>string</code>
Read a header by name: Node normalizes names to lowercase, so try the name as
given and fall back to its lowercase form. Non-string and non-string-array
values count as absent.

**Kind**: global function  
src: src/basic-auth.guard.ts:78  
dist: dist/basic-auth.guard.js:30
<a name="customHeaderCredentials"></a>

## customHeaderCredentials() ⇒ <code>Credentials</code>
Credentials from the custom headers: returned only when both `username` and
`password` are non-empty strings (absent/non-string/empty means "not provided").

**Kind**: global function  
src: src/basic-auth.guard.ts:89  
dist: dist/basic-auth.guard.js:41
<a name="bodyCredentials"></a>

## bodyCredentials() ⇒ <code>Credentials</code>
Credentials from a parsed request body: `body.auth.username` / `body.auth.password`,
read with own-property checks only (a crafted body with inherited `auth` is not trusted).

**Kind**: global function  
src: src/basic-auth.guard.ts:99  
dist: dist/basic-auth.guard.js:50
<a name="timingSafeCompare"></a>

## timingSafeCompare() ⇒ <code>boolean</code>
Compare two strings in constant time. Both buffers are padded to the same
length so `timingSafeEqual` runs unconditionally — it neither throws nor
short-circuits, so timing reveals neither the lengths nor the value.

**Kind**: global function  
src: src/basic-auth.guard.ts:115  
dist: dist/basic-auth.guard.js:67
