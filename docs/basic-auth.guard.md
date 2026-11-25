## Members

<dl>
<dt><a href="#BasicAuthGuard">BasicAuthGuard</a></dt>
<dd><p>HTTP Basic authentication guard (RFC 7617).</p>
<p>Credentials are taken from the first source that has them:</p>
<ol>
<li>the <code>Authorization</code> header, which is authoritative when non-empty
(a malformed value is rejected, with no fallback);</li>
<li>the <code>headerNames</code> header pair;</li>
<li><code>body.auth</code>, when <code>body: true</code>.</li>
</ol>
<p>Routes marked <code>@SkipBasicAuth()</code> pass without checks. On success <code>req.user</code> is
set to the credentials; on failure a <code>WWW-Authenticate</code> challenge is set and a
401 is thrown.</p>
<p>Works as <code>new BasicAuthGuard(options)</code>, <code>@UseGuards(BasicAuthGuard)</code>, or via
<code>BasicAuthModule.forRoot(options)</code>.</p>
</dd>
</dl>

## Constants

<dl>
<dt><a href="#BASIC_AUTH_OPTIONS">BASIC_AUTH_OPTIONS</a></dt>
<dd><p>Injection token for <a href="BasicAuthOptions">BasicAuthOptions</a> (provided by <code>BasicAuthModule.forRoot()</code>).</p>
</dd>
</dl>

## Functions

<dl>
<dt><a href="#digest">digest()</a> ⇒ <code>NonSharedBuffer</code></dt>
<dd><p>SHA-256 digest: fixed length, so <code>timingSafeEqual</code> never throws and lengths never leak.</p>
</dd>
<dt><a href="#readHeader">readHeader()</a></dt>
<dd><p>Node lowercases header names; only <code>set-cookie</code> is ever an array.</p>
</dd>
</dl>

<a name="BasicAuthGuard"></a>

## BasicAuthGuard
HTTP Basic authentication guard (RFC 7617).

Credentials are taken from the first source that has them:
1. the `Authorization` header, which is authoritative when non-empty
   (a malformed value is rejected, with no fallback);
2. the `headerNames` header pair;
3. `body.auth`, when `body: true`.

Routes marked `@SkipBasicAuth()` pass without checks. On success `req.user` is
set to the credentials; on failure a `WWW-Authenticate` challenge is set and a
401 is thrown.

Works as `new BasicAuthGuard(options)`, `@UseGuards(BasicAuthGuard)`, or via
`BasicAuthModule.forRoot(options)`.

**Kind**: global variable  
src: src/basic-auth.guard.ts:79  
dist: dist/basic-auth.guard.js:50
<a name="BasicAuthGuard+matches"></a>

### basicAuthGuard.matches() ⇒ <code>boolean</code>
Constant-time check against every expected pair; both comparisons always run.

**Kind**: instance method of [<code>BasicAuthGuard</code>](#BasicAuthGuard)  
src: src/basic-auth.guard.ts:156  
dist: dist/basic-auth.guard.js:109
<a name="BASIC_AUTH_OPTIONS"></a>

## BASIC\_AUTH\_OPTIONS
Injection token for [BasicAuthOptions](BasicAuthOptions) (provided by `BasicAuthModule.forRoot()`).

**Kind**: global constant  
src: src/basic-auth.guard.ts:21  
dist: dist/basic-auth.guard.js:21
<a name="digest"></a>

## digest() ⇒ <code>NonSharedBuffer</code>
SHA-256 digest: fixed length, so `timingSafeEqual` never throws and lengths never leak.

**Kind**: global function  
src: src/basic-auth.guard.ts:54  
dist: dist/basic-auth.guard.js:28
<a name="readHeader"></a>

## readHeader()
Node lowercases header names; only `set-cookie` is ever an array.

**Kind**: global function  
src: src/basic-auth.guard.ts:57  
dist: dist/basic-auth.guard.js:30
