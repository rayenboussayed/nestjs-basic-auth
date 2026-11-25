## Constants

<dl>
<dt><a href="#SKIP_BASIC_AUTH_KEY">SKIP_BASIC_AUTH_KEY</a></dt>
<dd><p>Metadata key used to mark a route or controller as public.
Set by <a href="#SkipBasicAuth">SkipBasicAuth</a> and read by <code>BasicAuthGuard</code>.</p>
</dd>
<dt><a href="#SkipBasicAuth">SkipBasicAuth</a> ⇒ <code>import(&quot;@nestjs/common&quot;).CustomDecorator&lt;string&gt;</code></dt>
<dd><p>Marks a route handler or controller as public: <code>BasicAuthGuard</code> skips all
Basic auth checks for it, so no credentials are required and <code>req.user</code> is
left untouched.</p>
<p>Works with global guards (<code>app.useGlobalGuards(new BasicAuthGuard())</code>),
per-route guards (<code>@UseGuards(...)</code>), and guards provided through
<code>BasicAuthModule.forRoot()</code> — the decorators only need Nest&#39;s metadata, not
dependency injection.</p>
<p>Method-level metadata takes precedence over class-level metadata, so a
protected route inside a public controller can opt back in by setting the
key to <code>false</code> with <code>SetMetadata(SKIP_BASIC_AUTH_KEY, false)</code>.</p>
</dd>
</dl>

<a name="SKIP_BASIC_AUTH_KEY"></a>

## SKIP\_BASIC\_AUTH\_KEY
Metadata key used to mark a route or controller as public.
Set by [SkipBasicAuth](#SkipBasicAuth) and read by `BasicAuthGuard`.

**Kind**: global constant  
src: src/skip-basic-auth.decorator.ts:7  
dist: dist/skip-basic-auth.decorator.js:6
<a name="SkipBasicAuth"></a>

## SkipBasicAuth ⇒ <code>import(&quot;@nestjs/common&quot;).CustomDecorator&lt;string&gt;</code>
Marks a route handler or controller as public: `BasicAuthGuard` skips all
Basic auth checks for it, so no credentials are required and `req.user` is
left untouched.

Works with global guards (`app.useGlobalGuards(new BasicAuthGuard())`),
per-route guards (`@UseGuards(...)`), and guards provided through
`BasicAuthModule.forRoot()` — the decorators only need Nest's metadata, not
dependency injection.

Method-level metadata takes precedence over class-level metadata, so a
protected route inside a public controller can opt back in by setting the
key to `false` with `SetMetadata(SKIP_BASIC_AUTH_KEY, false)`.

**Kind**: global constant  
**Controller(&quot;health&quot;)**: export class HealthController {  
**Get()**:   
**Skipbasicauth()**: check(): string {
    return "ok";
  }
}
```  
**Example**  
```ts
import { Controller, Get } from "@nestjs/common";
import { SkipBasicAuth } from "nest-basic-auth";
src: src/skip-basic-auth.decorator.ts:38  
dist: dist/skip-basic-auth.decorator.js:36
