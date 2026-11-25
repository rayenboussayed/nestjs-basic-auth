<a name="BasicAuthModule"></a>

## BasicAuthModule
Minimal NestJS module for the Basic auth guard.

`forRoot(options?)` returns a `DynamicModule` that provides `BasicAuthGuard`
with the resolved options (via `useFactory`, so the guard carries them
regardless of how Nest instantiates it).

**Kind**: global variable  
src: src/basic-auth.module.ts:13  
dist: dist/basic-auth.module.js:17
<a name="BasicAuthModule.forRoot"></a>

### BasicAuthModule.forRoot(options) ⇒ <code>DynamicModule</code>
Registers `BasicAuthGuard` as a provider carrying `options`.

**Kind**: static method of [<code>BasicAuthModule</code>](#BasicAuthModule)  
**Returns**: <code>DynamicModule</code> - A `DynamicModule` exporting `BasicAuthGuard`.  

| Param | Type | Description |
| --- | --- | --- |
| options | <code>BasicAuthOptions</code> | Guard options; omitted values fall back to the environment/defaults. |

src: src/basic-auth.module.ts:19  
dist: dist/basic-auth.module.js:23
