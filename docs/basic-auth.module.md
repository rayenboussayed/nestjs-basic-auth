<a name="BasicAuthModule"></a>

## BasicAuthModule
NestJS module that provides and exports [BasicAuthGuard](BasicAuthGuard) configured by `forRoot()`.

**Kind**: global variable  
src: src/basic-auth.module.ts:7  
dist: dist/basic-auth.module.js:11
<a name="BasicAuthModule.forRoot"></a>

### BasicAuthModule.forRoot() ⇒ <code>{ module: typeof BasicAuthModule; providers: (typeof BasicAuthGuard \| { provide: string; useValue: BasicAuthOptions; })[]; exports: (string \| typeof BasicAuthGuard)[]; }</code>
Provides and exports `BasicAuthGuard` configured with `options`.

**Kind**: static method of [<code>BasicAuthModule</code>](#BasicAuthModule)  
src: src/basic-auth.module.ts:9  
dist: dist/basic-auth.module.js:13
