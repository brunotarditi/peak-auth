import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import http from 'node:http';
import * as jose from 'jose';
import { generatePKCE, generateState, validateState } from './pkce.js';
import { PeakAuthClient } from './client.js';
import { peakAuthMiddleware, type ExpressRequest, type ExpressResponse } from './express.js';

describe('Peak Auth TypeScript SDK', () => {
  describe('PKCE Generator', () => {
    it('debe generar un par PKCE válido con code_verifier y code_challenge', async () => {
      const pkce = await generatePKCE();
      assert.ok(pkce.codeVerifier);
      assert.ok(pkce.codeChallenge);
      assert.ok(pkce.codeVerifier.length >= 43 && pkce.codeVerifier.length <= 128);

      const encoder = new TextEncoder();
      const digest = await crypto.subtle.digest('SHA-256', encoder.encode(pkce.codeVerifier));
      const expectedChallenge = Buffer.from(digest).toString('base64url');
      assert.strictEqual(pkce.codeChallenge, expectedChallenge);
    });

    it('debe generar verifiers aleatorios únicos en cada invocación', async () => {
      const p1 = await generatePKCE();
      const p2 = await generatePKCE();
      assert.notStrictEqual(p1.codeVerifier, p2.codeVerifier);
    });
  });

  describe('PeakAuthClient', () => {
    it('debe requerir issuerUrl y clientId', () => {
      assert.throws(() => new PeakAuthClient({ issuerUrl: '', clientId: 'app' }), /issuerUrl es requerido/);
      assert.throws(() => new PeakAuthClient({ issuerUrl: 'http://localhost', clientId: '' }), /clientId es requerido/);
    });

    it('debe construir la URL de autorización correctamente con parámetros PKCE', () => {
      const client = new PeakAuthClient({
        issuerUrl: 'https://auth.example.com',
        clientId: 'my-app',
        redirectUri: 'https://app.com/callback',
      });

      const url = client.getAuthorizationUrl({
        state: 'xyz123',
        codeChallenge: 'challenge456',
        scope: 'openid profile',
      });

      const parsed = new URL(url);
      assert.strictEqual(parsed.origin, 'https://auth.example.com');
      assert.strictEqual(parsed.pathname, '/oauth/authorize');
      assert.strictEqual(parsed.searchParams.get('client_id'), 'my-app');
      assert.strictEqual(parsed.searchParams.get('redirect_uri'), 'https://app.com/callback');
      assert.strictEqual(parsed.searchParams.get('response_type'), 'code');
      assert.strictEqual(parsed.searchParams.get('state'), 'xyz123');
      assert.strictEqual(parsed.searchParams.get('code_challenge'), 'challenge456');
      assert.strictEqual(parsed.searchParams.get('code_challenge_method'), 'S256');
      assert.strictEqual(parsed.searchParams.get('scope'), 'openid profile');
    });

    it('debe construir la URL de logout con client_id y post_logout_redirect_uri', () => {
      const client = new PeakAuthClient({
        issuerUrl: 'https://auth.example.com',
        clientId: 'my-app',
        redirectUri: 'https://app.com/default-callback',
      });

      const urlDefault = client.getLogoutUrl();
      const parsed1 = new URL(urlDefault);
      assert.strictEqual(parsed1.origin, 'https://auth.example.com');
      assert.strictEqual(parsed1.pathname, '/oauth/logout');
      assert.strictEqual(parsed1.searchParams.get('client_id'), 'my-app');
      assert.strictEqual(parsed1.searchParams.get('post_logout_redirect_uri'), 'https://app.com/default-callback');

      const urlCustom = client.getLogoutUrl({
        redirectUri: 'https://app.com/auth/login',
        state: 'session-cleared',
        idTokenHint: 'ey.mock.jwt',
      });
      const parsed2 = new URL(urlCustom);
      assert.strictEqual(parsed2.searchParams.get('client_id'), 'my-app');
      assert.strictEqual(parsed2.searchParams.get('post_logout_redirect_uri'), 'https://app.com/auth/login');
      assert.strictEqual(parsed2.searchParams.get('state'), 'session-cleared');
      assert.strictEqual(parsed2.searchParams.get('id_token_hint'), 'ey.mock.jwt');

      const clientNoRedirect = new PeakAuthClient({
        issuerUrl: 'https://auth.example.com',
        clientId: 'my-app',
      });
      const urlNoRedirect = clientNoRedirect.getLogoutUrl();
      const parsed3 = new URL(urlNoRedirect);
      assert.strictEqual(parsed3.searchParams.get('client_id'), 'my-app');
      assert.strictEqual(parsed3.searchParams.get('post_logout_redirect_uri'), null);
    });
  });

  describe('Token Verification contra JWKS Mock', () => {
    let server: http.Server;
    let serverUrl: string;
    let keyPair: jose.GenerateKeyPairResult;
    const kid = 'test-rsa-kid-1';

    before(async () => {
      keyPair = await jose.generateKeyPair('RS256');
      const publicJwk = await jose.exportJWK(keyPair.publicKey);
      publicJwk.kid = kid;
      publicJwk.use = 'sig';
      publicJwk.alg = 'RS256';

      await new Promise<void>((resolve) => {
        server = http.createServer((req, res) => {
          if (req.url === '/.well-known/jwks.json') {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ keys: [publicJwk] }));
            return;
          }
          res.writeHead(404);
          res.end();
        });
        server.listen(0, '127.0.0.1', () => {
          const addr = server.address() as { port: number };
          serverUrl = `http://127.0.0.1:${addr.port}`;
          resolve();
        });
      });
    });

    after(async () => {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    });

    it('debe validar exitosamente un token firmado con la clave del JWKS', async () => {
      const client = new PeakAuthClient({
        issuerUrl: serverUrl,
        clientId: 'target-app',
        expectedIssuer: 'peak-auth',
        insecureAllowHttp: true,
      });

      const jwt = await new jose.SignJWT({
        username: 'bruno@peak.test',
        app_id: 'target-app',
        roles: ['ADMIN', 'USER'],
      })
        .setProtectedHeader({ alg: 'RS256', kid })
        .setIssuer('peak-auth')
        .setAudience('target-app')
        .setSubject('101')
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(keyPair.privateKey);

      const claims = await client.verifyToken(jwt);
      assert.strictEqual(claims.sub, '101');
      assert.strictEqual(claims.username, 'bruno@peak.test');
      assert.strictEqual(claims.app_id, 'target-app');
      assert.deepStrictEqual(claims.roles, ['ADMIN', 'USER']);
    });

    it('debe rechazar un token con audiencia incorrecta', async () => {
      const client = new PeakAuthClient({
        issuerUrl: serverUrl,
        clientId: 'different-app',
        expectedIssuer: 'peak-auth',
        insecureAllowHttp: true,
      });

      const jwt = await new jose.SignJWT({
        username: 'hacker@test.com',
        app_id: 'target-app',
        roles: ['USER'],
      })
        .setProtectedHeader({ alg: 'RS256', kid })
        .setIssuer('peak-auth')
        .setAudience('target-app')
        .setExpirationTime('1h')
        .sign(keyPair.privateKey);

      await assert.rejects(async () => {
        await client.verifyToken(jwt);
      }, /unexpected "aud" claim value/);
    });

    it('debe rechazar un token sin claim exp', async () => {
      const client = new PeakAuthClient({
        issuerUrl: serverUrl,
        clientId: 'target-app',
        expectedIssuer: 'peak-auth',
        insecureAllowHttp: true,
      });

      const jwt = await new jose.SignJWT({
        username: 'noexp@peak.test',
        app_id: 'target-app',
        roles: ['USER'],
      })
        .setProtectedHeader({ alg: 'RS256', kid })
        .setIssuer('peak-auth')
        .setAudience('target-app')
        .setIssuedAt()
        .sign(keyPair.privateKey);

      await assert.rejects(async () => {
        await client.verifyToken(jwt);
      }, /claim 'exp' es obligatorio/);
    });
  });

  describe('JWKS y RSA Validación Estricta', () => {
    let keyPair2048: jose.GenerateKeyPairResult;
    let validJwk: jose.JWK;

    before(async () => {
      keyPair2048 = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
      validJwk = await jose.exportJWK(keyPair2048.publicKey);
      validJwk.kid = 'k-valid';
      validJwk.use = 'sig';
      validJwk.alg = 'RS256';
    });

    const testCases: { name: string; jwk: Record<string, unknown>; expectedSuccess: boolean }[] = [
      {
        name: 'clave válida 2048-bit con e=65537',
        jwk: { kty: 'RSA', alg: 'RS256', use: 'sig', kid: 'k1', n: '', e: 'AQAB' },
        expectedSuccess: true,
      },
      {
        name: 'alg ausente',
        jwk: { kty: 'RSA', use: 'sig', kid: 'k2', n: '', e: 'AQAB' },
        expectedSuccess: false,
      },
      {
        name: 'use ausente',
        jwk: { kty: 'RSA', alg: 'RS256', kid: 'k3', n: '', e: 'AQAB' },
        expectedSuccess: false,
      },
      {
        name: 'alg incorrecto (HS256)',
        jwk: { kty: 'RSA', alg: 'HS256', use: 'sig', kid: 'k4', n: '', e: 'AQAB' },
        expectedSuccess: false,
      },
      {
        name: 'use incorrecto (enc)',
        jwk: { kty: 'RSA', alg: 'RS256', use: 'enc', kid: 'k5', n: '', e: 'AQAB' },
        expectedSuccess: false,
      },
      {
        name: 'RSA de menos de 2048 bits (1024 bits)',
        jwk: { kty: 'RSA', alg: 'RS256', use: 'sig', kid: 'k6', n: Buffer.alloc(128, 1).toString('base64url'), e: 'AQAB' },
        expectedSuccess: false,
      },
      {
        name: 'exponente 1',
        jwk: { kty: 'RSA', alg: 'RS256', use: 'sig', kid: 'k7', n: '', e: Buffer.from([1]).toString('base64url') },
        expectedSuccess: false,
      },
      {
        name: 'exponente 2',
        jwk: { kty: 'RSA', alg: 'RS256', use: 'sig', kid: 'k8', n: '', e: Buffer.from([2]).toString('base64url') },
        expectedSuccess: false,
      },
      {
        name: 'exponente par (4)',
        jwk: { kty: 'RSA', alg: 'RS256', use: 'sig', kid: 'k9', n: '', e: Buffer.from([4]).toString('base64url') },
        expectedSuccess: false,
      },
      {
        name: 'exponente par (65536)',
        jwk: { kty: 'RSA', alg: 'RS256', use: 'sig', kid: 'k10', n: '', e: Buffer.from([1, 0, 0]).toString('base64url') },
        expectedSuccess: false,
      },
      {
        name: 'exponente gigante/overflow (> 4 bytes)',
        jwk: { kty: 'RSA', alg: 'RS256', use: 'sig', kid: 'k11', n: '', e: Buffer.from([1, 2, 3, 4, 5]).toString('base64url') },
        expectedSuccess: false,
      },
    ];

    for (const tc of testCases) {
      it(`debe procesar adecuadamente: ${tc.name}`, async () => {
        const jwkToTest = {
          ...tc.jwk,
          n: tc.jwk.n === '' ? validJwk.n : tc.jwk.n,
        };

        let srv: http.Server;
        let srvUrl = '';
        await new Promise<void>((resolve) => {
          srv = http.createServer((req, res) => {
            if (req.url === '/.well-known/jwks.json') {
              res.writeHead(200, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ keys: [jwkToTest] }));
              return;
            }
            res.writeHead(404).end();
          });
          srv.listen(0, '127.0.0.1', () => {
            const addr = srv.address() as { port: number };
            srvUrl = `http://127.0.0.1:${addr.port}`;
            resolve();
          });
        });

        const client = new PeakAuthClient({
          issuerUrl: srvUrl,
          clientId: 'app',
          insecureAllowHttp: true,
        });

        const jwt = await new jose.SignJWT({ username: 'u1' })
          .setProtectedHeader({ alg: 'RS256', kid: String((tc.jwk as { kid?: string }).kid ?? 'k1') })
          .setIssuer('peak-auth')
          .setAudience('app')
          .setExpirationTime('1h')
          .sign(keyPair2048.privateKey);

        if (tc.expectedSuccess) {
          const claims = await client.verifyToken(jwt);
          assert.strictEqual(claims.username, 'u1');
        } else {
          await assert.rejects(async () => {
            await client.verifyToken(jwt);
          });
        }

        await new Promise<void>((resolve) => srv.close(() => resolve()));
      });
    }
  });

  describe('Transport Security y PKCE Estricto', () => {
    it('debe rechazar emisor HTTP remoto SIEMPRE, incluso si se pasa insecureAllowHttp', () => {
      // 1. Sin insecureAllowHttp
      assert.throws(
        () => new PeakAuthClient({ issuerUrl: 'http://auth.empresa.com', clientId: 'app' }),
        /HTTPS es obligatorio para hosts remotos/
      );

      // 2. Con insecureAllowHttp=true DEBE FALLAR TAMBIÉN para host remoto
      assert.throws(
        () => new PeakAuthClient({ issuerUrl: 'http://auth.empresa.com', clientId: 'app', insecureAllowHttp: true }),
        /HTTPS es obligatorio para hosts remotos/
      );

      // 3. Loopback sin insecureAllowHttp debe fallar
      assert.throws(
        () => new PeakAuthClient({ issuerUrl: 'http://localhost:8080', clientId: 'app' }),
        /requiere insecureAllowHttp = true/
      );

      // 4. Loopbacks con insecureAllowHttp deben permitirse
      const loopbacks = ['http://localhost:8080', 'http://127.0.0.1:9009', 'http://127.0.0.2:8080', 'http://[::1]:8080'];
      for (const lb of loopbacks) {
        const client = new PeakAuthClient({
          issuerUrl: lb,
          clientId: 'app',
          insecureAllowHttp: true,
        });
        assert.ok(client);
      }

      // 5. Rechazar subdominios y direcciones IP privadas genéricas (incluso con insecureAllowHttp = true)
      const rejectedNonLoopbacks = [
        'http://foo.localhost:8080',
        'http://app.localhost:9000',
        'http://10.0.0.1:8080',
        'http://192.168.1.1:8080',
        'http://172.16.0.1:8080',
      ];
      for (const badHost of rejectedNonLoopbacks) {
        assert.throws(
          () => new PeakAuthClient({ issuerUrl: badHost, clientId: 'app', insecureAllowHttp: true }),
          /HTTPS es obligatorio para hosts remotos/
        );
      }

      // 6. Rechazar URLs con credenciales, fragments o queries en issuerUrl
      const badUrls = [
        'https://user:pass@auth.empresa.com',
        'http://user:pass@localhost:8080',
        'https://auth.empresa.com#fragment',
        'https://auth.empresa.com?param=value',
        'ftp://auth.empresa.com',
      ];
      for (const bu of badUrls) {
        assert.throws(
          () => new PeakAuthClient({ issuerUrl: bu, clientId: 'app', insecureAllowHttp: true }),
          /inválida|credenciales|fragmentos|query parameters|esquema/
        );
      }
    });

    it('debe exigir PKCE para clientes públicos (sin clientSecret)', async () => {
      const publicClient = new PeakAuthClient({
        issuerUrl: 'https://auth.example.com',
        clientId: 'public-client',
        redirectUri: 'https://app.com/callback',
      });

      assert.throws(
        () => publicClient.getAuthorizationUrl({ state: 's1' }),
        /code_challenge es obligatorio para clientes públicos/
      );

      await assert.rejects(
        async () => publicClient.exchangeCode({ code: 'abc' }),
        /code_verifier es obligatorio para clientes públicos/
      );
    });
  });

  describe('State Generator y Timing-Safe Validation', () => {
    it('debe generar y validar estados OAuth de forma segura', async () => {
      const s1 = generateState();
      const s2 = generateState();
      assert.ok(s1 && s2);
      assert.notStrictEqual(s1, s2);

      assert.strictEqual(validateState(s1, s1), true);
      assert.strictEqual(validateState(s1, s2), false);
      assert.strictEqual(validateState(s1, ''), false);
      assert.strictEqual(validateState('', s1), false);
    });
  });

  describe('Single-Flight Refresh Token', () => {
    let refreshServer: http.Server;
    let refreshUrl: string;
    let refreshCalls = 0;

    before(async () => {
      await new Promise<void>((resolve) => {
        refreshServer = http.createServer((req, res) => {
          if (req.url === '/api/v1/refresh') {
            refreshCalls++;
            setTimeout(() => {
              res.writeHead(200, { 'Content-Type': 'application/json' });
              res.end(
                JSON.stringify({
                  access_token: 'new-acc',
                  refresh_token: 'new-ref',
                  token_type: 'Bearer',
                  expires_in: 3600,
                })
              );
            }, 50);
            return;
          }
          res.writeHead(404);
          res.end();
        });
        refreshServer.listen(0, '127.0.0.1', () => {
          const addr = refreshServer.address() as { port: number };
          refreshUrl = `http://127.0.0.1:${addr.port}`;
          resolve();
        });
      });
    });

    after(async () => {
      await new Promise<void>((resolve) => refreshServer.close(() => resolve()));
    });

    it('debe deduplicar llamadas concurrentes a refreshToken mediante single-flight', async () => {
      const client = new PeakAuthClient({
        issuerUrl: refreshUrl,
        clientId: 'app',
        insecureAllowHttp: true,
      });

      const promises = Array.from({ length: 5 }, () => client.refreshToken('same-refresh-tok'));
      const results = await Promise.all(promises);

      for (const res of results) {
        assert.strictEqual(res.access_token, 'new-acc');
      }
      assert.strictEqual(refreshCalls, 1, 'Debe ejecutarse solo 1 llamada HTTP concurrente por single-flight');
    });
  });

  describe('Express Middleware y Safe Errors', () => {
    let introServer: http.Server;
    let introUrl: string;

    before(async () => {
      await new Promise<void>((resolve) => {
        introServer = http.createServer((req, res) => {
          if (req.url === '/api/v1/introspect') {
            let data = '';
            req.on('data', (chunk) => {
              data += chunk;
            });
            req.on('end', () => {
              const parsed = JSON.parse(data);
              if (parsed.token === 'valid-online-token') {
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(
                  JSON.stringify({
                    active: true,
                    sub: 'u100',
                    username: 'intro@test.com',
                    aud: 'app',
                    iss: 'peak-auth',
                    roles: ['ADMIN'],
                  })
                );
              } else {
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ active: false }));
              }
            });
            return;
          }
          res.writeHead(404).end();
        });
        introServer.listen(0, '127.0.0.1', () => {
          const addr = introServer.address() as { port: number };
          introUrl = `http://127.0.0.1:${addr.port}`;
          resolve();
        });
      });
    });

    after(async () => {
      await new Promise<void>((resolve) => introServer.close(() => resolve()));
    });

    it('debe manejar introspección activa e inactiva retornando respuestas genéricas y seguras', async () => {
      const client = new PeakAuthClient({
        issuerUrl: introUrl,
        clientId: 'app',
        clientSecret: 'secret',
        insecureAllowHttp: true,
      });

      const middleware = peakAuthMiddleware(client, { useIntrospection: true, requiredRoles: ['ADMIN'] });

      // 1. Token activo
      const reqActive: ExpressRequest = {
        headers: { authorization: 'Bearer valid-online-token' },
      };
      let statusCalled = 0;
      let jsonBody: unknown = null;
      let nextCalled = false;
      const resActive: ExpressResponse = {
        status(c) {
          statusCalled = c;
          return this;
        },
        json(b) {
          jsonBody = b;
          return b;
        },
      };

      await middleware(reqActive, resActive, () => {
        nextCalled = true;
      });
      assert.strictEqual(nextCalled, true);
      assert.strictEqual(reqActive.user?.username, 'intro@test.com');

      // 2. Token inactivo
      const reqInactive: ExpressRequest = {
        headers: { authorization: 'Bearer inactive-token' },
      };
      nextCalled = false;
      await middleware(reqInactive, resActive, () => {
        nextCalled = true;
      });
      assert.strictEqual(nextCalled, false);
      assert.strictEqual(statusCalled, 401);
      assert.deepStrictEqual(jsonBody, { error: 'invalid_token', message: 'Token revocado o inválido' });

      // 3. Token malformado en verificación offline
      const offlineMiddleware = peakAuthMiddleware(client);
      const reqMalformed: ExpressRequest = {
        headers: { authorization: 'Bearer malformed.token.here' },
      };
      await offlineMiddleware(reqMalformed, resActive, () => {
        nextCalled = true;
      });
      assert.strictEqual(statusCalled, 401);
      assert.deepStrictEqual(jsonBody, { error: 'invalid_token', message: 'Token inválido o expirado' });
    });
  });

  describe('OIDC Discovery Validación Estricta', () => {
    const baseIssuer = 'https://auth.empresa.com';

    const discoveryCases = [
      {
        name: 'issuer host mismatch',
        data: {
          issuer: 'https://attacker.com',
          authorization_endpoint: 'https://auth.empresa.com/oauth/authorize',
          token_endpoint: 'https://auth.empresa.com/oauth/token',
          jwks_uri: 'https://auth.empresa.com/.well-known/jwks.json',
        },
      },
      {
        name: 'issuer scheme mismatch (http vs https)',
        data: {
          issuer: 'http://auth.empresa.com',
          authorization_endpoint: 'https://auth.empresa.com/oauth/authorize',
          token_endpoint: 'https://auth.empresa.com/oauth/token',
          jwks_uri: 'https://auth.empresa.com/.well-known/jwks.json',
        },
      },
      {
        name: 'issuer port mismatch',
        data: {
          issuer: 'https://auth.empresa.com:8443',
          authorization_endpoint: 'https://auth.empresa.com/oauth/authorize',
          token_endpoint: 'https://auth.empresa.com/oauth/token',
          jwks_uri: 'https://auth.empresa.com/.well-known/jwks.json',
        },
      },
      {
        name: 'issuer path mismatch',
        data: {
          issuer: 'https://auth.empresa.com/other-path',
          authorization_endpoint: 'https://auth.empresa.com/oauth/authorize',
          token_endpoint: 'https://auth.empresa.com/oauth/token',
          jwks_uri: 'https://auth.empresa.com/.well-known/jwks.json',
        },
      },
      {
        name: 'issuer con query parameter',
        data: {
          issuer: 'https://auth.empresa.com?param=bad',
          authorization_endpoint: 'https://auth.empresa.com/oauth/authorize',
          token_endpoint: 'https://auth.empresa.com/oauth/token',
          jwks_uri: 'https://auth.empresa.com/.well-known/jwks.json',
        },
      },
      {
        name: 'authorization_endpoint vacío',
        data: {
          issuer: 'https://auth.empresa.com',
          authorization_endpoint: '',
          token_endpoint: 'https://auth.empresa.com/oauth/token',
          jwks_uri: 'https://auth.empresa.com/.well-known/jwks.json',
        },
      },
      {
        name: 'token_endpoint relativo',
        data: {
          issuer: 'https://auth.empresa.com',
          authorization_endpoint: 'https://auth.empresa.com/oauth/authorize',
          token_endpoint: '/oauth/token',
          jwks_uri: 'https://auth.empresa.com/.well-known/jwks.json',
        },
      },
      {
        name: 'jwks_uri remoto HTTP inseguro',
        data: {
          issuer: 'https://auth.empresa.com',
          authorization_endpoint: 'https://auth.empresa.com/oauth/authorize',
          token_endpoint: 'https://auth.empresa.com/oauth/token',
          jwks_uri: 'http://auth.empresa.com/.well-known/jwks.json',
        },
      },
    ];

    for (const dc of discoveryCases) {
      it(`debe rechazar discovery con ${dc.name}`, async () => {
        let srv: http.Server;
        let srvUrl = '';
        await new Promise<void>((resolve) => {
          srv = http.createServer((req, res) => {
            if (req.url === '/.well-known/openid-configuration') {
              res.writeHead(200, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify(dc.data));
              return;
            }
            res.writeHead(404).end();
          });
          srv.listen(0, '127.0.0.1', () => {
            const addr = srv.address() as { port: number };
            srvUrl = `http://127.0.0.1:${addr.port}`;
            resolve();
          });
        });

        const client = new PeakAuthClient({
          issuerUrl: baseIssuer,
          clientId: 'app',
        });
        // Override internal issuerUrl for the fetch test
        (client as unknown as { config: { issuerUrl: string; insecureAllowHttp: boolean } }).config.issuerUrl = srvUrl;
        (client as unknown as { config: { issuerUrl: string; insecureAllowHttp: boolean } }).config.insecureAllowHttp = true;

        await assert.rejects(async () => {
          await client.getOpenIDConfiguration();
        });

        await new Promise<void>((resolve) => srv.close(() => resolve()));
      });
    }
  });
});
