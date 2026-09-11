import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import http from 'node:http';
import * as jose from 'jose';
import { generatePKCE } from './pkce.js';
import { PeakAuthClient } from './client.js';

describe('Peak Auth TypeScript SDK', () => {
  describe('PKCE Generator', () => {
    it('debe generar un par PKCE válido con code_verifier y code_challenge', async () => {
      const pkce = await generatePKCE();
      assert.ok(pkce.codeVerifier);
      assert.ok(pkce.codeChallenge);
      assert.ok(pkce.codeVerifier.length >= 43 && pkce.codeVerifier.length <= 128);

      // Verificamos que code_challenge sea el hash SHA-256 en base64url
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
  });

  describe('Token Verification contra JWKS Mock', () => {
    let server: http.Server;
    let serverUrl: string;
    let keyPair: jose.GenerateKeyPairResult;
    const kid = 'test-rsa-kid-1';

    before(async () => {
      // 1. Generar par de claves RSA RS256
      keyPair = await jose.generateKeyPair('RS256');
      const publicJwk = await jose.exportJWK(keyPair.publicKey);
      publicJwk.kid = kid;
      publicJwk.use = 'sig';
      publicJwk.alg = 'RS256';

      // 2. Levantar servidor HTTP mock de JWKS
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
      });

      // Firmar token JWT con la clave privada y cabecera kid
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
  });
});
