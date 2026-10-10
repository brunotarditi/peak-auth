import { createLocalJWKSet, jwtVerify, type JWTVerifyGetKey, type JWK } from 'jose';
import { generatePKCE } from './pkce.js';
import type {
  PeakAuthConfig,
  PeakClaims,
  PKCEPair,
  LogoutUrlParams,
  TokenResponse,
  OpenIDConfiguration,
  IntrospectionResponse,
} from './types.js';

function isLoopback(hostname: string): boolean {
  const h = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (h === 'localhost' || h === '127.0.0.1' || h === '::1' || h === '0:0:0:0:0:0:0:1') {
    return true;
  }
  const parts = h.split('.');
  if (parts.length === 4 && parts[0] === '127') {
    return parts.every((part) => {
      const n = Number(part);
      return Number.isInteger(n) && n >= 0 && n <= 255 && String(n) === part;
    });
  }
  return false;
}

function validateUrl(rawUrl: string, isIssuer: boolean, insecureAllowHttp?: boolean): URL {
  if (!rawUrl || !rawUrl.trim()) {
    throw new Error('PeakAuth: URL no puede estar vacía');
  }

  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error(`PeakAuth: URL inválida o malformada: ${rawUrl}`);
  }

  if (parsed.username || parsed.password) {
    throw new Error(`PeakAuth: URL no puede contener credenciales de usuario (${rawUrl})`);
  }
  if (parsed.hash) {
    throw new Error(`PeakAuth: URL no puede contener fragmentos (#) (${rawUrl})`);
  }
  if (isIssuer && parsed.search) {
    throw new Error(`PeakAuth: issuerUrl no puede contener query parameters (?) (${rawUrl})`);
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new Error(`PeakAuth: esquema de URL no válido (${parsed.protocol}): debe ser https o http`);
  }
  if (parsed.protocol === 'http:') {
    if (!isLoopback(parsed.hostname)) {
      throw new Error(`PeakAuth: URL insegura (${rawUrl}): HTTPS es obligatorio para hosts remotos; HTTP no está permitido para hosts no loopback bajo ninguna circunstancia`);
    }
    if (!insecureAllowHttp) {
      throw new Error(`PeakAuth: URL loopback con HTTP (${rawUrl}) requiere insecureAllowHttp = true para desarrollo local controlado`);
    }
  }
  return parsed;
}

function decodeBase64Url(str: string): Uint8Array {
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad = base64.length % 4;
  const padded = pad ? base64 + '='.repeat(4 - pad) : base64;
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(padded, 'base64');
  }
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export class PeakAuthClient {
  private config: PeakAuthConfig;
  private jwksCache: { getKey: JWTVerifyGetKey; expiresAt: number } | null = null;
  private openIDConfigCache: { data: OpenIDConfiguration; expiresAt: number } | null = null;
  private refreshPromises = new Map<string, Promise<TokenResponse>>();

  constructor(config: PeakAuthConfig) {
    if (!config.issuerUrl) throw new Error('PeakAuth: issuerUrl es requerido');
    if (!config.clientId) throw new Error('PeakAuth: clientId es requerido');

    const parsedIssuer = validateUrl(config.issuerUrl, true, config.insecureAllowHttp);

    this.config = {
      ...config,
      issuerUrl: parsedIssuer.origin + parsedIssuer.pathname.replace(/\/+$/, ''),
      expectedIssuer: config.expectedIssuer || 'peak-auth',
      jwksCacheTtlMs: config.jwksCacheTtlMs || 60 * 60 * 1000, // 1 hora
    };
  }

  /**
   * Emite un registro interno seguro si un registrador fue provisto en la configuración.
   */
  log(message: string, ...args: unknown[]): void {
    if (this.config.logger) {
      this.config.logger(message, ...args);
    }
  }

  /**
   * Genera un par PKCE criptográfico (code_verifier y code_challenge).
   */
  async generatePKCE(length?: number): Promise<PKCEPair> {
    return generatePKCE(length);
  }

  /**
   * Construye la URL de inicio de sesión OAuth 2.0 con soporte PKCE.
   * Para clientes públicos (sin clientSecret), codeChallenge es obligatorio.
   */
  getAuthorizationUrl(params?: {
    redirectUri?: string;
    state?: string;
    codeChallenge?: string;
    scope?: string;
  }): string {
    const redirectUri = params?.redirectUri || this.config.redirectUri;
    if (!redirectUri) {
      throw new Error('PeakAuth: redirectUri es requerido para generar la URL de autorización');
    }

    if (!this.config.clientSecret && !params?.codeChallenge) {
      throw new Error('PeakAuth: code_challenge es obligatorio para clientes públicos (sin clientSecret)');
    }

    const url = new URL(`${this.config.issuerUrl}/oauth/authorize`);
    url.searchParams.set('client_id', this.config.clientId);
    url.searchParams.set('redirect_uri', redirectUri);
    url.searchParams.set('response_type', 'code');

    if (params?.state) {
      url.searchParams.set('state', params.state);
    }
    if (params?.codeChallenge) {
      url.searchParams.set('code_challenge', params.codeChallenge);
      url.searchParams.set('code_challenge_method', 'S256');
    }
    if (params?.scope) {
      url.searchParams.set('scope', params.scope);
    }

    return url.toString();
  }

  /**
   * Construye la URL de cierre de sesión (Federated Logout).
   * Inyecta automáticamente el clientId registrado para cumplir con las políticas anti Open-Redirect.
   */
  getLogoutUrl(params?: LogoutUrlParams): string {
    const redirect = params?.postLogoutRedirectUri || params?.redirectUri || this.config.redirectUri;
    const url = new URL(`${this.config.issuerUrl}/oauth/logout`);

    url.searchParams.set('client_id', this.config.clientId);

    if (redirect) {
      url.searchParams.set('post_logout_redirect_uri', redirect);
    }
    if (params?.idTokenHint) {
      url.searchParams.set('id_token_hint', params.idTokenHint);
    }
    if (params?.state) {
      url.searchParams.set('state', params.state);
    }

    return url.toString();
  }

  /**
   * Intercambia el código de autorización por un Access Token (+ Refresh Token si aplica) en /oauth/token.
   * Para clientes públicos (sin clientSecret), codeVerifier es obligatorio.
   */
  async exchangeCode(params: {
    code: string;
    codeVerifier?: string;
    redirectUri?: string;
  }): Promise<TokenResponse> {
    if (!this.config.clientSecret && !params.codeVerifier) {
      throw new Error('PeakAuth: code_verifier es obligatorio para clientes públicos (sin clientSecret)');
    }

    const redirectUri = params.redirectUri || this.config.redirectUri;
    if (!redirectUri) {
      throw new Error('PeakAuth: redirectUri es requerido para el canje de código');
    }

    const body: Record<string, string> = {
      grant_type: 'authorization_code',
      client_id: this.config.clientId,
      code: params.code,
      redirect_uri: redirectUri,
    };

    if (this.config.clientSecret) {
      body.client_secret = this.config.clientSecret;
    }
    if (params.codeVerifier) {
      body.code_verifier = params.codeVerifier;
    }

    const res = await fetch(`${this.config.issuerUrl}/oauth/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      },
      body: new URLSearchParams(body).toString(),
    });

    if (!res.ok) {
      let errorDesc = `HTTP ${res.status}`;
      try {
        const errorJson = (await res.json()) as { error?: string; error_description?: string };
        errorDesc = errorJson.error_description || errorJson.error || errorDesc;
      } catch {
        // Ignorar fallo de parseo JSON
      }
      throw new Error(`PeakAuth token exchange falló: ${errorDesc}`);
    }

    return (await res.json()) as TokenResponse;
  }

  /**
   * Renueva el Access Token utilizando un Refresh Token.
   * Implementa deduplicación single-flight para evitar invalidaciones concurrentes de tokens rotativos.
   */
  async refreshToken(refreshToken: string, clientId?: string): Promise<TokenResponse> {
    if (!refreshToken || !refreshToken.trim()) {
      throw new Error('PeakAuth: refreshToken no puede estar vacío');
    }

    const key = `${clientId || this.config.clientId}:${refreshToken}`;
    const inFlight = this.refreshPromises.get(key);
    if (inFlight) {
      return inFlight;
    }

    const refreshPromise = this.executeRefreshToken(refreshToken, clientId);
    this.refreshPromises.set(key, refreshPromise);

    try {
      return await refreshPromise;
    } finally {
      this.refreshPromises.delete(key);
    }
  }

  private async executeRefreshToken(refreshToken: string, clientId?: string): Promise<TokenResponse> {
    const payload: Record<string, string> = { refresh_token: refreshToken };
    const effectiveClientId = clientId || this.config.clientId;
    if (effectiveClientId) {
      payload.client_id = effectiveClientId;
    }

    const res = await fetch(`${this.config.issuerUrl}/api/v1/refresh`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      let errorDesc = `HTTP ${res.status}`;
      try {
        const errorJson = (await res.json()) as { error?: string };
        errorDesc = errorJson.error || errorDesc;
      } catch {
        // Fallback
      }
      throw new Error(`PeakAuth token refresh falló: ${errorDesc}`);
    }

    return (await res.json()) as TokenResponse;
  }

  private async getJWKS(): Promise<JWTVerifyGetKey> {
    const now = Date.now();
    if (this.jwksCache && this.jwksCache.expiresAt > now) {
      return this.jwksCache.getKey;
    }

    const jwksUri = `${this.config.issuerUrl}/.well-known/jwks.json`;
    const res = await fetch(jwksUri);
    if (!res.ok) {
      throw new Error(`PeakAuth: fallo al descargar JWKS desde ${jwksUri} (HTTP ${res.status})`);
    }

    const body = (await res.json()) as { keys?: JWK[] };
    if (!body.keys || !Array.isArray(body.keys)) {
      throw new Error('PeakAuth: respuesta JWKS inválida');
    }

    const validKeys: JWK[] = [];
    for (const k of body.keys) {
      if (!k.kid || typeof k.kid !== 'string' || !k.kid.trim()) {
        continue;
      }
      if (k.kty !== 'RSA') {
        continue;
      }
      if (k.alg !== 'RS256') {
        this.log(`Rechazando clave JWKS ${k.kid}: alg inválido o ausente (${k.alg})`);
        continue;
      }
      if (k.use !== 'sig') {
        this.log(`Rechazando clave JWKS ${k.kid}: use inválido o ausente (${k.use})`);
        continue;
      }
      if (!k.n || typeof k.n !== 'string' || !k.e || typeof k.e !== 'string') {
        this.log(`Rechazando clave JWKS ${k.kid}: n o e ausentes`);
        continue;
      }
      let modulusBytes: Uint8Array;
      let exponentBytes: Uint8Array;
      try {
        modulusBytes = decodeBase64Url(k.n);
        exponentBytes = decodeBase64Url(k.e);
      } catch {
        this.log(`Rechazando clave JWKS ${k.kid}: error decodificando n o e`);
        continue;
      }
      if (modulusBytes.length < 256) {
        this.log(`Rechazando clave JWKS ${k.kid}: tamaño RSA inferior a 2048 bits (${modulusBytes.length * 8} bits)`);
        continue;
      }
      if (exponentBytes.length === 0 || exponentBytes.length > 4) {
        this.log(`Rechazando clave JWKS ${k.kid}: exponente vacío o con overflow (${exponentBytes.length} bytes)`);
        continue;
      }
      let e = 0;
      for (const b of exponentBytes) {
        e = (e << 8) | b;
      }
      if (e <= 0 || !Number.isSafeInteger(e) || e > 2147483647) {
        this.log(`Rechazando clave JWKS ${k.kid}: exponente fuera de rango (${e})`);
        continue;
      }
      if (e < 3) {
        this.log(`Rechazando clave JWKS ${k.kid}: exponente debe ser >= 3 (${e})`);
        continue;
      }
      if (e % 2 === 0) {
        this.log(`Rechazando clave JWKS ${k.kid}: exponente debe ser impar (${e})`);
        continue;
      }
      validKeys.push(k);
    }

    if (validKeys.length === 0) {
      throw new Error('PeakAuth: no se encontraron claves RSA válidas de 2048+ bits para RS256 en el JWKS');
    }

    const getKey = createLocalJWKSet({ keys: validKeys });
    this.jwksCache = {
      getKey,
      expiresAt: now + (this.config.jwksCacheTtlMs || 3600 * 1000),
    };
    return getKey;
  }

  /**
   * Valida offline un token JWT verificando su firma RS256 contra el JWKS remoto cacheado,
   * así como su expiración obligatoria, emisor (iss) y audiencia (aud == clientId).
   */
  async verifyToken(tokenString: string): Promise<PeakClaims> {
    const getKey = await this.getJWKS();
    const tolerance = this.config.clockToleranceSeconds ?? 45;

    const { payload } = await jwtVerify(tokenString, getKey, {
      issuer: this.config.expectedIssuer,
      audience: this.config.clientId,
      algorithms: ['RS256'],
      clockTolerance: tolerance,
    });

    if (payload.exp === undefined) {
      throw new Error("PeakAuth: Token inválido (claim 'exp' es obligatorio)");
    }
    const now = Math.floor(Date.now() / 1000);
    if (payload.iat !== undefined && payload.iat > now + tolerance) {
      throw new Error("PeakAuth: Token inválido (claim 'iat' emitido en el futuro)");
    }

    return payload as PeakClaims;
  }

  /**
   * Realiza una validación online del token contra el servidor de autorización.
   * Este método consulta el endpoint /api/v1/introspect para verificar el estado actual del token,
   * incluyendo si ha sido revocado mediante authz_version. Requiere que el cliente tenga configurado clientSecret.
   */
  async introspectToken(tokenString: string): Promise<IntrospectionResponse> {
    if (!this.config.clientSecret) {
      throw new Error('PeakAuth: clientSecret es requerido para introspección');
    }

    const res = await fetch(`${this.config.issuerUrl}/api/v1/introspect`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        'X-App-Id': this.config.clientId,
        'X-App-Secret': this.config.clientSecret,
      },
      body: JSON.stringify({ token: tokenString }),
    });

    if (!res.ok) {
      throw new Error(`PeakAuth introspección falló: HTTP ${res.status}`);
    }

    return (await res.json()) as IntrospectionResponse;
  }

  /**
   * Obtiene y cachea la configuración OIDC de descubrimiento desde /.well-known/openid-configuration.
   * Valida que issuer, endpoints y jwks_uri pertenezcan al mismo host y usen transporte seguro.
   */
  async getOpenIDConfiguration(): Promise<OpenIDConfiguration> {
    const now = Date.now();
    if (this.openIDConfigCache && this.openIDConfigCache.expiresAt > now) {
      return this.openIDConfigCache.data;
    }

    const res = await fetch(`${this.config.issuerUrl}/.well-known/openid-configuration`);
    if (!res.ok) {
      throw new Error(`Error al obtener openid-configuration: HTTP ${res.status}`);
    }

    const data = (await res.json()) as OpenIDConfiguration;

    const baseIssuer = new URL(this.config.issuerUrl);
    const discIssuer = validateUrl(data.issuer, true, this.config.insecureAllowHttp);

    if (discIssuer.protocol !== baseIssuer.protocol) {
      throw new Error(`PeakAuth openid-configuration: esquema del issuer (${discIssuer.protocol}) no coincide con el emisor configurado (${baseIssuer.protocol})`);
    }
    if (discIssuer.hostname.toLowerCase() !== baseIssuer.hostname.toLowerCase()) {
      throw new Error(`PeakAuth openid-configuration: host del issuer (${discIssuer.hostname}) no coincide con el emisor configurado (${baseIssuer.hostname})`);
    }
    if (discIssuer.port !== baseIssuer.port) {
      throw new Error(`PeakAuth openid-configuration: puerto del issuer (${discIssuer.port}) no coincide con el emisor configurado (${baseIssuer.port})`);
    }
    const normDiscPath = discIssuer.pathname.replace(/\/+$/, '');
    const normBasePath = baseIssuer.pathname.replace(/\/+$/, '');
    if (normDiscPath !== normBasePath) {
      throw new Error(`PeakAuth openid-configuration: path del issuer (${normDiscPath}) no coincide con el emisor configurado (${normBasePath})`);
    }

    const endpoints = {
      authorization_endpoint: data.authorization_endpoint,
      token_endpoint: data.token_endpoint,
      jwks_uri: data.jwks_uri,
    };
    for (const [epName, epVal] of Object.entries(endpoints)) {
      if (!epVal || typeof epVal !== 'string' || !epVal.trim()) {
        throw new Error(`PeakAuth openid-configuration: ${epName} es obligatorio y no puede estar vacío`);
      }
      const epUrl = validateUrl(epVal, false, this.config.insecureAllowHttp);
      if (epUrl.protocol !== baseIssuer.protocol) {
        throw new Error(`PeakAuth openid-configuration: esquema de ${epName} (${epUrl.protocol}) no coincide con el emisor (${baseIssuer.protocol})`);
      }
      if (epUrl.hostname.toLowerCase() !== baseIssuer.hostname.toLowerCase()) {
        throw new Error(`PeakAuth openid-configuration: hostname de ${epName} (${epUrl.hostname}) no coincide con el emisor (${baseIssuer.hostname})`);
      }
      if (epUrl.port !== baseIssuer.port) {
        throw new Error(`PeakAuth openid-configuration: puerto de ${epName} (${epUrl.port}) no coincide con el emisor (${baseIssuer.port})`);
      }
    }

    this.openIDConfigCache = {
      data,
      expiresAt: now + 3600 * 1000,
    };
    return data;
  }
}
