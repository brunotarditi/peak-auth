import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from 'jose';
import { generatePKCE } from './pkce.js';
import type {
  PeakAuthConfig,
  PeakClaims,
  PKCEPair,
  TokenResponse,
  OpenIDConfiguration,
} from './types.js';

export class PeakAuthClient {
  private config: PeakAuthConfig;
  private jwks: JWTVerifyGetKey;
  private openIDConfigCache: { data: OpenIDConfiguration; expiresAt: number } | null = null;

  constructor(config: PeakAuthConfig) {
    if (!config.issuerUrl) throw new Error('PeakAuth: issuerUrl es requerido');
    if (!config.clientId) throw new Error('PeakAuth: clientId es requerido');

    this.config = {
      ...config,
      issuerUrl: config.issuerUrl.replace(/\/+$/, ''),
      expectedIssuer: config.expectedIssuer || 'peak-auth',
      jwksCacheTtlMs: config.jwksCacheTtlMs || 60 * 60 * 1000, // 1 hora
    };

    const jwksUri = new URL(`${this.config.issuerUrl}/.well-known/jwks.json`);
    this.jwks = createRemoteJWKSet(jwksUri, {
      cooldownDuration: 30000,
      cacheMaxAge: this.config.jwksCacheTtlMs,
    });
  }

  /**
   * Genera un par PKCE criptográfico (code_verifier y code_challenge).
   */
  async generatePKCE(length?: number): Promise<PKCEPair> {
    return generatePKCE(length);
  }

  /**
   * Construye la URL de inicio de sesión OAuth 2.0 con soporte PKCE.
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
   * Intercambia el código de autorización por un Access Token (+ Refresh Token si aplica) en /oauth/token.
   */
  async exchangeCode(params: {
    code: string;
    codeVerifier?: string;
    redirectUri?: string;
  }): Promise<TokenResponse> {
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
   */
  async refreshToken(refreshToken: string, clientId?: string): Promise<TokenResponse> {
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

  /**
   * Valida offline un token JWT verificando su firma RS256 contra el JWKS remoto cacheado,
   * así como su expiración, emisor (iss) y audiencia (aud == clientId).
   */
  async verifyToken(tokenString: string): Promise<PeakClaims> {
    const { payload } = await jwtVerify(tokenString, this.jwks, {
      issuer: this.config.expectedIssuer,
      audience: this.config.clientId,
      algorithms: ['RS256'],
      clockTolerance: 45, // 45 segundos para mitigar clock skew
    });

    return payload as PeakClaims;
  }

  /**
   * Obtiene y cachea la configuración OIDC de descubrimiento desde /.well-known/openid-configuration.
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
    this.openIDConfigCache = {
      data,
      expiresAt: now + 3600 * 1000,
    };
    return data;
  }
}
