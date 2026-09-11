import type { JWTPayload } from 'jose';

export interface PeakAuthConfig {
  /**
   * URL base del servidor Peak Auth (ej. "https://auth.tuempresa.com" o "http://localhost:8080")
   */
  issuerUrl: string;

  /**
   * Identificador único de tu aplicación (Client ID registrado en Peak Auth)
   */
  clientId: string;

  /**
   * Secret de la aplicación (solo requerido para clientes confidenciales en backend)
   */
  clientSecret?: string;

  /**
   * URL de redirección por defecto tras el inicio de sesión
   */
  redirectUri?: string;

  /**
   * Issuer esperado en el JWT. Por defecto: "peak-auth"
   */
  expectedIssuer?: string;

  /**
   * Tiempo de vida del cache JWKS en milisegundos. Por defecto: 1 hora
   */
  jwksCacheTtlMs?: number;
}

export interface PKCEPair {
  codeVerifier: string;
  codeChallenge: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  [key: string]: unknown;
}

export interface PeakClaims extends JWTPayload {
  sub: string;
  username: string;
  email?: string;
  app_id: string;
  roles: string[];
  mfa_verified: boolean;
  token_type: string;
}

export interface OpenIDConfiguration {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  response_types_supported: string[];
  subject_types_supported: string[];
  id_token_signing_alg_values_supported: string[];
  code_challenge_methods_supported: string[];
  token_endpoint_auth_methods_supported: string[];
  [key: string]: unknown;
}
