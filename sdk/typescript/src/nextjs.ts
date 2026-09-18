import type { PeakAuthClient } from './client.js';
import type { PeakClaims } from './types.js';

export interface NextAuthOptions {
  /**
   * Nombre de la cookie donde se almacena el access token (por defecto: 'peak_access_token')
   */
  cookieName?: string;

  /**
   * Roles requeridos para autorizar el acceso
   */
  requiredRoles?: string[];

  /**
   * Controla el modo de validación del token:
   *   - undefined (por defecto): usa introspección automáticamente si clientSecret está configurado
   *   - true: fuerza validación online vía /api/v1/introspect (requiere clientSecret)
   *   - false: fuerza validación offline (solo firma/expiración, NO detecta revocación)
   *
   * ADVERTENCIA: La validación offline (false) NO verifica revocación de tokens.
   * Los tokens emitidos antes de revocar acceso seguirán siendo aceptados hasta su expiración.
   * Solo use validación offline si comprende las implicaciones de seguridad.
   */
  useIntrospection?: boolean;
}

/**
 * Extrae y valida el JWT de una petición estándar de Next.js (Route Handler o Server Action).
 * Busca el token primero en el encabezado Authorization: Bearer, y luego en cookies.
 * Por defecto, usa introspección online si clientSecret está configurado para detectar revocación inmediata.
 */
export async function verifyNextRequest(
  request: Request,
  client: PeakAuthClient,
  options?: NextAuthOptions
): Promise<PeakClaims> {
  const authHeader = request.headers.get('authorization');
  let token: string | null = null;

  if (authHeader && authHeader.toLowerCase().startsWith('bearer ')) {
    token = authHeader.slice(7).trim();
  } else {
    // Buscar en cookie
    const cookieHeader = request.headers.get('cookie') || '';
    const cookieName = options?.cookieName || 'peak_access_token';
    const match = cookieHeader.match(new RegExp(`(?:^|;\\s*)${cookieName}=([^;]*)`));
    if (match) {
      token = decodeURIComponent(match[1]);
    }
  }

  if (!token) {
    throw new Error('No se encontró un token de autenticación válido en la petición');
  }

  let claims: PeakClaims;

  // Determinar modo de validación: por defecto usa introspección si clientSecret está disponible
  const useIntrospection = options?.useIntrospection !== undefined
    ? options.useIntrospection
    : client.hasClientSecret();

  if (useIntrospection) {
    // Validación online con verificación de revocación
    const introspection = await client.introspectToken(token);
    if (!introspection.active) {
      throw new Error('Token revocado o inválido');
    }
    // Construir claims desde la respuesta de introspección
    claims = {
      sub: introspection.sub || '',
      username: introspection.username || '',
      app_id: introspection.aud || '',
      roles: introspection.roles || [],
      mfa_verified: introspection.mfa_verified || false,
      token_type: introspection.token_type || 'access',
      authz_version: 0, // No disponible en introspección
      iss: introspection.iss,
      aud: introspection.aud,
      exp: introspection.exp,
      iat: introspection.iat,
    };
  } else {
    // Validación offline tradicional (solo firma y expiración, NO verifica revocación)
    claims = await client.verifyToken(token);
  }

  if (options?.requiredRoles && options.requiredRoles.length > 0) {
    const userRoles = claims.roles || [];
    const hasRole = options.requiredRoles.some((r) => userRoles.includes(r));
    if (!hasRole) {
      throw new Error('Permisos insuficientes para acceder a este recurso');
    }
  }

  return claims;
}
