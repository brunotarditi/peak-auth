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
}

/**
 * Extrae y valida el JWT de una petición estándar de Next.js (Route Handler o Server Action).
 * Busca el token primero en el encabezado Authorization: Bearer, y luego en cookies.
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

  const claims = await client.verifyToken(token);

  if (options?.requiredRoles && options.requiredRoles.length > 0) {
    const userRoles = claims.roles || [];
    const hasRole = options.requiredRoles.some((r) => userRoles.includes(r));
    if (!hasRole) {
      throw new Error('Permisos insuficientes para acceder a este recurso');
    }
  }

  return claims;
}
