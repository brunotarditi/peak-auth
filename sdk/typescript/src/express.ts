import type { PeakAuthClient } from './client.js';
import type { PeakClaims } from './types.js';

export interface ExpressAuthOptions {
  /**
   * Roles requeridos para acceder a la ruta. Si el usuario no tiene al menos uno, responde 403.
   */
  requiredRoles?: string[];

  /**
   * Mensaje de error personalizado en caso de falla de autenticación.
   */
  unauthorizedMessage?: string;

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

export interface ExpressRequest {
  headers: {
    authorization?: string;
    [key: string]: string | string[] | undefined;
  };
  user?: PeakClaims;
  auth?: PeakClaims;
  [key: string]: unknown;
}

export interface ExpressResponse {
  status(code: number): this;
  json(body: unknown): unknown;
  [key: string]: unknown;
}

export type ExpressNextFunction = (err?: unknown) => void;

/**
 * Middleware para Express que protege rutas validando el token Bearer JWT contra Peak Auth vía JWKS.
 * Por defecto, usa introspección online si clientSecret está configurado para detectar revocación inmediata.
 */
export function peakAuthMiddleware(
  client: PeakAuthClient,
  options?: ExpressAuthOptions
) {
  return async (req: ExpressRequest, res: ExpressResponse, next: ExpressNextFunction) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.toLowerCase().startsWith('bearer ')) {
      return res.status(401).json({
        error: 'unauthorized',
        message: options?.unauthorizedMessage || 'Token Bearer no proporcionado',
      });
    }

    const token = authHeader.slice(7).trim();

    try {
      let userRoles: string[] = [];

      // Determinar modo de validación: por defecto usa introspección si clientSecret está disponible
      const useIntrospection = options?.useIntrospection !== undefined
        ? options.useIntrospection
        : client.hasClientSecret();

      if (useIntrospection) {
        // Validación online con verificación de revocación
        const introspection = await client.introspectToken(token);
        if (!introspection.active) {
          return res.status(401).json({
            error: 'invalid_token',
            message: 'Token revocado o inválido',
          });
        }
        userRoles = introspection.roles || [];
        // Construir claims desde la respuesta de introspección
        req.user = {
          sub: introspection.sub || '',
          username: introspection.username || '',
          app_id: introspection.aud || '',
          roles: userRoles,
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
        const claims = await client.verifyToken(token);
        userRoles = claims.roles || [];
        req.user = claims;
      }

      // Verificación de roles si se solicitaron
      if (options?.requiredRoles && options.requiredRoles.length > 0) {
        const hasRole = options.requiredRoles.some((role) => userRoles.includes(role));

        if (!hasRole) {
          return res.status(403).json({
            error: 'forbidden',
            message: 'Permisos insuficientes para acceder a este recurso',
          });
        }
      }

      req.auth = req.user;
      next();
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Token inválido';
      return res.status(401).json({
        error: 'invalid_token',
        message,
      });
    }
  };
}
