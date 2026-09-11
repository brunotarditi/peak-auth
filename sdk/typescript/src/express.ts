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
      const claims = await client.verifyToken(token);

      // Verificación de roles si se solicitaron
      if (options?.requiredRoles && options.requiredRoles.length > 0) {
        const userRoles = claims.roles || [];
        const hasRole = options.requiredRoles.some((role) => userRoles.includes(role));

        if (!hasRole) {
          return res.status(403).json({
            error: 'forbidden',
            message: 'Permisos insuficientes para acceder a este recurso',
          });
        }
      }

      req.user = claims;
      req.auth = claims;
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
