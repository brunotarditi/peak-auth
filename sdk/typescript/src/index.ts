export { PeakAuthClient } from './client.js';
export { generatePKCE, generateState, validateState } from './pkce.js';
export {
  peakAuthMiddleware,
  type ExpressAuthOptions,
  type ExpressRequest,
  type ExpressResponse,
  type ExpressNextFunction,
} from './express.js';
export { verifyNextRequest, type NextAuthOptions } from './nextjs.js';
export type {
  PeakAuthConfig,
  PeakClaims,
  PKCEPair,
  TokenResponse,
  OpenIDConfiguration,
} from './types.js';
