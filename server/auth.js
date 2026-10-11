import { verifyToken } from '@clerk/backend';

export function createTokenVerifier({ jwtKey, secretKey, issuer, authorizedParties }) {
  if ((!jwtKey && !secretKey) || !issuer || !authorizedParties?.length) {
    throw new Error('Configure Clerk verification keys, CLERK_ISSUER, and allowed origins before starting the relay.');
  }
  return async (token) => {
    if (typeof token !== 'string' || token.length > 16000) throw new Error('Sign in before connecting.');
    const claims = await verifyToken(token, { jwtKey, secretKey, authorizedParties });
    if (claims.iss !== issuer || !claims.sub || !claims.sid || claims.sts === 'pending' ||
        !authorizedParties.includes(claims.azp) || !Number.isFinite(claims.exp) || claims.exp * 1000 <= Date.now()) {
      throw new Error('An active session from this application is required.');
    }
    return { userId: claims.sub, sessionId: claims.sid, expiresAt: claims.exp * 1000 };
  };
}
