import { generateKeyPairSync, sign } from 'node:crypto';
import { once } from 'node:events';
import { WebSocket } from 'ws';
import { createTokenVerifier } from '../server/auth.js';
import { registrationBytes } from '../src/auth/registration.js';

export const origin = 'http://localhost:5173';
export function testAuth() {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const issuer = 'https://test.clerk.accounts.dev';
  const verifySession = createTokenVerifier({ jwtKey: publicKey.export({ type: 'spki', format: 'pem' }), issuer, authorizedParties: [origin] });
  const token = (userId = 'user_alice', overrides = {}) => {
    const time = Math.floor(Date.now() / 1000);
    const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid: 'test' })).toString('base64url');
    const body = Buffer.from(JSON.stringify({ sub: userId, sid: `session_${userId}`, iss: issuer, azp: origin, iat: time, nbf: time - 1, exp: time + 120, ...overrides })).toString('base64url');
    const input = `${header}.${body}`;
    return `${input}.${sign('RSA-SHA256', Buffer.from(input), privateKey).toString('base64url')}`;
  };
  return { token, verifySession };
}

export async function connect(url) {
  const socket = new WebSocket(url, { origin });
  const challenge = once(socket, 'message');
  await once(socket, 'open');
  return { socket, challenge: JSON.parse((await challenge)[0]).challenge };
}

export async function register(connection, identity, pq, userId, token, proofKey = identity.keys.dsa.privateKey) {
  const proof = await pq.sign(registrationBytes(connection.challenge, userId, identity.fingerprint), proofKey);
  const response = once(connection.socket, 'message');
  connection.socket.send(JSON.stringify({ type: 'register', token, publicExport: identity.publicExport, proof: Buffer.from(proof).toString('base64') }));
  return JSON.parse((await response)[0]);
}
