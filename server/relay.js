import http from 'node:http';
import { pathToFileURL } from 'node:url';
import { WebSocketServer, WebSocket } from 'ws';
import { randomBytes } from 'node:crypto';
import { createTokenVerifier } from './auth.js';
import { createBindingStore } from './bindings.js';
import { createPqProvider, importPublicBundle, publicBytesFromBundle } from '../src/crypto.js';
import { registrationBytes } from '../src/auth/registration.js';

export function createRelay({ verifySession, bindingStore, allowedOrigins = ['http://localhost:5173'] } = {}) {
  if (typeof verifySession !== 'function' || !bindingStore) throw new Error('Relay authentication is required.');
  const server = http.createServer((_req, res) => { res.writeHead(200); res.end('Ciphertext relay\n'); });
  const wss = new WebSocketServer({ server, maxPayload: 200000, verifyClient: ({ origin }) => allowedOrigins.includes(origin) });
  const clients = new Map();
  const pq = createPqProvider();
  wss.on('connection', (socket) => {
    let fingerprint;
    let session;
    let expirationTimer;
    const challenge = randomBytes(32).toString('hex');
    const registrationDeadline = setTimeout(() => socket.close(4001, 'Registration timed out.'), 15000);
    let count = 0;
    const timer = setInterval(() => { count = 0; }, 1000);
    const send = (frame) => { if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify(frame)); };
    const updateSession = (next) => {
      if (session && (session.userId !== next.userId || session.sessionId !== next.sessionId)) throw new Error('Session changed. Reconnect.');
      session = next;
      clearTimeout(expirationTimer);
      expirationTimer = setTimeout(() => socket.close(4001, 'Session expired.'), Math.max(1, next.expiresAt - Date.now()));
    };
    send({ type: 'challenge', challenge });
    let queue = Promise.resolve();
    socket.on('message', (data) => {
      if (++count > 20) { socket.close(4008, 'Rate limit exceeded.'); return; }
      queue = queue.then(async () => {
        if (socket.readyState !== WebSocket.OPEN) return;
        const frame = JSON.parse(data.toString());
        if (frame.type === 'register') {
          if (fingerprint) throw new Error('Already registered.');
          const verified = await verifySession(frame.token);
          if (!verified?.userId || !verified.sessionId || verified.expiresAt <= Date.now()) throw new Error('Invalid session.');
          if (typeof frame.publicExport !== 'string' || frame.publicExport.length > 15000 || typeof frame.proof !== 'string' || frame.proof.length > 5000) throw new Error('Invalid registration.');
          const imported = await importPublicBundle(frame.publicExport);
          const publicKey = publicBytesFromBundle(imported.publicBundle).mldsa;
          const valid = await (await pq).verify(registrationBytes(challenge, verified.userId, imported.fingerprint), new Uint8Array(Buffer.from(frame.proof, 'base64')), publicKey);
          if (!valid) throw new Error('Encryption key ownership proof failed.');
          if (socket.readyState !== WebSocket.OPEN) return;
          if (clients.has(imported.fingerprint)) throw new Error('Encryption identity is already connected.');
          bindingStore.bind(imported.fingerprint, verified.userId, imported.publicExport);
          fingerprint = imported.fingerprint;
          updateSession(verified);
          clearTimeout(registrationDeadline);
          clients.set(fingerprint, socket);
          send({ type: 'registered' });
          return;
        }
        if (!session || session.expiresAt <= Date.now()) throw new Error('Sign in before sending messages.');
        if (frame.type === 'auth') {
          updateSession(await verifySession(frame.token));
          send({ type: 'authenticated' });
          return;
        }
        if (!fingerprint || frame.type !== 'message' || frame.packet?.header?.sender !== fingerprint) throw new Error('Invalid relay frame.');
        const recipient = clients.get(frame.packet.header.recipient);
        if (!recipient || recipient.readyState !== WebSocket.OPEN) throw new Error('Recipient is offline.');
        // Forward public routing metadata and ciphertext only.
        recipient.send(JSON.stringify({ type: 'message', packet: frame.packet }));
        send({ type: 'delivered', id: frame.packet.header.id });
      }).catch(() => {
        // Never echo token/provider errors or credentials into a response.
        send({ type: 'error', message: fingerprint ? 'Unable to deliver packet or renew session.' : 'Registration failed. Check sign-in and encryption identity.' });
        if (!fingerprint) socket.close(4001, 'Registration failed.');
      });
    });
    socket.on('error', () => {});
    socket.on('close', () => { clearInterval(timer); clearTimeout(registrationDeadline); clearTimeout(expirationTimer); if (clients.get(fingerprint) === socket) clients.delete(fingerprint); });
  });
  return { server, wss };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const allowedOrigins = (process.env.RELAY_ALLOWED_ORIGINS || 'http://localhost:5173').split(',').map((origin) => origin.trim()).filter(Boolean);
    const verifySession = createTokenVerifier({ jwtKey: process.env.CLERK_JWT_KEY?.replace(/\\n/g, '\n'), secretKey: process.env.CLERK_SECRET_KEY, issuer: process.env.CLERK_ISSUER, authorizedParties: allowedOrigins });
    const { server } = createRelay({ verifySession, allowedOrigins, bindingStore: createBindingStore('data/identity-bindings.json') });
    server.listen(8787, '127.0.0.1', () => console.log('Authenticated local relay: ws://127.0.0.1:8787'));
  } catch {
    console.error('Relay configuration missing or invalid. Set Clerk server keys and CLERK_ISSUER in .env.local; see README.md.');
    process.exitCode = 1;
  }
}
