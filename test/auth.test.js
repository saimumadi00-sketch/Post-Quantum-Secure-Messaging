import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { WebSocket } from 'ws';
import { createTokenVerifier } from '../server/auth.js';
import { createBindingStore } from '../server/bindings.js';
import { createRelay } from '../server/relay.js';
import { createPqProvider, generateHybridMaterial } from '../src/crypto.js';
import { testAuth, connect, register } from '../test-support/auth.js';

test('session verification rejects missing, forged, expired, wrong-issuer/origin and pending tokens', async () => {
  assert.throws(() => createTokenVerifier({}), /Configure/);
  const auth = testAuth();
  assert.equal((await auth.verifySession(auth.token())).userId, 'user_alice');
  await assert.rejects(auth.verifySession(undefined));
  await assert.rejects(auth.verifySession('invalid'));
  await assert.rejects(auth.verifySession(testAuth().token()));
  for (const overrides of [{ exp: 1 }, { iss: 'https://other.clerk.accounts.dev' }, { azp: 'http://evil.example' }, { sts: 'pending' }, { sid: '' }]) {
    await assert.rejects(auth.verifySession(auth.token('user_alice', overrides)));
  }
});

test('identity/account bindings survive restart and reject different owners or keys', (t) => {
  const directory = mkdtempSync(path.join(tmpdir(), 'pq-bindings-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const filename = path.join(directory, 'bindings.json');
  createBindingStore(filename).bind('abcd', 'user_alice', 'public-key');
  const reopened = createBindingStore(filename);
  reopened.bind('abcd', 'user_alice', 'public-key');
  assert.throws(() => reopened.bind('abcd', 'user_bob', 'public-key'), /another account/);
  assert.throws(() => reopened.bind('abcd', 'user_alice', 'different-key'), /another account/);
});

test('relay rejects anonymous traffic, wrong-key proofs, challenge replay and cross-account identity theft', { timeout: 15000 }, async (t) => {
  const auth = testAuth();
  const owners = new Map();
  const { server, wss } = createRelay({ verifySession: auth.verifySession, bindingStore: { bind(fingerprint, userId) {
    if (owners.has(fingerprint) && owners.get(fingerprint) !== userId) throw new Error('Wrong owner');
    owners.set(fingerprint, userId);
  } } });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => { for (const client of wss.clients) client.terminate(); wss.close(); server.close(); });
  const url = `ws://127.0.0.1:${server.address().port}`;
  const pq = await createPqProvider();
  const identity = await generateHybridMaterial(pq);
  const other = await generateHybridMaterial(pq);
  const anonymous = await connect(url);
  const denied = once(anonymous.socket, 'message');
  anonymous.socket.send(JSON.stringify({ type: 'message', packet: {} }));
  assert.equal(JSON.parse((await denied)[0]).type, 'error');
  const wrong = await connect(url);
  assert.equal((await register(wrong, identity, pq, 'user_alice', auth.token(), other.keys.dsa.privateKey)).type, 'error');
  const replay = await connect(url);
  assert.equal((await register({ ...replay, challenge: wrong.challenge }, identity, pq, 'user_alice', auth.token())).type, 'error');
  const valid = await connect(url);
  assert.equal((await register(valid, identity, pq, 'user_alice', auth.token())).type, 'registered');
  const renewed = once(valid.socket, 'message');
  valid.socket.send(JSON.stringify({ type: 'auth', token: auth.token() }));
  assert.equal(JSON.parse((await renewed)[0]).type, 'authenticated');
  const closed = once(valid.socket, 'close');
  valid.socket.close();
  await closed;
  const stolen = await connect(url);
  assert.equal((await register(stolen, identity, pq, 'user_bob', auth.token('user_bob'))).type, 'error');
  const badOrigin = new WebSocket(url, { origin: 'http://evil.example' });
  const error = await new Promise((resolve) => badOrigin.once('error', resolve));
  assert.match(error.message, /401|403/);
});

test('relay disconnects an expired session', { timeout: 5000 }, async (t) => {
  const { server, wss } = createRelay({ verifySession: async () => ({ userId: 'user_alice', sessionId: 'session', expiresAt: Date.now() + 150 }), bindingStore: { bind() {} } });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => { for (const client of wss.clients) client.terminate(); wss.close(); server.close(); });
  const connection = await connect(`ws://127.0.0.1:${server.address().port}`);
  const pq = await createPqProvider();
  const identity = await generateHybridMaterial(pq);
  const closed = once(connection.socket, 'close');
  assert.equal((await register(connection, identity, pq, 'user_alice', 'test-token')).type, 'registered');
  assert.equal((await closed)[0], 4001);
});
