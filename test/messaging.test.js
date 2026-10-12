import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createRelay } from '../server/relay.js';
import { createPqProvider, generateHybridMaterial, encryptMessage, decryptMessage, importPublicBundle } from '../src/crypto.js';
import { testAuth, connect, register } from '../test-support/auth.js';

test('real PQ round trip rejects tampering, wrong keys, and invalid bundles', async () => {
  const pq = await createPqProvider();
  const sender = await generateHybridMaterial(pq);
  const recipient = await generateHybridMaterial(pq);
  const encrypted = await encryptMessage({ plaintext: 'Hello বাংলা 🔒', senderKeys: sender.keys, senderPublicBundle: sender.publicBundle, recipientPublicBundle: recipient.publicBundle, pq });
  assert.equal(pq.name, 'noble-post-quantum');
  assert.equal(encrypted.byteCounts.signature, 3309);
  const message = { packet: encrypted.packet, senderPublicBundle: sender.publicBundle, recipientPublicBundle: recipient.publicBundle };
  const open = (candidate, keys = recipient.keys) => decryptMessage({ message: candidate, recipientKeys: keys, pq });
  assert.equal((await open(message)).plaintext, 'Hello বাংলা 🔒');
  for (const field of ['signature', 'ciphertext', 'kem_ct', 'iv', 'tag']) {
    const altered = structuredClone(message);
    const bytes = Buffer.from(altered.packet[field], 'base64');
    bytes[0] ^= 1;
    altered.packet[field] = bytes.toString('base64');
    await assert.rejects(open(altered));
  }
  const altered = structuredClone(message);
  altered.packet.header.id += '-changed';
  await assert.rejects(open(altered), /Invalid signature/);
  await assert.rejects(open(message, sender.keys), /Wrong recipient/);
  for (const mutate of [(b) => { b.version = 9; }, (b) => { b.alg.kem = 'unknown'; }, (b) => { b.mlkem = 'AA=='; }]) {
    const bundle = structuredClone(sender.publicBundle);
    mutate(bundle);
    await assert.rejects(importPublicBundle(Buffer.from(JSON.stringify(bundle)).toString('base64')));
  }
});

test('two independent clients exchange only ciphertext through local relay', { timeout: 10000 }, async (t) => {
  const auth = testAuth();
  const { server, wss } = createRelay({ verifySession: auth.verifySession, bindingStore: { bind() {} } });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => { for (const client of wss.clients) client.terminate(); wss.close(); server.close(); });
  const pq = await createPqProvider();
  const alice = await generateHybridMaterial(pq);
  const bob = await generateHybridMaterial(pq);
  const url = `ws://127.0.0.1:${server.address().port}`;
  const connectionA = await connect(url);
  const connectionB = await connect(url);
  const a = connectionA.socket;
  const b = connectionB.socket;
  for (const [connection, identity, userId] of [[connectionA, alice, 'user_alice'], [connectionB, bob, 'user_bob']]) {
    assert.equal((await register(connection, identity, pq, userId, auth.token(userId))).type, 'registered');
  }
  const { packet } = await encryptMessage({ plaintext: 'Relay hello', senderKeys: alice.keys, senderPublicBundle: alice.publicBundle, recipientPublicBundle: bob.publicBundle, pq });
  const incoming = once(b, 'message');
  const delivered = once(a, 'message');
  a.send(JSON.stringify({ type: 'message', packet }));
  const frame = JSON.parse((await incoming)[0]);
  assert.deepEqual(Object.keys(frame).sort(), ['packet', 'type']);
  assert.equal(JSON.stringify(frame).includes('Relay hello'), false);
  assert.equal((await decryptMessage({ message: { packet: frame.packet, senderPublicBundle: alice.publicBundle, recipientPublicBundle: bob.publicBundle }, recipientKeys: bob.keys, pq })).plaintext, 'Relay hello');
  assert.equal(JSON.parse((await delivered)[0]).type, 'delivered');
  const offline = once(a, 'message');
  a.send(JSON.stringify({ type: 'message', packet: { ...packet, header: { ...packet.header, recipient: '0'.repeat(32) } } }));
  assert.equal(JSON.parse((await offline)[0]).type, 'error');
});
