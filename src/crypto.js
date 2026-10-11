import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
const KEM_ALG = "ML-KEM-768";
const SIG_ALG = "ML-DSA-65";
const KEX_ALG = "X25519";
const AES_ALG = "AES-256-GCM";
const HKDF_INFO = new TextEncoder().encode("pq-secure-messaging:v1:aes-256-gcm");

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function ensureWebCrypto() {
  if (!globalThis.crypto?.subtle) {
    throw new Error("Web Crypto API is unavailable in this browser.");
  }
  return globalThis.crypto;
}

function newId(prefix) {
  return `${prefix}-${globalThis.crypto?.randomUUID?.() || `${Date.now()}-${Math.random().toString(16).slice(2)}`}`;
}

function randomBytes(length) {
  const out = new Uint8Array(length);
  ensureWebCrypto().getRandomValues(out);
  return out;
}

function concatBytes(...chunks) {
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

function toHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function shortHex(bytes, chars = 80) {
  const value = toHex(bytes);
  return value.length > chars ? `${value.slice(0, chars)}...` : value;
}

function bytesToBase64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

function base64ToBytes(value) {
  const normalized = value.trim().replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

function formatBytes(length) {
  return `${Math.round(length)} B`;
}

async function sha256(bytes) {
  return new Uint8Array(await ensureWebCrypto().subtle.digest("SHA-256", bytes));
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}

async function generateX25519KeyPair() {
  const pair = await ensureWebCrypto().subtle.generateKey({ name: KEX_ALG }, true, ["deriveBits"]);
  return {
    publicKey: pair.publicKey,
    privateKey: pair.privateKey,
    publicRaw: new Uint8Array(await ensureWebCrypto().subtle.exportKey("raw", pair.publicKey)),
  };
}

async function deriveX25519(privateKey, peerPublicRaw) {
  const peerPublicKey = await ensureWebCrypto().subtle.importKey("raw", peerPublicRaw, { name: KEX_ALG }, false, []);
  return new Uint8Array(
    await ensureWebCrypto().subtle.deriveBits({ name: KEX_ALG, public: peerPublicKey }, privateKey, 256)
  );
}

async function deriveAesKey(pqSecret, classicalSecret, kemCiphertext, senderX25519Public, recipientX25519Public) {
  const ikm = concatBytes(pqSecret, classicalSecret);
  const salt = await sha256(concatBytes(kemCiphertext, senderX25519Public, recipientX25519Public));
  const hkdfKey = await ensureWebCrypto().subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);

  // RFC 5869: HKDF-SHA-256 extracts from PQ + classical shared secrets and expands to 32 bytes.
  const aesRaw = new Uint8Array(
    await ensureWebCrypto().subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt, info: HKDF_INFO },
      hkdfKey,
      256
    )
  );

  return ensureWebCrypto().subtle.importKey("raw", aesRaw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

function canonicalPublicBundle(bundle) {
  return {
    version: 1,
    alg: { kex: KEX_ALG, kem: KEM_ALG, sig: SIG_ALG },
    x25519: bundle.x25519,
    mlkem: bundle.mlkem,
    mldsa: bundle.mldsa,
  };
}

function publicBundleBytes(bundle) {
  return encoder.encode(JSON.stringify(canonicalPublicBundle(bundle)));
}

function exportPublicBundle(bundle) {
  return bytesToBase64(publicBundleBytes(bundle));
}

function publicBytesFromBundle(bundle) {
  validateBundle(bundle);
  return {
    x25519: base64ToBytes(bundle.x25519),
    mlkem: base64ToBytes(bundle.mlkem),
    mldsa: base64ToBytes(bundle.mldsa),
  };
}

async function fingerprintForBundle(bundle) {
  return toHex(await sha256(publicBundleBytes(bundle))).slice(0, 16);
}

async function importPublicBundle(value) {
  const parsed = JSON.parse(decoder.decode(base64ToBytes(value)));
  validateBundle(parsed);
  const bundle = canonicalPublicBundle(parsed);
  const publicBytes = publicBytesFromBundle(bundle);
  if (publicBytes.x25519.length !== 32) throw new Error("Imported public key is not an X25519 bundle.");
  if (!publicBytes.mlkem.length || !publicBytes.mldsa.length) throw new Error("Imported public key is missing PQ keys.");
  return {
    publicBundle: bundle,
    publicExport: exportPublicBundle(bundle),
    fingerprint: await fingerprintForBundle(bundle),
  };
}

async function generateHybridMaterial(pq) {
  const x25519 = await generateX25519KeyPair();
  const kem = await pq.generateKemKeyPair();
  const dsa = await pq.generateDsaKeyPair();

  const publicBundle = canonicalPublicBundle({
    x25519: bytesToBase64(x25519.publicRaw),
    mlkem: bytesToBase64(kem.publicKey),
    mldsa: bytesToBase64(dsa.publicKey),
  });

  return {
    keys: { x25519, kem, dsa },
    publicBundle,
    publicExport: exportPublicBundle(publicBundle),
    fingerprint: await fingerprintForBundle(publicBundle),
  };
}

function packetBytes(packet) {
  if (!packet || typeof packet !== 'object') throw new Error('Invalid packet.');
  for (const key of ['kem_ct', 'iv', 'ciphertext', 'tag', 'signature']) {
    if (typeof packet[key] !== 'string' || packet[key].length > 200000) throw new Error('Invalid packet field.');
  }
  if (base64ToBytes(packet.kem_ct).length !== 1088 || base64ToBytes(packet.iv).length !== 12 || base64ToBytes(packet.tag).length !== 16 || base64ToBytes(packet.signature).length !== 3309) throw new Error('Invalid packet lengths.');
  return {
    kemCt: base64ToBytes(packet.kem_ct),
    iv: base64ToBytes(packet.iv),
    ciphertext: base64ToBytes(packet.ciphertext),
    tag: base64ToBytes(packet.tag),
    signature: base64ToBytes(packet.signature),
  };
}

function packetToWireBytes(packet) {
  const fields = packetBytes(packet);
  return concatBytes(fields.kemCt, fields.iv, fields.ciphertext, fields.tag, fields.signature);
}

function signedPayload(kemCt, ciphertext, iv, tag, header) {
  return concatBytes(encoder.encode(JSON.stringify(header)), kemCt, ciphertext, iv, tag);
}

async function encryptMessage({ plaintext, senderKeys, senderPublicBundle, recipientPublicBundle, pq }) {
  const recipientPublic = publicBytesFromBundle(recipientPublicBundle);

  // FIPS 203: ML-KEM-768 encapsulates a PQ shared secret to the recipient public key.
  const kem = await pq.kemEncapsulate(recipientPublic.mlkem);

  // RFC 7748: X25519 ECDH derives the classical shared secret through Web Crypto.
  const classicalSecret = await deriveX25519(senderKeys.x25519.privateKey, recipientPublic.x25519);

  const aesKey = await deriveAesKey(
    kem.sharedSecret,
    classicalSecret,
    kem.ciphertext,
    senderKeys.x25519.publicRaw,
    recipientPublic.x25519
  );

  const header = { version: 2, suite: 'X25519+ML-KEM-768+ML-DSA-65+AES-256-GCM', id: newId('packet'), sender: await fingerprintForBundle(senderPublicBundle), recipient: await fingerprintForBundle(recipientPublicBundle) };
  const additionalData = encoder.encode(JSON.stringify(header));
  const iv = randomBytes(12);

  // FIPS 197 AES + NIST SP 800-38D: AES-256-GCM encrypts plaintext with a 12-byte IV and 16-byte tag.
  const sealed = new Uint8Array(
    await ensureWebCrypto().subtle.encrypt(
      { name: "AES-GCM", iv, tagLength: 128, additionalData },
      aesKey,
      encoder.encode(plaintext)
    )
  );
  const ciphertext = sealed.slice(0, sealed.length - 16);
  const tag = sealed.slice(sealed.length - 16);

  // FIPS 204: ML-DSA-65 signs KEM_ct || AES_ct || IV || tag.
  const signature = await pq.sign(signedPayload(kem.ciphertext, ciphertext, iv, tag, header), senderKeys.dsa.privateKey);

  return {
    packet: {
      header,
      kem_ct: bytesToBase64(kem.ciphertext),
      iv: bytesToBase64(iv),
      ciphertext: bytesToBase64(ciphertext),
      tag: bytesToBase64(tag),
      signature: bytesToBase64(signature),
    },
    byteCounts: {
      kemCt: kem.ciphertext.length,
      iv: iv.length,
      ciphertext: ciphertext.length,
      tag: tag.length,
      signature: signature.length,
    },
    simulatedPq: pq.simulated,
  };
}

async function decryptMessage({ message, recipientKeys, pq }) {
  const header = message.packet?.header;
  if (!header || header.version !== 2 || header.suite !== 'X25519+ML-KEM-768+ML-DSA-65+AES-256-GCM' || typeof header.id !== 'string' || header.id.length > 100 || header.sender !== await fingerprintForBundle(message.senderPublicBundle) || header.recipient !== await fingerprintForBundle(message.recipientPublicBundle)) throw new Error('Invalid authenticated packet header.');
  if (!constantTimeEqual(base64ToBytes(message.recipientPublicBundle.x25519), recipientKeys.x25519.publicRaw)) throw new Error('Wrong recipient key.');
  const senderPublic = publicBytesFromBundle(message.senderPublicBundle);
  const fields = packetBytes(message.packet);

  // FIPS 203: ML-KEM-768 decapsulates the PQ shared secret with the recipient private key.
  const pqSecret = await pq.kemDecapsulate(fields.kemCt, recipientKeys.kem.privateKey);

  // RFC 7748: X25519 ECDH derives the classical shared secret through Web Crypto.
  const classicalSecret = await deriveX25519(recipientKeys.x25519.privateKey, senderPublic.x25519);

  const aesKey = await deriveAesKey(
    pqSecret,
    classicalSecret,
    fields.kemCt,
    senderPublic.x25519,
    recipientKeys.x25519.publicRaw
  );

  // FIPS 204: ML-DSA-65 verifies KEM_ct || AES_ct || IV || tag before plaintext display.
  const signatureValid = await pq.verify(
    signedPayload(fields.kemCt, fields.ciphertext, fields.iv, fields.tag, header),
    fields.signature,
    senderPublic.mldsa
  );

  if (!signatureValid) throw new Error("Invalid signature: message rejected.");

  // FIPS 197 AES + NIST SP 800-38D: AES-256-GCM opens ciphertext || tag with the derived key.
  const opened = await ensureWebCrypto().subtle.decrypt(
    { name: "AES-GCM", iv: fields.iv, tagLength: 128, additionalData: encoder.encode(JSON.stringify(header)) },
    aesKey,
    concatBytes(fields.ciphertext, fields.tag)
  );

  return { plaintext: decoder.decode(opened), signatureValid };
}

async function buildDemoApp(pq) {
  const identity = await generateHybridMaterial(pq);
  const aliceMaterial = await generateHybridMaterial(pq);
  const aliceId = newId("alice");

  const alice = {
    id: aliceId,
    name: "Alice",
    publicBundle: aliceMaterial.publicBundle,
    publicExport: aliceMaterial.publicExport,
    fingerprint: aliceMaterial.fingerprint,
    privateKeys: aliceMaterial.keys,
    demoPrivate: true,
  };

  const encrypted = await encryptMessage({
    plaintext: "Post-quantum hello from Alice. This packet was sealed to your hybrid public key.",
    senderKeys: aliceMaterial.keys,
    senderPublicBundle: aliceMaterial.publicBundle,
    recipientPublicBundle: identity.publicBundle,
    pq,
  });

  const demoMessage = {
    id: newId("msg"),
    contactId: aliceId,
    direction: "incoming",
    senderId: aliceId,
    recipientId: "me",
    senderName: "Alice",
    recipientName: "You",
    senderPublicBundle: aliceMaterial.publicBundle,
    recipientPublicBundle: identity.publicBundle,
    packet: encrypted.packet,
    byteCounts: encrypted.byteCounts,
    simulatedPq: encrypted.simulatedPq,
    createdAt: Date.now(),
    decrypted: null,
  };

  return {
    identity,
    contacts: [alice],
    selectedContactId: aliceId,
    messages: { [aliceId]: [demoMessage] },
  };
}


function validateBundle(bundle) {
  if (!bundle || bundle.version !== 1 || bundle.alg?.kex !== KEX_ALG || bundle.alg?.kem !== KEM_ALG || bundle.alg?.sig !== SIG_ALG) throw new Error('Unsupported public key bundle.');
  for (const [field, length] of [['x25519', 32], ['mlkem', 1184], ['mldsa', 1952]]) {
    if (typeof bundle[field] !== 'string' || bundle[field].length > 10000 || base64ToBytes(bundle[field]).length !== length) throw new Error('Invalid ' + field + ' public key length.');
  }
}
async function createPqProvider() {
  return {
    name: 'noble-post-quantum', simulated: false,
    async generateKemKeyPair() { const pair = ml_kem768.keygen(); return { publicKey: pair.publicKey, privateKey: pair.secretKey }; },
    async kemEncapsulate(publicKey) { const result = ml_kem768.encapsulate(publicKey); return { ciphertext: result.cipherText, sharedSecret: result.sharedSecret }; },
    async kemDecapsulate(ciphertext, privateKey) { return ml_kem768.decapsulate(ciphertext, privateKey); },
    async generateDsaKeyPair() { const pair = ml_dsa65.keygen(); return { publicKey: pair.publicKey, privateKey: pair.secretKey }; },
    async sign(message, privateKey) { return ml_dsa65.sign(message, privateKey); },
    async verify(message, signature, publicKey) { return ml_dsa65.verify(signature, message, publicKey); },
  };
}

export { KEM_ALG,SIG_ALG,KEX_ALG,AES_ALG,HKDF_INFO,newId,toHex,shortHex,formatBytes,publicBytesFromBundle,importPublicBundle,packetBytes,packetToWireBytes,encryptMessage,decryptMessage,buildDemoApp,createPqProvider,generateHybridMaterial,fingerprintForBundle };
