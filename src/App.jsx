import React, { useCallback, useEffect, useMemo, useReducer, useRef, useState } from "react";

const KEM_ALG = "ML-KEM-768";
const SIG_ALG = "ML-DSA-65";
const KEX_ALG = "X25519";
const AES_ALG = "AES-256-GCM";
const HKDF_INFO = new TextEncoder().encode("pq-secure-messaging:v1:aes-256-gcm");

const initialState = {
  phase: "booting",
  pq: null,
  identity: null,
  contacts: [],
  selectedContactId: null,
  messages: {},
  isBusy: false,
  busyLabel: "",
  toasts: [],
  bootError: "",
};

function reducer(state, action) {
  switch (action.type) {
    case "SET_BUSY":
      return { ...state, isBusy: action.isBusy, busyLabel: action.label || "" };
    case "BOOT_SUCCESS":
      return {
        ...state,
        phase: "ready",
        pq: action.pq,
        identity: action.identity,
        contacts: action.contacts,
        selectedContactId: action.selectedContactId,
        messages: action.messages,
        isBusy: false,
        busyLabel: "",
        bootError: "",
      };
    case "BOOT_ERROR":
      return { ...state, phase: "error", bootError: action.error, isBusy: false, busyLabel: "" };
    case "ADD_TOAST":
      return { ...state, toasts: [action.toast, ...state.toasts].slice(0, 4) };
    case "DISMISS_TOAST":
      return { ...state, toasts: state.toasts.filter((toast) => toast.id !== action.id) };
    case "SELECT_CONTACT":
      return { ...state, selectedContactId: action.id };
    case "ADD_CONTACT":
      return {
        ...state,
        contacts: [...state.contacts, action.contact],
        selectedContactId: action.contact.id,
        messages: { ...state.messages, [action.contact.id]: [] },
      };
    case "ADD_MESSAGE":
      return {
        ...state,
        messages: {
          ...state.messages,
          [action.message.contactId]: [...(state.messages[action.message.contactId] || []), action.message],
        },
      };
    case "SET_DECRYPTED": {
      const thread = state.messages[action.contactId] || [];
      return {
        ...state,
        messages: {
          ...state.messages,
          [action.contactId]: thread.map((message) =>
            message.id === action.messageId
              ? { ...message, decrypted: { ...action.result, revealed: true } }
              : message
          ),
        },
      };
    }
    case "HIDE_DECRYPTED": {
      const thread = state.messages[action.contactId] || [];
      return {
        ...state,
        messages: {
          ...state.messages,
          [action.contactId]: thread.map((message) =>
            message.id === action.messageId && message.decrypted
              ? { ...message, decrypted: { ...message.decrypted, revealed: false } }
              : message
          ),
        },
      };
    }
    default:
      return state;
  }
}

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

async function hmacSha256(keyBytes, message) {
  const key = await ensureWebCrypto().subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return new Uint8Array(await ensureWebCrypto().subtle.sign("HMAC", key, message));
}

function coerceBytes(value) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  if (Array.isArray(value)) return new Uint8Array(value);
  if (typeof value === "string") return base64ToBytes(value);
  throw new Error("Unable to normalize byte output from liboqs-wasm.");
}

function normalizeKeyPair(result) {
  if (Array.isArray(result)) return { publicKey: coerceBytes(result[0]), privateKey: coerceBytes(result[1]) };
  const publicValue = result.publicKey || result.public_key || result.pk;
  const privateValue = result.privateKey || result.secretKey || result.secret_key || result.sk;
  if (!publicValue || !privateValue) throw new Error("liboqs-wasm returned an unsupported keypair shape.");
  return { publicKey: coerceBytes(publicValue), privateKey: coerceBytes(privateValue) };
}

function normalizeEncapsulation(result) {
  if (Array.isArray(result)) return { ciphertext: coerceBytes(result[0]), sharedSecret: coerceBytes(result[1]) };
  const ciphertext = result.ciphertext || result.cipherText || result.ct;
  const sharedSecret = result.sharedSecret || result.shared_secret || result.ss;
  if (!ciphertext || !sharedSecret) throw new Error("liboqs-wasm returned an unsupported encapsulation shape.");
  return { ciphertext: coerceBytes(ciphertext), sharedSecret: coerceBytes(sharedSecret) };
}

async function callAny(instance, names, argOrders) {
  for (const name of names) {
    if (typeof instance?.[name] !== "function") continue;
    for (const args of argOrders) {
      try {
        return await instance[name](...args);
      } catch {
        // Try the next liboqs-wasm binding shape.
      }
    }
  }
  throw new Error("No compatible liboqs-wasm method was found.");
}

function instantiateAlgorithm(Constructor, names) {
  for (const name of names) {
    try {
      return new Constructor(name);
    } catch {
      // Try alternate NIST/legacy names.
    }
  }
  return null;
}

async function tryCreateLiboqsProvider() {
  try {
    let oqs = globalThis.liboqs || globalThis.oqs || globalThis.OQS || globalThis.Module?.liboqs;
    if (!oqs) return null;
    if (typeof oqs.default === "function") oqs = await oqs.default();
    if (typeof oqs.ready === "function") await oqs.ready();
    if (oqs.ready?.then) await oqs.ready;
    if (typeof oqs.init === "function") await oqs.init();

    const KemConstructor = oqs.KEM || oqs.Kem || oqs.OQS_KEM;
    const SigConstructor = oqs.Signature || oqs.SIG || oqs.OQS_SIG || oqs.Sign;
    if (!KemConstructor || !SigConstructor) return null;

    const makeKem = () => instantiateAlgorithm(KemConstructor, [KEM_ALG, "Kyber768"]);
    const makeSig = () => instantiateAlgorithm(SigConstructor, [SIG_ALG, "Dilithium3"]);

    const provider = {
      name: "liboqs-wasm",
      simulated: false,
      async generateKemKeyPair() {
        const kem = makeKem();
        const result = await callAny(kem, ["generateKeypair", "generate_keypair", "keypair"], [[]]);
        return normalizeKeyPair(result);
      },
      async kemEncapsulate(publicKey) {
        const kem = makeKem();
        const result = await callAny(kem, ["encapsulate", "encap", "kem_encapsulate"], [[publicKey]]);
        return normalizeEncapsulation(result);
      },
      async kemDecapsulate(ciphertext, privateKey) {
        const kem = makeKem();
        const result = await callAny(kem, ["decapsulate", "decap", "kem_decapsulate"], [
          [ciphertext, privateKey],
          [privateKey, ciphertext],
        ]);
        return coerceBytes(result.sharedSecret || result.shared_secret || result.ss || result);
      },
      async generateDsaKeyPair() {
        const sig = makeSig();
        const result = await callAny(sig, ["generateKeypair", "generate_keypair", "keypair"], [[]]);
        return normalizeKeyPair(result);
      },
      async sign(message, privateKey) {
        const sig = makeSig();
        const result = await callAny(sig, ["sign", "signDetached", "signature_sign"], [
          [message, privateKey],
          [privateKey, message],
        ]);
        return coerceBytes(result.signature || result.sig || result);
      },
      async verify(message, signature, publicKey) {
        const sig = makeSig();
        const result = await callAny(sig, ["verify", "verifyDetached", "signature_verify"], [
          [message, signature, publicKey],
          [signature, message, publicKey],
          [publicKey, message, signature],
        ]);
        return Boolean(result);
      },
    };

    const kem = await provider.generateKemKeyPair();
    const encapsulated = await provider.kemEncapsulate(kem.publicKey);
    const decapsulated = await provider.kemDecapsulate(encapsulated.ciphertext, kem.privateKey);
    const sig = await provider.generateDsaKeyPair();
    const probe = encoder.encode("liboqs-wasm probe");
    const signature = await provider.sign(probe, sig.privateKey);
    const verified = await provider.verify(probe, signature, sig.publicKey);

    return constantTimeEqual(encapsulated.sharedSecret, decapsulated) && verified ? provider : null;
  } catch {
    return null;
  }
}

function createMockPqProvider() {
  return {
    name: "deterministic mock",
    simulated: true,
    async generateKemKeyPair() {
      return {
        publicKey: randomBytes(1184),
        privateKey: { publicKey: randomBytes(0), secretKey: randomBytes(2400) },
      };
    },
    async kemEncapsulate(recipientPublicKey) {
      const nonce = randomBytes(32);
      const ciphertext = concatBytes(nonce, randomBytes(1088 - nonce.length));
      return {
        ciphertext,
        sharedSecret: await sha256(concatBytes(recipientPublicKey, nonce)),
      };
    },
    async kemDecapsulate(ciphertext, privateKey) {
      const nonce = ciphertext.slice(0, 32);
      return sha256(concatBytes(privateKey.publicKey, nonce));
    },
    async generateDsaKeyPair() {
      const seed = randomBytes(32);
      return {
        publicKey: concatBytes(seed, randomBytes(1952 - seed.length)),
        privateKey: concatBytes(seed, randomBytes(4032 - seed.length)),
      };
    },
    async sign(message, privateKey) {
      return hmacSha256(privateKey.slice(0, 32), message);
    },
    async verify(message, signature, publicKey) {
      const expected = await hmacSha256(publicKey.slice(0, 32), message);
      return constantTimeEqual(expected, signature);
    },
  };
}

async function createPqProvider() {
  return (await tryCreateLiboqsProvider()) || createMockPqProvider();
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
  if (pq.simulated && kem.privateKey.publicKey.length === 0) kem.privateKey.publicKey = kem.publicKey;
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

function signedPayload(kemCt, ciphertext, iv, tag) {
  return concatBytes(kemCt, ciphertext, iv, tag);
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

  const iv = randomBytes(12);

  // FIPS 197 AES + NIST SP 800-38D: AES-256-GCM encrypts plaintext with a 12-byte IV and 16-byte tag.
  const sealed = new Uint8Array(
    await ensureWebCrypto().subtle.encrypt(
      { name: "AES-GCM", iv, tagLength: 128 },
      aesKey,
      encoder.encode(plaintext)
    )
  );
  const ciphertext = sealed.slice(0, sealed.length - 16);
  const tag = sealed.slice(sealed.length - 16);

  // FIPS 204: ML-DSA-65 signs KEM_ct || AES_ct || IV || tag.
  const signature = await pq.sign(signedPayload(kem.ciphertext, ciphertext, iv, tag), senderKeys.dsa.privateKey);

  return {
    packet: {
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
    signedPayload(fields.kemCt, fields.ciphertext, fields.iv, fields.tag),
    fields.signature,
    senderPublic.mldsa
  );

  // FIPS 197 AES + NIST SP 800-38D: AES-256-GCM opens ciphertext || tag with the derived key.
  const opened = await ensureWebCrypto().subtle.decrypt(
    { name: "AES-GCM", iv: fields.iv, tagLength: 128 },
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

function errorText(error) {
  return error?.message || String(error);
}

function Pill({ children, tone = "purple" }) {
  const tones = {
    purple: "border-[#7c3aed]/40 bg-[#7c3aed]/15 text-violet-200",
    yellow: "border-amber-400/40 bg-amber-400/15 text-amber-200",
    green: "border-emerald-400/40 bg-emerald-400/15 text-emerald-200",
    red: "border-rose-400/40 bg-rose-400/15 text-rose-200",
    zinc: "border-white/10 bg-white/5 text-zinc-300",
  };
  return (
    <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium ${tones[tone]}`}>
      {children}
    </span>
  );
}

function SimulatedBadge() {
  return <Pill tone="yellow">⚠ Simulated PQ</Pill>;
}

function SignatureBadge({ valid }) {
  return valid ? <Pill tone="green">✓ Signature valid</Pill> : <Pill tone="red">✗ Invalid</Pill>;
}

function LockIcon({ active = false, className = "" }) {
  return (
    <svg
      viewBox="0 0 24 24"
      className={`${active ? "animate-pulse text-[#7c3aed]" : "text-zinc-300"} ${className}`}
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <rect x="4.5" y="10" width="15" height="10" rx="2" />
      <path d="M8 10V7a4 4 0 0 1 8 0v3" />
      <path d="M12 14v2" />
    </svg>
  );
}

function CopyIcon({ className = "" }) {
  return (
    <svg
      viewBox="0 0 24 24"
      className={className}
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <rect x="9" y="9" width="11" height="11" rx="2" />
      <rect x="4" y="4" width="11" height="11" rx="2" />
    </svg>
  );
}

function RefreshIcon({ className = "" }) {
  return (
    <svg
      viewBox="0 0 24 24"
      className={className}
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M20 12a8 8 0 0 1-14.8 4.2" />
      <path d="M4 12A8 8 0 0 1 18.8 7.8" />
      <path d="M18 3v5h-5" />
      <path d="M6 21v-5h5" />
    </svg>
  );
}

function SendIcon({ className = "" }) {
  return (
    <svg
      viewBox="0 0 24 24"
      className={className}
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="m22 2-7 20-4-9-9-4 20-7Z" />
      <path d="M22 2 11 13" />
    </svg>
  );
}

function ToastStack({ toasts, onDismiss }) {
  return (
    <div className="fixed right-4 top-4 z-50 flex w-[min(420px,calc(100vw-2rem))] flex-col gap-2">
      {toasts.map((toast) => (
        <div
          key={toast.id}
          className={`rounded-lg border px-3 py-2 text-sm shadow-2xl backdrop-blur ${
            toast.kind === "success"
              ? "border-emerald-400/30 bg-emerald-950/80 text-emerald-100"
              : toast.kind === "warning"
                ? "border-amber-400/30 bg-amber-950/80 text-amber-100"
                : "border-rose-400/30 bg-rose-950/80 text-rose-100"
          }`}
        >
          <div className="flex items-start justify-between gap-3">
            <span>{toast.message}</span>
            <button
              type="button"
              onClick={() => onDismiss(toast.id)}
              className="rounded px-1 text-xs text-white/70 hover:bg-white/10 hover:text-white"
              aria-label="Dismiss toast"
            >
              ×
            </button>
          </div>
        </div>
      ))}
    </div>
  );
}

function AlgorithmSidebar() {
  return (
    <aside className="rounded-lg border border-white/10 bg-white/[0.03] p-4">
      <div className="mb-4 flex items-center justify-between gap-3">
        <h2 className="text-sm font-semibold text-zinc-100">Algorithm Stack</h2>
        <Pill tone="purple">hybrid</Pill>
      </div>

      <div className="space-y-2 text-xs">
        {[
          ["ML-KEM-768", "FIPS 203"],
          ["ML-DSA-65", "FIPS 204"],
          ["AES-256-GCM", "AES + GCM"],
          ["HKDF-SHA-256", "RFC 5869"],
        ].map(([name, ref]) => (
          <div key={name} className="flex items-center justify-between rounded-md border border-white/10 bg-black/20 px-3 py-2">
            <span className="text-zinc-100">{name}</span>
            <span className="text-zinc-500">{ref}</span>
          </div>
        ))}
      </div>

      <div className="mt-5">
        <div className="mb-2 flex items-center justify-between text-[10px] text-zinc-500">
          <span>classical only</span>
          <span>hybrid</span>
          <span>full PQ</span>
        </div>
        <div className="grid h-3 grid-cols-3 gap-1 overflow-hidden rounded-full border border-white/10 bg-black/30 p-0.5">
          <div className="rounded-full bg-zinc-700" />
          <div className="rounded-full bg-[#7c3aed] shadow-[0_0_18px_rgba(124,58,237,0.6)]" />
          <div className="rounded-full bg-zinc-800" />
        </div>
        <div className="mt-3">
          <Pill tone="zinc">X25519 + ML-KEM</Pill>
        </div>
      </div>
    </aside>
  );
}

function MessageCard({ message, identity, contacts, pq, onCopy, onDecrypt, onHide }) {
  const wireBytes = useMemo(() => packetToWireBytes(message.packet), [message.packet]);
  const fields = useMemo(() => packetBytes(message.packet), [message.packet]);
  const isOutgoing = message.direction === "outgoing";
  const canReveal = Boolean(message.decrypted?.revealed);

  return (
    <div className={`flex ${isOutgoing ? "justify-end" : "justify-start"}`}>
      <div
        className={`w-full max-w-[760px] rounded-lg border p-3 ${
          isOutgoing ? "border-[#7c3aed]/30 bg-[#7c3aed]/10" : "border-white/10 bg-black/20"
        }`}
      >
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="min-w-0">
            <div className="text-xs font-semibold text-zinc-100">
              {isOutgoing ? "You → " : `${message.senderName} → `}
              {isOutgoing ? message.recipientName : "You"}
            </div>
            <div className="text-[11px] text-zinc-500">{new Date(message.createdAt).toLocaleString()}</div>
          </div>
          <div className="flex flex-wrap items-center gap-1.5">
            <Pill tone="purple">{KEM_ALG}</Pill>
            <Pill tone="purple">{AES_ALG}</Pill>
            {message.simulatedPq && <SimulatedBadge />}
          </div>
        </div>

        <div className="mt-3 rounded-md border border-white/10 bg-black/40 p-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex flex-wrap gap-1.5 text-[11px]">
              <Pill tone="zinc">KEM ct {formatBytes(fields.kemCt.length)}</Pill>
              <Pill tone="zinc">AES ct {formatBytes(fields.ciphertext.length)}</Pill>
              <Pill tone="zinc">tag {formatBytes(fields.tag.length)}</Pill>
              <Pill tone="zinc">sig {formatBytes(fields.signature.length)}</Pill>
            </div>
            <button
              type="button"
              onClick={() => onCopy(toHex(wireBytes), "Full encrypted packet copied.")}
              className="inline-flex h-8 w-8 items-center justify-center rounded-md border border-white/10 text-zinc-300 hover:border-[#7c3aed]/60 hover:text-violet-200"
              title="Copy full encrypted packet"
              aria-label="Copy full encrypted packet"
            >
              <CopyIcon className="h-4 w-4" />
            </button>
          </div>
          <pre className="mt-2 max-h-24 overflow-auto whitespace-pre-wrap break-all rounded bg-[#0d0f14] p-2 font-mono text-xs leading-5 text-violet-100">
            {shortHex(wireBytes, 80)}
          </pre>
        </div>

        <div className="mt-3 flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => (canReveal ? onHide(message) : onDecrypt(message))}
            className="inline-flex items-center gap-2 rounded-md border border-[#7c3aed]/50 bg-[#7c3aed]/20 px-3 py-2 text-xs font-semibold text-violet-100 hover:bg-[#7c3aed]/30 disabled:cursor-not-allowed disabled:opacity-50"
            disabled={!identity || !pq}
          >
            <LockIcon active={false} className="h-4 w-4" />
            {canReveal ? "Hide plaintext" : "Decrypt"}
          </button>
          {message.decrypted?.revealed && <SignatureBadge valid={message.decrypted.signatureValid} />}
        </div>

        {message.decrypted?.revealed && (
          <div className="mt-3 rounded-md border border-emerald-400/20 bg-emerald-400/10 p-3 text-sm text-emerald-50">
            <div className="mb-2 flex flex-wrap gap-1.5">
              <Pill tone="green">plaintext</Pill>
              <Pill tone="zinc">{HKDF_INFO.length} B HKDF info</Pill>
            </div>
            <p className="whitespace-pre-wrap break-words font-sans leading-6">{message.decrypted.plaintext}</p>
          </div>
        )}
      </div>
    </div>
  );
}

export default function App() {
  const [state, dispatch] = useReducer(reducer, initialState);
  const [contactName, setContactName] = useState("");
  const [contactKey, setContactKey] = useState("");
  const [composer, setComposer] = useState("");
  const initialized = useRef(false);

  const pushToast = useCallback((message, kind = "error") => {
    dispatch({ type: "ADD_TOAST", toast: { id: newId("toast"), message, kind } });
  }, []);

  const loadDemo = useCallback(
    async (existingPq = null) => {
      dispatch({ type: "SET_BUSY", isBusy: true, label: "generating keys" });
      try {
        const pq = existingPq || (await createPqProvider());
        const demo = await buildDemoApp(pq);
        dispatch({
          type: "BOOT_SUCCESS",
          pq,
          identity: demo.identity,
          contacts: demo.contacts,
          selectedContactId: demo.selectedContactId,
          messages: demo.messages,
        });
        if (pq.simulated) pushToast("liboqs-wasm unavailable; PQ primitives are running in simulated mode.", "warning");
      } catch (error) {
        dispatch({ type: "BOOT_ERROR", error: errorText(error) });
        pushToast(errorText(error), "error");
      }
    },
    [pushToast]
  );

  useEffect(() => {
    if (initialized.current) return;
    initialized.current = true;
    loadDemo();
  }, [loadDemo]);

  const selectedContact = useMemo(
    () => state.contacts.find((contact) => contact.id === state.selectedContactId) || null,
    [state.contacts, state.selectedContactId]
  );

  const thread = selectedContact ? state.messages[selectedContact.id] || [] : [];

  const keyStats = useMemo(() => {
    if (!state.identity) return null;
    const publicBytes = publicBytesFromBundle(state.identity.publicBundle);
    return {
      x25519: publicBytes.x25519.length,
      mlkem: publicBytes.mlkem.length,
      mldsa: publicBytes.mldsa.length,
    };
  }, [state.identity]);

  const copyText = useCallback(
    async (text, message = "Copied.") => {
      try {
        await navigator.clipboard.writeText(text);
        pushToast(message, "success");
      } catch (error) {
        pushToast(`Copy failed: ${errorText(error)}`, "error");
      }
    },
    [pushToast]
  );

  const handleRegenerate = useCallback(async () => {
    if (!window.confirm("Regenerate hybrid keys? Existing demo threads will be replaced.")) return;
    await loadDemo(state.pq);
    pushToast("Hybrid keys regenerated.", "success");
  }, [loadDemo, pushToast, state.pq]);

  const handleAddContact = useCallback(async () => {
    try {
      if (!contactName.trim()) throw new Error("Contact name is required.");
      if (!contactKey.trim()) throw new Error("Base64 public key is required.");

      const imported = await importPublicBundle(contactKey.trim());
      const contact = {
        id: newId("contact"),
        name: contactName.trim(),
        publicBundle: imported.publicBundle,
        publicExport: imported.publicExport,
        fingerprint: imported.fingerprint,
        privateKeys: null,
        demoPrivate: false,
      };

      dispatch({ type: "ADD_CONTACT", contact });
      setContactName("");
      setContactKey("");
      pushToast("Contact added.", "success");
    } catch (error) {
      pushToast(errorText(error), "error");
    }
  }, [contactKey, contactName, pushToast]);

  const handleSend = useCallback(async () => {
    if (!state.identity || !state.pq || !selectedContact) return;
    if (!composer.trim()) {
      pushToast("Message text is required.", "error");
      return;
    }

    dispatch({ type: "SET_BUSY", isBusy: true, label: "encrypting" });
    try {
      const encrypted = await encryptMessage({
        plaintext: composer,
        senderKeys: state.identity.keys,
        senderPublicBundle: state.identity.publicBundle,
        recipientPublicBundle: selectedContact.publicBundle,
        pq: state.pq,
      });

      const message = {
        id: newId("msg"),
        contactId: selectedContact.id,
        direction: "outgoing",
        senderId: "me",
        recipientId: selectedContact.id,
        senderName: "You",
        recipientName: selectedContact.name,
        senderPublicBundle: state.identity.publicBundle,
        recipientPublicBundle: selectedContact.publicBundle,
        packet: encrypted.packet,
        byteCounts: encrypted.byteCounts,
        simulatedPq: encrypted.simulatedPq,
        createdAt: Date.now(),
        decrypted: null,
      };

      dispatch({ type: "ADD_MESSAGE", message });
      setComposer("");
      pushToast("Encrypted packet stored in thread.", "success");
    } catch (error) {
      pushToast(errorText(error), "error");
    } finally {
      dispatch({ type: "SET_BUSY", isBusy: false });
    }
  }, [composer, pushToast, selectedContact, state.identity, state.pq]);

  const handleDecrypt = useCallback(
    async (message) => {
      if (!state.identity || !state.pq) return;

      dispatch({ type: "SET_BUSY", isBusy: true, label: "decrypting" });
      try {
        const recipientKeys =
          message.recipientId === "me"
            ? state.identity.keys
            : state.contacts.find((contact) => contact.id === message.recipientId)?.privateKeys;

        if (!recipientKeys) {
          throw new Error("Recipient private key is unavailable for imported contacts.");
        }

        const result = await decryptMessage({ message, recipientKeys, pq: state.pq });
        dispatch({ type: "SET_DECRYPTED", contactId: message.contactId, messageId: message.id, result });
      } catch (error) {
        pushToast(errorText(error), "error");
      } finally {
        dispatch({ type: "SET_BUSY", isBusy: false });
      }
    },
    [pushToast, state.contacts, state.identity, state.pq]
  );

  const handleHide = useCallback((message) => {
    dispatch({ type: "HIDE_DECRYPTED", contactId: message.contactId, messageId: message.id });
  }, []);

  return (
    <div className="min-h-screen bg-[#0d0f14] font-mono text-zinc-100">
      <ToastStack toasts={state.toasts} onDismiss={(id) => dispatch({ type: "DISMISS_TOAST", id })} />

      <header className="border-b border-white/10 bg-black/30">
        <div className="mx-auto flex max-w-7xl flex-col gap-3 px-4 py-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-[#7c3aed]/40 bg-[#7c3aed]/15">
              <LockIcon active={state.isBusy} className="h-5 w-5" />
            </div>
            <div>
              <h1 className="text-lg font-semibold text-white">Post-Quantum Secure Messaging</h1>
              <div className="mt-1 flex flex-wrap gap-1.5">
                <Pill tone="purple">{KEX_ALG}</Pill>
                <Pill tone="purple">{KEM_ALG}</Pill>
                <Pill tone="purple">{SIG_ALG}</Pill>
              </div>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {state.pq?.simulated && <SimulatedBadge />}
            <Pill tone="green">WebCrypto native</Pill>
            {state.isBusy && <Pill tone="purple">{state.busyLabel || "working"}</Pill>}
          </div>
        </div>
      </header>

      {state.phase === "booting" && (
        <main className="mx-auto flex max-w-7xl items-center justify-center px-4 py-24">
          <div className="rounded-lg border border-white/10 bg-white/[0.03] p-6 text-center">
            <LockIcon active className="mx-auto mb-4 h-9 w-9" />
            <div className="text-sm text-zinc-300">Generating hybrid key material...</div>
          </div>
        </main>
      )}

      {state.phase === "error" && (
        <main className="mx-auto max-w-2xl px-4 py-16">
          <div className="rounded-lg border border-rose-400/30 bg-rose-950/30 p-5">
            <h2 className="mb-2 text-sm font-semibold text-rose-100">Initialization failed</h2>
            <p className="break-words text-sm text-rose-200">{state.bootError}</p>
          </div>
        </main>
      )}

      {state.phase === "ready" && (
        <main className="mx-auto grid max-w-7xl grid-cols-1 gap-4 p-4 lg:grid-cols-[360px_minmax(0,1fr)]">
          <aside className="space-y-4">
            <section className="rounded-lg border border-white/10 bg-white/[0.03] p-4">
              <div className="mb-3 flex items-center justify-between gap-3">
                <h2 className="text-sm font-semibold text-zinc-100">Key Management</h2>
                <button
                  type="button"
                  onClick={handleRegenerate}
                  className="inline-flex items-center gap-2 rounded-md border border-white/10 px-2.5 py-1.5 text-xs text-zinc-200 hover:border-[#7c3aed]/60 hover:text-violet-200"
                >
                  <RefreshIcon className="h-3.5 w-3.5" />
                  Regenerate
                </button>
              </div>

              <div className="mb-3 rounded-md border border-[#7c3aed]/30 bg-[#7c3aed]/10 p-3">
                <div className="mb-1 text-[11px] text-zinc-500">public fingerprint</div>
                <div className="font-mono text-lg text-violet-100">{state.identity?.fingerprint}</div>
              </div>

              <div className="mb-3 grid grid-cols-1 gap-2 text-xs">
                <div className="flex items-center justify-between rounded-md border border-white/10 bg-black/20 px-3 py-2">
                  <Pill tone="zinc">{KEX_ALG}</Pill>
                  <span className="text-zinc-400">{keyStats && formatBytes(keyStats.x25519)}</span>
                </div>
                <div className="flex items-center justify-between rounded-md border border-white/10 bg-black/20 px-3 py-2">
                  <Pill tone="zinc">{KEM_ALG}</Pill>
                  <span className="text-zinc-400">{keyStats && formatBytes(keyStats.mlkem)}</span>
                </div>
                <div className="flex items-center justify-between rounded-md border border-white/10 bg-black/20 px-3 py-2">
                  <Pill tone="zinc">{SIG_ALG}</Pill>
                  <span className="text-zinc-400">{keyStats && formatBytes(keyStats.mldsa)}</span>
                </div>
              </div>

              <div className="text-[11px] text-zinc-500">public key export</div>
              <div className="mt-2 flex gap-2">
                <textarea
                  readOnly
                  value={state.identity?.publicExport || ""}
                  className="h-24 min-w-0 flex-1 resize-none rounded-md border border-white/10 bg-black/40 p-2 font-mono text-xs text-zinc-300 outline-none"
                />
                <button
                  type="button"
                  onClick={() => copyText(state.identity?.publicExport || "", "Public key copied.")}
                  className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-md border border-white/10 text-zinc-300 hover:border-[#7c3aed]/60 hover:text-violet-200"
                  title="Copy public key"
                  aria-label="Copy public key"
                >
                  <CopyIcon className="h-4 w-4" />
                </button>
              </div>
            </section>

            <section className="rounded-lg border border-white/10 bg-white/[0.03] p-4">
              <h2 className="mb-3 text-sm font-semibold text-zinc-100">Contact Book</h2>

              <div className="space-y-2">
                <input
                  value={contactName}
                  onChange={(event) => setContactName(event.target.value)}
                  placeholder="Display name"
                  className="w-full rounded-md border border-white/10 bg-black/40 px-3 py-2 text-sm text-zinc-100 outline-none placeholder:text-zinc-600 focus:border-[#7c3aed]/60"
                />
                <textarea
                  value={contactKey}
                  onChange={(event) => setContactKey(event.target.value)}
                  placeholder="Base64 public key"
                  className="h-20 w-full resize-none rounded-md border border-white/10 bg-black/40 px-3 py-2 text-sm text-zinc-100 outline-none placeholder:text-zinc-600 focus:border-[#7c3aed]/60"
                />
                <button
                  type="button"
                  onClick={handleAddContact}
                  className="w-full rounded-md border border-[#7c3aed]/50 bg-[#7c3aed]/20 px-3 py-2 text-sm font-semibold text-violet-100 hover:bg-[#7c3aed]/30"
                >
                  Add contact
                </button>
              </div>

              <div className="mt-4 space-y-2">
                {state.contacts.map((contact) => (
                  <button
                    key={contact.id}
                    type="button"
                    onClick={() => dispatch({ type: "SELECT_CONTACT", id: contact.id })}
                    className={`w-full rounded-md border p-3 text-left transition ${
                      contact.id === state.selectedContactId
                        ? "border-[#7c3aed]/70 bg-[#7c3aed]/15"
                        : "border-white/10 bg-black/20 hover:border-white/20"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="truncate text-sm font-semibold text-zinc-100">{contact.name}</span>
                      {contact.demoPrivate && <Pill tone="green">demo</Pill>}
                    </div>
                    <div className="mt-1 font-mono text-xs text-zinc-500">{contact.fingerprint}</div>
                  </button>
                ))}
              </div>
            </section>
          </aside>

          <section className="grid min-w-0 grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1fr)_300px]">
            <div className="flex min-w-0 flex-col rounded-lg border border-white/10 bg-white/[0.03]">
              <div className="border-b border-white/10 p-4">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <h2 className="text-sm font-semibold text-zinc-100">
                      {selectedContact ? selectedContact.name : "No contact selected"}
                    </h2>
                    {selectedContact && <div className="mt-1 font-mono text-xs text-zinc-500">{selectedContact.fingerprint}</div>}
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    <Pill tone="purple">{KEM_ALG}</Pill>
                    <Pill tone="purple">{AES_ALG}</Pill>
                  </div>
                </div>
              </div>

              <div className="h-[52vh] min-h-[420px] space-y-3 overflow-y-auto p-4">
                {thread.length === 0 && (
                  <div className="rounded-lg border border-dashed border-white/10 p-6 text-center text-sm text-zinc-500">
                    No encrypted packets in this thread.
                  </div>
                )}
                {thread.map((message) => (
                  <MessageCard
                    key={message.id}
                    message={message}
                    identity={state.identity}
                    contacts={state.contacts}
                    pq={state.pq}
                    onCopy={copyText}
                    onDecrypt={handleDecrypt}
                    onHide={handleHide}
                  />
                ))}
              </div>

              <div className="border-t border-white/10 p-4">
                <div className="flex flex-col gap-3 sm:flex-row">
                  <textarea
                    value={composer}
                    onChange={(event) => setComposer(event.target.value)}
                    placeholder={selectedContact ? `Message ${selectedContact.name}` : "Select a contact"}
                    className="min-h-24 min-w-0 flex-1 resize-none rounded-md border border-white/10 bg-black/40 px-3 py-2 text-sm text-zinc-100 outline-none placeholder:text-zinc-600 focus:border-[#7c3aed]/60"
                    disabled={!selectedContact || state.isBusy}
                  />
                  <button
                    type="button"
                    onClick={handleSend}
                    disabled={!selectedContact || state.isBusy}
                    className="inline-flex items-center justify-center gap-2 rounded-md border border-[#7c3aed]/50 bg-[#7c3aed]/25 px-4 py-3 text-sm font-semibold text-violet-100 hover:bg-[#7c3aed]/35 disabled:cursor-not-allowed disabled:opacity-50 sm:w-44"
                  >
                    <SendIcon className="h-4 w-4" />
                    Encrypt & Send
                  </button>
                </div>
              </div>
            </div>

            <AlgorithmSidebar />
          </section>
        </main>
      )}
    </div>
  );
}