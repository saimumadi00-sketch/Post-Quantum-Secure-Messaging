import React, { useCallback, useEffect, useMemo, useReducer, useRef, useState } from "react";

import { KEM_ALG,SIG_ALG,KEX_ALG,AES_ALG,newId,toHex,shortHex,formatBytes,publicBytesFromBundle,importPublicBundle,packetBytes,packetToWireBytes,encryptMessage,decryptMessage,buildDemoApp,createPqProvider } from './crypto.js';
import { registrationBytes } from './auth/registration.js';

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
    case "SET_REVEALED": {
      const thread = state.messages[action.contactId] || [];
      return {
        ...state,
        messages: {
          ...state.messages,
          [action.contactId]: thread.map((message) =>
            message.id === action.messageId && message.decrypted
              ? { ...message, decrypted: { ...message.decrypted, revealed: action.revealed } }
              : message
          ),
        },
      };
    }
    default:
      return state;
  }
}

function errorText(error) {
  return error?.message || String(error);
}

// Algorithm names, byte counts and other technical labels render in mono.
function Pill({ children, tone = "neutral", mono = false }) {
  const tones = {
    neutral: "bg-canvas-soft-2 text-body shadow-hairline",
    success: "bg-link-bg-soft text-link-deep",
    warning: "bg-warning-soft text-warning-deep",
    error: "bg-error-soft text-error-deep",
  };
  return (
    <span
      className={`inline-flex h-5 items-center whitespace-nowrap rounded-full px-2 ${
        mono ? "font-mono text-[11px]" : "text-xs font-medium"
      } ${tones[tone]}`}
    >
      {children}
    </span>
  );
}

function SignatureBadge({ valid }) {
  return valid ? <Pill tone="success">✓ Signature valid</Pill> : <Pill tone="error">✗ Invalid signature</Pill>;
}

const buttonPrimary =
  "inline-flex items-center justify-center gap-2 rounded-md bg-ink px-3 font-medium text-on-primary transition-colors hover:bg-[#383838] disabled:cursor-not-allowed disabled:bg-canvas-soft-2 disabled:text-hairline-strong disabled:shadow-hairline";
const buttonSecondary =
  "inline-flex items-center justify-center gap-2 rounded-md bg-canvas px-3 font-medium text-ink shadow-hairline transition-colors hover:bg-canvas-soft-2 disabled:cursor-not-allowed disabled:text-hairline-strong";
const iconButton =
  "inline-flex shrink-0 items-center justify-center rounded-md bg-canvas text-body shadow-hairline transition-colors hover:bg-canvas-soft-2 hover:text-ink";
const formField =
  "w-full rounded-md border border-hairline bg-canvas px-3 text-sm text-ink outline-none transition-shadow placeholder:text-mute focus:border-hairline-strong focus:ring-2 focus:ring-ink/10 disabled:bg-canvas-soft-2";
const card = "rounded-lg bg-canvas shadow-subtle";
const eyebrow = "font-mono text-xs uppercase text-mute";

function LockIcon({ active = false, className = "" }) {
  return (
    <svg
      viewBox="0 0 24 24"
      className={`${active ? "animate-pulse" : ""} ${className}`}
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
    <div className="fixed right-4 top-4 z-50 flex w-[min(420px,calc(100vw-2rem))] flex-col gap-2" role="status" aria-live="polite">
      {toasts.map((toast) => (
        <div key={toast.id} className="rounded-lg bg-canvas px-4 py-3 text-sm text-ink shadow-modal">
          <div className="flex items-start justify-between gap-3">
            <span className="flex items-start gap-2.5">
              <span
                aria-hidden="true"
                className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${
                  toast.kind === "success" ? "bg-link" : toast.kind === "warning" ? "bg-warning" : "bg-error"
                }`}
              />
              <span>{toast.message}</span>
            </span>
            <button
              type="button"
              onClick={() => onDismiss(toast.id)}
              className="rounded px-1.5 text-body hover:bg-canvas-soft-2 hover:text-ink"
              aria-label="Dismiss notification"
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
    <aside className={`${card} self-start p-5`}>
      <div className="mb-4 flex items-center justify-between gap-3">
        <h2 className="text-sm font-semibold tracking-[-0.28px]">Algorithm stack</h2>
        <Pill>Hybrid</Pill>
      </div>

      <div className="divide-y divide-hairline rounded-md shadow-hairline">
        {[
          ["ML-KEM-768", "FIPS 203"],
          ["ML-DSA-65", "FIPS 204"],
          ["AES-256-GCM", "AES + GCM"],
          ["HKDF-SHA-256", "RFC 5869"],
        ].map(([name, ref]) => (
          <div key={name} className="flex items-center justify-between px-3 py-2.5">
            <span className="font-mono text-xs text-ink">{name}</span>
            <span className="text-xs text-mute">{ref}</span>
          </div>
        ))}
      </div>

      <div className="mt-6">
        <div className={`${eyebrow} mb-2`}>Protection level</div>
        <div className="grid h-1.5 grid-cols-3 gap-1">
          <div className="rounded-full bg-hairline" />
          <div className="rounded-full bg-ink" />
          <div className="rounded-full bg-hairline" />
        </div>
        <div className="mt-2 grid grid-cols-3 text-xs text-mute">
          <span>Classical</span>
          <span className="text-center font-medium text-ink">Hybrid</span>
          <span className="text-right">Full PQ</span>
        </div>
        <div className="mt-4">
          <Pill mono>X25519 + ML-KEM</Pill>
        </div>
      </div>
    </aside>
  );
}

function MessageCard({ message, identity, pq, isBusy, onCopy, onDecrypt, onHide }) {
  const wireBytes = useMemo(() => packetToWireBytes(message.packet), [message.packet]);
  const fields = useMemo(() => packetBytes(message.packet), [message.packet]);
  const isOutgoing = message.direction === "outgoing";
  const canReveal = Boolean(message.decrypted?.revealed);

  return (
    <div className={`flex ${isOutgoing ? "justify-end" : "justify-start"}`}>
      <div className={`w-full max-w-[680px] rounded-lg p-4 ${isOutgoing ? "bg-canvas-soft shadow-hairline" : "bg-canvas shadow-subtle"}`}>
        <div className="flex flex-wrap items-start justify-between gap-2">
          <div className="min-w-0">
            <div className="text-sm font-medium tracking-[-0.28px]">
              {isOutgoing ? "You → " : `${message.senderName} → `}
              {isOutgoing ? message.recipientName : "You"}
            </div>
            <div className="text-xs text-mute">{new Date(message.createdAt).toLocaleString()}</div>
          </div>
          <div className="flex flex-wrap items-center gap-1.5">
            <Pill mono>{KEM_ALG}</Pill>
            <Pill mono>{AES_ALG}</Pill>
          </div>
        </div>

        <div className="mt-3 overflow-hidden rounded-md bg-ink">
          <div className="flex items-center justify-between gap-2 border-b border-white/10 px-3 py-2">
            <div className="flex flex-wrap gap-x-3 gap-y-1 font-mono text-[11px] text-hairline-strong">
              <span>KEM ct {formatBytes(fields.kemCt.length)}</span>
              <span>AES ct {formatBytes(fields.ciphertext.length)}</span>
              <span>tag {formatBytes(fields.tag.length)}</span>
              <span>sig {formatBytes(fields.signature.length)}</span>
            </div>
            <button
              type="button"
              onClick={() => onCopy(toHex(wireBytes), "Full encrypted packet copied.")}
              className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-md text-hairline-strong transition-colors hover:bg-white/10 hover:text-on-primary"
              title="Copy full encrypted packet"
              aria-label="Copy full encrypted packet"
            >
              <CopyIcon className="h-4 w-4" />
            </button>
          </div>
          <pre className="max-h-24 overflow-auto whitespace-pre-wrap break-all px-3 py-2.5 font-mono text-[13px] leading-5 text-[#ededed]">
            {shortHex(wireBytes, 80)}
          </pre>
        </div>

        <div className="mt-3 flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => (canReveal ? onHide(message) : onDecrypt(message))}
            className={`${canReveal ? buttonSecondary : buttonPrimary} h-8 text-sm`}
            disabled={!identity || !pq || isBusy}
          >
            <LockIcon className="h-4 w-4" />
            {canReveal ? "Hide plaintext" : "Decrypt"}
          </button>
          {message.decrypted?.revealed && <SignatureBadge valid={message.decrypted.signatureValid} />}
        </div>

        {message.decrypted?.revealed && (
          <div className="mt-3 rounded-md bg-canvas p-3 shadow-hairline">
            <div className={`${eyebrow} mb-2`}>Plaintext</div>
            <p className="whitespace-pre-wrap break-words leading-6 text-ink">{message.decrypted.plaintext}</p>
          </div>
        )}
      </div>
    </div>
  );
}

export default function App({ auth = null }) {
  const [state, dispatch] = useReducer(reducer, initialState);
  const [contactName, setContactName] = useState("");
  const [contactKey, setContactKey] = useState("");
  const [composer, setComposer] = useState("");
  const initialized = useRef(false);
  const relay = useRef(null);
  const seenPackets = useRef(new Set());
  const operation = useRef(false);
  const [relayStatus, setRelayStatus] = useState('offline');
  const [relayAttempt, setRelayAttempt] = useState(0);
  const getToken = useRef(auth?.getToken);
  getToken.current = auth?.getToken;
  const accountId = auth?.userId;
  const accountSessionId = auth?.sessionId;

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
        return true;
      } catch (error) {
        dispatch({ type: "BOOT_ERROR", error: errorText(error) });
        pushToast(errorText(error), "error");
        return false;
      }
    },
    [pushToast]
  );

  useEffect(() => {
    if (initialized.current) return;
    initialized.current = true;
    loadDemo();
  }, [loadDemo]);

  const receiveState = useRef(state);
  receiveState.current = state;
  useEffect(() => {
    if (!state.identity || !accountId || !accountSessionId) return;
    const socket = new WebSocket(import.meta.env.VITE_RELAY_URL || 'ws://127.0.0.1:8787');
    relay.current = socket;
    setRelayStatus('connecting');
    const sendToken = async () => {
      const token = await getToken.current({ skipCache: true });
      if (!token) throw new Error('Sign in again to connect.');
      if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ type: 'auth', token }));
    };
    const refresh = setInterval(() => { if (socket.readyState === WebSocket.OPEN) sendToken().catch(() => socket.close()); }, 25000);
    socket.onclose = () => { if (relay.current === socket) setRelayStatus('offline'); };
    socket.onerror = () => { if (relay.current === socket) setRelayStatus('offline'); };
    // Serialize received verification so duplicate packets cannot race.
    let queue = Promise.resolve();
    socket.onmessage = (event) => {
      queue = queue.then(async () => {
        const frame = JSON.parse(event.data);
        if (frame.type === 'challenge') {
          const token = await getToken.current({ skipCache: true });
          if (!token) throw new Error('Sign in again to connect.');
          const proof = await state.pq.sign(registrationBytes(frame.challenge, accountId, state.identity.fingerprint), state.identity.keys.dsa.privateKey);
          const encoded = btoa(String.fromCharCode(...proof));
          if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ type: 'register', token, publicExport: state.identity.publicExport, proof: encoded }));
          return;
        }
        if (frame.type === 'registered') { setRelayStatus('connected'); return; }
        if (frame.type === 'error') { pushToast(frame.message); return; }
        if (frame.type === 'delivered') { pushToast('Packet delivered to recipient browser.', 'success'); return; }
        if (frame.type !== 'message') return;
        const current = receiveState.current;
        const header = frame.packet?.header;
        if (!header || seenPackets.current.has(header.id)) throw new Error('Duplicate or invalid packet rejected.');
        const contact = current.contacts.find((entry) => !entry.demoPrivate && entry.fingerprint === header.sender);
        if (!contact) throw new Error('Unknown sender. Import and verify their public key first.');
        const message = { id: header.id, contactId: contact.id, direction: 'incoming', senderId: contact.id, recipientId: 'me', senderName: contact.name, recipientName: 'You', senderPublicBundle: contact.publicBundle, recipientPublicBundle: current.identity.publicBundle, packet: frame.packet, createdAt: Date.now(), decrypted: null };
        // Verify before accepting; keep the result hidden so Decrypt only reveals it.
        const result = await decryptMessage({ message, recipientKeys: current.identity.keys, pq: current.pq });
        if (relay.current !== socket) return;
        seenPackets.current.add(header.id);
        dispatch({ type: 'ADD_MESSAGE', message: { ...message, decrypted: { ...result, revealed: false } } });
        pushToast('Authenticated message received.', 'success');
      }).catch((error) => pushToast(errorText(error)));
    };
    return () => { clearInterval(refresh); if (relay.current === socket) relay.current = null; socket.close(); };
  }, [state.identity, pushToast, accountId, accountSessionId, relayAttempt]);

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
    if (operation.current) return;
    if (!window.confirm("Regenerate hybrid keys? Existing demo threads will be replaced.")) return;
    operation.current = true;
    let regenerated = false;
    try { regenerated = await loadDemo(state.pq); } finally { operation.current = false; }
    if (regenerated) pushToast("Hybrid keys regenerated.", "success");
  }, [loadDemo, pushToast, state.pq]);

  const handleAddContact = useCallback(async () => {
    try {
      if (!contactName.trim()) throw new Error("Contact name is required.");
      if (!contactKey.trim()) throw new Error("Base64 public key is required.");

      const imported = await importPublicBundle(contactKey.trim());
      if (state.contacts.some((contact) => contact.fingerprint === imported.fingerprint)) throw new Error("Contact already exists.");
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
  }, [contactKey, contactName, pushToast, state.contacts]);

  const handleSend = useCallback(async () => {
    if (!state.identity || !state.pq || !selectedContact || operation.current) return;
    if (!selectedContact.demoPrivate && relayStatus !== 'connected') { pushToast('Start the relay and connect the recipient browser.'); return; }
    if (!composer.trim()) {
      pushToast("Message text is required.", "error");
      return;
    }

    operation.current = true;
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
        createdAt: Date.now(),
        decrypted: null,
      };

      if (!selectedContact.demoPrivate) {
        if (relay.current?.readyState !== WebSocket.OPEN) throw new Error('Relay disconnected.');
        relay.current.send(JSON.stringify({ type: 'message', packet: encrypted.packet }));
      }
      dispatch({ type: "ADD_MESSAGE", message });
      setComposer("");
      pushToast("Encrypted packet stored in thread.", "success");
    } catch (error) {
      pushToast(errorText(error), "error");
    } finally {
      operation.current = false;
        dispatch({ type: "SET_BUSY", isBusy: false });
    }
  }, [composer, pushToast, selectedContact, state.identity, state.pq, relayStatus]);

  const handleDecrypt = useCallback(
    async (message) => {
      if (message.decrypted) {
        dispatch({ type: "SET_REVEALED", contactId: message.contactId, messageId: message.id, revealed: true });
        return;
      }
      if (!state.identity || !state.pq || operation.current) return;
      operation.current = true;

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
        operation.current = false;
      dispatch({ type: "SET_BUSY", isBusy: false });
      }
    },
    [pushToast, state.contacts, state.identity, state.pq]
  );

  const handleHide = useCallback((message) => {
    dispatch({ type: "SET_REVEALED", contactId: message.contactId, messageId: message.id, revealed: false });
  }, []);

  return (
    <div className="min-h-screen bg-canvas-soft font-sans text-ink">
      <ToastStack toasts={state.toasts} onDismiss={(id) => dispatch({ type: "DISMISS_TOAST", id })} />

      <header className="border-b border-hairline bg-canvas">
        <div className="mx-auto flex max-w-7xl flex-col gap-3 px-6 py-3 sm:min-h-16 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-8 w-8 items-center justify-center rounded-md bg-ink text-on-primary">
              <LockIcon active={state.isBusy} className="h-4 w-4" />
            </div>
            <h1 className="text-base font-semibold tracking-[-0.32px]">Post-Quantum Secure Messaging</h1>
            <div className="hidden flex-wrap gap-1.5 md:flex">
              <Pill mono>{KEX_ALG}</Pill>
              <Pill mono>{KEM_ALG}</Pill>
              <Pill mono>{SIG_ALG}</Pill>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Pill>WebCrypto + real PQ</Pill>
            <span className="inline-flex h-5 items-center gap-1.5 rounded-full bg-canvas-soft-2 px-2 text-xs font-medium text-body shadow-hairline">
              <span
                aria-hidden="true"
                className={`h-1.5 w-1.5 rounded-full ${
                  relayStatus === "connected" ? "bg-link" : relayStatus === "connecting" ? "animate-pulse bg-warning" : "bg-hairline-strong"
                }`}
              />
              Relay {relayStatus}
            </span>
            {accountId && relayStatus === 'offline' && <button className={`${buttonSecondary} h-7 text-xs`} onClick={() => setRelayAttempt((attempt) => attempt + 1)}>Reconnect</button>}
            {state.isBusy && <Pill mono>{state.busyLabel || "working"}…</Pill>}
          </div>
        </div>
      </header>

      {state.phase === "booting" && (
        <main className="mx-auto flex max-w-7xl items-center justify-center px-6 py-24">
          <div className={`${card} p-8 text-center`}>
            <LockIcon active className="mx-auto mb-4 h-8 w-8" />
            <div className="text-sm text-body">Generating hybrid key material…</div>
          </div>
        </main>
      )}

      {state.phase === "error" && (
        <main className="mx-auto max-w-2xl px-6 py-16">
          <div className="rounded-lg bg-error-soft p-5" role="alert">
            <h2 className="mb-2 text-sm font-semibold text-error-deep">Initialization failed</h2>
            <p className="break-words text-sm text-error-deep">{state.bootError}</p>
          </div>
        </main>
      )}

      {state.phase === "ready" && (
        <main className="mx-auto grid max-w-7xl grid-cols-1 gap-6 px-6 py-6 lg:grid-cols-[340px_minmax(0,1fr)]">
          <aside className="space-y-6">
            <section className={`${card} p-5`}>
              <div className="mb-4 flex items-center justify-between gap-3">
                <h2 className="text-sm font-semibold tracking-[-0.28px]">Key management</h2>
                <button
                  type="button"
                  disabled={state.isBusy}
                  onClick={handleRegenerate}
                  className={`${buttonSecondary} h-7 px-2.5 text-xs`}
                >
                  <RefreshIcon className="h-3.5 w-3.5" />
                  Regenerate
                </button>
              </div>

              <div className={eyebrow}>Public fingerprint</div>
              <div className="mt-1 break-all font-mono text-lg tracking-tight">{state.identity?.fingerprint}</div>

              <div className="mt-4 divide-y divide-hairline rounded-md shadow-hairline">
                {[
                  [KEX_ALG, keyStats?.x25519],
                  [KEM_ALG, keyStats?.mlkem],
                  [SIG_ALG, keyStats?.mldsa],
                ].map(([name, size]) => (
                  <div key={name} className="flex items-center justify-between px-3 py-2">
                    <span className="font-mono text-xs">{name}</span>
                    <span className="font-mono text-xs text-mute">{size !== undefined && formatBytes(size)}</span>
                  </div>
                ))}
              </div>

              <div className={`${eyebrow} mt-4`}>Public key export</div>
              <div className="mt-2 flex gap-2">
                <textarea
                  readOnly
                  aria-label="Public key export"
                  value={state.identity?.publicExport || ""}
                  className={`${formField} h-24 min-w-0 flex-1 resize-none bg-canvas-soft py-2 font-mono text-xs text-body`}
                />
                <button
                  type="button"
                  onClick={() => copyText(state.identity?.publicExport || "", "Public key copied.")}
                  className={`${iconButton} h-9 w-9`}
                  title="Copy public key"
                  aria-label="Copy public key"
                >
                  <CopyIcon className="h-4 w-4" />
                </button>
              </div>
            </section>

            <section className={`${card} p-5`}>
              <h2 className="mb-4 text-sm font-semibold tracking-[-0.28px]">Contact book</h2>

              <div className="space-y-2">
                <input
                  value={contactName}
                  onChange={(event) => setContactName(event.target.value)}
                  placeholder="Display name"
                  aria-label="Contact display name"
                  className={`${formField} h-10`}
                />
                <textarea
                  value={contactKey}
                  onChange={(event) => setContactKey(event.target.value)}
                  placeholder="Base64 public key"
                  aria-label="Contact base64 public key"
                  className={`${formField} h-20 resize-none py-2 font-mono text-xs`}
                />
                <button
                  type="button"
                  disabled={state.isBusy}
                  onClick={handleAddContact}
                  className={`${buttonPrimary} h-10 w-full text-sm`}
                >
                  Add contact
                </button>
              </div>

              <div className="mt-5 space-y-1">
                {state.contacts.map((contact) => {
                  const selected = contact.id === state.selectedContactId;
                  return (
                    <button
                      key={contact.id}
                      type="button"
                      aria-pressed={selected}
                      onClick={() => dispatch({ type: "SELECT_CONTACT", id: contact.id })}
                      className={`w-full rounded-md px-3 py-2.5 text-left transition-colors ${
                        selected ? "bg-canvas-soft-2 shadow-[inset_2px_0_0_var(--color-ink)]" : "hover:bg-canvas-soft"
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className={`truncate text-sm ${selected ? "font-medium text-ink" : "text-body"}`}>{contact.name}</span>
                        {contact.demoPrivate && <Pill>Demo</Pill>}
                      </div>
                      <div className="mt-0.5 font-mono text-xs text-mute">{contact.fingerprint}</div>
                    </button>
                  );
                })}
              </div>
            </section>
          </aside>

          <section className="grid min-w-0 grid-cols-1 gap-6 xl:grid-cols-[minmax(0,1fr)_280px]">
            <div className={`${card} flex min-w-0 flex-col`}>
              <div className="border-b border-hairline px-5 py-4">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <h2 className="text-xl font-semibold tracking-[-0.6px]">
                      {selectedContact ? selectedContact.name : "No contact selected"}
                    </h2>
                    {selectedContact && <div className="mt-0.5 font-mono text-xs text-mute">{selectedContact.fingerprint}</div>}
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    <Pill mono>{KEM_ALG}</Pill>
                    <Pill mono>{AES_ALG}</Pill>
                  </div>
                </div>
              </div>

              <div className="h-[52vh] min-h-[420px] space-y-4 overflow-y-auto bg-canvas-soft/60 p-5">
                {thread.length === 0 && (
                  <div className="rounded-lg border border-dashed border-hairline-strong/60 p-8 text-center text-sm text-mute">
                    No encrypted packets in this thread yet.
                  </div>
                )}
                {thread.map((message) => (
                  <MessageCard
                    key={message.id}
                    message={message}
                    identity={state.identity}
                    pq={state.pq}
                    isBusy={state.isBusy}
                    onCopy={copyText}
                    onDecrypt={handleDecrypt}
                    onHide={handleHide}
                  />
                ))}
              </div>

              <div className="border-t border-hairline p-4">
                <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
                  <textarea
                    value={composer}
                    onChange={(event) => setComposer(event.target.value)}
                    placeholder={selectedContact ? `Message ${selectedContact.name}` : "Select a contact"}
                    aria-label="Message"
                    className={`${formField} min-h-24 min-w-0 flex-1 resize-none py-2.5`}
                    disabled={!selectedContact || state.isBusy}
                  />
                  <button
                    type="button"
                    onClick={handleSend}
                    disabled={!selectedContact || state.isBusy}
                    className={`${buttonPrimary} h-10 px-4 text-sm sm:w-44`}
                  >
                    <SendIcon className="h-4 w-4" />
                    Encrypt & send
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
