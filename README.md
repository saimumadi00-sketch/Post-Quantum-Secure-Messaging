# Post-Quantum Secure Messaging

A browser-based React prototype of hybrid encrypted messaging. It combines native Web Crypto operations with real ML-KEM-768 and ML-DSA-65 from `@noble/post-quantum` to demonstrate key management, encryption, signatures, and packet inspection.

## Getting started

Install Node.js 22.21 or newer and npm, then run:

```sh
npm ci
npm run dev
```

Open the local URL printed by Vite. Use localhost or HTTPS: Web Crypto requires a secure browser context. The browser must support Web Crypto X25519.

Without Clerk configuration, the app offers an explicit offline Alice demo. Messaging other users requires account setup below.

On Windows, if PowerShell blocks `npm.ps1`, use `npm.cmd` in place of `npm`.

To build and preview the production bundle:

```sh
npm run build
npm run preview
```

## Messaging between two browsers

Complete the Clerk setup first.

Start the local relay in a second terminal:

```sh
npm run relay
```

1. Open the Vite app in two separate browser profiles (or one normal and one private window) and sign in with two accounts. Each window creates its own encryption identity.
2. Wait for **Relay connected** in both windows.
3. Copy the public key export from each window and add it as a contact in the other.
4. Compare the displayed fingerprints directly with the other person's window before sending.
5. Select the imported contact and click **Encrypt & Send**. The receiving window verifies the packet before adding it to the thread; click **Decrypt** to reveal it.

Both clients must be online. The relay binds to `127.0.0.1:8787` and forwards ciphertext and public routing metadata. It verifies Clerk sessions and requires a fresh ML-DSA proof before binding an encryption identity to an account. It does not retain offline messages. `VITE_RELAY_URL` can override the default WebSocket URL; an HTTPS client requires a secure `wss://` endpoint. Use **Reconnect** after restarting the relay.

The built-in Alice contact remains a local demo. Messages to Alice do not pass through the relay. Refreshing either window changes its identity, so exchange the new public bundles again.

## Features

- Generate a local hybrid identity and a demo contact named Alice.
- Copy public key bundles and import contacts from Base64-encoded bundles.
- Encrypt messages and inspect packet sizes and hexadecimal contents.
- Decrypt the initial Alice message and outgoing messages to demo contacts.
- Show signature verification results and hide revealed plaintext.
- Regenerate keys and replace the current contacts and threads with fresh demo data.
- Account sign-in and sign-up using the methods enabled in your Clerk application.
- Account settings for passkeys, linked social accounts, optional TOTP, backup codes, and active devices.
- Session-authenticated relay registration with proof of encryption key ownership.

Messages to imported contacts are forwarded through the relay. Imported contacts have no local private keys, so their outgoing messages cannot be decrypted in the sender's window. The recipient can decrypt them using their own identity.

## Authentication setup (Clerk)

1. Create a development application in the [Clerk Dashboard](https://dashboard.clerk.com/).
2. Copy `.env.example` to `.env.local`. Fill in `VITE_CLERK_PUBLISHABLE_KEY` and `CLERK_SECRET_KEY` from the same Clerk application. Keep the secret key server-only: never give it a `VITE_` prefix or commit `.env.local`.
3. Set `CLERK_ISSUER` to the exact issuer URL of that application's session tokens, such as `https://your-instance.clerk.accounts.dev`. The issuer is public configuration; it must match the token's `iss` claim. Use `RELAY_ALLOWED_ORIGINS=http://localhost:5173` for local development.
4. In **User & authentication**, enable email sign-up, email verification, password sign-in, and passkey sign-in.
5. In **SSO connections**, enable Google; optionally enable GitHub. Use the provider configuration that Clerk requests, including your own OAuth credentials for production.
6. In **Multi-factor authentication**, enable authenticator application (TOTP) and backup codes. Leave **Require multi-factor authentication** disabled if users should choose whether to enroll.
7. Restart `npm run dev` and `npm run relay`. Create an account, then open **Account & security** to link methods and enroll factors.

The prebuilt Clerk forms show the methods your provider has actually enabled; the application does not show fake login buttons for disabled providers. Passkeys are enrolled after sign-up and must be created and used on the same domain. Clerk currently requires a paid plan for production passkeys and MFA, while development supports trying these features. See [Clerk sign-in and MFA configuration](https://clerk.com/docs/guides/configure/auth-strategies/sign-up-sign-in-options).

The provider stores account information and manages passwords, OAuth, factors, and recovery. The relay stores public encryption bundles and their account ownership in `data/identity-bindings.json`, using atomic file replacement. Run one local relay process against this file; use a transactional database before supporting multiple relay instances.

The server validates token signatures, issuer, authorized origin, active-session status, and expiry. The browser renews its relay token every 25 seconds, and the relay disconnects when the token expires. Signed-out or switched accounts unmount the messaging app and discard its in-memory keys. Revoked sessions can remain usable until their short-lived token expires; this prototype does not query Clerk's session status on every message. See [Clerk token verification](https://clerk.com/docs/reference/backend/verify-token).

Account recovery and encryption recovery are separate. Password resets, backup codes, or linked login methods restore access to an account but cannot restore this app's ephemeral encryption keys or lost messages. Persistent encrypted key backup is not implemented.

## Cryptography and limitations

The native operations are X25519 key agreement, HKDF-SHA-256 key derivation, and AES-256-GCM encryption. The intended post-quantum algorithms are ML-KEM-768 and ML-DSA-65.

The app uses a pinned `@noble/post-quantum` provider, with no simulated fallback. Packet headers bind the protocol version, algorithm suite, message ID, and sender/recipient fingerprints through both signatures and AES-GCM associated data. Invalid signatures, malformed key bundles, wrong recipient keys, and duplicate received IDs are rejected. Replay tracking lasts for the current identity's in-memory session.

This is an educational demo and should not be used for confidential communications. Additional current limitations:

- Keys, contacts, packets, and revealed plaintext remain in memory only. Reloading the page discards them.
- Demo contact private keys are held in the same app as the local user's keys.
- The local relay does not provide TLS, offline queues, or delivery guarantees. A delivery acknowledgement means forwarding to an online socket, rather than recipient verification.
- Contact trust relies on manually comparing fingerprints. The server sees routing fingerprints and traffic timing.
- There is no forward-secrecy ratchet, protected persistent key storage, or independent security review of this application's protocol.
- JavaScript cryptography does not provide a constant-time execution guarantee.

## Verification

```sh
npm test
npm run build
```

Tests cover real-PQ round trips, altered packet fields and headers, wrong recipient keys, malformed public bundles, two independent authenticated WebSocket clients, offline-recipient errors, signed JWT verification, rejected anonymous connections, challenge replay, key ownership proofs, persistent account bindings, session renewal, and expiry. Auth tests use locally generated signing keys rather than a live Clerk tenant.

Manual acceptance checks with a configured Clerk development tenant:

- Create an email/password account and complete email verification.
- Sign out and sign in through Google; link Google from account settings for an existing user.
- Enroll a passkey, sign out, and sign in using it on the same domain.
- Enroll TOTP, save backup codes, and verify both second-factor flows.
- Sign out or switch accounts and confirm old messages and keys disappear.
- Exchange messages between two accounts, restart the relay, and reconnect.

These live provider/browser flows require your Clerk configuration and have not been verified by the automated tests.

## Project structure

| File | Purpose |
| --- | --- |
| `index.html` | HTML entry point |
| `src/main.jsx` | React root and stylesheet import |
| `src/App.jsx` | Demo state, relay client, and UI components |
| `src/crypto.js` | PQ provider, hybrid encryption, bundles, and packet validation |
| `src/auth/AuthApp.jsx` | Clerk sign-in, sign-up, account settings, and offline-demo gate |
| `src/auth/registration.js` | Domain-separated encryption-key ownership proof |
| `server/relay.js` | Authenticated local WebSocket ciphertext relay |
| `server/auth.js` | Clerk session token verification |
| `server/bindings.js` | Persistent account/encryption-identity bindings |
| `test/messaging.test.js` | Cryptography and relay integration tests |
| `test/auth.test.js` | Session, registration, and account ownership tests |
| `src/index.css` | Tailwind directives and base styles |
| `tailwind.config.js` | Tailwind configuration |
| `postcss.config.js` | PostCSS configuration |

## Stack

React 18, Vite 5, Tailwind CSS 3, Web Crypto, `@noble/post-quantum`, Clerk React/backend SDKs, and `ws`. Available npm scripts are `dev`, `build`, `preview`, `relay`, and `test`.
