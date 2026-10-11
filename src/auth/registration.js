// Domain separation keeps login/key ownership proofs distinct from message signatures.
export function registrationBytes(challenge, userId, fingerprint) {
  if (typeof challenge !== 'string' || !/^[a-f0-9]{64}$/.test(challenge) ||
      typeof userId !== 'string' || !userId || userId.length > 200 ||
      typeof fingerprint !== 'string' || !/^[a-f0-9]{16}$/.test(fingerprint)) {
    throw new Error('Invalid registration proof context.');
  }
  return new TextEncoder().encode(JSON.stringify({ purpose: 'pq-messaging:relay-registration:v1', challenge, userId, fingerprint }));
}
