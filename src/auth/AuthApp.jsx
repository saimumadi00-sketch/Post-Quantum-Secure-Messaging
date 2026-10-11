import React, { useState } from 'react';
import { ClerkProvider, SignIn, SignUp, UserButton, UserProfile, useAuth, useUser } from '@clerk/react';
import App from '../App.jsx';

// Clerk widgets follow the DESIGN.md tokens.
const appearance = {
  variables: { colorPrimary: '#171717', colorBackground: '#ffffff', colorForeground: '#171717', colorMutedForeground: '#4d4d4d', colorInput: '#ffffff', colorInputForeground: '#171717', colorDanger: '#ee0000', colorWarning: '#f5a623', borderRadius: '0.375rem', fontFamily: '"Geist Variable", Inter, system-ui, sans-serif' },
};

const segment = 'h-8 rounded-md px-3 text-sm font-medium transition-colors';

function AccountApp() {
  const { isLoaded, isSignedIn, userId, sessionId, getToken } = useAuth();
  const { user } = useUser();
  const [screen, setScreen] = useState(() => new URLSearchParams(window.location.search).get('auth') === 'sign-up' ? 'sign-up' : 'sign-in');
  if (!isLoaded) return <div className="min-h-screen bg-canvas-soft p-12 text-center text-sm text-body">Loading your account…</div>;
  if (!isSignedIn) return (
    <main className="flex min-h-screen flex-col items-center justify-center gap-6 bg-canvas-soft px-4 py-12 text-ink">
      <div className="max-w-md text-center">
        <h1 className="text-[32px] font-semibold leading-10 tracking-[-1.28px]">Your account. Your choice.</h1>
        <p className="mt-3 text-sm leading-6 text-body">Choose an available sign-in method below. After joining, open account settings to add passkeys, connect other accounts, and set up an authenticator.</p>
      </div>
      <div className="flex gap-1 rounded-lg bg-canvas p-1 shadow-hairline" role="group" aria-label="Account access">
        <button aria-pressed={screen === 'sign-in'} className={`${segment} ${screen === 'sign-in' ? 'bg-ink text-on-primary' : 'text-body hover:text-ink'}`} onClick={() => setScreen('sign-in')}>Sign in</button>
        <button aria-pressed={screen === 'sign-up'} className={`${segment} ${screen === 'sign-up' ? 'bg-ink text-on-primary' : 'text-body hover:text-ink'}`} onClick={() => setScreen('sign-up')}>Create account</button>
      </div>
      {screen === 'sign-up' ? <SignUp routing="hash" signInUrl="/?auth=sign-in" forceRedirectUrl="/" /> : <SignIn routing="hash" signUpUrl="/?auth=sign-up" forceRedirectUrl="/" />}
      <p className="max-w-md text-center text-xs leading-5 text-mute">Account recovery restores sign-in access. Encryption keys and message history currently last only for this browser session.</p>
    </main>
  );
  return (
    <>
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-hairline bg-canvas px-6 py-2 font-sans text-ink">
        <div className="text-sm text-body">{user?.primaryEmailAddress?.emailAddress || user?.fullName || 'Signed in'}</div>
        <div className="flex items-center gap-3">
          <button className="h-8 rounded-md bg-canvas px-3 text-sm font-medium text-ink shadow-hairline transition-colors hover:bg-canvas-soft-2" onClick={() => setScreen(screen === 'settings' ? 'messages' : 'settings')}>{screen === 'settings' ? 'Back to messages' : 'Account & security'}</button>
          <UserButton />
        </div>
      </div>
      {screen === 'settings' && (
        <section className="min-h-screen bg-canvas-soft px-6 py-10 font-sans text-ink">
          <div className="mx-auto max-w-4xl">
            <h1 className="mb-2 text-[32px] font-semibold leading-10 tracking-[-1.28px]">Account & security</h1>
            <p className="mb-6 text-sm leading-6 text-body">Manage your available login methods, passkeys, connected accounts, two-step verification, recovery codes, and active devices. Changing login methods does not back up encryption keys.</p>
            <UserProfile routing="hash" />
          </div>
        </section>
      )}
      <div hidden={screen === 'settings'}>
        <App key={`${userId}:${sessionId}`} auth={{ userId, sessionId, getToken }} />
      </div>
    </>
  );
}

export default function AuthApp() {
  const [demo, setDemo] = useState(false);
  const publishableKey = import.meta.env.VITE_CLERK_PUBLISHABLE_KEY;
  if (!publishableKey) {
    if (demo) return <><div className="bg-warning-soft px-4 py-2 text-center font-sans text-sm text-warning-deep">Offline demo · Account sign-in is not configured. <button className="font-medium underline underline-offset-2" onClick={() => setDemo(false)}>Back</button></div><App /></>;
    return (
      <main className="flex min-h-screen items-center justify-center bg-canvas-soft p-6 text-ink">
        <div className="max-w-lg rounded-lg bg-canvas p-8 shadow-soft">
          <div className="font-mono text-xs uppercase text-mute">ML-KEM-768 · ML-DSA-65 · X25519</div>
          <h1 className="mt-3 text-[32px] font-semibold leading-10 tracking-[-1.28px]">Secure messaging.</h1>
          <p className="mt-4 leading-7 text-body">Account sign-in needs to be connected before you can message other users. Follow the authentication setup in README.md, or explore the local Alice demo.</p>
          <button className="mt-6 h-10 rounded-md bg-ink px-4 text-sm font-medium text-on-primary transition-colors hover:bg-[#383838]" onClick={() => setDemo(true)}>Explore offline demo</button>
        </div>
      </main>
    );
  }
  return <ClerkProvider publishableKey={publishableKey} appearance={appearance}><AccountApp /></ClerkProvider>;
}
