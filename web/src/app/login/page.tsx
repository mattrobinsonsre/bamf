'use client'

import { Suspense, useEffect, useState } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import { setAuth } from '@/lib/auth'

interface Provider {
  name: string
  type: string
}

/**
 * Generate PKCE code verifier (random 43-char base64url string)
 * and its S256 challenge.
 */
async function generatePKCE() {
  const array = new Uint8Array(32)
  crypto.getRandomValues(array)
  const verifier = base64url(array)

  const encoded = new TextEncoder().encode(verifier)
  const digest = await crypto.subtle.digest('SHA-256', encoded)
  const challenge = base64url(new Uint8Array(digest))

  return { verifier, challenge }
}

function base64url(bytes: Uint8Array): string {
  let binary = ''
  for (const b of bytes) binary += String.fromCharCode(b)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function generateState(): string {
  const array = new Uint8Array(16)
  crypto.getRandomValues(array)
  return base64url(array)
}

export default function LoginPage() {
  return (
    <Suspense fallback={
      <main className="h-screen flex items-center justify-center p-4">
        <div className="text-slate-500">Loading...</div>
      </main>
    }>
      <LoginContent />
    </Suspense>
  )
}

function LoginContent() {
  const router = useRouter()
  const searchParams = useSearchParams()
  const [providers, setProviders] = useState<Provider[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)

  // Local auth form state
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')

  // CLI redirect mode: when cli_state is present, the login form does a
  // traditional POST to /api/v1/auth/local/login which redirects the browser
  // back to the CLI's localhost callback.
  const cliState = searchParams.get('cli_state')

  // Proxy redirect: when redirect is present (from proxy auth flow), navigate
  // there after login instead of the dashboard.
  const redirectUrl = searchParams.get('redirect')

  const hasLocalProvider = providers.some((p) => p.type === 'local')
  const externalProviders = providers.filter((p) => p.type !== 'local')

  useEffect(() => {
    fetch('/api/v1/auth/providers')
      .then(async (res) => {
        if (!res.ok) throw new Error('Failed to load providers')
        const data = await res.json()
        setProviders(data.providers || [])
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false))
  }, [])

  /** Local auth: collect credentials inline, call JSON endpoint, exchange token. */
  const handleLocalLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setSubmitting(true)

    try {
      const { verifier, challenge } = await generatePKCE()
      const state = generateState()

      // Step 1: Authenticate + get bamf_code in one call
      const authRes = await fetch('/api/v1/auth/local/authorize', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email,
          password,
          code_challenge: challenge,
          code_challenge_method: 'S256',
          state,
        }),
      })

      if (!authRes.ok) {
        const data = await authRes.json().catch(() => ({}))
        throw new Error(data.detail || `Authentication failed (${authRes.status})`)
      }

      const { code } = await authRes.json()

      // Step 2: Exchange bamf_code + PKCE verifier for session token.
      // credentials: 'include' ensures the browser processes Set-Cookie
      // headers in the response (needed for the bamf_session cookie on
      // the parent domain to be persisted for proxy subdomains).
      const tokenRes = await fetch('/api/v1/auth/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        credentials: 'include',
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          code_verifier: verifier,
        }).toString(),
      })

      if (!tokenRes.ok) {
        const data = await tokenRes.json().catch(() => ({}))
        throw new Error(data.detail || `Token exchange failed (${tokenRes.status})`)
      }

      const tokenData = await tokenRes.json()
      setAuth(tokenData.session_token, tokenData.email, tokenData.roles, tokenData.expires_at)

      // If we came from a proxy auth redirect, go back to the original URL.
      // Use window.location for cross-origin redirects (different subdomain).
      if (redirectUrl) {
        window.location.href = redirectUrl
      } else {
        router.push('/')
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed')
    } finally {
      setSubmitting(false)
    }
  }

  /** External SSO: redirect to /authorize (Auth0, Okta, etc.) */
  const startExternalLogin = async (providerName: string) => {
    try {
      const { verifier, challenge } = await generatePKCE()
      const state = generateState()

      sessionStorage.setItem('bamf_pkce_verifier', verifier)
      sessionStorage.setItem('bamf_auth_state', state)
      // Preserve redirect URL across the external SSO redirect
      if (redirectUrl) {
        sessionStorage.setItem('bamf_redirect_after_login', redirectUrl)
      }

      const params = new URLSearchParams({
        provider: providerName,
        redirect_uri: `${window.location.origin}/auth/callback`,
        code_challenge: challenge,
        code_challenge_method: 'S256',
        state,
        response_type: 'code',
      })

      window.location.href = `/api/v1/auth/authorize?${params.toString()}`
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start login')
    }
  }

  const subtitle = cliState
    ? 'Sign in to complete CLI authentication'
    : 'Sign in to access your resources'

  return (
    <main className="h-screen flex flex-col items-center justify-center p-4 pb-[20vh]">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <img src="/logo.svg" alt="BAMF" className="w-24 h-24 mx-auto mb-4" />
          <h1 className="text-3xl font-bold">BAMF</h1>
          <p className="text-slate-400 mt-2">{subtitle}</p>
        </div>

        <div className="bg-slate-800 rounded-lg shadow-lg p-6 border border-slate-700/50">
          {error && (
            <div className="mb-4 p-3 bg-red-900/30 text-red-400 rounded-lg text-sm border border-red-800/50">
              {error}
            </div>
          )}

          {loading ? (
            <div className="text-center text-slate-500 py-4">Loading...</div>
          ) : (
            <div className="space-y-4">
              {/* Local auth form */}
              {hasLocalProvider && cliState ? (
                // CLI mode: traditional form POST that redirects to CLI callback
                <form method="POST" action="/api/v1/auth/local/login" className="space-y-3">
                  <input type="hidden" name="state" value={cliState} />
                  <div>
                    <label htmlFor="email" className="block text-sm font-medium text-slate-300 mb-1">
                      Email
                    </label>
                    <input
                      id="email"
                      name="email"
                      type="text"
                      required
                      autoComplete="username"
                      autoFocus
                      className="w-full px-3 py-2 border border-slate-600 rounded-lg bg-slate-700 text-slate-100 focus:outline-none focus:ring-2 focus:ring-brand-500 focus:border-transparent"
                    />
                  </div>
                  <div>
                    <label htmlFor="password" className="block text-sm font-medium text-slate-300 mb-1">
                      Password
                    </label>
                    <input
                      id="password"
                      name="password"
                      type="password"
                      required
                      autoComplete="current-password"
                      className="w-full px-3 py-2 border border-slate-600 rounded-lg bg-slate-700 text-slate-100 focus:outline-none focus:ring-2 focus:ring-brand-500 focus:border-transparent"
                    />
                  </div>
                  <button
                    type="submit"
                    className="w-full font-medium py-3 px-4 rounded-lg transition-colors bg-brand-600 hover:bg-brand-500 text-white btn-smoke"
                  >
                    Sign in
                  </button>
                </form>
              ) : hasLocalProvider ? (
                // Web UI mode: SPA fetch-based login
                <form onSubmit={handleLocalLogin} className="space-y-3">
                  <div>
                    <label htmlFor="email" className="block text-sm font-medium text-slate-300 mb-1">
                      Email
                    </label>
                    <input
                      id="email"
                      type="text"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      required
                      autoComplete="username"
                      autoFocus
                      className="w-full px-3 py-2 border border-slate-600 rounded-lg bg-slate-700 text-slate-100 focus:outline-none focus:ring-2 focus:ring-brand-500 focus:border-transparent"
                    />
                  </div>
                  <div>
                    <label htmlFor="password" className="block text-sm font-medium text-slate-300 mb-1">
                      Password
                    </label>
                    <input
                      id="password"
                      type="password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      required
                      autoComplete="current-password"
                      className="w-full px-3 py-2 border border-slate-600 rounded-lg bg-slate-700 text-slate-100 focus:outline-none focus:ring-2 focus:ring-brand-500 focus:border-transparent"
                    />
                  </div>
                  <button
                    type="submit"
                    disabled={submitting}
                    className="w-full font-medium py-3 px-4 rounded-lg transition-colors bg-brand-600 hover:bg-brand-500 disabled:bg-brand-800 disabled:text-brand-400 text-white btn-smoke"
                  >
                    {submitting ? 'Signing in...' : 'Sign in'}
                  </button>
                </form>
              ) : null}

              {/* Divider between local and SSO */}
              {hasLocalProvider && externalProviders.length > 0 && !cliState && (
                <div className="relative">
                  <div className="absolute inset-0 flex items-center">
                    <div className="w-full border-t border-slate-600" />
                  </div>
                  <div className="relative flex justify-center text-sm">
                    <span className="px-2 bg-slate-800 text-slate-500">or</span>
                  </div>
                </div>
              )}

              {/* External SSO providers (hidden in CLI mode — CLI specifies the provider) */}
              {!cliState && externalProviders.map((provider) => (
                <button
                  key={provider.name}
                  onClick={() => startExternalLogin(provider.name)}
                  className="w-full font-medium py-3 px-4 rounded-lg transition-colors bg-brand-700 hover:bg-brand-600 text-white"
                >
                  Sign in with {provider.name}
                </button>
              ))}

              {providers.length === 0 && !error && (
                <p className="text-center text-slate-500">
                  No authentication providers configured
                </p>
              )}
            </div>
          )}
        </div>
      </div>
    </main>
  )
}
