'use client'

import { useEffect, useMemo, useState } from 'react'
import { useRouter } from 'next/navigation'
import { setAuth } from '@/lib/auth'

interface CallbackState {
  error: string
  code: string
  verifier: string
}

function validateCallback(): CallbackState {
  if (typeof window === 'undefined') return { error: '', code: '', verifier: '' }

  const params = new URLSearchParams(window.location.search)

  const errorParam = params.get('error')
  if (errorParam) return { error: params.get('error_description') || errorParam, code: '', verifier: '' }

  const code = params.get('code')
  const returnedState = params.get('state')
  if (!code || !returnedState) return { error: 'Missing authorization code or state', code: '', verifier: '' }

  const savedState = sessionStorage.getItem('bamf_auth_state')
  if (!savedState || returnedState !== savedState) {
    return { error: 'State mismatch — possible CSRF attack', code: '', verifier: '' }
  }

  const verifier = sessionStorage.getItem('bamf_pkce_verifier')
  if (!verifier) {
    return { error: 'Missing PKCE verifier — please try logging in again', code: '', verifier: '' }
  }

  return { error: '', code, verifier }
}

export default function CallbackHandler() {
  const router = useRouter()
  const initial = useMemo(() => validateCallback(), [])
  const [error, setError] = useState(initial.error)

  useEffect(() => {
    if (initial.error || !initial.code || !initial.verifier) return

    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code: initial.code,
      code_verifier: initial.verifier,
    })

    fetch('/api/v1/auth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    })
      .then(async (res) => {
        if (!res.ok) {
          const data = await res.json().catch(() => ({}))
          throw new Error(data.detail || `Token exchange failed (${res.status})`)
        }
        return res.json()
      })
      .then((data) => {
        setAuth(data.session_token, data.email, data.roles, data.expires_at)
        sessionStorage.removeItem('bamf_pkce_verifier')
        sessionStorage.removeItem('bamf_auth_state')
        const redirect = sessionStorage.getItem('bamf_redirect_after_login')
        sessionStorage.removeItem('bamf_redirect_after_login')
        if (redirect) {
          window.location.href = redirect
        } else {
          router.push('/')
        }
      })
      .catch((err) => {
        setError(err.message)
      })
  }, [router, initial])

  if (error) {
    return (
      <main className="min-h-screen flex items-center justify-center p-4">
        <div className="w-full max-w-md text-center">
          <img src="/logo.svg" alt="BAMF" className="w-16 h-16 mx-auto mb-4" />
          <h1 className="text-xl font-bold mb-2">Authentication Failed</h1>
          <p className="text-red-400 mb-6">{error}</p>
          <a
            href="/login"
            className="bg-brand-600 hover:bg-brand-500 text-white font-medium py-2 px-6 rounded-lg transition-colors inline-block btn-smoke"
          >
            Try Again
          </a>
        </div>
      </main>
    )
  }

  return (
    <main className="min-h-screen flex items-center justify-center">
      <div className="text-center">
        <img src="/logo.svg" alt="BAMF" className="w-16 h-16 mx-auto mb-4 animate-pulse" />
        <p className="text-slate-500">Completing sign in...</p>
      </div>
    </main>
  )
}
