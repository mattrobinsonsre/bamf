'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { setAuth } from '@/lib/auth'

export default function CallbackHandler() {
  const router = useRouter()
  const [error, setError] = useState('')

  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const code = params.get('code')
    const returnedState = params.get('state')
    const errorParam = params.get('error')

    if (errorParam) {
      setError(params.get('error_description') || errorParam)
      return
    }

    if (!code || !returnedState) {
      setError('Missing authorization code or state')
      return
    }

    const savedState = sessionStorage.getItem('bamf_auth_state')
    const verifier = sessionStorage.getItem('bamf_pkce_verifier')

    if (!savedState || returnedState !== savedState) {
      setError('State mismatch — possible CSRF attack')
      return
    }

    if (!verifier) {
      setError('Missing PKCE verifier — please try logging in again')
      return
    }

    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      code_verifier: verifier,
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
        setAuth(data.session_token, data.email, data.roles)
        sessionStorage.removeItem('bamf_pkce_verifier')
        sessionStorage.removeItem('bamf_auth_state')
        router.push('/')
      })
      .catch((err) => {
        setError(err.message)
      })
  }, [router])

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
