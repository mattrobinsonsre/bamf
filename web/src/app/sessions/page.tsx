'use client'

import { useEffect, useMemo, useState } from 'react'
import { useRouter } from 'next/navigation'
import { Trash2 } from 'lucide-react'
import NavBar from '@/components/nav-bar'
import { getAuthState, isAdmin, clearAuth } from '@/lib/auth'

interface SessionResponse {
  email: string
  roles: string[]
  provider_name: string
  created_at: string
  expires_at: string
  last_active_at: string
  token_hint: string
  is_current: boolean
}

function timeAgo(iso: string): string {
  const seconds = Math.floor((Date.now() - new Date(iso).getTime()) / 1000)
  if (seconds < 60) return 'just now'
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  return `${days}d ago`
}

function timeUntil(iso: string): string {
  const seconds = Math.floor((new Date(iso).getTime() - Date.now()) / 1000)
  if (seconds <= 0) return 'expired'
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}m`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h`
  const days = Math.floor(hours / 24)
  return `${days}d`
}

export default function SessionsPage() {
  const router = useRouter()
  const [sessions, setSessions] = useState<SessionResponse[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [admin, setAdmin] = useState(false)
  const [revokingUser, setRevokingUser] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  useEffect(() => {
    const state = getAuthState()
    if (!state) {
      router.push('/login')
      return
    }
    setAdmin(isAdmin())
    fetchSessions()
  }, [router])

  const authHeaders = (): HeadersInit => {
    const state = getAuthState()
    if (!state) {
      clearAuth()
      router.push('/login')
      return {}
    }
    return { Authorization: `Bearer ${state.token}` }
  }

  const fetchSessions = async () => {
    try {
      const endpoint = isAdmin() ? '/api/v1/auth/sessions/all' : '/api/v1/auth/sessions'
      const response = await fetch(endpoint, { headers: authHeaders() })
      if (response.status === 401) {
        clearAuth()
        router.push('/login')
        return
      }
      if (!response.ok) throw new Error('Failed to fetch sessions')
      const data = await response.json()
      setSessions(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load sessions')
    } finally {
      setLoading(false)
    }
  }

  const handleRevokeUser = async (email: string) => {
    setSubmitting(true)
    setError('')
    try {
      const response = await fetch(`/api/v1/auth/sessions/user/${encodeURIComponent(email)}`, {
        method: 'DELETE',
        headers: authHeaders(),
      })
      if (!response.ok) {
        const b = await response.json().catch(() => ({}))
        throw new Error(b.detail || `Failed to revoke sessions (${response.status})`)
      }

      // If we revoked our own sessions, redirect to login
      const state = getAuthState()
      if (state && state.email === email) {
        clearAuth()
        router.push('/login')
        return
      }

      setRevokingUser(null)
      setSessions((prev) => prev.filter((s) => s.email !== email))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to revoke sessions')
    } finally {
      setSubmitting(false)
    }
  }

  // Group sessions by email
  const grouped = useMemo(() => {
    const map = new Map<string, SessionResponse[]>()
    for (const s of sessions) {
      const list = map.get(s.email) || []
      list.push(s)
      map.set(s.email, list)
    }
    // Sort each group by created_at descending
    for (const list of map.values()) {
      list.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
    }
    // Sort groups: current user first, then alphabetically
    const state = getAuthState()
    const entries = Array.from(map.entries())
    entries.sort((a, b) => {
      if (state) {
        if (a[0] === state.email) return -1
        if (b[0] === state.email) return 1
      }
      return a[0].localeCompare(b[0])
    })
    return entries
  }, [sessions])

  return (
    <div className="min-h-screen flex flex-col">
      <NavBar />
      <main className="flex-1 max-w-7xl mx-auto w-full px-4 sm:px-6 lg:px-8 py-6">
        <div className="mb-6">
          <h1 className="text-xl font-semibold text-slate-100">Sessions</h1>
          <p className="text-sm text-slate-400 mt-1">
            {admin ? 'All active sessions across the platform.' : 'Your active sessions.'}
          </p>
        </div>

        {error && (
          <div className="p-4 bg-red-900/30 text-red-400 rounded-lg mb-6 border border-red-800/50">
            {error}
          </div>
        )}

        {loading && (
          <div className="text-center py-12">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-brand-500 mx-auto"></div>
            <p className="mt-4 text-slate-500">Loading sessions...</p>
          </div>
        )}

        {!loading && (
          <div className="space-y-6">
            {grouped.map(([email, userSessions]) => (
              <div key={email} className="space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <h2 className="text-sm font-semibold text-slate-200">{email}</h2>
                    <span className="text-xs text-slate-500">
                      {userSessions.length} session{userSessions.length !== 1 ? 's' : ''}
                    </span>
                  </div>
                  {admin && (
                    <>
                      {revokingUser === email ? (
                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => setRevokingUser(null)}
                            className="px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors"
                          >
                            Cancel
                          </button>
                          <button
                            onClick={() => handleRevokeUser(email)}
                            disabled={submitting}
                            className="px-3 py-1.5 text-xs font-medium bg-red-600 hover:bg-red-500 disabled:bg-red-800 text-white rounded transition-colors"
                          >
                            {submitting ? 'Revoking...' : 'Confirm Revoke All?'}
                          </button>
                        </div>
                      ) : (
                        <button
                          onClick={() => setRevokingUser(email)}
                          className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-slate-400 hover:text-red-400 hover:bg-slate-700/50 rounded transition-colors"
                        >
                          <Trash2 size={12} />
                          Revoke All
                        </button>
                      )}
                    </>
                  )}
                </div>

                <div className="space-y-1.5">
                  {userSessions.map((s) => (
                    <div
                      key={s.token_hint}
                      className={`p-3 rounded-lg border ${
                        s.is_current
                          ? 'bg-brand-900/20 border-brand-700/50'
                          : 'bg-slate-800/50 border-slate-700/50'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <span className="text-xs font-mono text-slate-500">...{s.token_hint}</span>
                          <span className="px-2 py-0.5 text-xs rounded-full bg-slate-700/50 text-slate-300">
                            {s.provider_name}
                          </span>
                          {s.is_current && (
                            <span className="px-2 py-0.5 text-xs rounded-full bg-brand-600/30 text-brand-400 font-medium">
                              Current
                            </span>
                          )}
                        </div>
                        <div className="flex items-center gap-4 text-xs text-slate-500">
                          <span title={`Created: ${new Date(s.created_at).toLocaleString()}`}>
                            Created {timeAgo(s.created_at)}
                          </span>
                          <span title={`Last active: ${new Date(s.last_active_at).toLocaleString()}`}>
                            Active {timeAgo(s.last_active_at)}
                          </span>
                          <span title={`Expires: ${new Date(s.expires_at).toLocaleString()}`}>
                            Expires in {timeUntil(s.expires_at)}
                          </span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}

            {sessions.length === 0 && !error && (
              <p className="text-slate-500 text-center py-12">No active sessions</p>
            )}
          </div>
        )}
      </main>
    </div>
  )
}
