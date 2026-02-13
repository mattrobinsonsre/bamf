'use client'

import { useEffect, useMemo, useState } from 'react'
import { useRouter } from 'next/navigation'
import { Plus, KeyRound, Trash2 } from 'lucide-react'
import { zxcvbnAsync, zxcvbnOptions } from '@zxcvbn-ts/core'
import * as zxcvbnCommonPackage from '@zxcvbn-ts/language-common'
import NavBar from '@/components/nav-bar'
import { getAuthState, isAdmin, clearAuth } from '@/lib/auth'

zxcvbnOptions.setOptions({
  dictionary: { ...zxcvbnCommonPackage.dictionary },
  graphs: zxcvbnCommonPackage.adjacencyGraphs,
})

const SCORE_LABELS = ['Very weak', 'Weak', 'Fair', 'Good', 'Strong'] as const
const SCORE_COLORS = ['bg-red-500', 'bg-red-500', 'bg-yellow-500', 'bg-brand-500', 'bg-green-500']
const SCORE_TEXT = ['text-red-400', 'text-red-400', 'text-yellow-400', 'text-brand-400', 'text-green-400']
const MIN_SCORE = 3

function usePasswordStrength(password: string) {
  const [result, setResult] = useState<{ score: number; warning: string; suggestions: string[] }>({
    score: 0, warning: '', suggestions: [],
  })

  useEffect(() => {
    if (!password) {
      setResult({ score: 0, warning: '', suggestions: [] })
      return
    }
    let cancelled = false
    zxcvbnAsync(password).then((r) => {
      if (!cancelled) {
        setResult({
          score: r.score,
          warning: r.feedback.warning || '',
          suggestions: r.feedback.suggestions || [],
        })
      }
    })
    return () => { cancelled = true }
  }, [password])

  return result
}

function PasswordStrength({ password }: { password: string }) {
  const { score, warning, suggestions } = usePasswordStrength(password)
  if (!password) return null

  const feedback = [warning, ...suggestions].filter(Boolean)

  return (
    <div className="mt-2 space-y-2">
      <div className="flex items-center gap-2">
        <div className="flex gap-1 flex-1">
          {[0, 1, 2, 3, 4].map((i) => (
            <div
              key={i}
              className={`h-1 flex-1 rounded-full transition-colors ${
                i <= score ? SCORE_COLORS[score] : 'bg-slate-700'
              }`}
            />
          ))}
        </div>
        <span className={`text-xs font-medium ${SCORE_TEXT[score]}`}>{SCORE_LABELS[score]}</span>
      </div>
      {feedback.length > 0 && (
        <ul className="space-y-0.5">
          {feedback.map((msg, i) => (
            <li key={i} className="text-xs text-slate-400">{msg}</li>
          ))}
        </ul>
      )}
    </div>
  )
}

function usePasswordValid(password: string): boolean {
  const { score } = usePasswordStrength(password)
  return !!password && score >= MIN_SCORE
}

interface UserResponse {
  email: string
  is_active: boolean
  created_at: string
  updated_at: string
}

export default function UsersPage() {
  const router = useRouter()
  const [users, setUsers] = useState<UserResponse[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [nextCursor, setNextCursor] = useState<string | null>(null)
  const [hasMore, setHasMore] = useState(false)

  const [showCreate, setShowCreate] = useState(false)
  const [editingUser, setEditingUser] = useState<string | null>(null)
  const [deletingUser, setDeletingUser] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  useEffect(() => {
    if (!isAdmin()) {
      router.push('/')
      return
    }
    fetchUsers()
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

  const fetchUsers = async (cursor?: string) => {
    try {
      const params = new URLSearchParams()
      if (cursor) params.set('cursor', cursor)

      const response = await fetch(`/api/v1/users?${params}`, {
        headers: authHeaders(),
      })
      if (response.status === 401) {
        clearAuth()
        router.push('/login')
        return
      }
      if (!response.ok) throw new Error('Failed to fetch users')

      const data = await response.json()
      if (cursor) {
        setUsers((prev) => [...prev, ...data.items])
      } else {
        setUsers(data.items)
      }
      setNextCursor(data.next_cursor)
      setHasMore(data.has_more)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load users')
    } finally {
      setLoading(false)
    }
  }

  const handleCreate = async (data: { email: string; password?: string }) => {
    setSubmitting(true)
    setError('')
    try {
      const body: Record<string, unknown> = { email: data.email }
      if (data.password) body.password = data.password

      const response = await fetch('/api/v1/users', {
        method: 'POST',
        headers: { ...authHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      if (!response.ok) {
        const b = await response.json().catch(() => ({}))
        const detail = Array.isArray(b.detail) ? b.detail[0]?.msg : b.detail
        throw new Error(detail || `Failed to create user (${response.status})`)
      }
      setShowCreate(false)
      setUsers([])
      setLoading(true)
      fetchUsers()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create user')
    } finally {
      setSubmitting(false)
    }
  }

  const handlePasswordReset = async (email: string, password: string) => {
    setSubmitting(true)
    setError('')
    try {
      const body = { password }

      const response = await fetch(`/api/v1/users/${encodeURIComponent(email)}`, {
        method: 'PATCH',
        headers: { ...authHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      if (!response.ok) {
        const b = await response.json().catch(() => ({}))
        const detail = Array.isArray(b.detail) ? b.detail[0]?.msg : b.detail
        throw new Error(detail || `Failed to update user (${response.status})`)
      }
      setEditingUser(null)
      setUsers([])
      setLoading(true)
      fetchUsers()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update user')
    } finally {
      setSubmitting(false)
    }
  }

  const handleDelete = async (email: string) => {
    setSubmitting(true)
    setError('')
    try {
      const response = await fetch(`/api/v1/users/${encodeURIComponent(email)}`, {
        method: 'DELETE',
        headers: authHeaders(),
      })
      if (!response.ok && response.status !== 204) {
        const b = await response.json().catch(() => ({}))
        const detail = Array.isArray(b.detail) ? b.detail[0]?.msg : b.detail
        throw new Error(detail || `Failed to delete user (${response.status})`)
      }
      setDeletingUser(null)
      setUsers((prev) => prev.filter((u) => u.email !== email))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete user')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="min-h-screen flex flex-col">
      <NavBar />
      <main className="flex-1 max-w-7xl mx-auto w-full px-4 sm:px-6 lg:px-8 py-6">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-xl font-semibold text-slate-100">Users</h1>
            <p className="text-sm text-slate-400 mt-1">
              Local user accounts. Manage role assignments on the Access page.
            </p>
          </div>
          {!showCreate && (
            <button
              onClick={() => { setShowCreate(true); setEditingUser(null) }}
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium bg-brand-600 hover:bg-brand-500 text-white rounded-lg transition-colors btn-smoke"
            >
              <Plus size={16} />
              Create User
            </button>
          )}
        </div>

        {error && (
          <div className="p-4 bg-red-900/30 text-red-400 rounded-lg mb-6 border border-red-800/50">
            {error}
          </div>
        )}

        {showCreate && (
          <div className="mb-6">
            <UserForm
              onSubmit={(data) => handleCreate(data)}
              onCancel={() => setShowCreate(false)}
              submitting={submitting}
            />
          </div>
        )}

        {loading && (
          <div className="text-center py-12">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-brand-500 mx-auto"></div>
            <p className="mt-4 text-slate-500">Loading users...</p>
          </div>
        )}

        {!loading && (
          <div className="space-y-3">
            {users.map((user) => (
              <div key={user.email}>
                {editingUser === user.email ? (
                  <PasswordForm
                    email={user.email}
                    onSubmit={(password) => handlePasswordReset(user.email, password)}
                    onCancel={() => setEditingUser(null)}
                    submitting={submitting}
                  />
                ) : (
                  <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <h3 className="font-semibold text-slate-100">{user.email}</h3>
                      </div>
                      <div className="flex items-center gap-1 ml-4">
                        <button
                          onClick={() => { setEditingUser(user.email); setShowCreate(false) }}
                          className="p-2 text-slate-400 hover:text-slate-200 hover:bg-slate-700/50 rounded transition-colors"
                          title="Reset password"
                        >
                          <KeyRound size={14} />
                        </button>
                        {deletingUser === user.email ? (
                          <button
                            onClick={() => handleDelete(user.email)}
                            disabled={submitting}
                            className="px-3 py-1.5 text-xs font-medium bg-red-600 hover:bg-red-500 disabled:bg-red-800 text-white rounded transition-colors"
                          >
                            {submitting ? 'Deleting...' : 'Confirm Delete?'}
                          </button>
                        ) : (
                          <button
                            onClick={() => setDeletingUser(user.email)}
                            className="p-2 text-slate-400 hover:text-red-400 hover:bg-slate-700/50 rounded transition-colors"
                            title="Delete"
                          >
                            <Trash2 size={14} />
                          </button>
                        )}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            ))}

            {users.length === 0 && !error && (
              <p className="text-slate-500 text-center py-12">No users found</p>
            )}

            {hasMore && (
              <div className="text-center pt-2">
                <button
                  onClick={() => fetchUsers(nextCursor ?? undefined)}
                  className="px-4 py-2 text-sm text-brand-400 hover:text-brand-300 transition-colors"
                >
                  Load more
                </button>
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  )
}

function UserForm({
  onSubmit,
  onCancel,
  submitting,
}: {
  onSubmit: (data: { email: string; password?: string }) => void
  onCancel: () => void
  submitting: boolean
}) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const passwordValid = usePasswordValid(password)

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    onSubmit({
      email,
      password: password || undefined,
    })
  }

  return (
    <form onSubmit={handleSubmit} className="p-4 bg-slate-800/80 rounded-lg border border-slate-700/50 space-y-4">
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-slate-300 mb-1">Email</label>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            placeholder="user@example.com"
            className="w-full px-3 py-2 border border-slate-600 rounded-lg bg-slate-700 text-slate-100 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-slate-300 mb-1">Password (optional)</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Enter a strong password"
            autoComplete="new-password"
            className="w-full px-3 py-2 border border-slate-600 rounded-lg bg-slate-700 text-slate-100 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
          />
          <PasswordStrength password={password} />
        </div>
      </div>

      <div className="flex gap-2 justify-end">
        <button
          type="button"
          onClick={onCancel}
          className="px-4 py-2 text-sm text-slate-400 hover:text-slate-200 transition-colors"
        >
          Cancel
        </button>
        <button
          type="submit"
          disabled={submitting || (!!password && !passwordValid)}
          className="px-4 py-2 text-sm font-medium bg-brand-600 hover:bg-brand-500 disabled:bg-brand-800 disabled:text-brand-400 text-white rounded-lg transition-colors btn-smoke"
        >
          {submitting ? 'Creating...' : 'Create'}
        </button>
      </div>
    </form>
  )
}

function PasswordForm({
  email,
  onSubmit,
  onCancel,
  submitting,
}: {
  email: string
  onSubmit: (password: string) => void
  onCancel: () => void
  submitting: boolean
}) {
  const [password, setPassword] = useState('')
  const passwordValid = usePasswordValid(password)

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    onSubmit(password)
  }

  return (
    <form onSubmit={handleSubmit} className="p-4 bg-slate-800/80 rounded-lg border border-slate-700/50 space-y-4">
      <div className="flex items-center gap-3">
        <span className="font-semibold text-slate-100">{email}</span>
      </div>

      <div>
        <label className="block text-sm font-medium text-slate-300 mb-1">New Password</label>
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
          placeholder="Enter a strong password"
          autoComplete="new-password"
          className="w-full px-3 py-2 border border-slate-600 rounded-lg bg-slate-700 text-slate-100 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
        />
        <PasswordStrength password={password} />
      </div>

      <div className="flex gap-2 justify-end">
        <button
          type="button"
          onClick={onCancel}
          className="px-4 py-2 text-sm text-slate-400 hover:text-slate-200 transition-colors"
        >
          Cancel
        </button>
        <button
          type="submit"
          disabled={submitting || !passwordValid}
          className="px-4 py-2 text-sm font-medium bg-brand-600 hover:bg-brand-500 disabled:bg-brand-800 disabled:text-brand-400 text-white rounded-lg transition-colors btn-smoke"
        >
          {submitting ? 'Saving...' : 'Reset Password'}
        </button>
      </div>
    </form>
  )
}
