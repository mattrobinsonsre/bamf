'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { Plus, Trash2, Copy, Check, Tag } from 'lucide-react'
import NavBar from '@/components/nav-bar'
import { getAuthState, isAdmin, isAdminOrAudit, clearAuth, loginRedirectUrl } from '@/lib/auth'

interface JoinTokenResponse {
  id: string
  name: string
  expires_at: string
  max_uses: number | null
  use_count: number
  agent_labels: Record<string, string>
  is_revoked: boolean
  created_at: string
  created_by: string
}

interface JoinTokenCreateResponse extends JoinTokenResponse {
  token: string
}

export default function TokensPage() {
  const router = useRouter()
  const [tokens, setTokens] = useState<JoinTokenResponse[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [nextCursor, setNextCursor] = useState<string | null>(null)
  const [hasMore, setHasMore] = useState(false)
  const [includeRevoked, setIncludeRevoked] = useState(false)

  const [showCreate, setShowCreate] = useState(false)
  const [revokingToken, setRevokingToken] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  // Created token display
  const [createdToken, setCreatedToken] = useState<JoinTokenCreateResponse | null>(null)
  const [copied, setCopied] = useState(false)

  // Form state
  const [formName, setFormName] = useState('')
  const [formExpiresHours, setFormExpiresHours] = useState('24')
  const [formMaxUses, setFormMaxUses] = useState('')
  const [formLabels, setFormLabels] = useState<{ key: string; value: string }[]>([{ key: '', value: '' }])

  const [canEdit, setCanEdit] = useState(false)

  useEffect(() => {
    if (!getAuthState()) {
      router.push(loginRedirectUrl())
      return
    }
    setCanEdit(isAdmin())
    if (!isAdminOrAudit()) {
      router.push('/')
      return
    }
    fetchTokens()
  }, [router, includeRevoked])

  const authHeaders = (): HeadersInit => {
    const state = getAuthState()
    if (!state) {
      clearAuth()
      router.push(loginRedirectUrl())
      return {}
    }
    return { Authorization: `Bearer ${state.token}` }
  }

  const fetchTokens = async (cursor?: string) => {
    try {
      const params = new URLSearchParams()
      if (cursor) params.set('cursor', cursor)
      if (includeRevoked) params.set('include_revoked', 'true')

      const response = await fetch(`/api/v1/tokens?${params}`, {
        headers: authHeaders(),
      })

      if (response.status === 401) {
        clearAuth()
        router.push(loginRedirectUrl())
        return
      }
      if (!response.ok) throw new Error('Failed to fetch tokens')

      const data = await response.json()
      if (cursor) {
        setTokens((prev) => [...prev, ...data.items])
      } else {
        setTokens(data.items)
      }
      setNextCursor(data.next_cursor)
      setHasMore(data.has_more)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load tokens')
    } finally {
      setLoading(false)
    }
  }

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    setSubmitting(true)
    setError('')

    const labels: Record<string, string> = {}
    for (const { key, value } of formLabels) {
      if (key.trim() && value.trim()) {
        labels[key.trim()] = value.trim()
      }
    }

    try {
      const response = await fetch('/api/v1/tokens', {
        method: 'POST',
        headers: { ...authHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: formName,
          expires_in_hours: parseInt(formExpiresHours, 10),
          max_uses: formMaxUses ? parseInt(formMaxUses, 10) : null,
          agent_labels: labels,
        }),
      })

      if (!response.ok) {
        const body = await response.json().catch(() => ({}))
        throw new Error(body.detail || `Failed to create token (${response.status})`)
      }

      const created = await response.json()
      setCreatedToken(created)
      setShowCreate(false)
      resetForm()
      setTokens([])
      setLoading(true)
      fetchTokens()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create token')
    } finally {
      setSubmitting(false)
    }
  }

  const handleRevoke = async (id: string) => {
    setSubmitting(true)
    setError('')
    try {
      const response = await fetch(`/api/v1/tokens/${id}`, {
        method: 'DELETE',
        headers: authHeaders(),
      })
      if (!response.ok) {
        const body = await response.json().catch(() => ({}))
        throw new Error(body.detail || `Failed to revoke token (${response.status})`)
      }
      setRevokingToken(null)
      setTokens([])
      setLoading(true)
      fetchTokens()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to revoke token')
    } finally {
      setSubmitting(false)
    }
  }

  const resetForm = () => {
    setFormName('')
    setFormExpiresHours('24')
    setFormMaxUses('')
    setFormLabels([{ key: '', value: '' }])
  }

  const copyToken = async () => {
    if (!createdToken) return
    await navigator.clipboard.writeText(createdToken.token)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const formatDate = (iso: string) => {
    return new Date(iso).toLocaleString()
  }

  const isExpired = (expiresAt: string) => {
    return new Date(expiresAt) < new Date()
  }

  const updateLabel = (index: number, field: 'key' | 'value', value: string) => {
    const updated = [...formLabels]
    updated[index] = { ...updated[index], [field]: value }
    setFormLabels(updated)
  }

  const addLabel = () => {
    setFormLabels([...formLabels, { key: '', value: '' }])
  }

  const removeLabel = (index: number) => {
    if (formLabels.length <= 1) {
      setFormLabels([{ key: '', value: '' }])
    } else {
      setFormLabels(formLabels.filter((_, i) => i !== index))
    }
  }

  return (
    <div className="min-h-screen flex flex-col">
      <NavBar />
      <main className="flex-1 max-w-7xl mx-auto w-full px-4 sm:px-6 lg:px-8 py-6">
        <div className="flex items-center justify-between mb-6">
          <h1 className="text-xl font-semibold text-slate-100">Join Tokens</h1>
          <div className="flex items-center gap-4">
            <label className="flex items-center gap-2 text-sm text-slate-400">
              <input
                type="checkbox"
                checked={includeRevoked}
                onChange={(e) => {
                  setIncludeRevoked(e.target.checked)
                  setTokens([])
                  setLoading(true)
                }}
                className="rounded border-slate-600 bg-slate-700 text-brand-500 focus:ring-brand-500"
              />
              Show revoked
            </label>
            {canEdit && !showCreate && (
              <button
                onClick={() => setShowCreate(true)}
                className="flex items-center gap-2 px-4 py-2 text-sm font-medium bg-brand-600 hover:bg-brand-500 text-white rounded-lg transition-colors btn-smoke"
              >
                <Plus size={16} />
                Create Token
              </button>
            )}
          </div>
        </div>

        {error && (
          <div className="p-4 bg-red-900/30 text-red-400 rounded-lg mb-6 border border-red-800/50">
            {error}
          </div>
        )}

        {/* Created token display */}
        {createdToken && (
          <div className="p-4 bg-green-900/20 border border-green-800/50 rounded-lg mb-6">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-sm font-semibold text-green-400">Token Created Successfully</h3>
              <button
                onClick={() => setCreatedToken(null)}
                className="text-slate-500 hover:text-slate-300"
              >
                &times;
              </button>
            </div>
            <p className="text-xs text-slate-400 mb-2">
              Copy this token now — it will not be shown again.
            </p>
            <div className="flex items-center gap-2">
              <code className="flex-1 p-2 bg-slate-900 rounded text-sm text-green-300 font-mono break-all">
                {createdToken.token}
              </code>
              <button
                onClick={copyToken}
                className="p-2 text-slate-400 hover:text-slate-200 hover:bg-slate-700/50 rounded transition-colors"
                title="Copy to clipboard"
              >
                {copied ? <Check size={16} className="text-green-400" /> : <Copy size={16} />}
              </button>
            </div>
          </div>
        )}

        {/* Create form */}
        {showCreate && (
          <form onSubmit={handleCreate} className="p-4 bg-slate-800/80 rounded-lg border border-slate-700/50 mb-6 space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">Name</label>
                <input
                  type="text"
                  value={formName}
                  onChange={(e) => setFormName(e.target.value)}
                  required
                  pattern="[a-z][a-z0-9-]*"
                  maxLength={63}
                  placeholder="production-agents"
                  className="w-full px-3 py-2 border border-slate-600 rounded-lg bg-slate-700 text-slate-100 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">Expires In (hours)</label>
                <input
                  type="number"
                  value={formExpiresHours}
                  onChange={(e) => setFormExpiresHours(e.target.value)}
                  required
                  min={1}
                  max={8760}
                  className="w-full px-3 py-2 border border-slate-600 rounded-lg bg-slate-700 text-slate-100 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">Max Uses (optional)</label>
                <input
                  type="number"
                  value={formMaxUses}
                  onChange={(e) => setFormMaxUses(e.target.value)}
                  min={1}
                  placeholder="Unlimited"
                  className="w-full px-3 py-2 border border-slate-600 rounded-lg bg-slate-700 text-slate-100 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
                />
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1">Agent Labels</label>
              <p className="text-xs text-slate-500 mb-2">Labels to apply to agents that use this token</p>
              {formLabels.map((label, i) => (
                <div key={i} className="flex gap-2 items-center mb-2">
                  <input
                    type="text"
                    placeholder="key"
                    value={label.key}
                    onChange={(e) => updateLabel(i, 'key', e.target.value)}
                    className="w-32 px-2 py-1.5 border border-slate-600 rounded bg-slate-700 text-slate-100 text-sm focus:outline-none focus:ring-1 focus:ring-brand-500"
                  />
                  <span className="text-slate-500">=</span>
                  <input
                    type="text"
                    placeholder="value"
                    value={label.value}
                    onChange={(e) => updateLabel(i, 'value', e.target.value)}
                    className="flex-1 px-2 py-1.5 border border-slate-600 rounded bg-slate-700 text-slate-100 text-sm focus:outline-none focus:ring-1 focus:ring-brand-500"
                  />
                  <button
                    type="button"
                    onClick={() => removeLabel(i)}
                    className="text-slate-500 hover:text-slate-300 p-1"
                  >
                    &times;
                  </button>
                </div>
              ))}
              <button
                type="button"
                onClick={addLabel}
                className="text-xs text-brand-400 hover:text-brand-300"
              >
                + Add label
              </button>
            </div>

            <div className="flex gap-2 justify-end">
              <button
                type="button"
                onClick={() => { setShowCreate(false); resetForm() }}
                className="px-4 py-2 text-sm text-slate-400 hover:text-slate-200 transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={submitting}
                className="px-4 py-2 text-sm font-medium bg-brand-600 hover:bg-brand-500 disabled:bg-brand-800 disabled:text-brand-400 text-white rounded-lg transition-colors btn-smoke"
              >
                {submitting ? 'Creating...' : 'Create Token'}
              </button>
            </div>
          </form>
        )}

        {loading && (
          <div className="text-center py-12">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-brand-500 mx-auto"></div>
            <p className="mt-4 text-slate-500">Loading tokens...</p>
          </div>
        )}

        {!loading && (
          <div className="space-y-3">
            {tokens.map((token) => (
              <div
                key={token.id}
                className={`p-4 bg-slate-800/50 rounded-lg border ${
                  token.is_revoked ? 'border-red-800/50 opacity-60' : 'border-slate-700/50'
                }`}
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <h3 className="font-semibold text-slate-100">{token.name}</h3>
                      {token.is_revoked && (
                        <span className="px-2 py-0.5 text-xs bg-red-900/30 text-red-400 rounded">
                          revoked
                        </span>
                      )}
                      {!token.is_revoked && isExpired(token.expires_at) && (
                        <span className="px-2 py-0.5 text-xs bg-yellow-900/30 text-yellow-400 rounded">
                          expired
                        </span>
                      )}
                    </div>
                    <div className="text-sm text-slate-400 mt-1 space-y-1">
                      <p>
                        Expires: {formatDate(token.expires_at)}
                        {' · '}
                        Uses: {token.use_count}{token.max_uses ? ` / ${token.max_uses}` : ' (unlimited)'}
                      </p>
                      <p className="text-xs text-slate-500">
                        Created by {token.created_by} on {formatDate(token.created_at)}
                      </p>
                    </div>
                    {Object.keys(token.agent_labels).length > 0 && (
                      <div className="flex flex-wrap items-center gap-1 mt-2">
                        <Tag size={12} className="text-slate-500" />
                        {Object.entries(token.agent_labels).map(([k, v]) => (
                          <span key={k} className="px-2 py-0.5 text-xs bg-slate-700 text-slate-300 rounded">
                            {k}={v}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                  {canEdit && !token.is_revoked && (
                    <div className="ml-4">
                      {revokingToken === token.id ? (
                        <button
                          onClick={() => handleRevoke(token.id)}
                          disabled={submitting}
                          className="px-3 py-1.5 text-xs font-medium bg-red-600 hover:bg-red-500 disabled:bg-red-800 text-white rounded transition-colors"
                        >
                          {submitting ? 'Revoking...' : 'Confirm Revoke?'}
                        </button>
                      ) : (
                        <button
                          onClick={() => setRevokingToken(token.id)}
                          className="p-2 text-slate-400 hover:text-red-400 hover:bg-slate-700/50 rounded transition-colors"
                          title="Revoke token"
                        >
                          <Trash2 size={14} />
                        </button>
                      )}
                    </div>
                  )}
                </div>
              </div>
            ))}

            {tokens.length === 0 && !error && (
              <p className="text-slate-500 text-center py-12">No join tokens found</p>
            )}

            {hasMore && (
              <div className="text-center pt-2">
                <button
                  onClick={() => fetchTokens(nextCursor ?? undefined)}
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
