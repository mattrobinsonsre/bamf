'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { Tag, Server, Clock, Shield, Trash2 } from 'lucide-react'
import NavBar from '@/components/nav-bar'
import { getAuthState, isAdmin, isAdminOrAudit, clearAuth } from '@/lib/auth'

interface AgentResponse {
  id: string
  name: string
  resource_count: number
  labels: Record<string, string>
  status: string
  last_heartbeat: string | null
  connected_bridge_id: string | null
  certificate_fingerprint: string
  certificate_expires_at: string
  created_at: string
}

export default function AgentsPage() {
  const router = useRouter()
  const [agents, setAgents] = useState<AgentResponse[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [nextCursor, setNextCursor] = useState<string | null>(null)
  const [hasMore, setHasMore] = useState(false)
  const [labelFilter, setLabelFilter] = useState('')
  const [deletingId, setDeletingId] = useState<string | null>(null)
  const [confirmDelete, setConfirmDelete] = useState<AgentResponse | null>(null)

  useEffect(() => {
    if (!isAdminOrAudit()) {
      router.push('/')
      return
    }
    fetchAgents()
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

  const fetchAgents = async (cursor?: string) => {
    try {
      const params = new URLSearchParams()
      if (cursor) params.set('cursor', cursor)
      if (labelFilter.trim()) {
        // Support multiple labels separated by comma
        labelFilter.split(',').forEach((l) => {
          const trimmed = l.trim()
          if (trimmed) params.append('label', trimmed)
        })
      }

      const response = await fetch(`/api/v1/agents?${params}`, {
        headers: authHeaders(),
      })

      if (response.status === 401) {
        clearAuth()
        router.push('/login')
        return
      }
      if (!response.ok) throw new Error('Failed to fetch agents')

      const data = await response.json()
      if (cursor) {
        setAgents((prev) => [...prev, ...data.items])
      } else {
        setAgents(data.items)
      }
      setNextCursor(data.next_cursor)
      setHasMore(data.has_more)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load agents')
    } finally {
      setLoading(false)
    }
  }

  const handleFilterSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    setAgents([])
    setLoading(true)
    fetchAgents()
  }

  const deleteAgent = async (agent: AgentResponse) => {
    setDeletingId(agent.id)
    try {
      const response = await fetch(`/api/v1/agents/${agent.id}`, {
        method: 'DELETE',
        headers: authHeaders(),
      })

      if (response.status === 401) {
        clearAuth()
        router.push('/login')
        return
      }
      if (!response.ok) {
        const data = await response.json()
        throw new Error(data.detail || 'Failed to delete agent')
      }

      // Remove from local state
      setAgents((prev) => prev.filter((a) => a.id !== agent.id))
      setConfirmDelete(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete agent')
    } finally {
      setDeletingId(null)
    }
  }

  const formatDate = (iso: string | null) => {
    if (!iso) return 'Never'
    return new Date(iso).toLocaleString()
  }

  const formatRelative = (iso: string | null) => {
    if (!iso) return 'Never'
    const date = new Date(iso)
    const now = new Date()
    const diffMs = now.getTime() - date.getTime()
    const diffSec = Math.floor(diffMs / 1000)

    if (diffSec < 60) return `${diffSec}s ago`
    if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`
    if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`
    return `${Math.floor(diffSec / 86400)}d ago`
  }

  const isCertExpiringSoon = (expiresAt: string) => {
    const expires = new Date(expiresAt)
    const now = new Date()
    const hoursUntilExpiry = (expires.getTime() - now.getTime()) / (1000 * 60 * 60)
    return hoursUntilExpiry < 6
  }

  return (
    <div className="min-h-screen flex flex-col">
      <NavBar />
      <main className="flex-1 max-w-7xl mx-auto w-full px-4 sm:px-6 lg:px-8 py-6">
        <div className="flex items-center justify-between mb-6">
          <h1 className="text-xl font-semibold text-slate-100">Agents</h1>
        </div>

        {/* Filter form */}
        <form onSubmit={handleFilterSubmit} className="mb-6 flex gap-2">
          <input
            type="text"
            value={labelFilter}
            onChange={(e) => setLabelFilter(e.target.value)}
            placeholder="Filter by labels (e.g., env=prod, team=platform)"
            className="flex-1 px-3 py-2 border border-slate-600 rounded-lg bg-slate-700 text-slate-100 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
          />
          <button
            type="submit"
            className="px-4 py-2 text-sm font-medium bg-slate-600 hover:bg-slate-500 text-white rounded-lg transition-colors"
          >
            Filter
          </button>
        </form>

        {error && (
          <div className="p-4 bg-red-900/30 text-red-400 rounded-lg mb-6 border border-red-800/50">
            {error}
          </div>
        )}

        {loading && (
          <div className="text-center py-12">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-brand-500 mx-auto"></div>
            <p className="mt-4 text-slate-500">Loading agents...</p>
          </div>
        )}

        {!loading && (
          <div className="space-y-3">
            {agents.map((agent) => (
              <div
                key={agent.id}
                className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50"
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <h3 className="font-semibold text-slate-100">{agent.name}</h3>
                      <span
                        className={`px-2 py-0.5 text-xs rounded ${
                          agent.status === 'online'
                            ? 'bg-green-900/30 text-green-400'
                            : 'bg-slate-700 text-slate-400'
                        }`}
                      >
                        {agent.status}
                      </span>
                      {agent.connected_bridge_id && (
                        <span className="px-2 py-0.5 text-xs bg-blue-900/30 text-blue-400 rounded">
                          connected
                        </span>
                      )}
                    </div>

                    <div className="flex flex-wrap items-center gap-4 mt-2 text-sm text-slate-400">
                      <span className="flex items-center gap-1">
                        <Server size={14} />
                        {agent.resource_count} resource{agent.resource_count !== 1 ? 's' : ''}
                      </span>
                      <span className="flex items-center gap-1">
                        <Clock size={14} />
                        Last heartbeat: {formatRelative(agent.last_heartbeat)}
                      </span>
                      <span className={`flex items-center gap-1 ${isCertExpiringSoon(agent.certificate_expires_at) ? 'text-yellow-400' : ''}`}>
                        <Shield size={14} />
                        Cert expires: {formatDate(agent.certificate_expires_at)}
                      </span>
                    </div>

                    {Object.keys(agent.labels).length > 0 && (
                      <div className="flex flex-wrap items-center gap-1 mt-2">
                        <Tag size={12} className="text-slate-500" />
                        {Object.entries(agent.labels).map(([k, v]) => (
                          <span key={k} className="px-2 py-0.5 text-xs bg-slate-700 text-slate-300 rounded">
                            {k}={v}
                          </span>
                        ))}
                      </div>
                    )}

                    <p className="text-xs text-slate-500 mt-2">
                      ID: {agent.id}
                    </p>
                  </div>

                  {isAdmin() && (
                    <button
                      onClick={() => setConfirmDelete(agent)}
                      disabled={deletingId === agent.id}
                      className="p-2 text-slate-500 hover:text-red-400 hover:bg-red-900/20 rounded transition-colors disabled:opacity-50"
                      title="Delete agent"
                    >
                      <Trash2 size={16} />
                    </button>
                  )}
                </div>
              </div>
            ))}

            {agents.length === 0 && !error && (
              <p className="text-slate-500 text-center py-12">No agents found</p>
            )}

            {hasMore && (
              <div className="text-center pt-2">
                <button
                  onClick={() => fetchAgents(nextCursor ?? undefined)}
                  className="px-4 py-2 text-sm text-brand-400 hover:text-brand-300 transition-colors"
                >
                  Load more
                </button>
              </div>
            )}
          </div>
        )}

        {/* Delete confirmation modal */}
        {confirmDelete && (
          <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
            <div className="bg-slate-800 rounded-lg p-6 max-w-md w-full mx-4 border border-slate-700">
              <h2 className="text-lg font-semibold text-slate-100 mb-4">Delete Agent</h2>
              <p className="text-slate-300 mb-2">
                Are you sure you want to delete agent <strong>{confirmDelete.name}</strong>?
              </p>
              <p className="text-slate-400 text-sm mb-6">
                This will revoke the agent&apos;s certificate and remove all associated resources.
                The agent will need to re-register with a new join token.
              </p>
              <div className="flex justify-end gap-3">
                <button
                  onClick={() => setConfirmDelete(null)}
                  disabled={deletingId !== null}
                  className="px-4 py-2 text-sm font-medium text-slate-300 hover:text-slate-100 transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={() => deleteAgent(confirmDelete)}
                  disabled={deletingId !== null}
                  className="px-4 py-2 text-sm font-medium bg-red-600 hover:bg-red-500 text-white rounded-lg transition-colors disabled:opacity-50"
                >
                  {deletingId ? 'Deleting...' : 'Delete Agent'}
                </button>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  )
}
