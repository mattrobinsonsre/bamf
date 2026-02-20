'use client'

import { useEffect, useState, useCallback } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import { Shield, CheckCircle, XCircle, Filter, ChevronDown, ChevronUp, Film } from 'lucide-react'
import NavBar from '@/components/nav-bar'
import { getAuthState, isAdminOrAudit, clearAuth, loginRedirectUrl } from '@/lib/auth'

interface AuditEntry {
  id: string
  timestamp: string
  event_type: string
  action: string
  actor_type: string
  actor_id: string | null
  actor_ip: string | null
  target_type: string | null
  target_id: string | null
  request_id: string | null
  details: Record<string, unknown>
  success: boolean
  error_message: string | null
}

const EVENT_TYPE_STYLES: Record<string, string> = {
  auth: 'bg-blue-900/30 text-blue-400',
  access: 'bg-green-900/30 text-green-400',
  admin: 'bg-purple-900/30 text-purple-400',
}

const ACTION_LABELS: Record<string, string> = {
  login: 'Login',
  login_failed: 'Login Failed',
  logout: 'Logout',
  access_granted: 'Access Granted',
  access_denied: 'Access Denied',
  session_started: 'Session Started',
  session_ended: 'Session Ended',
  session_reconnected: 'Session Reconnected',
  user_created: 'User Created',
  user_updated: 'User Updated',
  user_deleted: 'User Deleted',
  role_created: 'Role Created',
  role_updated: 'Role Updated',
  role_deleted: 'Role Deleted',
  token_created: 'Token Created',
  token_revoked: 'Token Revoked',
  agent_registered: 'Agent Registered',
  agent_deleted: 'Agent Deleted',
  role_assigned: 'Role Assigned',
  role_unassigned: 'Role Unassigned',
}

export default function AuditPage() {
  const router = useRouter()
  const [entries, setEntries] = useState<AuditEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [nextCursor, setNextCursor] = useState<string | null>(null)
  const [hasMore, setHasMore] = useState(false)
  const [loadingMore, setLoadingMore] = useState(false)
  const [expandedId, setExpandedId] = useState<string | null>(null)

  // Filters
  const [showFilters, setShowFilters] = useState(false)
  const [eventTypeFilter, setEventTypeFilter] = useState('')
  const [actionFilter, setActionFilter] = useState('')
  const [actorFilter, setActorFilter] = useState('')

  const authHeaders = useCallback((): HeadersInit => {
    const state = getAuthState()
    if (!state) {
      clearAuth()
      router.push(loginRedirectUrl())
      return {}
    }
    return { Authorization: `Bearer ${state.token}` }
  }, [router])

  const fetchAudit = useCallback(async (cursor?: string) => {
    try {
      const params = new URLSearchParams()
      if (cursor) params.set('cursor', cursor)
      params.set('limit', '50')
      if (eventTypeFilter) params.set('event_type', eventTypeFilter)
      if (actionFilter) params.set('action', actionFilter)
      if (actorFilter) params.set('actor_id', actorFilter)

      const response = await fetch(`/api/v1/audit?${params}`, {
        headers: authHeaders(),
      })

      if (response.status === 401) {
        clearAuth()
        router.push(loginRedirectUrl())
        return
      }
      if (response.status === 403) {
        router.push('/')
        return
      }
      if (!response.ok) throw new Error('Failed to fetch audit log')

      const data = await response.json()
      if (cursor) {
        setEntries((prev) => [...prev, ...data.items])
      } else {
        setEntries(data.items)
      }
      setNextCursor(data.next_cursor)
      setHasMore(data.has_more)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load audit log')
    } finally {
      setLoading(false)
      setLoadingMore(false)
    }
  }, [authHeaders, eventTypeFilter, actionFilter, actorFilter, router])

  useEffect(() => {
    if (!getAuthState()) {
      router.push(loginRedirectUrl())
      return
    }
    if (!isAdminOrAudit()) {
      router.push('/')
      return
    }
    fetchAudit()
  }, [router, fetchAudit])

  const handleFilter = () => {
    setEntries([])
    setLoading(true)
    fetchAudit()
  }

  const handleLoadMore = () => {
    if (!nextCursor) return
    setLoadingMore(true)
    fetchAudit(nextCursor)
  }

  const formatTimestamp = (iso: string) => {
    const date = new Date(iso)
    return date.toLocaleString(undefined, {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    })
  }

  const formatRelative = (iso: string) => {
    const date = new Date(iso)
    const now = new Date()
    const diffMs = now.getTime() - date.getTime()
    const diffSec = Math.floor(diffMs / 1000)

    if (diffSec < 60) return `${diffSec}s ago`
    if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`
    if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`
    return `${Math.floor(diffSec / 86400)}d ago`
  }

  return (
    <div className="min-h-screen flex flex-col">
      <NavBar />
      <main className="flex-1 max-w-7xl mx-auto w-full px-4 sm:px-6 lg:px-8 py-6">
        <div className="flex items-center justify-between mb-6">
          <h1 className="text-xl font-semibold text-slate-100">Audit Log</h1>
          <button
            onClick={() => setShowFilters(!showFilters)}
            className="flex items-center gap-2 px-3 py-2 text-sm font-medium text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg transition-colors"
          >
            <Filter size={16} />
            Filters
            {showFilters ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
          </button>
        </div>

        {/* Filters */}
        {showFilters && (
          <div className="flex flex-wrap gap-3 mb-6 p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
            <select
              value={eventTypeFilter}
              onChange={(e) => setEventTypeFilter(e.target.value)}
              className="px-3 py-2 border border-slate-600 rounded-lg bg-slate-700 text-slate-200 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
            >
              <option value="">All Types</option>
              <option value="auth">Auth</option>
              <option value="access">Access</option>
              <option value="admin">Admin</option>
            </select>
            <input
              type="text"
              value={actionFilter}
              onChange={(e) => setActionFilter(e.target.value)}
              placeholder="Action (e.g., login, access_granted)"
              className="px-3 py-2 border border-slate-600 rounded-lg bg-slate-700 text-slate-200 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
            />
            <input
              type="text"
              value={actorFilter}
              onChange={(e) => setActorFilter(e.target.value)}
              placeholder="Actor (e.g., admin@example.com)"
              className="px-3 py-2 border border-slate-600 rounded-lg bg-slate-700 text-slate-200 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
            />
            <button
              onClick={handleFilter}
              className="px-4 py-2 text-sm font-medium bg-brand-600 hover:bg-brand-500 text-white rounded-lg transition-colors"
            >
              Apply
            </button>
          </div>
        )}

        {error && (
          <div className="p-4 bg-red-900/30 text-red-400 rounded-lg mb-6 border border-red-800/50">
            {error}
          </div>
        )}

        {loading && (
          <div className="text-center py-12">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-brand-500 mx-auto"></div>
            <p className="mt-4 text-slate-500">Loading audit log...</p>
          </div>
        )}

        {!loading && (
          <div className="space-y-1">
            {/* Header */}
            <div className="hidden md:grid md:grid-cols-12 gap-2 px-4 py-2 text-xs font-medium text-slate-500 uppercase tracking-wider">
              <div className="col-span-2">Time</div>
              <div className="col-span-1">Type</div>
              <div className="col-span-2">Action</div>
              <div className="col-span-3">Actor</div>
              <div className="col-span-3">Target</div>
              <div className="col-span-1">Status</div>
            </div>

            {entries.map((entry) => (
              <div key={entry.id}>
                <button
                  onClick={() => setExpandedId(expandedId === entry.id ? null : entry.id)}
                  className="w-full text-left px-4 py-3 bg-slate-800/50 rounded-lg border border-slate-700/50 hover:border-slate-600/50 transition-colors"
                >
                  {/* Desktop layout */}
                  <div className="hidden md:grid md:grid-cols-12 gap-2 items-center">
                    <div className="col-span-2 text-sm text-slate-400" title={new Date(entry.timestamp).toISOString()}>
                      {formatRelative(entry.timestamp)}
                    </div>
                    <div className="col-span-1">
                      <span className={`px-2 py-0.5 text-xs rounded ${EVENT_TYPE_STYLES[entry.event_type] || 'bg-slate-700 text-slate-300'}`}>
                        {entry.event_type}
                      </span>
                    </div>
                    <div className="col-span-2 text-sm text-slate-200">
                      {ACTION_LABELS[entry.action] || entry.action}
                    </div>
                    <div className="col-span-3 text-sm text-slate-300 truncate" title={entry.actor_id || undefined}>
                      {entry.actor_id || '-'}
                    </div>
                    <div className="col-span-3 text-sm text-slate-400 truncate" title={entry.target_id || undefined}>
                      {entry.target_type && entry.target_id
                        ? `${entry.target_type}: ${entry.target_id}`
                        : entry.target_id || '-'}
                    </div>
                    <div className="col-span-1">
                      {entry.success ? (
                        <CheckCircle size={16} className="text-green-500" />
                      ) : (
                        <XCircle size={16} className="text-red-500" />
                      )}
                    </div>
                  </div>

                  {/* Mobile layout */}
                  <div className="md:hidden space-y-1">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className={`px-2 py-0.5 text-xs rounded ${EVENT_TYPE_STYLES[entry.event_type] || 'bg-slate-700 text-slate-300'}`}>
                          {entry.event_type}
                        </span>
                        <span className="text-sm text-slate-200">
                          {ACTION_LABELS[entry.action] || entry.action}
                        </span>
                      </div>
                      {entry.success ? (
                        <CheckCircle size={16} className="text-green-500" />
                      ) : (
                        <XCircle size={16} className="text-red-500" />
                      )}
                    </div>
                    <div className="text-sm text-slate-400">
                      {entry.actor_id || '-'}
                    </div>
                    <div className="text-xs text-slate-500">
                      {formatRelative(entry.timestamp)}
                    </div>
                  </div>
                </button>

                {/* Expanded details */}
                {expandedId === entry.id && (
                  <div className="mx-4 mt-1 mb-2 p-4 bg-slate-900/50 rounded-lg border border-slate-700/30 text-sm space-y-2">
                    <div className="grid grid-cols-2 gap-x-8 gap-y-2">
                      <div>
                        <span className="text-slate-500">Timestamp:</span>{' '}
                        <span className="text-slate-300">{formatTimestamp(entry.timestamp)}</span>
                      </div>
                      <div>
                        <span className="text-slate-500">Actor IP:</span>{' '}
                        <span className="text-slate-300">{entry.actor_ip || '-'}</span>
                      </div>
                      <div>
                        <span className="text-slate-500">Actor Type:</span>{' '}
                        <span className="text-slate-300">{entry.actor_type}</span>
                      </div>
                      <div>
                        <span className="text-slate-500">Request ID:</span>{' '}
                        <span className="text-slate-300 font-mono text-xs">{entry.request_id || '-'}</span>
                      </div>
                      {entry.target_type && (
                        <div>
                          <span className="text-slate-500">Target:</span>{' '}
                          <span className="text-slate-300">{entry.target_type}: {entry.target_id}</span>
                        </div>
                      )}
                      {entry.error_message && (
                        <div className="col-span-2">
                          <span className="text-slate-500">Error:</span>{' '}
                          <span className="text-red-400">{entry.error_message}</span>
                        </div>
                      )}
                    </div>
                    {(entry.action === 'session_started' || entry.action === 'session_ended') &&
                      typeof entry.details.session_id === 'string' ? (
                      <div>
                        <Link
                          href={`/audit/recordings?session_id=${entry.details.session_id}`}
                          className="inline-flex items-center gap-1.5 text-sm text-brand-400 hover:text-brand-300 transition-colors"
                        >
                          <Film size={14} />
                          View Recording
                        </Link>
                      </div>
                    ) : null}
                    {Object.keys(entry.details).length > 0 && (
                      <div>
                        <span className="text-slate-500">Details:</span>
                        <pre className="mt-1 p-2 bg-slate-800 rounded text-xs text-slate-300 overflow-x-auto">
                          {JSON.stringify(entry.details, null, 2)}
                        </pre>
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}

            {entries.length === 0 && !error && (
              <div className="text-center py-12">
                <Shield size={48} className="mx-auto text-slate-600 mb-4" />
                <p className="text-slate-500">No audit events found</p>
              </div>
            )}

            {hasMore && (
              <div className="text-center pt-4">
                <button
                  onClick={handleLoadMore}
                  disabled={loadingMore}
                  className="px-4 py-2 text-sm text-brand-400 hover:text-brand-300 transition-colors disabled:opacity-50"
                >
                  {loadingMore ? 'Loading...' : 'Load more'}
                </button>
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  )
}
