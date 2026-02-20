'use client'

import { Suspense, useEffect, useState, useCallback } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import Link from 'next/link'
import { Film, Terminal, Database, Globe } from 'lucide-react'
import NavBar from '@/components/nav-bar'
import { getAuthState, isAdminOrAudit, clearAuth, loginRedirectUrl } from '@/lib/auth'

interface RecordingEntry {
  id: string
  session_id: string
  user_email: string
  resource_name: string
  recording_type: string
  started_at: string
  ended_at: string | null
}

function RecordingsList() {
  const router = useRouter()
  const searchParams = useSearchParams()
  const [recordings, setRecordings] = useState<RecordingEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [nextCursor, setNextCursor] = useState<string | null>(null)
  const [hasMore, setHasMore] = useState(false)
  const [loadingMore, setLoadingMore] = useState(false)

  const authHeaders = useCallback((): HeadersInit => {
    const state = getAuthState()
    if (!state) {
      clearAuth()
      router.push(loginRedirectUrl())
      return {}
    }
    return { Authorization: `Bearer ${state.token}` }
  }, [router])

  const fetchRecordings = useCallback(async (cursor?: string) => {
    try {
      const params = new URLSearchParams()
      if (cursor) params.set('cursor', cursor)
      params.set('limit', '50')

      // Pass through URL search params as filters
      const sessionId = searchParams.get('session_id')
      const recordingType = searchParams.get('type')
      const userEmail = searchParams.get('user')
      const resourceName = searchParams.get('resource')

      if (sessionId) params.set('session_id', sessionId)
      if (recordingType) params.set('recording_type', recordingType)
      if (userEmail) params.set('user_email', userEmail)
      if (resourceName) params.set('resource_name', resourceName)

      const response = await fetch(`/api/v1/audit/recordings?${params}`, {
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
      if (!response.ok) throw new Error('Failed to fetch recordings')

      const data = await response.json()
      if (cursor) {
        setRecordings((prev) => [...prev, ...data.items])
      } else {
        setRecordings(data.items)
      }
      setNextCursor(data.next_cursor)
      setHasMore(data.has_more)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load recordings')
    } finally {
      setLoading(false)
      setLoadingMore(false)
    }
  }, [authHeaders, searchParams, router])

  useEffect(() => {
    if (!getAuthState()) {
      router.push(loginRedirectUrl())
      return
    }
    if (!isAdminOrAudit()) {
      router.push('/')
      return
    }
    fetchRecordings()
  }, [router, fetchRecordings])

  const handleLoadMore = () => {
    if (!nextCursor) return
    setLoadingMore(true)
    fetchRecordings(nextCursor)
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

  const formatDuration = (start: string, end: string | null) => {
    if (!end) return '-'
    const ms = new Date(end).getTime() - new Date(start).getTime()
    const sec = Math.floor(ms / 1000)
    if (sec < 60) return `${sec}s`
    if (sec < 3600) return `${Math.floor(sec / 60)}m ${sec % 60}s`
    return `${Math.floor(sec / 3600)}h ${Math.floor((sec % 3600) / 60)}m`
  }

  if (loading) {
    return (
      <div className="text-center py-12">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-brand-500 mx-auto"></div>
        <p className="mt-4 text-slate-500">Loading recordings...</p>
      </div>
    )
  }

  return (
    <>
      {error && (
        <div className="p-4 bg-red-900/30 text-red-400 rounded-lg mb-6 border border-red-800/50">
          {error}
        </div>
      )}

      <div className="space-y-1">
        {/* Header */}
        <div className="hidden md:grid md:grid-cols-12 gap-2 px-4 py-2 text-xs font-medium text-slate-500 uppercase tracking-wider">
          <div className="col-span-3">Time</div>
          <div className="col-span-1">Type</div>
          <div className="col-span-3">User</div>
          <div className="col-span-3">Resource</div>
          <div className="col-span-2">Duration</div>
        </div>

        {recordings.map((rec) => (
          <Link
            key={rec.id}
            href={`/audit/recordings/${rec.id}`}
            className="block px-4 py-3 bg-slate-800/50 rounded-lg border border-slate-700/50 hover:border-slate-600/50 transition-colors"
          >
            {/* Desktop layout */}
            <div className="hidden md:grid md:grid-cols-12 gap-2 items-center">
              <div className="col-span-3 text-sm text-slate-400">
                {formatTimestamp(rec.started_at)}
              </div>
              <div className="col-span-1">
                {rec.recording_type === 'terminal' ? (
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 text-xs rounded bg-green-900/30 text-green-400">
                    <Terminal size={12} />
                    SSH
                  </span>
                ) : rec.recording_type === 'http' ? (
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 text-xs rounded bg-amber-900/30 text-amber-400">
                    <Globe size={12} />
                    HTTP
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 text-xs rounded bg-blue-900/30 text-blue-400">
                    <Database size={12} />
                    DB
                  </span>
                )}
              </div>
              <div className="col-span-3 text-sm text-slate-300 truncate" title={rec.user_email}>
                {rec.user_email}
              </div>
              <div className="col-span-3 text-sm text-slate-400 truncate" title={rec.resource_name}>
                {rec.resource_name}
              </div>
              <div className="col-span-2 text-sm text-slate-400">
                {formatDuration(rec.started_at, rec.ended_at)}
              </div>
            </div>

            {/* Mobile layout */}
            <div className="md:hidden space-y-1">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  {rec.recording_type === 'terminal' ? (
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 text-xs rounded bg-green-900/30 text-green-400">
                      <Terminal size={12} />
                      SSH
                    </span>
                  ) : rec.recording_type === 'http' ? (
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 text-xs rounded bg-amber-900/30 text-amber-400">
                      <Globe size={12} />
                      HTTP
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 text-xs rounded bg-blue-900/30 text-blue-400">
                      <Database size={12} />
                      DB
                    </span>
                  )}
                  <span className="text-sm text-slate-200">{rec.resource_name}</span>
                </div>
                <span className="text-xs text-slate-500">
                  {formatDuration(rec.started_at, rec.ended_at)}
                </span>
              </div>
              <div className="text-sm text-slate-400">{rec.user_email}</div>
              <div className="text-xs text-slate-500">{formatTimestamp(rec.started_at)}</div>
            </div>
          </Link>
        ))}

        {recordings.length === 0 && !error && (
          <div className="text-center py-12">
            <Film size={48} className="mx-auto text-slate-600 mb-4" />
            <p className="text-slate-500">No recordings found</p>
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
    </>
  )
}

export default function RecordingsPage() {
  return (
    <div className="min-h-screen flex flex-col">
      <NavBar />
      <main className="flex-1 max-w-7xl mx-auto w-full px-4 sm:px-6 lg:px-8 py-6">
        <div className="flex items-center justify-between mb-6">
          <h1 className="text-xl font-semibold text-slate-100">Recordings</h1>
        </div>
        <Suspense fallback={
          <div className="text-center py-12">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-brand-500 mx-auto"></div>
            <p className="mt-4 text-slate-500">Loading recordings...</p>
          </div>
        }>
          <RecordingsList />
        </Suspense>
      </main>
    </div>
  )
}
