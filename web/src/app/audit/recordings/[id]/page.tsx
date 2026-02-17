'use client'

import { useEffect, useState, useCallback } from 'react'
import { useRouter, useParams } from 'next/navigation'
import Link from 'next/link'
import { ArrowLeft, Terminal, Database, Globe, Clock, User, Server } from 'lucide-react'
import NavBar from '@/components/nav-bar'
import { getAuthState, isAdminOrAudit, clearAuth } from '@/lib/auth'
import dynamic from 'next/dynamic'
import QueryViewer from '@/components/query-viewer'
import HttpExchangeViewer from '@/components/http-exchange-viewer'

// Dynamic import for RecordingPlayer (depends on asciinema-player which has no SSR)
const RecordingPlayer = dynamic(() => import('@/components/recording-player'), {
  ssr: false,
  loading: () => (
    <div className="flex items-center justify-center h-64 bg-slate-900 rounded-lg border border-slate-700/50">
      <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-brand-500"></div>
    </div>
  ),
})

interface RecordingDetail {
  id: string
  session_id: string
  user_email: string
  resource_name: string
  recording_type: string
  format: string
  recording_data: string
  started_at: string
  ended_at: string | null
}

export default function RecordingDetailPage() {
  const router = useRouter()
  const params = useParams()
  const [recording, setRecording] = useState<RecordingDetail | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const authHeaders = useCallback((): HeadersInit => {
    const state = getAuthState()
    if (!state) {
      clearAuth()
      router.push('/login')
      return {}
    }
    return { Authorization: `Bearer ${state.token}` }
  }, [router])

  useEffect(() => {
    if (!isAdminOrAudit()) {
      router.push('/')
      return
    }

    const fetchRecording = async () => {
      try {
        const response = await fetch(`/api/v1/audit/recordings/${params.id}`, {
          headers: authHeaders(),
        })

        if (response.status === 401) {
          clearAuth()
          router.push('/login')
          return
        }
        if (response.status === 403) {
          router.push('/')
          return
        }
        if (response.status === 404) {
          setError('Recording not found')
          return
        }
        if (!response.ok) throw new Error('Failed to fetch recording')

        setRecording(await response.json())
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load recording')
      } finally {
        setLoading(false)
      }
    }

    fetchRecording()
  }, [router, params.id, authHeaders])

  const formatTimestamp = (iso: string) => {
    return new Date(iso).toLocaleString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    })
  }

  const formatDuration = (start: string, end: string | null) => {
    if (!end) return 'In progress'
    const ms = new Date(end).getTime() - new Date(start).getTime()
    const sec = Math.floor(ms / 1000)
    if (sec < 60) return `${sec}s`
    if (sec < 3600) return `${Math.floor(sec / 60)}m ${sec % 60}s`
    return `${Math.floor(sec / 3600)}h ${Math.floor((sec % 3600) / 60)}m`
  }

  return (
    <div className="min-h-screen flex flex-col">
      <NavBar />
      <main className="flex-1 max-w-7xl mx-auto w-full px-4 sm:px-6 lg:px-8 py-6">
        <Link
          href="/audit/recordings"
          className="inline-flex items-center gap-1 text-sm text-slate-400 hover:text-slate-200 mb-4 transition-colors"
        >
          <ArrowLeft size={16} />
          Back to Recordings
        </Link>

        {error && (
          <div className="p-4 bg-red-900/30 text-red-400 rounded-lg mb-6 border border-red-800/50">
            {error}
          </div>
        )}

        {loading && (
          <div className="text-center py-12">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-brand-500 mx-auto"></div>
            <p className="mt-4 text-slate-500">Loading recording...</p>
          </div>
        )}

        {!loading && recording && (
          <div className="space-y-6">
            {/* Metadata header */}
            <div className="flex flex-wrap items-center gap-4 p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
              <div className="flex items-center gap-2">
                {recording.recording_type === 'terminal' ? (
                  <span className="inline-flex items-center gap-1 px-2.5 py-1 text-sm rounded bg-green-900/30 text-green-400">
                    <Terminal size={14} />
                    Terminal Recording
                  </span>
                ) : recording.recording_type === 'http' ? (
                  <span className="inline-flex items-center gap-1 px-2.5 py-1 text-sm rounded bg-amber-900/30 text-amber-400">
                    <Globe size={14} />
                    HTTP Exchange
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1 px-2.5 py-1 text-sm rounded bg-blue-900/30 text-blue-400">
                    <Database size={14} />
                    Database Queries
                  </span>
                )}
              </div>
              <div className="flex items-center gap-1.5 text-sm text-slate-300">
                <User size={14} className="text-slate-500" />
                {recording.user_email}
              </div>
              <div className="flex items-center gap-1.5 text-sm text-slate-300">
                <Server size={14} className="text-slate-500" />
                {recording.resource_name}
              </div>
              <div className="flex items-center gap-1.5 text-sm text-slate-400">
                <Clock size={14} className="text-slate-500" />
                {formatTimestamp(recording.started_at)}
              </div>
              <div className="text-sm text-slate-400">
                Duration: {formatDuration(recording.started_at, recording.ended_at)}
              </div>
            </div>

            {/* Recording content */}
            {recording.recording_type === 'terminal' ? (
              <RecordingPlayer recording={recording.recording_data} />
            ) : recording.recording_type === 'http' ? (
              <HttpExchangeViewer
                exchange={(() => {
                  try {
                    return JSON.parse(recording.recording_data)
                  } catch {
                    return null
                  }
                })()}
              />
            ) : (
              <QueryViewer
                queries={(() => {
                  try {
                    return JSON.parse(recording.recording_data)
                  } catch {
                    return []
                  }
                })()}
              />
            )}
          </div>
        )}
      </main>
    </div>
  )
}
