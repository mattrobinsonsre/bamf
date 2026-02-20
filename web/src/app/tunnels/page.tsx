'use client'

import { useEffect, useState, useCallback } from 'react'
import { useRouter } from 'next/navigation'
import { Zap, Users, Server, Box, RefreshCw, XCircle } from 'lucide-react'
import NavBar from '@/components/nav-bar'
import { getAuthState, isAdmin, isAdminOrAudit, clearAuth, loginRedirectUrl } from '@/lib/auth'

const REFRESH_INTERVAL = 5000

interface ActiveTunnel {
  session_id: string
  user_email: string
  resource_name: string
  protocol: string
  bridge_id: string
  status: string
  created_at: string
  established_at: string | null
  duration_seconds: number | null
}

interface ActiveTunnelsResponse {
  tunnels: ActiveTunnel[]
  total: number
  by_user: Record<string, number>
  by_resource: Record<string, number>
  by_bridge: Record<string, number>
  by_protocol: Record<string, number>
}

function formatDuration(seconds: number | null): string {
  if (seconds === null || seconds < 0) return '-'
  if (seconds < 60) return `${Math.floor(seconds)}s`
  if (seconds < 3600) {
    const m = Math.floor(seconds / 60)
    const s = Math.floor(seconds % 60)
    return `${m}m ${s}s`
  }
  const h = Math.floor(seconds / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  return `${h}h ${m}m`
}

function formatTimeAgo(seconds: number): string {
  if (seconds < 5) return 'just now'
  if (seconds < 60) return `${Math.floor(seconds)}s ago`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`
  return `${Math.floor(seconds / 3600)}h ago`
}

const PROTOCOL_COLORS: Record<string, string> = {
  ssh: 'bg-blue-900/30 text-blue-400',
  'ssh-audit': 'bg-indigo-900/30 text-indigo-400',
  postgres: 'bg-emerald-900/30 text-emerald-400',
  'postgres-audit': 'bg-teal-900/30 text-teal-400',
  mysql: 'bg-orange-900/30 text-orange-400',
  'mysql-audit': 'bg-amber-900/30 text-amber-400',
  http: 'bg-purple-900/30 text-purple-400',
  kubernetes: 'bg-cyan-900/30 text-cyan-400',
  tcp: 'bg-slate-700/30 text-slate-300',
}

function StatCard({
  icon: Icon,
  label,
  value,
}: {
  icon: React.ComponentType<{ size: number; className?: string }>
  label: string
  value: number
}) {
  return (
    <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
      <div className="flex items-center gap-3">
        <div className="p-2 bg-slate-700/50 rounded-lg">
          <Icon size={20} className="text-brand-400" />
        </div>
        <div>
          <p className="text-2xl font-bold text-slate-100">{value}</p>
          <p className="text-sm text-slate-400">{label}</p>
        </div>
      </div>
    </div>
  )
}

export default function TunnelsPage() {
  const router = useRouter()
  const [data, setData] = useState<ActiveTunnelsResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)
  const [now, setNow] = useState(new Date())

  const authHeaders = useCallback((): HeadersInit => {
    const state = getAuthState()
    if (!state) {
      clearAuth()
      router.push(loginRedirectUrl())
      return {}
    }
    return { Authorization: `Bearer ${state.token}` }
  }, [router])

  const fetchTunnels = useCallback(async () => {
    try {
      const response = await fetch('/api/v1/tunnels/active', {
        headers: authHeaders(),
      })

      if (response.status === 401) {
        clearAuth()
        router.push(loginRedirectUrl())
        return
      }
      if (!response.ok) throw new Error('Failed to fetch tunnels')

      const result: ActiveTunnelsResponse = await response.json()
      setData(result)
      setLastUpdated(new Date())
      setError('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load tunnels')
    } finally {
      setLoading(false)
    }
  }, [authHeaders, router])

  useEffect(() => {
    if (!getAuthState()) {
      router.push(loginRedirectUrl())
      return
    }
    if (!isAdminOrAudit()) {
      router.push('/')
      return
    }
    fetchTunnels()
    const interval = setInterval(fetchTunnels, REFRESH_INTERVAL)
    return () => clearInterval(interval)
  }, [router, fetchTunnels])

  // Tick "Updated X ago" every second
  useEffect(() => {
    const tick = setInterval(() => setNow(new Date()), 1000)
    return () => clearInterval(tick)
  }, [])

  const secondsSinceUpdate = lastUpdated
    ? Math.floor((now.getTime() - lastUpdated.getTime()) / 1000)
    : 0

  const terminateTunnel = useCallback(async (sessionId: string) => {
    const state = getAuthState()
    if (!state) return

    try {
      const resp = await fetch(`/api/v1/tunnels/${sessionId}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${state.token}` },
      })
      if (resp.status === 401) {
        clearAuth()
        router.push(loginRedirectUrl())
        return
      }
      if (!resp.ok) {
        const errData = await resp.json().catch(() => ({ detail: 'Failed to terminate' }))
        setError(errData.detail || 'Failed to terminate tunnel')
        return
      }
      // Remove from local state immediately
      setData((prev) => {
        if (!prev) return prev
        const tunnels = prev.tunnels.filter((t) => t.session_id !== sessionId)
        return { ...prev, tunnels, total: tunnels.length }
      })
    } catch {
      setError('Failed to terminate tunnel')
    }
  }, [router])

  const currentEmail = getAuthState()?.email
  const userIsAdmin = isAdmin()

  const uniqueUsers = data ? Object.keys(data.by_user).length : 0
  const uniqueResources = data ? Object.keys(data.by_resource).length : 0
  const uniqueBridges = data ? Object.keys(data.by_bridge).length : 0

  return (
    <div className="min-h-screen flex flex-col">
      <NavBar />
      <main className="flex-1 max-w-7xl mx-auto w-full px-4 sm:px-6 lg:px-8 py-6">
        <div className="flex items-center justify-between mb-6">
          <h1 className="text-xl font-semibold text-slate-100">Active Tunnels</h1>
          <div className="flex items-center gap-3 text-sm text-slate-400">
            {lastUpdated && (
              <span>Updated {formatTimeAgo(secondsSinceUpdate)}</span>
            )}
            <button
              onClick={fetchTunnels}
              className="p-1.5 rounded hover:bg-slate-800 transition-colors"
              title="Refresh now"
            >
              <RefreshCw size={14} />
            </button>
          </div>
        </div>

        {error && (
          <div className="p-4 bg-red-900/30 text-red-400 rounded-lg mb-6 border border-red-800/50">
            {error}
          </div>
        )}

        {loading && (
          <div className="text-center py-12">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-brand-500 mx-auto"></div>
            <p className="mt-4 text-slate-500">Loading tunnels...</p>
          </div>
        )}

        {!loading && data && (
          <>
            {/* Summary cards */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
              <StatCard icon={Zap} label="Total Tunnels" value={data.total} />
              <StatCard icon={Users} label="Active Users" value={uniqueUsers} />
              <StatCard icon={Server} label="Resources" value={uniqueResources} />
              <StatCard icon={Box} label="Bridges" value={uniqueBridges} />
            </div>

            {/* Tunnel table */}
            {data.tunnels.length === 0 ? (
              <div className="text-center py-12">
                <Zap size={32} className="mx-auto text-slate-600 mb-3" />
                <p className="text-slate-500">No active tunnels</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-slate-700/50 text-left text-slate-400">
                      <th className="py-3 px-3 font-medium">User</th>
                      <th className="py-3 px-3 font-medium">Resource</th>
                      <th className="py-3 px-3 font-medium">Protocol</th>
                      <th className="py-3 px-3 font-medium">Bridge</th>
                      <th className="py-3 px-3 font-medium">Status</th>
                      <th className="py-3 px-3 font-medium">Duration</th>
                      <th className="py-3 px-3 font-medium w-20"></th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.tunnels.map((tunnel) => (
                      <tr
                        key={tunnel.session_id}
                        className="border-b border-slate-800/50 hover:bg-slate-800/30 transition-colors"
                      >
                        <td className="py-3 px-3 text-slate-200">{tunnel.user_email}</td>
                        <td className="py-3 px-3 text-slate-200 font-mono text-xs">
                          {tunnel.resource_name}
                        </td>
                        <td className="py-3 px-3">
                          <span
                            className={`px-2 py-0.5 text-xs rounded ${
                              PROTOCOL_COLORS[tunnel.protocol] || 'bg-slate-700 text-slate-300'
                            }`}
                          >
                            {tunnel.protocol}
                          </span>
                        </td>
                        <td className="py-3 px-3 text-slate-400 font-mono text-xs">
                          {tunnel.bridge_id}
                        </td>
                        <td className="py-3 px-3">
                          <span
                            className={`px-2 py-0.5 text-xs rounded ${
                              tunnel.status === 'established'
                                ? 'bg-green-900/30 text-green-400'
                                : 'bg-yellow-900/30 text-yellow-400'
                            }`}
                          >
                            {tunnel.status}
                          </span>
                        </td>
                        <td className="py-3 px-3 text-slate-400 tabular-nums">
                          {formatDuration(tunnel.duration_seconds)}
                        </td>
                        <td className="py-3 px-3">
                          {(userIsAdmin || tunnel.user_email === currentEmail) && (
                            <button
                              onClick={() => terminateTunnel(tunnel.session_id)}
                              className="p-1 text-slate-500 hover:text-red-400 transition-colors"
                              title={userIsAdmin && tunnel.user_email !== currentEmail
                                ? `Terminate ${tunnel.user_email}'s tunnel`
                                : 'Terminate tunnel'}
                            >
                              <XCircle size={16} />
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
      </main>
    </div>
  )
}
