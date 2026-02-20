'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { Search, Terminal } from 'lucide-react'
import NavBar from '@/components/nav-bar'
import { clearAuth, getAuthState, loginRedirectUrl } from '@/lib/auth'

interface Resource {
  name: string
  resource_type: string
  labels: Record<string, string>
  status: string
  agent_name?: string
  connect_url?: string
}

export default function Home() {
  const router = useRouter()
  const [resources, setResources] = useState<Resource[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [filter, setFilter] = useState('')
  const [typeFilter, setTypeFilter] = useState('')
  useEffect(() => {
    const state = getAuthState()
    if (!state) {
      router.push(loginRedirectUrl())
      return
    }
    fetchResources(state.token)
  }, [router])

  const fetchResources = async (token: string) => {
    try {
      const response = await fetch('/api/v1/resources', {
        headers: { Authorization: `Bearer ${token}` },
      })

      if (response.status === 401) {
        clearAuth()
        router.push(loginRedirectUrl())
        return
      }

      if (!response.ok) throw new Error('Failed to fetch resources')

      const data = await response.json()
      setResources(data.resources)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load resources')
    } finally {
      setLoading(false)
    }
  }

  const filteredResources = resources.filter((r) => {
    if (filter && !r.name.toLowerCase().includes(filter.toLowerCase())) return false
    if (typeFilter && !r.resource_type.startsWith(typeFilter)) return false
    return true
  })

  const terminalTypes = new Set([
    'ssh', 'ssh-audit', 'postgres', 'postgres-audit', 'mysql', 'mysql-audit',
  ])

  const openTerminal = (resource: Resource) => {
    router.push(
      `/terminal/new?type=${resource.resource_type}&resource=${encodeURIComponent(resource.name)}`
    )
  }

  const resourceTypes = ['ssh', 'http', 'postgres', 'mysql', 'kubernetes', 'tcp']

  const typeColors: Record<string, string> = {
    ssh: 'bg-green-900/30 text-green-400',
    kubernetes: 'bg-blue-900/30 text-blue-400',
    postgres: 'bg-purple-900/30 text-purple-400',
    mysql: 'bg-purple-900/30 text-purple-400',
    http: 'bg-orange-900/30 text-orange-400',
    tcp: 'bg-slate-700/50 text-slate-300',
  }

  return (
    <div className="min-h-screen flex flex-col">
      <NavBar />

      {/* Main Content */}
      <main className="flex-1 max-w-7xl mx-auto w-full px-4 sm:px-6 lg:px-8 py-6">
        {/* Filters */}
        <div className="flex gap-3 mb-6">
          <div className="relative flex-1 max-w-md">
            <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              placeholder="Search resources..."
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              className="w-full pl-9 pr-4 py-2 border border-slate-700 rounded-lg bg-slate-800/50 text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-brand-500/50 focus:border-brand-500/50"
            />
          </div>
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="px-4 py-2 border border-slate-700 rounded-lg bg-slate-800/50 text-slate-200 focus:outline-none focus:ring-2 focus:ring-brand-500/50 focus:border-brand-500/50"
          >
            <option value="">All Types</option>
            {resourceTypes.map((type) => (
              <option key={type} value={type}>
                {type.charAt(0).toUpperCase() + type.slice(1)}
              </option>
            ))}
          </select>
        </div>

        {/* Error State */}
        {error && (
          <div className="p-4 bg-red-900/30 text-red-400 rounded-lg mb-6 border border-red-800/50">
            {error}
          </div>
        )}

        {/* Loading State */}
        {loading && (
          <div className="text-center py-12">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-brand-500 mx-auto"></div>
            <p className="mt-4 text-slate-500">Loading resources...</p>
          </div>
        )}

        {/* Resources Grid */}
        {!loading && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {filteredResources.map((resource) => (
              <div
                key={resource.name}
                className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50 hover:border-brand-600/30 transition-colors"
              >
                <div className="flex justify-between items-start mb-2">
                  <h3 className="font-semibold text-slate-100">{resource.name}</h3>
                  <span
                    className={`px-2 py-1 text-xs font-medium rounded ${
                      typeColors[resource.resource_type] || 'bg-slate-700 text-slate-300'
                    }`}
                  >
                    {resource.resource_type}
                  </span>
                </div>

                <div className="flex items-center gap-2 mb-3">
                  <span
                    className={`w-2 h-2 rounded-full ${
                      resource.status === 'available' ? 'bg-green-500' : 'bg-slate-500'
                    }`}
                  ></span>
                  <span className={`text-sm ${
                    resource.status === 'available' ? 'text-green-400' : 'text-slate-500'
                  }`}>
                    {resource.status}
                  </span>
                </div>

                {Object.keys(resource.labels).length > 0 && (
                  <div className="flex flex-wrap gap-1 mb-3">
                    {Object.entries(resource.labels).map(([key, value]) => (
                      <span
                        key={key}
                        className="px-2 py-0.5 text-xs bg-slate-700/50 text-slate-400 rounded"
                      >
                        {key}={value}
                      </span>
                    ))}
                  </div>
                )}

                <div className="flex gap-2">
                  {resource.connect_url && (
                    <a
                      href={resource.connect_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex-1 block text-center py-2 bg-brand-600 hover:bg-brand-500 text-white text-sm font-medium rounded-lg transition-colors btn-smoke"
                    >
                      Open
                    </a>
                  )}
                  {terminalTypes.has(resource.resource_type) && resource.status === 'available' && (
                    <button
                      onClick={() => openTerminal(resource)}
                      className="flex-1 flex items-center justify-center gap-1.5 py-2 bg-brand-600 hover:bg-brand-500 text-white text-sm font-medium rounded-lg transition-colors btn-smoke"
                      title="Open web terminal"
                    >
                      <Terminal size={14} />
                      Terminal
                    </button>
                  )}
                </div>
              </div>
            ))}
            {filteredResources.length === 0 && !error && (
              <p className="text-slate-500 col-span-full text-center py-12">
                No resources found
              </p>
            )}
          </div>
        )}
      </main>
    </div>
  )
}
