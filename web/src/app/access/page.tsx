'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { Plus, Pencil, Trash2 } from 'lucide-react'
import NavBar from '@/components/nav-bar'
import { getAuthState, isAdmin, clearAuth, loginRedirectUrl } from '@/lib/auth'

interface Identity {
  provider_name: string
  email: string
  display_name: string | null
  roles: string[]
}

interface RoleOption {
  name: string
  is_builtin: boolean
}

export default function AccessPage() {
  const router = useRouter()
  const [identities, setIdentities] = useState<Identity[]>([])
  const [availableRoles, setAvailableRoles] = useState<RoleOption[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const [showAssign, setShowAssign] = useState(false)
  const [editingKey, setEditingKey] = useState<string | null>(null)
  const [deletingKey, setDeletingKey] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  useEffect(() => {
    if (!getAuthState()) {
      router.push(loginRedirectUrl())
      return
    }
    if (!isAdmin()) {
      router.push('/')
      return
    }
    fetchIdentities()
    fetchRoles()
  }, [router])

  const authHeaders = (): HeadersInit => {
    const state = getAuthState()
    if (!state) {
      clearAuth()
      router.push(loginRedirectUrl())
      return {}
    }
    return { Authorization: `Bearer ${state.token}` }
  }

  const fetchIdentities = async () => {
    try {
      const response = await fetch('/api/v1/role-assignments/identities', {
        headers: authHeaders(),
      })
      if (response.status === 401) {
        clearAuth()
        router.push(loginRedirectUrl())
        return
      }
      if (!response.ok) throw new Error('Failed to fetch identities')
      const data = await response.json()
      setIdentities(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load identities')
    } finally {
      setLoading(false)
    }
  }

  const fetchRoles = async () => {
    try {
      const response = await fetch('/api/v1/roles?limit=100', {
        headers: authHeaders(),
      })
      if (response.ok) {
        const data = await response.json()
        setAvailableRoles(
          data.items
            .filter((r: RoleOption) => r.name !== 'everyone')
            .map((r: RoleOption) => ({ name: r.name, is_builtin: r.is_builtin }))
        )
      }
    } catch {
      // Non-critical
    }
  }

  const handleSaveRoles = async (providerName: string, email: string, roles: string[]) => {
    setSubmitting(true)
    setError('')
    try {
      const response = await fetch('/api/v1/role-assignments', {
        method: 'PUT',
        headers: { ...authHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider_name: providerName, email, roles }),
      })
      if (!response.ok) {
        const b = await response.json().catch(() => ({}))
        const detail = Array.isArray(b.detail) ? b.detail[0]?.msg : b.detail
        throw new Error(detail || `Failed to update roles (${response.status})`)
      }
      setEditingKey(null)
      setShowAssign(false)
      // Update local list — avoids read-after-write against a stale replica
      setIdentities((prev) => {
        const exists = prev.some(
          (i) => i.provider_name === providerName && i.email === email
        )
        if (exists) {
          return prev.map((i) =>
            i.provider_name === providerName && i.email === email
              ? { ...i, roles }
              : i
          )
        }
        // New identity — prepend
        return [{ provider_name: providerName, email, display_name: null, roles }, ...prev]
      })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update roles')
    } finally {
      setSubmitting(false)
    }
  }

  const handleRemoveAll = async (providerName: string, email: string) => {
    setSubmitting(true)
    setError('')
    try {
      const response = await fetch('/api/v1/role-assignments', {
        method: 'PUT',
        headers: { ...authHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider_name: providerName, email, roles: [] }),
      })
      if (!response.ok) {
        const b = await response.json().catch(() => ({}))
        const detail = Array.isArray(b.detail) ? b.detail[0]?.msg : b.detail
        throw new Error(detail || `Failed to remove roles (${response.status})`)
      }
      setDeletingKey(null)
      // Remove from local list — avoids read-after-write against a stale replica
      setIdentities((prev) =>
        prev.filter((i) => !(i.provider_name === providerName && i.email === email))
      )
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to remove roles')
    } finally {
      setSubmitting(false)
    }
  }

  const identityKey = (i: Identity) => `${i.provider_name}:${i.email}`

  return (
    <div className="min-h-screen flex flex-col">
      <NavBar />
      <main className="flex-1 max-w-7xl mx-auto w-full px-4 sm:px-6 lg:px-8 py-6">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-xl font-semibold text-slate-100">Access</h1>
            <p className="text-sm text-slate-400 mt-1">
              Manage role assignments for local and SSO users
            </p>
          </div>
          {!showAssign && (
            <button
              onClick={() => { setShowAssign(true); setEditingKey(null) }}
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium bg-brand-600 hover:bg-brand-500 text-white rounded-lg transition-colors btn-smoke"
            >
              <Plus size={16} />
              Assign Roles
            </button>
          )}
        </div>

        {error && (
          <div className="p-4 bg-red-900/30 text-red-400 rounded-lg mb-6 border border-red-800/50">
            {error}
          </div>
        )}

        {showAssign && (
          <div className="mb-6">
            <NewAssignmentForm
              identities={identities}
              availableRoles={availableRoles}
              onSubmit={(provider, email, roles) => handleSaveRoles(provider, email, roles)}
              onCancel={() => setShowAssign(false)}
              submitting={submitting}
            />
          </div>
        )}

        {loading && (
          <div className="text-center py-12">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-brand-500 mx-auto"></div>
            <p className="mt-4 text-slate-500">Loading identities...</p>
          </div>
        )}

        {!loading && (
          <div className="space-y-3">
            {identities.map((identity) => {
              const key = identityKey(identity)
              return (
                <div key={key}>
                  {editingKey === key ? (
                    <EditRolesForm
                      identity={identity}
                      availableRoles={availableRoles}
                      onSubmit={(roles) => handleSaveRoles(identity.provider_name, identity.email, roles)}
                      onCancel={() => setEditingKey(null)}
                      submitting={submitting}
                    />
                  ) : (
                    <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center gap-2">
                            <h3 className="font-semibold text-slate-100">{identity.email}</h3>
                            <span
                              className={`px-2 py-0.5 text-xs rounded ${
                                identity.provider_name === 'local'
                                  ? 'bg-slate-700 text-slate-300'
                                  : 'bg-purple-900/30 text-purple-400'
                              }`}
                            >
                              {identity.provider_name}
                            </span>
                            {identity.display_name && (
                              <span className="text-sm text-slate-500">{identity.display_name}</span>
                            )}
                          </div>
                          {identity.roles.length > 0 ? (
                            <div className="flex flex-wrap gap-1 mt-2">
                              {identity.roles.map((role) => (
                                <span
                                  key={role}
                                  className="px-2 py-0.5 text-xs rounded bg-brand-900/30 text-brand-400"
                                >
                                  {role}
                                </span>
                              ))}
                            </div>
                          ) : (
                            <p className="text-xs text-slate-500 mt-2">No roles assigned</p>
                          )}
                        </div>
                        <div className="flex items-center gap-1 ml-4">
                          <button
                            onClick={() => { setEditingKey(key); setShowAssign(false); setDeletingKey(null) }}
                            className="p-2 text-slate-400 hover:text-slate-200 hover:bg-slate-700/50 rounded transition-colors"
                            title="Edit roles"
                          >
                            <Pencil size={14} />
                          </button>
                          {identity.roles.length > 0 && (
                            deletingKey === key ? (
                              <button
                                onClick={() => handleRemoveAll(identity.provider_name, identity.email)}
                                disabled={submitting}
                                className="px-3 py-1.5 text-xs font-medium bg-red-600 hover:bg-red-500 disabled:bg-red-800 text-white rounded transition-colors"
                              >
                                {submitting ? 'Removing...' : 'Confirm Remove?'}
                              </button>
                            ) : (
                              <button
                                onClick={() => setDeletingKey(key)}
                                className="p-2 text-slate-400 hover:text-red-400 hover:bg-slate-700/50 rounded transition-colors"
                                title="Remove all roles"
                              >
                                <Trash2 size={14} />
                              </button>
                            )
                          )}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )
            })}

            {identities.length === 0 && !error && (
              <p className="text-slate-500 text-center py-12">No identities found</p>
            )}
          </div>
        )}
      </main>
    </div>
  )
}

function EditRolesForm({
  identity,
  availableRoles,
  onSubmit,
  onCancel,
  submitting,
}: {
  identity: Identity
  availableRoles: RoleOption[]
  onSubmit: (roles: string[]) => void
  onCancel: () => void
  submitting: boolean
}) {
  const [selectedRoles, setSelectedRoles] = useState<Set<string>>(new Set(identity.roles))

  const toggleRole = (name: string) => {
    setSelectedRoles((prev) => {
      const next = new Set(prev)
      if (next.has(name)) next.delete(name)
      else next.add(name)
      return next
    })
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    onSubmit(Array.from(selectedRoles))
  }

  return (
    <form onSubmit={handleSubmit} className="p-4 bg-slate-800/80 rounded-lg border border-slate-700/50 space-y-4">
      <div className="flex items-center gap-2">
        <span className="font-semibold text-slate-100">{identity.email}</span>
        <span
          className={`px-2 py-0.5 text-xs rounded ${
            identity.provider_name === 'local'
              ? 'bg-slate-700 text-slate-300'
              : 'bg-purple-900/30 text-purple-400'
          }`}
        >
          {identity.provider_name}
        </span>
      </div>

      {availableRoles.length > 0 && (
        <div>
          <label className="block text-sm font-medium text-slate-300 mb-2">Roles</label>
          <div className="flex flex-wrap gap-2">
            {availableRoles.map((role) => (
              <label
                key={role.name}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs cursor-pointer border transition-colors ${
                  selectedRoles.has(role.name)
                    ? 'border-brand-500 bg-brand-900/30 text-brand-400'
                    : 'border-slate-600 bg-slate-700/50 text-slate-400 hover:border-slate-500'
                }`}
              >
                <input
                  type="checkbox"
                  checked={selectedRoles.has(role.name)}
                  onChange={() => toggleRole(role.name)}
                  className="sr-only"
                />
                {role.name}
              </label>
            ))}
          </div>
        </div>
      )}

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
          disabled={submitting}
          className="px-4 py-2 text-sm font-medium bg-brand-600 hover:bg-brand-500 disabled:bg-brand-800 disabled:text-brand-400 text-white rounded-lg transition-colors btn-smoke"
        >
          {submitting ? 'Saving...' : 'Save'}
        </button>
      </div>
    </form>
  )
}

function NewAssignmentForm({
  identities,
  availableRoles,
  onSubmit,
  onCancel,
  submitting,
}: {
  identities: Identity[]
  availableRoles: RoleOption[]
  onSubmit: (provider: string, email: string, roles: string[]) => void
  onCancel: () => void
  submitting: boolean
}) {
  const providers = Array.from(new Set(identities.map((i) => i.provider_name))).sort(
    (a, b) => (a === 'local' ? -1 : b === 'local' ? 1 : a.localeCompare(b))
  )
  const [provider, setProvider] = useState(providers[0] || 'local')
  const [email, setEmail] = useState('')
  const [selectedRoles, setSelectedRoles] = useState<Set<string>>(new Set())

  const emailsForProvider = identities
    .filter((i) => i.provider_name === provider)
    .map((i) => i.email)
    .sort()

  const handleProviderChange = (newProvider: string) => {
    setProvider(newProvider)
    setEmail('')
  }

  const toggleRole = (name: string) => {
    setSelectedRoles((prev) => {
      const next = new Set(prev)
      if (next.has(name)) next.delete(name)
      else next.add(name)
      return next
    })
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    onSubmit(provider, email, Array.from(selectedRoles))
  }

  return (
    <form onSubmit={handleSubmit} className="p-4 bg-slate-800/80 rounded-lg border border-slate-700/50 space-y-4">
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-slate-300 mb-1">Provider</label>
          <select
            value={provider}
            onChange={(e) => handleProviderChange(e.target.value)}
            className="w-full px-3 py-2 border border-slate-600 rounded-lg bg-slate-700 text-slate-100 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
          >
            {providers.map((p) => (
              <option key={p} value={p}>{p}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="block text-sm font-medium text-slate-300 mb-1">Email</label>
          <input
            type="text"
            list="email-suggestions"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            placeholder="user@example.com"
            className="w-full px-3 py-2 border border-slate-600 rounded-lg bg-slate-700 text-slate-100 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
          />
          <datalist id="email-suggestions">
            {emailsForProvider.map((e) => (
              <option key={e} value={e} />
            ))}
          </datalist>
        </div>
      </div>

      {availableRoles.length > 0 && (
        <div>
          <label className="block text-sm font-medium text-slate-300 mb-2">Roles</label>
          <div className="flex flex-wrap gap-2">
            {availableRoles.map((role) => (
              <label
                key={role.name}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs cursor-pointer border transition-colors ${
                  selectedRoles.has(role.name)
                    ? 'border-brand-500 bg-brand-900/30 text-brand-400'
                    : 'border-slate-600 bg-slate-700/50 text-slate-400 hover:border-slate-500'
                }`}
              >
                <input
                  type="checkbox"
                  checked={selectedRoles.has(role.name)}
                  onChange={() => toggleRole(role.name)}
                  className="sr-only"
                />
                {role.name}
              </label>
            ))}
          </div>
        </div>
      )}

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
          disabled={submitting || selectedRoles.size === 0 || !email}
          className="px-4 py-2 text-sm font-medium bg-brand-600 hover:bg-brand-500 disabled:bg-brand-800 disabled:text-brand-400 text-white rounded-lg transition-colors btn-smoke"
        >
          {submitting ? 'Saving...' : 'Assign'}
        </button>
      </div>
    </form>
  )
}
