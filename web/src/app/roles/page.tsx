'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { Plus, Pencil, Trash2, X } from 'lucide-react'
import NavBar from '@/components/nav-bar'
import { getAuthState, isAdmin, clearAuth, loginRedirectUrl } from '@/lib/auth'

interface PermissionsBlock {
  labels: Record<string, string[]>
  names: string[]
}

interface RoleResponse {
  name: string
  description: string | null
  is_builtin: boolean
  allow: PermissionsBlock
  deny: PermissionsBlock
  created_at: string
  updated_at: string
}

interface LabelRow {
  key: string
  values: string
}

function emptyPermissions(): PermissionsBlock {
  return { labels: {}, names: [] }
}

function permissionsToLabelRows(p: PermissionsBlock): LabelRow[] {
  const rows = Object.entries(p.labels).map(([key, values]) => ({
    key,
    values: values.join(', '),
  }))
  return rows.length > 0 ? rows : [{ key: '', values: '' }]
}

function labelRowsToLabels(rows: LabelRow[]): Record<string, string[]> {
  const labels: Record<string, string[]> = {}
  for (const row of rows) {
    const key = row.key.trim()
    if (!key) continue
    const vals = row.values
      .split(',')
      .map((v) => v.trim())
      .filter(Boolean)
    if (vals.length > 0) labels[key] = vals
  }
  return labels
}

function namesToList(raw: string): string[] {
  return raw
    .split(',')
    .map((n) => n.trim())
    .filter(Boolean)
}

function PermissionsPills({ label, perms, color }: { label: string; perms: PermissionsBlock; color: 'green' | 'red' }) {
  const hasLabels = Object.keys(perms.labels).length > 0
  const hasNames = perms.names.length > 0
  if (!hasLabels && !hasNames) return null

  const bg = color === 'green' ? 'bg-green-900/30 text-green-400' : 'bg-red-900/30 text-red-400'

  return (
    <div className="flex flex-wrap items-center gap-1 mt-1">
      <span className="text-xs text-slate-500 mr-1">{label}:</span>
      {Object.entries(perms.labels).map(([key, vals]) => (
        <span key={`l-${key}`} className={`px-2 py-0.5 text-xs rounded ${bg}`}>
          {key}={vals.join(',')}
        </span>
      ))}
      {perms.names.map((n) => (
        <span key={`n-${n}`} className={`px-2 py-0.5 text-xs rounded ${bg}`}>
          {n}
        </span>
      ))}
    </div>
  )
}

function RoleForm({
  initial,
  nameReadOnly,
  onSubmit,
  onCancel,
  submitting,
}: {
  initial?: RoleResponse
  nameReadOnly?: boolean
  onSubmit: (data: { name: string; description: string; allow: PermissionsBlock; deny: PermissionsBlock }) => void
  onCancel: () => void
  submitting: boolean
}) {
  const [name, setName] = useState(initial?.name ?? '')
  const [description, setDescription] = useState(initial?.description ?? '')
  const [allowLabels, setAllowLabels] = useState<LabelRow[]>(
    initial ? permissionsToLabelRows(initial.allow) : [{ key: '', values: '' }]
  )
  const [allowNames, setAllowNames] = useState(initial?.allow.names.join(', ') ?? '')
  const [denyLabels, setDenyLabels] = useState<LabelRow[]>(
    initial ? permissionsToLabelRows(initial.deny) : [{ key: '', values: '' }]
  )
  const [denyNames, setDenyNames] = useState(initial?.deny.names.join(', ') ?? '')

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    onSubmit({
      name,
      description,
      allow: { labels: labelRowsToLabels(allowLabels), names: namesToList(allowNames) },
      deny: { labels: labelRowsToLabels(denyLabels), names: namesToList(denyNames) },
    })
  }

  const updateLabelRow = (
    rows: LabelRow[],
    setRows: (r: LabelRow[]) => void,
    index: number,
    field: 'key' | 'values',
    value: string
  ) => {
    const updated = [...rows]
    updated[index] = { ...updated[index], [field]: value }
    setRows(updated)
  }

  const addLabelRow = (rows: LabelRow[], setRows: (r: LabelRow[]) => void) => {
    setRows([...rows, { key: '', values: '' }])
  }

  const removeLabelRow = (rows: LabelRow[], setRows: (r: LabelRow[]) => void, index: number) => {
    if (rows.length <= 1) {
      setRows([{ key: '', values: '' }])
    } else {
      setRows(rows.filter((_, i) => i !== index))
    }
  }

  const LabelEditor = ({
    label,
    rows,
    setRows,
    namesValue,
    setNamesValue,
  }: {
    label: string
    rows: LabelRow[]
    setRows: (r: LabelRow[]) => void
    namesValue: string
    setNamesValue: (v: string) => void
  }) => (
    <div className="space-y-2">
      <h4 className="text-sm font-medium text-slate-300">{label}</h4>
      <div className="space-y-1">
        <label className="text-xs text-slate-500">Labels (key = comma-separated values)</label>
        {rows.map((row, i) => (
          <div key={i} className="flex gap-2 items-center">
            <input
              type="text"
              placeholder="key"
              value={row.key}
              onChange={(e) => updateLabelRow(rows, setRows, i, 'key', e.target.value)}
              className="w-32 px-2 py-1.5 border border-slate-600 rounded bg-slate-700 text-slate-100 text-sm focus:outline-none focus:ring-1 focus:ring-brand-500"
            />
            <span className="text-slate-500">=</span>
            <input
              type="text"
              placeholder="val1, val2"
              value={row.values}
              onChange={(e) => updateLabelRow(rows, setRows, i, 'values', e.target.value)}
              className="flex-1 px-2 py-1.5 border border-slate-600 rounded bg-slate-700 text-slate-100 text-sm focus:outline-none focus:ring-1 focus:ring-brand-500"
            />
            <button
              type="button"
              onClick={() => removeLabelRow(rows, setRows, i)}
              className="text-slate-500 hover:text-slate-300 p-1"
            >
              <X size={14} />
            </button>
          </div>
        ))}
        <button
          type="button"
          onClick={() => addLabelRow(rows, setRows)}
          className="text-xs text-brand-400 hover:text-brand-300"
        >
          + Add label
        </button>
      </div>
      <div>
        <label className="text-xs text-slate-500">Names (comma-separated)</label>
        <input
          type="text"
          placeholder="resource-a, resource-b"
          value={namesValue}
          onChange={(e) => setNamesValue(e.target.value)}
          className="w-full px-2 py-1.5 border border-slate-600 rounded bg-slate-700 text-slate-100 text-sm focus:outline-none focus:ring-1 focus:ring-brand-500"
        />
      </div>
    </div>
  )

  return (
    <form onSubmit={handleSubmit} className="p-4 bg-slate-800/80 rounded-lg border border-slate-700/50 space-y-4">
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-slate-300 mb-1">Name</label>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            disabled={nameReadOnly}
            required
            pattern="[a-z][a-z0-9-]*"
            maxLength={63}
            placeholder="my-role"
            className="w-full px-3 py-2 border border-slate-600 rounded-lg bg-slate-700 text-slate-100 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500 disabled:opacity-50"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-slate-300 mb-1">Description</label>
          <input
            type="text"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Optional description"
            className="w-full px-3 py-2 border border-slate-600 rounded-lg bg-slate-700 text-slate-100 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
          />
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <LabelEditor label="Allow" rows={allowLabels} setRows={setAllowLabels} namesValue={allowNames} setNamesValue={setAllowNames} />
        <LabelEditor label="Deny" rows={denyLabels} setRows={setDenyLabels} namesValue={denyNames} setNamesValue={setDenyNames} />
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
          disabled={submitting}
          className="px-4 py-2 text-sm font-medium bg-brand-600 hover:bg-brand-500 disabled:bg-brand-800 disabled:text-brand-400 text-white rounded-lg transition-colors btn-smoke"
        >
          {submitting ? 'Saving...' : 'Save'}
        </button>
      </div>
    </form>
  )
}

export default function RolesPage() {
  const router = useRouter()
  const [roles, setRoles] = useState<RoleResponse[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [nextCursor, setNextCursor] = useState<string | null>(null)
  const [hasMore, setHasMore] = useState(false)

  const [showCreate, setShowCreate] = useState(false)
  const [editingRole, setEditingRole] = useState<string | null>(null)
  const [deletingRole, setDeletingRole] = useState<string | null>(null)
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

  const fetchRoles = async (cursor?: string) => {
    try {
      const params = new URLSearchParams()
      if (cursor) params.set('cursor', cursor)

      const response = await fetch(`/api/v1/roles?${params}`, {
        headers: authHeaders(),
      })

      if (response.status === 401) {
        clearAuth()
        router.push(loginRedirectUrl())
        return
      }
      if (!response.ok) throw new Error('Failed to fetch roles')

      const data = await response.json()
      if (cursor) {
        setRoles((prev) => [...prev, ...data.items])
      } else {
        setRoles(data.items)
      }
      setNextCursor(data.next_cursor)
      setHasMore(data.has_more)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load roles')
    } finally {
      setLoading(false)
    }
  }

  const handleCreate = async (data: { name: string; description: string; allow: PermissionsBlock; deny: PermissionsBlock }) => {
    setSubmitting(true)
    setError('')
    try {
      const response = await fetch('/api/v1/roles', {
        method: 'POST',
        headers: { ...authHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      })
      if (!response.ok) {
        const body = await response.json().catch(() => ({}))
        throw new Error(body.detail || `Failed to create role (${response.status})`)
      }
      const created = await response.json()
      setShowCreate(false)
      // Prepend to local list — avoids read-after-write against a stale replica
      setRoles((prev) => [created, ...prev])
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create role')
    } finally {
      setSubmitting(false)
    }
  }

  const handleUpdate = async (name: string, data: { name: string; description: string; allow: PermissionsBlock; deny: PermissionsBlock }) => {
    setSubmitting(true)
    setError('')
    try {
      const response = await fetch(`/api/v1/roles/${encodeURIComponent(name)}`, {
        method: 'PATCH',
        headers: { ...authHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ description: data.description, allow: data.allow, deny: data.deny }),
      })
      if (!response.ok) {
        const body = await response.json().catch(() => ({}))
        throw new Error(body.detail || `Failed to update role (${response.status})`)
      }
      const updated = await response.json()
      setEditingRole(null)
      // Replace in local list — avoids read-after-write against a stale replica
      setRoles((prev) => prev.map((r) => (r.name === name ? updated : r)))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update role')
    } finally {
      setSubmitting(false)
    }
  }

  const handleDelete = async (name: string) => {
    setSubmitting(true)
    setError('')
    try {
      const response = await fetch(`/api/v1/roles/${encodeURIComponent(name)}`, {
        method: 'DELETE',
        headers: authHeaders(),
      })
      if (!response.ok && response.status !== 204) {
        const body = await response.json().catch(() => ({}))
        throw new Error(body.detail || `Failed to delete role (${response.status})`)
      }
      setDeletingRole(null)
      setRoles((prev) => prev.filter((r) => r.name !== name))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete role')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="min-h-screen flex flex-col">
      <NavBar />
      <main className="flex-1 max-w-7xl mx-auto w-full px-4 sm:px-6 lg:px-8 py-6">
        <div className="flex items-center justify-between mb-6">
          <h1 className="text-xl font-semibold text-slate-100">Roles</h1>
          {!showCreate && (
            <button
              onClick={() => { setShowCreate(true); setEditingRole(null) }}
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium bg-brand-600 hover:bg-brand-500 text-white rounded-lg transition-colors btn-smoke"
            >
              <Plus size={16} />
              Create Role
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
            <RoleForm
              onSubmit={handleCreate}
              onCancel={() => setShowCreate(false)}
              submitting={submitting}
            />
          </div>
        )}

        {loading && (
          <div className="text-center py-12">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-brand-500 mx-auto"></div>
            <p className="mt-4 text-slate-500">Loading roles...</p>
          </div>
        )}

        {!loading && (
          <div className="space-y-3">
            {roles.map((role) => (
              <div key={role.name}>
                {editingRole === role.name ? (
                  <RoleForm
                    initial={role}
                    nameReadOnly
                    onSubmit={(data) => handleUpdate(role.name, data)}
                    onCancel={() => setEditingRole(null)}
                    submitting={submitting}
                  />
                ) : (
                  <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          <h3 className="font-semibold text-slate-100">{role.name}</h3>
                          {role.is_builtin && (
                            <span className="px-2 py-0.5 text-xs bg-brand-900/30 text-brand-400 rounded">
                              built-in
                            </span>
                          )}
                        </div>
                        {role.description && (
                          <p className="text-sm text-slate-400 mt-1">{role.description}</p>
                        )}
                        <PermissionsPills label="Allow" perms={role.allow} color="green" />
                        <PermissionsPills label="Deny" perms={role.deny} color="red" />
                      </div>
                      {!role.is_builtin && (
                        <div className="flex items-center gap-1 ml-4">
                          <button
                            onClick={() => { setEditingRole(role.name); setShowCreate(false) }}
                            className="p-2 text-slate-400 hover:text-slate-200 hover:bg-slate-700/50 rounded transition-colors"
                            title="Edit"
                          >
                            <Pencil size={14} />
                          </button>
                          {deletingRole === role.name ? (
                            <button
                              onClick={() => handleDelete(role.name)}
                              disabled={submitting}
                              className="px-3 py-1.5 text-xs font-medium bg-red-600 hover:bg-red-500 disabled:bg-red-800 text-white rounded transition-colors"
                            >
                              {submitting ? 'Deleting...' : 'Confirm Delete?'}
                            </button>
                          ) : (
                            <button
                              onClick={() => setDeletingRole(role.name)}
                              className="p-2 text-slate-400 hover:text-red-400 hover:bg-slate-700/50 rounded transition-colors"
                              title="Delete"
                            >
                              <Trash2 size={14} />
                            </button>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            ))}

            {roles.length === 0 && !error && (
              <p className="text-slate-500 text-center py-12">No roles found</p>
            )}

            {hasMore && (
              <div className="text-center pt-2">
                <button
                  onClick={() => fetchRoles(nextCursor ?? undefined)}
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
