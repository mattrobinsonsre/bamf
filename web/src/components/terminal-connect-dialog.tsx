'use client'

import { useRef, useState } from 'react'
import { KeyRound, Database } from 'lucide-react'

export interface SSHConnectData {
  type: 'ssh_connect'
  username: string
  auth_method: 'key' | 'password'
  key?: string
  password?: string
  cols: number
  rows: number
}

export interface DBConnectData {
  type: 'db_connect'
  username: string
  database: string
  password: string
  db_type: 'postgres' | 'mysql'
  cols: number
  rows: number
}

export type ConnectData = SSHConnectData | DBConnectData

interface TerminalConnectDialogProps {
  resourceType: string // ssh, postgres, mysql, etc.
  resourceName: string
  onConnect: (data: ConnectData) => void
  onCancel: () => void
}

export default function TerminalConnectDialog({
  resourceType,
  resourceName,
  onConnect,
  onCancel,
}: TerminalConnectDialogProps) {
  const isSSH = resourceType === 'ssh' || resourceType === 'ssh-audit'
  const isPostgres = resourceType === 'postgres' || resourceType === 'postgres-audit'

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
      <div className="bg-slate-800 border border-slate-700 rounded-xl shadow-2xl w-full max-w-md mx-4">
        <div className="px-6 py-4 border-b border-slate-700">
          <div className="flex items-center gap-3">
            {isSSH ? (
              <KeyRound size={20} className="text-green-400" />
            ) : (
              <Database size={20} className="text-purple-400" />
            )}
            <div>
              <h2 className="text-lg font-semibold text-slate-100">
                Connect to {resourceName}
              </h2>
              <p className="text-sm text-slate-400">
                {isSSH ? 'SSH Terminal' : isPostgres ? 'PostgreSQL Terminal' : 'MySQL Terminal'}
              </p>
            </div>
          </div>
        </div>

        <div className="p-6">
          {isSSH ? (
            <SSHForm onConnect={onConnect} onCancel={onCancel} />
          ) : (
            <DBForm
              dbType={isPostgres ? 'postgres' : 'mysql'}
              onConnect={onConnect}
              onCancel={onCancel}
            />
          )}
        </div>
      </div>
    </div>
  )
}

function SSHForm({
  onConnect,
  onCancel,
}: {
  onConnect: (data: ConnectData) => void
  onCancel: () => void
}) {
  const [username, setUsername] = useState('')
  const [authMethod, setAuthMethod] = useState<'key' | 'password'>('password')
  const [keyContent, setKeyContent] = useState('')
  const [keyFileName, setKeyFileName] = useState('')
  const [password, setPassword] = useState('')
  const fileInputRef = useRef<HTMLInputElement>(null)

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    setKeyFileName(file.name)
    const text = await file.text()
    setKeyContent(text)
  }

  const canSubmit =
    username && (authMethod === 'key' ? !!keyContent : !!password)

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!canSubmit) return

    onConnect({
      type: 'ssh_connect',
      username,
      auth_method: authMethod,
      ...(authMethod === 'key' ? { key: keyContent } : { password }),
      cols: 120,
      rows: 40,
    })
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label className="block text-sm font-medium text-slate-300 mb-1">
          Username
        </label>
        <input
          type="text"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          placeholder="e.g. root, ubuntu"
          className="w-full px-3 py-2 bg-slate-900 border border-slate-600 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-brand-500/50"
          autoFocus
          required
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-slate-300 mb-2">
          Authentication
        </label>
        <div className="flex gap-2 mb-3">
          <button
            type="button"
            onClick={() => setAuthMethod('password')}
            className={`flex-1 px-3 py-1.5 text-sm rounded-lg border transition-colors ${
              authMethod === 'password'
                ? 'bg-brand-600/20 border-brand-500 text-brand-300'
                : 'bg-slate-900 border-slate-600 text-slate-400 hover:border-slate-500'
            }`}
          >
            Password
          </button>
          <button
            type="button"
            onClick={() => setAuthMethod('key')}
            className={`flex-1 px-3 py-1.5 text-sm rounded-lg border transition-colors ${
              authMethod === 'key'
                ? 'bg-brand-600/20 border-brand-500 text-brand-300'
                : 'bg-slate-900 border-slate-600 text-slate-400 hover:border-slate-500'
            }`}
          >
            Private Key
          </button>
        </div>

        {authMethod === 'password' ? (
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Enter password"
            className="w-full px-3 py-2 bg-slate-900 border border-slate-600 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-brand-500/50"
            required
          />
        ) : (
          <>
            <input
              ref={fileInputRef}
              type="file"
              accept=".pem,.key,.id_rsa,.id_ed25519,.id_ecdsa"
              onChange={handleFileChange}
              className="hidden"
            />
            <button
              type="button"
              onClick={() => fileInputRef.current?.click()}
              className="w-full px-3 py-2 bg-slate-900 border border-slate-600 border-dashed rounded-lg text-slate-400 hover:text-slate-300 hover:border-slate-500 transition-colors text-sm text-left"
            >
              {keyFileName || 'Choose private key file (.pem, .key, .id_rsa, ...)'}
            </button>
            {keyContent && (
              <p className="mt-1 text-xs text-green-400">
                Key loaded ({keyContent.length} bytes)
              </p>
            )}
          </>
        )}
      </div>

      <div className="flex gap-3 pt-2">
        <button
          type="button"
          onClick={onCancel}
          className="flex-1 px-4 py-2 border border-slate-600 rounded-lg text-slate-300 hover:bg-slate-700 transition-colors"
        >
          Cancel
        </button>
        <button
          type="submit"
          disabled={!canSubmit}
          className="flex-1 px-4 py-2 bg-brand-600 hover:bg-brand-500 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg transition-colors btn-smoke"
        >
          Connect
        </button>
      </div>
    </form>
  )
}

function DBForm({
  dbType,
  onConnect,
  onCancel,
}: {
  dbType: 'postgres' | 'mysql'
  onConnect: (data: ConnectData) => void
  onCancel: () => void
}) {
  const [username, setUsername] = useState('')
  const [database, setDatabase] = useState('')
  const [password, setPassword] = useState('')

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!username || !database) return

    onConnect({
      type: 'db_connect',
      username,
      database,
      password,
      db_type: dbType,
      cols: 120,
      rows: 40,
    })
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label className="block text-sm font-medium text-slate-300 mb-1">
          Username
        </label>
        <input
          type="text"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          placeholder={dbType === 'postgres' ? 'e.g. postgres' : 'e.g. root'}
          className="w-full px-3 py-2 bg-slate-900 border border-slate-600 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-brand-500/50"
          autoFocus
          required
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-slate-300 mb-1">
          Database
        </label>
        <input
          type="text"
          value={database}
          onChange={(e) => setDatabase(e.target.value)}
          placeholder="e.g. mydb"
          className="w-full px-3 py-2 bg-slate-900 border border-slate-600 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-brand-500/50"
          required
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-slate-300 mb-1">
          Password
        </label>
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Enter password"
          className="w-full px-3 py-2 bg-slate-900 border border-slate-600 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-brand-500/50"
        />
      </div>

      <div className="flex gap-3 pt-2">
        <button
          type="button"
          onClick={onCancel}
          className="flex-1 px-4 py-2 border border-slate-600 rounded-lg text-slate-300 hover:bg-slate-700 transition-colors"
        >
          Cancel
        </button>
        <button
          type="submit"
          disabled={!username || !database}
          className="flex-1 px-4 py-2 bg-brand-600 hover:bg-brand-500 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg transition-colors btn-smoke"
        >
          Connect
        </button>
      </div>
    </form>
  )
}
