'use client'

import { ArrowUp, ArrowDown, Clock, AlertTriangle } from 'lucide-react'

interface HttpExchange {
  version: number
  request: {
    method: string
    path: string
    query: string
    headers: Record<string, string>
    body: string | null
    body_size?: number
    body_truncated: boolean
  }
  response: {
    status: number
    headers: Record<string, string>
    body: string | null
    body_size?: number
    body_truncated: boolean
  }
  timing: {
    duration_ms: number
  }
}

interface HttpExchangeViewerProps {
  exchange: HttpExchange | null
}

const METHOD_STYLES: Record<string, string> = {
  GET: 'bg-green-900/30 text-green-400',
  POST: 'bg-blue-900/30 text-blue-400',
  PUT: 'bg-amber-900/30 text-amber-400',
  PATCH: 'bg-amber-900/30 text-amber-400',
  DELETE: 'bg-red-900/30 text-red-400',
  HEAD: 'bg-slate-700 text-slate-300',
  OPTIONS: 'bg-slate-700 text-slate-300',
}

function statusColor(status: number): string {
  if (status < 300) return 'bg-green-900/30 text-green-400'
  if (status < 400) return 'bg-amber-900/30 text-amber-400'
  if (status < 500) return 'bg-red-900/30 text-red-400'
  return 'bg-red-900/50 text-red-300'
}

function formatBody(body: string | null, headers: Record<string, string>): string {
  if (body === null) return ''
  if (!body) return ''

  const ct = (headers['content-type'] || headers['Content-Type'] || '').toLowerCase()
  if (ct.includes('json')) {
    try {
      return JSON.stringify(JSON.parse(body), null, 2)
    } catch {
      return body
    }
  }
  return body
}

function HeadersTable({ headers }: { headers: Record<string, string> }) {
  const entries = Object.entries(headers)
  if (entries.length === 0) {
    return <p className="text-xs text-slate-500 italic">No headers</p>
  }
  return (
    <div className="border border-slate-700/50 rounded overflow-hidden">
      <table className="w-full">
        <tbody className="divide-y divide-slate-800">
          {entries.map(([key, value]) => (
            <tr key={key} className="hover:bg-slate-800/50">
              <td className="px-3 py-1.5 text-xs font-mono text-slate-400 whitespace-nowrap align-top w-48">
                {key}
              </td>
              <td className="px-3 py-1.5 text-xs font-mono text-slate-200 break-all">
                {value}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function BodySection({
  body,
  bodySize,
  bodyTruncated,
  headers,
}: {
  body: string | null
  bodySize?: number
  bodyTruncated: boolean
  headers: Record<string, string>
}) {
  if (body === null && bodySize !== undefined) {
    return (
      <div className="flex items-center gap-2 text-xs text-slate-500 italic py-2">
        Binary body ({(bodySize / 1024).toFixed(1)} KB)
      </div>
    )
  }

  if (!body) {
    return <p className="text-xs text-slate-500 italic py-2">Empty body</p>
  }

  const formatted = formatBody(body, headers)

  return (
    <div>
      {bodyTruncated && (
        <div className="flex items-center gap-1.5 text-xs text-amber-400 mb-2">
          <AlertTriangle size={12} />
          Body truncated (exceeded 256KB limit)
        </div>
      )}
      <pre className="text-xs font-mono text-slate-200 bg-slate-900 rounded p-3 overflow-x-auto whitespace-pre-wrap break-all max-h-96 overflow-y-auto">
        {formatted}
      </pre>
    </div>
  )
}

export default function HttpExchangeViewer({ exchange }: HttpExchangeViewerProps) {
  if (!exchange) {
    return (
      <div className="text-center py-8 text-slate-500">
        Failed to parse HTTP exchange data
      </div>
    )
  }

  const { request, response, timing } = exchange
  const fullPath = request.query ? `${request.path}?${request.query}` : request.path

  return (
    <div className="space-y-6">
      {/* Summary bar */}
      <div className="flex flex-wrap items-center gap-3 p-3 bg-slate-800/50 rounded-lg border border-slate-700/50">
        <span className={`px-2 py-0.5 text-xs font-bold rounded ${METHOD_STYLES[request.method] || 'bg-slate-700 text-slate-300'}`}>
          {request.method}
        </span>
        <code className="text-sm text-slate-200 break-all">{fullPath}</code>
        <span className={`px-2 py-0.5 text-xs font-bold rounded ${statusColor(response.status)}`}>
          {response.status}
        </span>
        <span className="flex items-center gap-1 text-xs text-slate-400">
          <Clock size={12} />
          {timing.duration_ms}ms
        </span>
      </div>

      {/* Request */}
      <div className="space-y-3">
        <h3 className="flex items-center gap-2 text-sm font-medium text-slate-200">
          <ArrowUp size={14} className="text-blue-400" />
          Request
        </h3>
        <div className="space-y-3 pl-5">
          <div>
            <h4 className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-2">Headers</h4>
            <HeadersTable headers={request.headers} />
          </div>
          <div>
            <h4 className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-2">Body</h4>
            <BodySection
              body={request.body}
              bodySize={request.body_size}
              bodyTruncated={request.body_truncated}
              headers={request.headers}
            />
          </div>
        </div>
      </div>

      {/* Response */}
      <div className="space-y-3">
        <h3 className="flex items-center gap-2 text-sm font-medium text-slate-200">
          <ArrowDown size={14} className="text-green-400" />
          Response
        </h3>
        <div className="space-y-3 pl-5">
          <div>
            <h4 className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-2">Headers</h4>
            <HeadersTable headers={response.headers} />
          </div>
          <div>
            <h4 className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-2">Body</h4>
            <BodySection
              body={response.body}
              bodySize={response.body_size}
              bodyTruncated={response.body_truncated}
              headers={response.headers}
            />
          </div>
        </div>
      </div>
    </div>
  )
}
