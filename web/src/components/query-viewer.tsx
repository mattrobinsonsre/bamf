'use client'

import { useState, useMemo } from 'react'
import { Search } from 'lucide-react'

interface QueryEvent {
  timestamp: string
  query: string
  type: string
}

interface QueryViewerProps {
  queries: QueryEvent[]
}

const TYPE_STYLES: Record<string, string> = {
  simple: 'bg-green-900/30 text-green-400',
  com_query: 'bg-green-900/30 text-green-400',
  prepare: 'bg-blue-900/30 text-blue-400',
  execute: 'bg-amber-900/30 text-amber-400',
}

export default function QueryViewer({ queries }: QueryViewerProps) {
  const [search, setSearch] = useState('')

  const filtered = useMemo(() => {
    if (!search) return queries
    const lower = search.toLowerCase()
    return queries.filter((q) => q.query.toLowerCase().includes(lower))
  }, [queries, search])

  const formatTimestamp = (iso: string) => {
    const date = new Date(iso)
    return date.toLocaleTimeString(undefined, {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      fractionalSecondDigits: 3,
    })
  }

  return (
    <div className="space-y-3">
      {/* Search bar */}
      <div className="relative">
        <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Filter queries..."
          className="w-full pl-9 pr-3 py-2 text-sm bg-slate-800 border border-slate-700 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-brand-500"
        />
      </div>

      {/* Summary */}
      <div className="text-xs text-slate-500">
        {filtered.length} {filtered.length === 1 ? 'query' : 'queries'}
        {search && ` matching "${search}"`}
      </div>

      {/* Query table */}
      <div className="border border-slate-700/50 rounded-lg overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="bg-slate-800/80">
              <th className="text-left px-4 py-2 text-xs font-medium text-slate-500 uppercase tracking-wider w-28">
                Time
              </th>
              <th className="text-left px-4 py-2 text-xs font-medium text-slate-500 uppercase tracking-wider w-20">
                Type
              </th>
              <th className="text-left px-4 py-2 text-xs font-medium text-slate-500 uppercase tracking-wider">
                Query
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {filtered.map((q, i) => (
              <tr key={i} className="hover:bg-slate-800/50 transition-colors">
                <td className="px-4 py-2 text-xs text-slate-400 font-mono whitespace-nowrap align-top">
                  {formatTimestamp(q.timestamp)}
                </td>
                <td className="px-4 py-2 align-top">
                  <span className={`px-1.5 py-0.5 text-xs rounded ${TYPE_STYLES[q.type] || 'bg-slate-700 text-slate-300'}`}>
                    {q.type}
                  </span>
                </td>
                <td className="px-4 py-2">
                  <pre className="text-xs text-slate-200 font-mono whitespace-pre-wrap break-all">
                    {q.query}
                  </pre>
                </td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={3} className="px-4 py-8 text-center text-slate-500 text-sm">
                  No queries found
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
