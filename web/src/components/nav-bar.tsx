'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { usePathname, useRouter } from 'next/navigation'
import { Server, Activity, Shield, Users, ShieldCheck, KeyRound, LogOut, Key, Bot } from 'lucide-react'
import { clearAuth, isAdmin, isAdminOrAudit } from '@/lib/auth'

function NavLink({
  href,
  children,
}: {
  href: string
  children: React.ReactNode
}) {
  const pathname = usePathname()
  const active = href === '/' ? pathname === '/' : pathname.startsWith(href)

  return (
    <Link
      href={href}
      className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
        active
          ? 'bg-brand-600/20 text-brand-400'
          : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
      }`}
    >
      {children}
    </Link>
  )
}

export default function NavBar() {
  const router = useRouter()
  const [admin, setAdmin] = useState(false)
  const [adminOrAudit, setAdminOrAudit] = useState(false)

  useEffect(() => {
    setAdmin(isAdmin())
    setAdminOrAudit(isAdminOrAudit())
  }, [])

  const handleLogout = () => {
    clearAuth()
    router.push('/login')
  }

  return (
    <nav className="border-b border-slate-800 bg-slate-900/80 backdrop-blur-sm sticky top-0 z-10">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-14">
          <div className="flex items-center gap-1">
            <Link href="/" className="flex items-center gap-2 mr-4">
              <img src="/logo.svg" alt="BAMF" className="w-7 h-7" />
              <span className="font-bold text-lg text-slate-100">BAMF</span>
            </Link>
            <NavLink href="/">
              <Server size={16} />
              Resources
            </NavLink>
            <NavLink href="/sessions">
              <Activity size={16} />
              Sessions
            </NavLink>
            {adminOrAudit && (
              <>
                <NavLink href="/agents">
                  <Bot size={16} />
                  Agents
                </NavLink>
                <NavLink href="/tokens">
                  <Key size={16} />
                  Tokens
                </NavLink>
                <NavLink href="/audit">
                  <Shield size={16} />
                  Audit
                </NavLink>
              </>
            )}
            {admin && (
              <>
                <NavLink href="/users">
                  <Users size={16} />
                  Users
                </NavLink>
                <NavLink href="/roles">
                  <ShieldCheck size={16} />
                  Roles
                </NavLink>
                <NavLink href="/access">
                  <KeyRound size={16} />
                  Access
                </NavLink>
              </>
            )}
          </div>
          <button
            onClick={handleLogout}
            className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          >
            <LogOut size={16} />
            Logout
          </button>
        </div>
      </div>
    </nav>
  )
}
