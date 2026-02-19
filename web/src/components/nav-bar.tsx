'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { usePathname, useRouter } from 'next/navigation'
import { Server, Activity, Shield, Users, ShieldCheck, KeyRound, LogOut, Key, Bot, Menu, X, Film, Zap } from 'lucide-react'
import { clearAuth, isAdmin, isAdminOrAudit } from '@/lib/auth'

function NavLink({
  href,
  children,
  onClick,
}: {
  href: string
  children: React.ReactNode
  onClick?: () => void
}) {
  const pathname = usePathname()
  // Exact match or prefix match, but /audit should not match /audit/recordings
  const active = href === '/'
    ? pathname === '/'
    : pathname === href || (pathname.startsWith(href + '/') && href !== '/audit')

  return (
    <Link
      href={href}
      onClick={onClick}
      className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium whitespace-nowrap transition-colors ${
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
  const [menuOpen, setMenuOpen] = useState(false)

  useEffect(() => {
    setAdmin(isAdmin())
    setAdminOrAudit(isAdminOrAudit())
  }, [])

  const handleLogout = () => {
    clearAuth()
    router.push('/login')
  }

  const closeMenu = () => setMenuOpen(false)

  const navLinks = (
    <>
      <NavLink href="/" onClick={closeMenu}>
        <Server size={16} />
        Resources
      </NavLink>
      <NavLink href="/sessions" onClick={closeMenu}>
        <Activity size={16} />
        Sessions
      </NavLink>
      {adminOrAudit && (
        <>
          <NavLink href="/agents" onClick={closeMenu}>
            <Bot size={16} />
            Agents
          </NavLink>
          <NavLink href="/tunnels" onClick={closeMenu}>
            <Zap size={16} />
            Tunnels
          </NavLink>
          <NavLink href="/tokens" onClick={closeMenu}>
            <Key size={16} />
            Tokens
          </NavLink>
          <NavLink href="/audit" onClick={closeMenu}>
            <Shield size={16} />
            Audit
          </NavLink>
          <NavLink href="/audit/recordings" onClick={closeMenu}>
            <Film size={16} />
            Recordings
          </NavLink>
        </>
      )}
      {admin && (
        <>
          <NavLink href="/users" onClick={closeMenu}>
            <Users size={16} />
            Users
          </NavLink>
          <NavLink href="/roles" onClick={closeMenu}>
            <ShieldCheck size={16} />
            Roles
          </NavLink>
          <NavLink href="/access" onClick={closeMenu}>
            <KeyRound size={16} />
            Access
          </NavLink>
        </>
      )}
    </>
  )

  return (
    <nav className="border-b border-slate-800 bg-slate-900/80 backdrop-blur-sm sticky top-0 z-10">
      <div className="px-4 sm:px-6 lg:px-8">
        {/* Desktop nav */}
        <div className="hidden md:flex items-center gap-1 py-2">
          <Link href="/" className="flex items-center gap-2 mr-3 flex-shrink-0">
            <img src="/logo.svg" alt="BAMF" className="w-7 h-7" />
            <span className="font-bold text-lg text-slate-100">BAMF</span>
          </Link>
          <div className="flex items-center gap-1 flex-wrap flex-1">
            {navLinks}
          </div>
          <button
            onClick={handleLogout}
            className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors flex-shrink-0 ml-2"
          >
            <LogOut size={16} />
            Logout
          </button>
        </div>

        {/* Mobile nav */}
        <div className="md:hidden flex items-center justify-between h-14">
          <Link href="/" className="flex items-center gap-2">
            <img src="/logo.svg" alt="BAMF" className="w-7 h-7" />
            <span className="font-bold text-lg text-slate-100">BAMF</span>
          </Link>
          <div className="flex items-center gap-1">
            <button
              onClick={() => setMenuOpen(!menuOpen)}
              className="p-2 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
            >
              {menuOpen ? <X size={20} /> : <Menu size={20} />}
            </button>
            <button
              onClick={handleLogout}
              className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
            >
              <LogOut size={16} />
              Logout
            </button>
          </div>
        </div>
        {menuOpen && (
          <div className="md:hidden flex flex-col gap-1 pb-3">
            {navLinks}
          </div>
        )}
      </div>
    </nav>
  )
}
