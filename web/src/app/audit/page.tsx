'use client'

import { useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { Shield } from 'lucide-react'
import NavBar from '@/components/nav-bar'
import { getAuthState } from '@/lib/auth'

export default function AuditPage() {
  const router = useRouter()

  useEffect(() => {
    if (!getAuthState()) {
      router.push('/login')
    }
  }, [router])

  return (
    <div className="min-h-screen flex flex-col">
      <NavBar />
      <main className="flex-1 max-w-7xl mx-auto w-full px-4 sm:px-6 lg:px-8 py-6">
        <h1 className="text-xl font-semibold text-slate-100 mb-6">Audit Log</h1>
        <div className="text-center py-12">
          <Shield size={48} className="mx-auto text-slate-600 mb-4" />
          <p className="text-slate-500">Audit log viewer coming soon.</p>
        </div>
      </main>
    </div>
  )
}
