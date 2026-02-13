/**
 * Auth helpers for client-side session state.
 *
 * Session metadata (token, email, roles) is stored in sessionStorage. This
 * survives page navigation and refreshes within the same tab but is cleared
 * when the tab is closed. More practical than pure in-memory storage (which
 * loses state on every navigation) while still scoped to the browser tab.
 */

const AUTH_KEY = 'bamf_auth'

interface AuthState {
  token: string
  email: string
  roles: string[]
}

function loadAuth(): AuthState | null {
  if (typeof window === 'undefined') return null
  try {
    const raw = sessionStorage.getItem(AUTH_KEY)
    if (!raw) return null
    return JSON.parse(raw) as AuthState
  } catch {
    return null
  }
}

export function setAuth(token: string, email: string, roles: string[]): void {
  const state: AuthState = { token, email, roles }
  if (typeof window !== 'undefined') {
    sessionStorage.setItem(AUTH_KEY, JSON.stringify(state))
  }
}

export function getAuthState(): AuthState | null {
  return loadAuth()
}

export function isAdmin(): boolean {
  return loadAuth()?.roles.includes('admin') ?? false
}

export function isAdminOrAudit(): boolean {
  const auth = loadAuth()
  if (!auth) return false
  return auth.roles.includes('admin') || auth.roles.includes('audit')
}

export function clearAuth(): void {
  if (typeof window !== 'undefined') {
    sessionStorage.removeItem(AUTH_KEY)
  }
}
