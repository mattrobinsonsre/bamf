/**
 * Auth helpers for client-side session state.
 *
 * Session metadata (token, email, roles) is stored in-memory. This is more
 * secure than localStorage since in-memory state is not accessible to other
 * scripts via the Storage API. The trade-off is that auth state is lost on
 * page refresh, requiring re-login.
 */

interface AuthState {
  token: string
  email: string
  roles: string[]
}

let currentAuth: AuthState | null = null

export function setAuth(token: string, email: string, roles: string[]): void {
  currentAuth = { token, email, roles }
}

export function getAuthState(): AuthState | null {
  return currentAuth
}

export function isAdmin(): boolean {
  return currentAuth?.roles.includes('admin') ?? false
}

export function isAdminOrAudit(): boolean {
  if (!currentAuth) return false
  return currentAuth.roles.includes('admin') || currentAuth.roles.includes('audit')
}

export function clearAuth(): void {
  currentAuth = null
}
