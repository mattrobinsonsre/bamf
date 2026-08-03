import { test, expect } from '@playwright/test'
import { mintSession, injectSession } from './helpers'

const ADMIN_EMAIL = process.env.BAMF_E2E_ADMIN_EMAIL || 'admin'
const ADMIN_PASSWORD = process.env.BAMF_E2E_ADMIN_PASSWORD || 'admin'
// User creation enforces a zxcvbn score >= 3; this random mixed string scores 4.
const NONADMIN_PASSWORD = 'x7Kq!mZ2rTvB9pLw3nD'

test.describe('RBAC', () => {
  test('a non-admin session is denied the admin Users page', async ({ page }) => {
    // Mint an admin session via the API (deterministic) to create the user.
    const adminToken = await mintSession(page, ADMIN_EMAIL, ADMIN_PASSWORD)

    // Create a local user with no roles (a non-admin). Unique email per attempt
    // so a Playwright retry doesn't 409 on an already-created user.
    const email = `e2e-viewer-${Date.now()}@example.com`
    const created = await page.request.post('/api/v1/users', {
      headers: { Authorization: `Bearer ${adminToken}` },
      data: { email, password: NONADMIN_PASSWORD, roles: [] },
    })
    expect(created.ok(), `create user failed: ${created.status()} ${await created.text()}`).toBeTruthy()

    // Boot the SPA as the non-admin by injecting a real session (minted via the
    // API), rather than driving the flaky SSR login form for the second login.
    const viewerToken = await mintSession(page, email, NONADMIN_PASSWORD)
    await injectSession(page, viewerToken, email, [])

    // The Users page is admin-only — the SPA redirects a non-admin away from it.
    await page.goto('/users')
    await expect(page).not.toHaveURL(/\/users/, { timeout: 10_000 })
  })
})
