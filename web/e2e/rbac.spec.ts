import { test, expect, type Page } from '@playwright/test'

const ADMIN_EMAIL = process.env.BAMF_E2E_ADMIN_EMAIL || 'admin'
const ADMIN_PASSWORD = process.env.BAMF_E2E_ADMIN_PASSWORD || 'admin'

// The SPA stores its session (token, email, roles) in localStorage under this key.
const AUTH_KEY = 'bamf_auth'
// User creation enforces a zxcvbn score >= 3; this random mixed string scores 4.
const NONADMIN_PASSWORD = 'x7Kq!mZ2rTvB9pLw3nD'

async function login(page: Page, email: string, password: string) {
  await page.goto('/login')
  // The standalone Next server can be slow to render the form on a cold route;
  // wait for it explicitly before interacting.
  await expect(page.locator('#email')).toBeVisible({ timeout: 20_000 })
  await page.locator('#email').fill(email)
  await page.locator('#password').fill(password)
  await page.getByRole('button', { name: /sign in/i }).click()
  // On success the SPA does the PKCE exchange and navigates off /login; give the
  // constrained CI stack room for those round-trips.
  await expect(page).not.toHaveURL(/\/login/, { timeout: 30_000 })
}

test.describe('RBAC', () => {
  test('a non-admin session is denied the admin Users page', async ({ page }) => {
    // Log in as admin so we can mint a non-admin user through the API.
    await login(page, ADMIN_EMAIL, ADMIN_PASSWORD)
    const token = await page.evaluate((k) => {
      const raw = localStorage.getItem(k)
      return raw ? (JSON.parse(raw).token as string) : null
    }, AUTH_KEY)
    expect(token, 'admin session token should be stored after login').toBeTruthy()

    // Create a local user with no roles (a non-admin). Unique email per attempt
    // so a Playwright retry doesn't 409 on an already-created user.
    const email = `e2e-viewer-${Date.now()}@example.com`
    const created = await page.request.post('/api/v1/users', {
      headers: { Authorization: `Bearer ${token}` },
      data: { email, password: NONADMIN_PASSWORD, roles: [] },
    })
    expect(created.ok(), `create user failed: ${created.status()} ${await created.text()}`).toBeTruthy()

    // Re-authenticate as the non-admin.
    await page.evaluate((k) => localStorage.removeItem(k), AUTH_KEY)
    await login(page, email, NONADMIN_PASSWORD)

    // The Users page is admin-only — the SPA redirects a non-admin away from it.
    await page.goto('/users')
    await expect(page).not.toHaveURL(/\/users/, { timeout: 10_000 })
  })
})
