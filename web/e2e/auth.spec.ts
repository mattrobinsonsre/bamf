import { test, expect } from '@playwright/test'

const ADMIN_EMAIL = process.env.BAMF_E2E_ADMIN_EMAIL || 'admin'
const ADMIN_PASSWORD = process.env.BAMF_E2E_ADMIN_PASSWORD || 'admin'

// The browser (web-UI) login is the SPA fetch form: inputs keyed by id
// (#email / #password), submit button "Sign in". The name="email" variant is
// only rendered in CLI mode (?cli_state=...), so target the ids here.
test.describe('authentication', () => {
  test('login page renders the local login form', async ({ page }) => {
    await page.goto('/login')
    await expect(page.locator('#email')).toBeVisible()
    await expect(page.locator('#password')).toBeVisible()
    await expect(page.getByRole('button', { name: /sign in/i })).toBeVisible()
  })

  test('unauthenticated access to a protected page redirects to login', async ({ page }) => {
    await page.goto('/users')
    await expect(page).toHaveURL(/\/login/)
  })

  test('admin can log in with local credentials', async ({ page }) => {
    await page.goto('/login')
    await page.locator('#email').fill(ADMIN_EMAIL)
    await page.locator('#password').fill(ADMIN_PASSWORD)
    await page.getByRole('button', { name: /sign in/i }).click()
    // On success the SPA navigates off /login to the dashboard.
    await expect(page).not.toHaveURL(/\/login/, { timeout: 15_000 })
  })
})
