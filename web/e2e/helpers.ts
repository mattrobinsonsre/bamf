import { expect, type Page } from '@playwright/test'

// Robust web-UI login for the SSR-rendered SPA form.
//
// The #email / #password inputs and the "Sign in" button are server-rendered, so
// a click can land *before* React has hydrated the button's onClick — the submit
// is then silently lost and the page sits on /login until the timeout. This is
// the single biggest source of E2E flake (it bit rbac.spec, which logs in
// twice). Retry the fill+submit until the SPA actually navigates off /login;
// `fill` is idempotent so re-filling each attempt is safe, and it also re-binds
// a value a pre-hydration fill may not have committed to React state.
export async function login(page: Page, email: string, password: string) {
  await page.goto('/login')
  await expect(page.locator('#email')).toBeVisible({ timeout: 20_000 })
  await expect(async () => {
    await page.locator('#email').fill(email)
    await page.locator('#password').fill(password)
    await page.getByRole('button', { name: /sign in/i }).click()
    await expect(page).not.toHaveURL(/\/login/, { timeout: 5_000 })
  }).toPass({ timeout: 30_000, intervals: [500, 1_000, 2_000] })
}
