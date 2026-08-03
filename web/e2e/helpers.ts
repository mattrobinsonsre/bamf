import { expect, type Page } from '@playwright/test'
import { createHash, randomBytes } from 'node:crypto'

// Robust web-UI login for the SSR-rendered SPA form.
//
// Two independent hazards to survive:
//  1. Pre-hydration lost click — the #email / #password inputs and the "Sign in"
//     button render server-side, so a click can land before React hydrates the
//     onClick; the submit is then silently lost and the page sits on /login.
//  2. Slow login — the PKCE exchange + role resolution is variably slow on a
//     constrained CI stack (seconds to tens of seconds), so a successful login
//     must not be mistaken for a lost click.
//
// Fill + click ONCE, then poll for navigation off /login. Only re-click when we
// are *still* on /login with the button present (a genuinely lost click) — never
// re-fill (values persist) and never click after we've navigated, which is what
// made a slow-but-successful login double-submit and then fail on a vanished
// #email locator.
export async function login(page: Page, email: string, password: string) {
  await page.goto('/login')
  await expect(page.locator('#email')).toBeVisible({ timeout: 20_000 })
  await page.locator('#email').fill(email)
  await page.locator('#password').fill(password)
  await page.getByRole('button', { name: /sign in/i }).click()

  await expect(async () => {
    if (/\/login/.test(page.url())) {
      const btn = page.getByRole('button', { name: /sign in/i })
      if (await btn.isVisible().catch(() => false)) {
        await btn.click().catch(() => {})
      }
    }
    await expect(page).not.toHaveURL(/\/login/, { timeout: 2_000 })
  }).toPass({ timeout: 45_000, intervals: [1_000, 2_000, 3_000] })
}

function b64url(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

// postJson POSTs to the API and retries the ingress rate-limit (429) with a
// short backoff, the same way the real BAMF clients (and the shell smoke) do.
async function postJson(
  page: Page,
  url: string,
  opts: Parameters<Page['request']['post']>[1],
  tries = 5,
) {
  for (let attempt = 0; ; attempt++) {
    const resp = await page.request.post(url, opts)
    if (resp.status() !== 429 || attempt >= tries) return resp
    await page.waitForTimeout(1_000 * (attempt + 1))
  }
}

// mintSession drives the scriptable local PKCE flow through the API (no browser
// UI) and returns an opaque session token. Deterministic — unlike the SSR login
// form — so tests that need a session for a specific user (e.g. a freshly-created
// non-admin) don't inherit the login-form's hydration/slow-login flake.
export async function mintSession(page: Page, email: string, password: string): Promise<string> {
  const verifier = b64url(randomBytes(32))
  const challenge = b64url(createHash('sha256').update(verifier).digest())
  const authz = await postJson(page, '/api/v1/auth/local/authorize', {
    data: {
      email,
      password,
      code_challenge: challenge,
      code_challenge_method: 'S256',
      state: 'e2e',
    },
  })
  expect(authz.ok(), `authorize failed: ${authz.status()} ${await authz.text()}`).toBeTruthy()
  const code = (await authz.json()).code as string
  const tok = await postJson(page, '/api/v1/auth/token', {
    form: { grant_type: 'authorization_code', code, code_verifier: verifier },
  })
  expect(tok.ok(), `token exchange failed: ${tok.status()} ${await tok.text()}`).toBeTruthy()
  return (await tok.json()).session_token as string
}

// injectSession places a session into the SPA's localStorage so the app boots
// authenticated as that user on the next navigation. Matches web/src/lib/auth.ts
// (AuthState = { token, email, roles }).
export async function injectSession(page: Page, token: string, email: string, roles: string[]) {
  await page.goto('/login')
  await page.evaluate(
    ({ token, email, roles }) =>
      localStorage.setItem('bamf_auth', JSON.stringify({ token, email, roles })),
    { token, email, roles },
  )
}
