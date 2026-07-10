import { defineConfig, devices } from '@playwright/test'

// E2E runs against a live BAMF stack (the Tilt dev stack by default). Point it
// elsewhere with BAMF_E2E_BASE_URL. The local stack uses an mkcert cert that
// isn't in the Node trust store, so HTTPS errors are ignored.
export default defineConfig({
  testDir: './e2e',
  // CI runs against a resource-constrained single-replica k3d stack, so the
  // login flow (form render + PKCE round-trips) is slower and needs more slack.
  timeout: process.env.CI ? 90_000 : 30_000,
  expect: { timeout: process.env.CI ? 20_000 : 10_000 },
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  // The CI stack is a single-replica standalone-Next pod on k3d; running specs
  // in parallel overloads it (routes compile/serve slowly under concurrent
  // first-loads). Serialize in CI for reliability — locally, parallel is fine.
  workers: process.env.CI ? 1 : undefined,
  reporter: process.env.CI ? [['github'], ['list']] : 'list',
  use: {
    baseURL: process.env.BAMF_E2E_BASE_URL || 'https://bamf.local',
    ignoreHTTPSErrors: true,
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
})
