import { defineConfig, devices } from '@playwright/test'

// E2E runs against a live BAMF stack (the Tilt dev stack by default). Point it
// elsewhere with BAMF_E2E_BASE_URL. The local stack uses an mkcert cert that
// isn't in the Node trust store, so HTTPS errors are ignored.
export default defineConfig({
  testDir: './e2e',
  timeout: 30_000,
  expect: { timeout: 10_000 },
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
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
