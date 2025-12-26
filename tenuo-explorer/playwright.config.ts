import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
    testDir: './e2e',
    fullyParallel: true,
    forbidOnly: !!process.env.CI,
    retries: process.env.CI ? 2 : 0,
    workers: process.env.CI ? 1 : undefined,
    reporter: 'html',

    use: {
        // Preview serves at /explorer/, dev redirects / to /explorer/
        baseURL: process.env.CI ? 'http://localhost:4173/explorer' : 'http://localhost:5173',
        trace: 'on-first-retry',
        screenshot: 'only-on-failure',
    },

    projects: [
        {
            name: 'chromium',
            use: { ...devices['Desktop Chrome'] },
        },
        {
            name: 'firefox',
            use: { ...devices['Desktop Firefox'] },
        },
        {
            name: 'webkit',
            use: { ...devices['Desktop Safari'] },
        },
    ],

    webServer: {
        // Use preview in CI (serves built dist/, fast), dev locally (HMR)
        command: process.env.CI ? 'npm run preview' : 'npm run dev',
        url: process.env.CI ? 'http://localhost:4173/explorer/' : 'http://localhost:5173',
        reuseExistingServer: !process.env.CI,
        timeout: 30000,
    },
});
