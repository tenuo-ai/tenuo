import { test, expect } from '@playwright/test';

test.describe('Tenuo Explorer - Critical User Flows', () => {
    test.beforeEach(async ({ page }) => {
        // Capture console errors for debugging
        page.on('console', msg => {
            if (msg.type() === 'error') {
                console.log(`[Browser Error] ${msg.text()}`);
            }
        });
        
        // baseURL includes /explorer in CI
        await page.goto('./');
        // Samples are generated only after the WASM module is ready. Opening the
        // menu and waiting for one gives every mode a stable readiness signal.
        const samplesButton = page.getByRole('button', { name: /Samples/ });
        await expect(samplesButton).toBeVisible({ timeout: 30000 });
        await samplesButton.click();
        await expect(page.getByText('Valid Read', { exact: false })).toBeVisible({ timeout: 30000 });
        await samplesButton.click();
    });

    test('can decode sample warrant', async ({ page }) => {
        // Load sample
        await page.click('button:has-text("Samples")');
        await page.getByText('Valid Read').click();

        // Verify warrant is loaded
        const textarea = page.locator('textarea').first();
        await expect(textarea).not.toHaveValue('');

        // Decode
        await page.click('button:has-text("Decode Warrant")');

        // Verify decoded output appears
        await expect(page.getByText('Authorized Tools')).toBeVisible();
        await expect(page.locator('span.tool-tag').filter({ hasText: 'read_file' })).toBeVisible();
    });

    test('authorization flow works with dry run', async ({ page }) => {
        // Load sample
        await page.click('button:has-text("Samples")');
        await page.getByText('Valid Read').click();
        await page.click('button:has-text("Decode Warrant")');

        // The explorer intentionally performs policy-only checks in dry-run mode.
        await page.click('button:has-text("Check Authorization")');

        // Verify result appears
        await expect(page.locator('text=/Authorized|Denied/').first()).toBeVisible();
    });

    test('decode shortcut and clear action work', async ({ page }) => {
        // Load sample
        await page.click('button:has-text("Samples")');
        await page.getByText('Valid Read').click();

        // Cmd+Enter to decode
        await page.keyboard.press('Meta+Enter');
        await expect(page.getByText('Authorized Tools')).toBeVisible();

        // Cmd+K to clear
        await page.keyboard.press('Meta+Shift+K');
        const textarea = page.locator('textarea').first();
        await expect(textarea).toHaveValue('');
    });

    test('mode switching works', async ({ page }) => {
        // Switch to diff mode
        await page.keyboard.press('Meta+3');
        await expect(page.getByText('Warrant Diff Viewer')).toBeVisible();

        // Switch to builder mode
        await page.keyboard.press('Meta+2');
        await expect(page.getByText('Warrant Builder')).toBeVisible();

        // Switch back to decoder
        await page.keyboard.press('Meta+1');
        await expect(page.getByText('Paste Warrant')).toBeVisible();

        // Receipt verification is also keyboard-accessible
        await page.keyboard.press('Meta+5');
        await expect(page.getByText('Paste Receipt(s)', { exact: true })).toBeVisible();
    });

    test('diff viewer compares warrants', async ({ page }) => {
        // Switch to diff mode
        await page.keyboard.press('Meta+3');

        // Load sample in both
        await page.click('button:has-text("Same Warrant")');

        // Compare
        await page.getByRole('button', { name: 'Compare Warrants', exact: true }).click();

        // Verify identical message
        await expect(page.getByText('Warrants are identical')).toBeVisible();
    });

    test('builder generates a warrant and working code', async ({ page }) => {
        await page.getByRole('tab', { name: 'Build' }).click();
        await page.getByRole('button', { name: 'Generate Preview' }).click();

        await expect(page.getByText(/Warrant \(Base64\)/i)).toBeVisible();
        await expect(page.getByText('Code Generation')).toBeVisible();
        await expect(page.locator('pre.code-block').filter({ hasText: 'Warrant.mint_builder()' })).toBeVisible();
    });

    test('sample delegation chain verifies end to end', async ({ page }) => {
        await page.getByRole('tab', { name: 'Delegate' }).click();
        await page.getByRole('button', { name: 'Load Sample Chain' }).click();

        await expect(page.getByText(/3\s*\/\s*3\s*warrants decoded/i)).toBeVisible();
        await page.getByRole('button', { name: 'Verify Chain Authorization' }).click();
        await expect(page.getByText('Chain Authorized')).toBeVisible();
    });

    test('validation warnings appear for issues', async ({ page }) => {
        // Load sample and decode
        await page.click('button:has-text("Samples")');
        await page.getByText('Valid Read').click();
        await page.click('button:has-text("Decode Warrant")');

        // Change tool to something not in warrant
        await page.getByPlaceholder('e.g., read_file').fill('write_file');

        // Should show warning
        await expect(page.getByText(/not in warrant/)).toBeVisible();
    });
});

test.describe('Regression Tests', () => {
    test('uses the public website theme and background treatment', async ({ page }) => {
        const readTheme = () => page.evaluate(() => {
            const root = getComputedStyle(document.documentElement);
            return {
                theme: document.documentElement.dataset.theme,
                background: getComputedStyle(document.body).backgroundColor,
                accent: root.getPropertyValue('--accent').trim(),
                gridSize: getComputedStyle(document.querySelector('.app-shell')!).backgroundSize,
                hasGlow: document.querySelector('.site-glow') !== null,
            };
        });

        await page.emulateMedia({ colorScheme: 'light' });
        await page.goto('./');
        expect(await readTheme()).toEqual({
            theme: 'light',
            background: 'rgb(244, 245, 248)',
            accent: '#4075d4',
            // WebKit collapses repeated layer sizes to one value.
            gridSize: expect.stringMatching(/^48px 48px(, 48px 48px)?$/),
            hasGlow: false,
        });

        await page.emulateMedia({ colorScheme: 'dark' });
        await page.reload();
        expect(await readTheme()).toMatchObject({
            theme: 'dark',
            background: 'rgb(0, 10, 29)',
            accent: '#73a5ff',
        });

        await expect(page.getByText(/WASM engine ready|Starting local engine/)).toHaveCount(0);
        const footer = page.locator('footer');
        await expect(footer).toContainText('Runs locally in your browser.');
        await expect(footer).toContainText('No uploads or account required.');
        await expect(footer).toContainText('© 2026 Tenuo');
        // Same destinations as the site header and footer on tenuo.ai.
        await expect(page.locator('header a[href="/in-the-wild"]')).toHaveCount(1);
        await expect(footer.locator('a[href="/in-the-wild"]')).toHaveText('Case studies & recognition');
    });

    test('code generator shows correct Python API', async ({ page }) => {
        // baseURL includes /explorer in CI
        await page.goto('./');
        await expect(page.getByRole('button', { name: /Samples/ })).toBeVisible({ timeout: 30000 });

        // Load and decode sample
        await page.click('button:has-text("Samples")');
        await page.getByText('Valid Read').click();
        await page.click('button:has-text("Decode Warrant")');

        // Switch to Code tab
        await page.getByRole('button', { name: 'Code', exact: true }).click();

        // Verify Python code uses correct API
        const codePanel = page.locator('.panel').filter({ hasText: 'Code Generation' }).last();
        const codeBlock = codePanel.locator('pre.code-block');
        await expect(codeBlock).toContainText('Warrant.mint_builder()');
        await expect(codeBlock).toContainText('.capability(');
        await expect(codeBlock).toContainText('.mint(');

        // Should NOT use deprecated API
        await expect(codeBlock).not.toContainText('Warrant.issue(');
        await expect(codeBlock).not.toContainText('Constraints.for_tool');
    });

    test('code generator shows correct Rust API', async ({ page }) => {
        // baseURL includes /explorer in CI
        await page.goto('./');
        await expect(page.getByRole('button', { name: /Samples/ })).toBeVisible({ timeout: 30000 });

        // Load and decode sample
        await page.click('button:has-text("Samples")');
        await page.getByText('Valid Read').click();
        await page.click('button:has-text("Decode Warrant")');

        // Switch to Code tab
        await page.getByRole('button', { name: 'Code', exact: true }).click();

        // Switch to Rust
        const codePanel = page.locator('.panel').filter({ hasText: 'Code Generation' }).last();
        await codePanel.getByRole('button', { name: 'rust', exact: true }).click();

        // Verify Rust code uses correct API
        const codeBlock = codePanel.locator('pre.code-block');
        await expect(codeBlock).toContainText('Warrant::builder()');
        await expect(codeBlock).toContainText('.capability(');
        await expect(codeBlock).toContainText('.build(&');
    });
});
