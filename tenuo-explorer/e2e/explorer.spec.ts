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
        await page.goto('/');
        // The label changes from "Loading WASM..." once initialization completes.
        // It remains disabled until a warrant is loaded, which is the correct UI state.
        await expect(page.getByText('Decode Warrant')).toBeVisible({ timeout: 30000 });
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
        await expect(page.getByText('read_file').first()).toBeVisible();
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

        // Dispatch the app shortcut directly; browser chrome reserves Cmd/Ctrl+K.
        await page.locator('body').dispatchEvent('keydown', { key: 'k', metaKey: true });
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
    });

    test('diff viewer compares warrants', async ({ page }) => {
        // Switch to diff mode
        await page.keyboard.press('Meta+3');

        // Load sample in both
        await page.click('button:has-text("Same Warrant")');

        // Compare
        await page.click('button:has-text("Compare")');

        // Verify identical message
        await expect(page.getByText('Warrants are identical')).toBeVisible();
    });

    test('validation warnings appear for issues', async ({ page }) => {
        // Load sample and decode
        await page.click('button:has-text("Samples")');
        await page.getByText('Valid Read').click();
        await page.click('button:has-text("Decode Warrant")');

        // Change tool to something not in warrant
        await page.fill('input[placeholder="e.g., read_file"]', 'write_file');

        // Should show warning
        await expect(page.getByText(/not in warrant/)).toBeVisible();
    });
});

test.describe('Regression Tests', () => {
    test('uses the public website theme and background treatment', async ({ page }) => {
        await page.goto('/');
        const theme = await page.evaluate(() => {
            const root = getComputedStyle(document.documentElement);
            return {
                background: getComputedStyle(document.body).backgroundColor,
                accent: root.getPropertyValue('--accent').trim(),
                gridSize: getComputedStyle(document.querySelector('.site-grid-bg')!).backgroundSize,
                hasGlow: getComputedStyle(document.querySelector('.site-glow')!).backgroundImage.includes('radial-gradient'),
            };
        });

        expect(theme).toEqual({
            background: 'rgb(4, 10, 15)',
            accent: '#38bdf8',
            gridSize: '48px 48px, 48px 48px',
            hasGlow: true,
        });
    });

    test('code generator shows correct Python API', async ({ page }) => {
        // baseURL includes /explorer in CI
        await page.goto('/');
        await expect(page.getByText('Decode Warrant')).toBeVisible({ timeout: 30000 });

        // Load and decode sample
        await page.click('button:has-text("Samples")');
        await page.getByText('Valid Read').click();
        await page.click('button:has-text("Decode Warrant")');

        // Switch to Code tab
        await page.click('button:has-text("💻 Code")');

        // Verify Python code uses correct API
        const codeBlock = page.locator('pre').first();
        await expect(codeBlock).toContainText('Warrant.mint_builder()');
        await expect(codeBlock).toContainText('.capability(');
        await expect(codeBlock).toContainText('.mint(');

        // Should NOT use deprecated API
        await expect(codeBlock).not.toContainText('Warrant.issue(');
        await expect(codeBlock).not.toContainText('Constraints.for_tool');
    });

    test('code generator shows correct Rust API', async ({ page }) => {
        // baseURL includes /explorer in CI
        await page.goto('/');
        await expect(page.getByText('Decode Warrant')).toBeVisible({ timeout: 30000 });

        // Load and decode sample
        await page.click('button:has-text("Samples")');
        await page.getByText('Valid Read').click();
        await page.click('button:has-text("Decode Warrant")');

        // Switch to Code tab
        await page.click('button:has-text("💻 Code")');

        // Switch to Rust
        await page.click('button:has-text("🦀 rust")');

        // Verify Rust code uses correct API
        const codeBlock = page.locator('pre').first();
        await expect(codeBlock).toContainText('Warrant::builder()');
        await expect(codeBlock).toContainText('.capability(');
        await expect(codeBlock).toContainText('.build(&');
    });
});
