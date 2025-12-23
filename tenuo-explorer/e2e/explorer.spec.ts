import { test, expect } from '@playwright/test';

test.describe('Tenuo Explorer - Critical User Flows', () => {
    test.beforeEach(async ({ page }) => {
        await page.goto('/');
        // Wait for WASM to load
        await expect(page.getByText('Decode Warrant')).toBeEnabled({ timeout: 10000 });
    });

    test('can decode sample warrant', async ({ page }) => {
        // Load sample
        await page.click('button:has-text("Samples")');
        await page.click('text=File Read Access');

        // Verify warrant is loaded
        const textarea = page.locator('textarea').first();
        await expect(textarea).not.toHaveValue('');

        // Decode
        await page.click('button:has-text("Decode Warrant")');

        // Verify decoded output appears
        await expect(page.getByText('Warrant Type')).toBeVisible();
        await expect(page.getByText('execution')).toBeVisible();
        await expect(page.getByText('read_file')).toBeVisible();
    });

    test('authorization flow works with dry run', async ({ page }) => {
        // Load sample
        await page.click('button:has-text("Samples")');
        await page.click('text=File Read Access');
        await page.click('button:has-text("Decode Warrant")');

        // Enable dry run
        const dryRunCheckbox = page.locator('input[type="checkbox"]').filter({ hasText: /dry run/i });
        await dryRunCheckbox.check();

        // Authorize
        await page.click('button:has-text("Check Authorization")');

        // Verify result appears
        await expect(page.locator('text=/Authorized|Denied/').first()).toBeVisible();
    });

    test('keyboard shortcuts work', async ({ page }) => {
        // Load sample
        await page.click('button:has-text("Samples")');
        await page.click('text=File Read Access');

        // Cmd+Enter to decode
        await page.keyboard.press('Meta+Enter');
        await expect(page.getByText('Warrant Type')).toBeVisible();

        // Cmd+K to clear
        await page.keyboard.press('Meta+K');
        const textarea = page.locator('textarea').first();
        await expect(textarea).toHaveValue('');
    });

    test('mode switching works', async ({ page }) => {
        // Switch to diff mode
        await page.keyboard.press('Meta+4');
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
        await page.keyboard.press('Meta+4');

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
        await page.click('text=File Read Access');
        await page.click('button:has-text("Decode Warrant")');

        // Change tool to something not in warrant
        await page.fill('input[placeholder*="Tool name"]', 'write_file');

        // Should show warning
        await expect(page.getByText(/not in warrant/)).toBeVisible();
    });
});

test.describe('Regression Tests', () => {
    test('code generator shows correct Python API', async ({ page }) => {
        await page.goto('/');
        await expect(page.getByText('Decode Warrant')).toBeEnabled({ timeout: 10000 });

        // Load and decode sample
        await page.click('button:has-text("Samples")');
        await page.click('text=File Read Access');
        await page.click('button:has-text("Decode Warrant")');

        // Switch to Code tab
        await page.click('button:has-text("💻 Code")');

        // Verify Python code uses correct API
        const codeBlock = page.locator('pre').first();
        await expect(codeBlock).toContainText('Warrant.issue(');
        await expect(codeBlock).toContainText('capabilities=Constraints.for_tool');
        await expect(codeBlock).toContainText('create_pop_signature');

        // Should NOT use old API
        await expect(codeBlock).not.toContainText('Warrant.builder()');
    });

    test('code generator shows correct Rust API', async ({ page }) => {
        await page.goto('/');
        await expect(page.getByText('Decode Warrant')).toBeEnabled({ timeout: 10000 });

        // Load and decode sample
        await page.click('button:has-text("Samples")');
        await page.click('text=File Read Access');
        await page.click('button:has-text("Decode Warrant")');

        // Switch to Code tab
        await page.click('button:has-text("💻 Code")');

        // Switch to Rust
        await page.click('button:has-text("🦀 rust")');

        // Verify Rust code uses correct API
        const codeBlock = page.locator('pre').first();
        await expect(codeBlock).toContainText('Warrant::builder()');
        await expect(codeBlock).toContainText('.build(&issuer_key)?');
        await expect(codeBlock).toContainText('create_pop_signature');
    });
});
