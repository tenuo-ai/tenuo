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

    test('diagnostics report policy evidence without authorizing execution', async ({ page }) => {
        // Load sample
        await page.click('button:has-text("Samples")');
        await page.getByText('Valid Read').click();
        await page.click('button:has-text("Decode Warrant")');

        // Use the shared diagnostic path, which never establishes possession.
        await page.click('button:has-text("Explain Call")');

        // Verify result appears
        await expect(page.getByText('Policy checks passed', { exact: true })).toBeVisible();
        await expect(page.getByText(/Chain: valid; constraints: satisfied; approvals: not_required; possession: not_checked/)).toBeVisible();
        await expect(page.getByText('Authorized', { exact: true })).toHaveCount(0);
    });

    test('chain diagnostics use the same evidence statuses', async ({ page }) => {
        await page.keyboard.press('Meta+4');
        await page.getByRole('button', { name: 'Load Sample Chain' }).click();
        await page.getByRole('button', { name: 'Explain Chain', exact: true }).click();
        await expect(page.getByText('✓ Policy checks passed', { exact: true })).toBeVisible();
        await expect(page.getByText(/Chain: valid; constraints: satisfied; approvals: not_required; possession: not_checked/)).toBeVisible();
        await expect(page.getByText('✓ Chain Authorized', { exact: true })).toHaveCount(0);
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
                gridSize: getComputedStyle(document.querySelector('.app-shell')!).backgroundSize,
                hasGlow: document.querySelector('.site-glow') !== null,
            };
        });

        expect(theme).toEqual({
            background: 'rgb(4, 10, 15)',
            accent: '#38bdf8',
            gridSize: '48px 48px, 48px 48px',
            hasGlow: false,
        });

        await expect(page.getByText(/WASM engine ready|Starting local engine/)).toHaveCount(0);
        const footer = page.locator('footer');
        await expect(footer).toContainText('Runs locally in your browser. No uploads or account required.');
        await expect(footer).toContainText('© 2026 Tenuo · Docs · GitHub · Early Access');
        await expect(footer.getByRole('link', { name: 'Docs' })).toHaveAttribute('href', 'https://tenuo.ai/quickstart');
        await expect(footer.getByRole('link', { name: 'GitHub' })).toHaveAttribute('href', 'https://github.com/tenuo-ai/tenuo');
        await expect(footer.getByRole('link', { name: 'Early Access' })).toHaveAttribute('href', 'https://tenuo.ai/early-access.html');
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
        await page.click('button:has-text("Code")');

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
        await page.click('button:has-text("Code")');

        // Switch to Rust
        await page.click('button:has-text("rust")');

        // Verify Rust code uses correct API
        const codeBlock = page.locator('pre').first();
        await expect(codeBlock).toContainText('Warrant::builder()');
        await expect(codeBlock).toContainText('.capability(');
        await expect(codeBlock).toContainText('.build(&');
    });
});

test.describe('Feedback regressions', () => {
    test.beforeEach(async ({ page }) => {
        await page.clock.install();
        await page.goto('/');
        await expect(page.getByText('Decode Warrant')).toBeVisible({ timeout: 30000 });
    });

    test('an expired warrant is denied without decoding first', async ({ page }) => {
        await page.click('button:has-text("Samples")');
        await page.getByText('Expiring (10s)').click();
        await page.clock.fastForward('00:13');
        await page.click('button:has-text("Explain Call")');
        await expect(page.getByText('Requirements not satisfied', { exact: true })).toBeVisible();
        await expect(page.getByText(/expired/i).first()).toBeVisible();
        await expect(page.getByText('Policy checks passed', { exact: true })).toHaveCount(0);
    });

    test('invalid input clears an earlier decode', async ({ page }) => {
        await page.click('button:has-text("Samples")');
        await page.getByText('Denied: Wrong Path').click();
        await page.click('button:has-text("Decode Warrant")');
        await expect(page.getByText('Authorized Tools')).toBeVisible();
        await page.locator('textarea').first().fill('not a warrant');
        await expect(page.getByText('Authorized Tools')).toHaveCount(0);
        await page.click('button:has-text("Decode Warrant")');
        await expect(page.getByText('Authorized Tools')).toHaveCount(0);
        await expect(page.getByText(/Invalid base64|too short|Failed to decode|Decode failed/).first()).toBeVisible();
    });

    test('an invalid constraint disables Generate Preview', async ({ page }) => {
        await page.getByRole('tab', { name: 'Build' }).click();
        await page.getByRole('button', { name: 'Limited Spend' }).click();
        const amount = page.locator('input[value="0-1000"]');
        await amount.fill('1000-0');
        await expect(page.getByText('Min cannot be greater than max')).toBeVisible();
        await expect(page.getByRole('button', { name: 'Generate Preview' })).toBeDisabled();
        await page.locator('input[value="1000-0"]').fill('0-1000');
        await expect(page.getByRole('button', { name: 'Generate Preview' })).toBeEnabled();
    });

    test('sample receipts: allow and deny verify, the tampered line fails', async ({ page }) => {
        await page.getByRole('tab', { name: 'Verify' }).click();
        await page.getByRole('button', { name: 'Load sample receipts' }).click();
        await expect(page.getByText(/2 of 3 receipts verify/)).toBeVisible();
        await expect(page.getByText(/ALLOW · read_file/)).toBeVisible();
        await expect(page.getByText(/DENY · read_file/)).toBeVisible();
        await expect(page.getByTestId('receipt-failed')).toHaveCount(1);
        await expect(page.getByText('Line 3: signature does not verify')).toBeVisible();
        await expect(page.getByTestId('sample-receipts-note')).toContainText('does not show the signing key speaks for anyone you trust');
    });
});
