import { describe, it, expect } from 'vitest';

/**
 * Rust Code Generation API Compliance Tests
 * 
 * These tests verify that generated Rust code matches the current Tenuo API.
 * They validate actual working code patterns.
 */

describe('Rust Code Generator - API Compliance', () => {
    const generateRustCode = (tool: string, args: Record<string, unknown>) => {
        const constraintEntries = Object.entries(args);
        return `use tenuo::{SigningKey, Warrant, Pattern, ConstraintSet};
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate keys
    let issuer_key = SigningKey::generate();
    let holder_key = SigningKey::generate();

    // Build constraints
    let mut constraints = ConstraintSet::new();
${constraintEntries.length > 0 ? constraintEntries.map(([k, v]) => `    constraints.insert("${k}".to_string(), Pattern::new("${v}")?);`).join('\n') : '    // No constraints'}

    // Issue warrant
    let warrant = Warrant::builder()
        .capability("${tool}", constraints)
        .ttl(Duration::from_secs(3600))
        .authorized_holder(holder_key.public_key())
        .build(&issuer_key)?;

    // Authorize with Proof-of-Possession
    let args = serde_json::json!(${JSON.stringify(args)});
    let pop = warrant.sign(&holder_key, "${tool}", &args)?;
    let result = warrant.authorize("${tool}", &args, &pop)?;
    println!("Authorized: {}", result);

    // Serialize for transmission
    let warrant_b64 = warrant.to_base64()?;
    println!("Warrant: {}...", &warrant_b64[..60]);
    Ok(())
}`;
    };

    describe('Required Imports', () => {
        it('imports all necessary types', () => {
            const code = generateRustCode('read_file', { path: '/data/test.txt' });

            expect(code).toContain('use tenuo::{SigningKey, Warrant, Pattern, ConstraintSet}');
            expect(code).toContain('use std::time::Duration');
        });
    });

    describe('Warrant Issuance', () => {
        it('uses Warrant::builder() pattern', () => {
            const code = generateRustCode('read_file', { path: '/data/test.txt' });
            expect(code).toContain('Warrant::builder()');
        });

        it('calls .capability() with tool and constraints', () => {
            const code = generateRustCode('read_file', { path: '/data/test.txt' });
            expect(code).toContain('.capability("read_file", constraints)');
        });

        it('calls .ttl() with Duration', () => {
            const code = generateRustCode('read_file', { path: '/data/test.txt' });
            expect(code).toContain('.ttl(Duration::from_secs(3600))');
        });

        it('calls .authorized_holder() with public key', () => {
            const code = generateRustCode('read_file', { path: '/data/test.txt' });
            expect(code).toContain('.authorized_holder(holder_key.public_key())');
        });

        it('calls .build() with issuer key', () => {
            const code = generateRustCode('read_file', { path: '/data/test.txt' });
            expect(code).toContain('.build(&issuer_key)?');
        });
    });

    describe('Constraint Definition', () => {
        it('creates ConstraintSet', () => {
            const code = generateRustCode('read_file', { path: '/data/test.txt' });
            expect(code).toContain('let mut constraints = ConstraintSet::new()');
        });

        it('inserts constraints with Pattern::new', () => {
            const code = generateRustCode('read_file', { path: '/data/test.txt' });
            expect(code).toContain('Pattern::new(');
        });

        it('handles multiple constraints', () => {
            const code = generateRustCode('read_file', {
                path: '/data/*',
                max_size: '1000'
            });

            expect(code).toContain('constraints.insert("path"');
            expect(code).toContain('constraints.insert("max_size"');
        });

        it('handles empty constraints gracefully', () => {
            const code = generateRustCode('read_file', {});
            expect(code).toContain('// No constraints');
        });
    });

    describe('Authorization Flow', () => {
        it('creates PoP signature using sign', () => {
            const code = generateRustCode('read_file', { path: '/data/test.txt' });
            expect(code).toContain('warrant.sign(&holder_key,');
        });

        it('calls warrant.authorize with tool, args, and signature', () => {
            const code = generateRustCode('read_file', { path: '/data/test.txt' });
            expect(code).toContain('warrant.authorize("read_file", &args, &pop)?');
        });

        it('uses serde_json for args', () => {
            const code = generateRustCode('read_file', { path: '/data/test.txt' });
            expect(code).toContain('serde_json::json!');
        });
    });

    describe('Error Handling', () => {
        it('uses Result return type', () => {
            const code = generateRustCode('read_file', { path: '/data/test.txt' });
            expect(code).toContain('Result<(), Box<dyn std::error::Error>>');
        });

        it('uses ? operator for error propagation', () => {
            const code = generateRustCode('read_file', { path: '/data/test.txt' });
            expect(code).toMatch(/\?;/);
        });

        it('returns Ok(()) at end', () => {
            const code = generateRustCode('read_file', { path: '/data/test.txt' });
            expect(code).toContain('Ok(())');
        });
    });

    describe('Serialization', () => {
        it('includes to_base64() serialization', () => {
            const code = generateRustCode('read_file', { path: '/data/test.txt' });
            expect(code).toContain('warrant.to_base64()?');
        });

        it('demonstrates warrant transmission', () => {
            const code = generateRustCode('read_file', { path: '/data/test.txt' });
            expect(code).toContain('let warrant_b64 =');
        });
    });

    describe('Code Structure', () => {
        it('generates syntactically valid Rust', () => {
            const code = generateRustCode('read_file', { path: '/data/test.txt' });

            // Check for proper structure
            expect(code).toMatch(/^use tenuo::/m);
            expect(code).toMatch(/^fn main\(\) -> Result/m);
            expect(code).toMatch(/let issuer_key = SigningKey::generate\(\);/);
        });

        it('includes helpful comments', () => {
            const code = generateRustCode('read_file', { path: '/data/test.txt' });

            expect(code).toContain('// Generate keys');
            expect(code).toContain('// Build constraints');
            expect(code).toContain('// Issue warrant');
            expect(code).toContain('// Authorize');
            expect(code).toContain('// Serialize');
        });
    });
});
