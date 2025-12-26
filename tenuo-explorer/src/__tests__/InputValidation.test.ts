import { describe, it, expect } from 'vitest';

/**
 * Input Validation Tests
 * 
 * These tests verify that user input (warrant, tool, args, rootKey) is properly validated
 * before being sent to WASM for processing.
 */

// Validation functions extracted from App.tsx validateInputs logic
const validateWarrant = (warrant: string): { valid: boolean; error?: string } => {
    const trimmed = warrant.trim();

    if (!trimmed) {
        return { valid: false, error: 'Warrant is required' };
    }

    // Check if it looks like base64 or base64url
    const base64Regex = /^[A-Za-z0-9+/\-_]+=*$/;
    const clean = trimmed.replace(/\s/g, '');

    if (!base64Regex.test(clean)) {
        return { valid: false, error: 'Invalid base64 format' };
    }

    if (clean.length < 50) {
        return { valid: false, error: 'Warrant seems too short' };
    }

    return { valid: true };
};

const validateTool = (tool: string): { valid: boolean; error?: string } => {
    const trimmed = tool.trim();

    if (!trimmed) {
        return { valid: false, error: 'Tool name is required' };
    }

    if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(trimmed)) {
        return { valid: false, error: 'Tool name should be alphanumeric' };
    }

    return { valid: true };
};

const validateArgs = (args: string): { valid: boolean; error?: string } => {
    const trimmed = args.trim();

    if (!trimmed) {
        return { valid: true }; // Empty args are allowed
    }

    try {
        const parsed = JSON.parse(trimmed);
        if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
            return { valid: false, error: 'Args must be a JSON object' };
        }
        return { valid: true };
    } catch {
        return { valid: false, error: 'Invalid JSON' };
    }
};

const validateRootKey = (rootKey: string): { valid: boolean; error?: string } => {
    const trimmed = rootKey.trim();

    if (!trimmed) {
        return { valid: true }; // Empty root key is allowed
    }

    const cleanHex = trimmed.toLowerCase();

    if (!/^[a-f0-9]+$/.test(cleanHex)) {
        return { valid: false, error: 'Root key must be hexadecimal' };
    }

    if (cleanHex.length !== 64) {
        return { valid: false, error: `Root key should be 64 hex characters (got ${cleanHex.length})` };
    }

    return { valid: true };
};

describe('Input Validation', () => {
    describe('Warrant Validation', () => {
        it('accepts valid base64 warrant', () => {
            // Base64url warrant without periods (Tenuo uses CBOR, not JWT)
            const warrant = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFZDI1NTE5In0eyJpc3MiOiJmMzJlNzRiNWI4NTY5ZGMyODhkYj';
            expect(validateWarrant(warrant).valid).toBe(true);
        });

        it('accepts base64url warrant with - and _', () => {
            const warrant = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFZDI1NTE5In0_eyJpc3MiOiJmMzJlNzRiNWI4-NjlkYz';
            expect(validateWarrant(warrant).valid).toBe(true);
        });

        it('rejects empty warrant', () => {
            expect(validateWarrant('').valid).toBe(false);
            expect(validateWarrant('').error).toBe('Warrant is required');
        });

        it('rejects whitespace-only warrant', () => {
            expect(validateWarrant('   ').valid).toBe(false);
        });

        it('rejects warrant with invalid characters', () => {
            const warrant = 'eyJ0eXAi!@#$%^&*()';
            expect(validateWarrant(warrant).valid).toBe(false);
            expect(validateWarrant(warrant).error).toContain('Invalid base64');
        });

        it('rejects too-short warrant', () => {
            const warrant = 'abc123';
            expect(validateWarrant(warrant).valid).toBe(false);
            expect(validateWarrant(warrant).error).toContain('too short');
        });

        it('ignores whitespace in warrant', () => {
            const warrant = 'eyJ0eXAiOiJKV1Qi LCJhbGci OiJFZDI1NTE5In0 eyJpc3Mi OiJmMzJl';
            expect(validateWarrant(warrant).valid).toBe(true);
        });
    });

    describe('Tool Name Validation', () => {
        it('accepts valid tool name', () => {
            expect(validateTool('read_file').valid).toBe(true);
        });

        it('accepts tool starting with underscore', () => {
            expect(validateTool('_private_tool').valid).toBe(true);
        });

        it('accepts tool with numbers', () => {
            expect(validateTool('tool123').valid).toBe(true);
        });

        it('rejects empty tool name', () => {
            expect(validateTool('').valid).toBe(false);
            expect(validateTool('').error).toBe('Tool name is required');
        });

        it('rejects tool starting with number', () => {
            expect(validateTool('123tool').valid).toBe(false);
            expect(validateTool('123tool').error).toContain('alphanumeric');
        });

        it('rejects tool with special characters', () => {
            expect(validateTool('read-file').valid).toBe(false);
            expect(validateTool('read.file').valid).toBe(false);
            expect(validateTool('read file').valid).toBe(false);
        });

        it('trims whitespace', () => {
            expect(validateTool('  read_file  ').valid).toBe(true);
        });
    });

    describe('Args Validation', () => {
        it('accepts valid JSON object', () => {
            expect(validateArgs('{"path": "/data/test.txt"}').valid).toBe(true);
        });

        it('accepts empty string', () => {
            expect(validateArgs('').valid).toBe(true);
        });

        it('accepts nested objects', () => {
            expect(validateArgs('{"a": {"b": {"c": 1}}}').valid).toBe(true);
        });

        it('rejects JSON array', () => {
            expect(validateArgs('[1, 2, 3]').valid).toBe(false);
            expect(validateArgs('[1, 2, 3]').error).toContain('JSON object');
        });

        it('rejects JSON primitive', () => {
            expect(validateArgs('"just a string"').valid).toBe(false);
            expect(validateArgs('123').valid).toBe(false);
            expect(validateArgs('true').valid).toBe(false);
            expect(validateArgs('null').valid).toBe(false);
        });

        it('rejects invalid JSON', () => {
            expect(validateArgs('{invalid json}').valid).toBe(false);
            expect(validateArgs('{invalid json}').error).toContain('Invalid JSON');
        });

        it('rejects JSON with trailing comma', () => {
            expect(validateArgs('{"a": 1,}').valid).toBe(false);
        });
    });

    describe('Root Key Validation', () => {
        it('accepts valid 64-char hex key', () => {
            const key = 'f32e74b5b8569dc288db0109b7ec0d8eb3b4e5be7b07c647171d53fd31e7391f';
            expect(validateRootKey(key).valid).toBe(true);
        });

        it('accepts empty root key', () => {
            expect(validateRootKey('').valid).toBe(true);
        });

        it('accepts uppercase hex', () => {
            const key = 'F32E74B5B8569DC288DB0109B7EC0D8EB3B4E5BE7B07C647171D53FD31E7391F';
            expect(validateRootKey(key).valid).toBe(true);
        });

        it('rejects non-hex characters', () => {
            const key = 'g32e74b5b8569dc288db0109b7ec0d8eb3b4e5be7b07c647171d53fd31e7391f';
            expect(validateRootKey(key).valid).toBe(false);
            expect(validateRootKey(key).error).toContain('hexadecimal');
        });

        it('rejects wrong length', () => {
            const shortKey = 'f32e74b5b8569dc288db0109b7ec0d8e';
            expect(validateRootKey(shortKey).valid).toBe(false);
            expect(validateRootKey(shortKey).error).toContain('64 hex characters');
        });

        it('rejects hex with spaces', () => {
            const key = 'f32e 74b5 b8569dc288db0109b7ec0d8eb3b4e5be7b07c647171d53fd31e7391f';
            expect(validateRootKey(key).valid).toBe(false);
        });
    });
});
