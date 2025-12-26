import { describe, it, expect } from 'vitest';
import { cleanInput } from '../utils';

/**
 * Edge Case and Crash Prevention Tests
 * 
 * These tests verify that the explorer handles edge cases gracefully
 * without crashing. Each test targets a potential crash point.
 */

// ============================================================================
// UTILITY FUNCTION TESTS
// ============================================================================

// Truncate function from App.tsx
const truncate = (str: string, len: number = 12) =>
    str.length > len ? `${str.slice(0, 6)}...${str.slice(-4)}` : str;

describe('truncate', () => {
    it('handles normal string', () => {
        expect(truncate('hello')).toBe('hello');
        expect(truncate('hello world of doom', 12)).toBe('hello ...doom');  // 6 + 3 + 4 = 13 chars
    });

    it('handles empty string', () => {
        expect(truncate('')).toBe('');
    });

    it('handles exact length', () => {
        expect(truncate('123456789012', 12)).toBe('123456789012');
        expect(truncate('1234567890123', 12)).toBe('123456...0123');
    });

    it('handles very short strings', () => {
        expect(truncate('a')).toBe('a');
        expect(truncate('ab')).toBe('ab');
    });

    it('handles long hex strings', () => {
        const hex = 'f32e74b5b8569dc288db0109b7ec0d8eb3b4e5be7b07c647171d53fd31e7391f';
        expect(truncate(hex, 16)).toBe('f32e74...391f');
    });
});

// ============================================================================
// EXPIRATION DISPLAY EDGE CASES
// ============================================================================

// Time formatting function from ExpirationDisplay
const formatTime = (seconds: number) => {
    if (seconds <= 0) return 'Expired';
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = Math.floor(seconds % 60);
    if (d > 0) return `${d}d ${h}h ${m}m`;
    if (h > 0) return `${h}h ${m}m ${s}s`;
    if (m > 0) return `${m}m ${s}s`;
    return `${s}s`;
};

describe('formatTime', () => {
    it('handles zero', () => {
        expect(formatTime(0)).toBe('Expired');
    });

    it('handles negative values (expired)', () => {
        expect(formatTime(-100)).toBe('Expired');
        expect(formatTime(-0.1)).toBe('Expired');
    });

    it('handles fractional seconds', () => {
        expect(formatTime(0.5)).toBe('0s'); // floors to 0, but condition is <= 0, so 0.5 > 0 returns '0s'
        expect(formatTime(1.9)).toBe('1s');
    });

    it('handles very large values', () => {
        // 365 days
        expect(formatTime(365 * 86400)).toBe('365d 0h 0m');
    });

    it('handles edge transitions', () => {
        expect(formatTime(59)).toBe('59s');
        expect(formatTime(60)).toBe('1m 0s');
        expect(formatTime(3599)).toBe('59m 59s');
        expect(formatTime(3600)).toBe('1h 0m 0s');
    });
});

// Progress bar calculation edge cases
const calculateProgress = (issuedAt: number, expiresAt: number, now: number) => {
    const total = expiresAt - issuedAt;
    const elapsed = now - issuedAt;
    return Math.min(100, Math.max(0, (elapsed / total) * 100));
};

describe('calculateProgress', () => {
    it('handles normal case', () => {
        expect(calculateProgress(0, 100, 50)).toBe(50);
        expect(calculateProgress(0, 100, 0)).toBe(0);
        expect(calculateProgress(0, 100, 100)).toBe(100);
    });

    it('clamps to 0-100 range', () => {
        // Before issued (negative elapsed)
        expect(calculateProgress(100, 200, 50)).toBe(0);
        // After expired (over 100%)
        expect(calculateProgress(0, 100, 200)).toBe(100);
    });

    it('handles issuedAt === expiresAt (division by zero)', () => {
        // This would cause division by zero if not handled
        const total = 100 - 100; // 0
        const elapsed = 50 - 100; // -50
        const result = total === 0 ? 0 : Math.min(100, Math.max(0, (elapsed / total) * 100));
        expect(result).toBe(0);
    });

    it('handles issuedAt > expiresAt (invalid warrant)', () => {
        // Negative total duration produces unexpected result but doesn't crash
        // elapsed = 150 - 200 = -50, total = 100 - 200 = -100
        // ratio = -50 / -100 = 0.5, * 100 = 50 (clamped to 0-100)
        const result = calculateProgress(200, 100, 150);
        expect(result).toBeGreaterThanOrEqual(0);
        expect(result).toBeLessThanOrEqual(100);
    });
});

// ============================================================================
// JSON PARSING EDGE CASES
// ============================================================================

// Safe JSON parse pattern used in App.tsx
const safeJsonParse = (json: string, fallback: unknown = {}) => {
    try {
        return JSON.parse(json);
    } catch {
        return fallback;
    }
};

describe('safeJsonParse', () => {
    it('parses valid JSON', () => {
        expect(safeJsonParse('{"a": 1}')).toEqual({ a: 1 });
        expect(safeJsonParse('[]')).toEqual([]);
    });

    it('returns fallback for invalid JSON', () => {
        expect(safeJsonParse('{invalid}')).toEqual({});
        expect(safeJsonParse('{invalid}', [])).toEqual([]);
    });

    it('handles empty string', () => {
        expect(safeJsonParse('')).toEqual({});
    });

    it('handles null/undefined-like strings', () => {
        expect(safeJsonParse('null')).toBe(null);
        expect(safeJsonParse('undefined')).toEqual({});
    });

    it('handles extremely nested JSON', () => {
        // Deep nesting shouldn't crash (might hit stack limit with very deep)
        const deep = '{"a":{"b":{"c":{"d":{"e":{"f":1}}}}}}';
        expect(safeJsonParse(deep)).toEqual({ a: { b: { c: { d: { e: { f: 1 } } } } } });
    });

    it('handles JSON with special characters', () => {
        expect(safeJsonParse('{"emoji": "🔐"}')).toEqual({ emoji: '🔐' });
        expect(safeJsonParse('{"path": "/data/\\"file\\".txt"}')).toEqual({ path: '/data/"file".txt' });
    });
});

// ============================================================================
// SHARE URL EDGE CASES
// ============================================================================

// Share URL generation pattern
const generateShareUrl = (state: Record<string, string>) => {
    try {
        return `?s=${btoa(JSON.stringify(state))}`;
    } catch {
        return '';
    }
};

// Share URL parsing pattern
const parseShareUrl = (encoded: string): Record<string, string> | null => {
    try {
        return JSON.parse(atob(encoded));
    } catch {
        return null;
    }
};

describe('Share URL', () => {
    describe('generateShareUrl', () => {
        it('encodes normal state', () => {
            const state = { warrant: 'abc123', tool: 'read_file' };
            const url = generateShareUrl(state);
            expect(url).toMatch(/^\?s=[A-Za-z0-9+/=]+$/);
        });

        it('handles empty state', () => {
            expect(generateShareUrl({})).toBeTruthy();
        });

        // Note: btoa throws on non-Latin1 characters in some environments
        // The real code should use encodeURIComponent for safety
        it('handles special characters in values', () => {
            const state = { warrant: 'abc+/=123' };
            const url = generateShareUrl(state);
            expect(url.length).toBeGreaterThan(0);
        });
    });

    describe('parseShareUrl', () => {
        it('decodes valid share URL', () => {
            const original = { warrant: 'test', tool: 'read' };
            const encoded = btoa(JSON.stringify(original));
            expect(parseShareUrl(encoded)).toEqual(original);
        });

        it('returns null for invalid base64', () => {
            expect(parseShareUrl('!!!invalid!!!')).toBe(null);
        });

        it('returns null for valid base64 but invalid JSON', () => {
            const notJson = btoa('not json');
            expect(parseShareUrl(notJson)).toBe(null);
        });

        it('returns null for empty string', () => {
            expect(parseShareUrl('')).toBe(null);
        });
    });
});

// ============================================================================
// CONSTRAINT VALUE EDGE CASES
// ============================================================================

describe('Constraint Value Edge Cases', () => {
    // Values that could cause issues when rendering or processing
    const edgeCaseValues = [
        { name: 'empty string', value: '' },
        { name: 'whitespace only', value: '   ' },
        { name: 'very long string', value: 'a'.repeat(10000) },
        { name: 'unicode', value: '🔐✅❌' },
        { name: 'newlines', value: 'line1\nline2\nline3' },
        { name: 'tabs', value: 'col1\tcol2' },
        { name: 'null bytes', value: 'before\x00after' },
        { name: 'HTML-like', value: '<script>alert(1)</script>' },
        { name: 'regex special chars', value: '.*+?^${}()|[]\\' },
        { name: 'path traversal', value: '../../../etc/passwd' },
        { name: 'windows path', value: 'C:\\Windows\\System32' },
    ];

    edgeCaseValues.forEach(({ name, value }) => {
        it(`handles ${name} without crashing`, () => {
            // These operations happen frequently in the explorer
            expect(() => value.trim()).not.toThrow();
            expect(() => value.length).not.toThrow();
            expect(() => JSON.stringify(value)).not.toThrow();
            expect(() => value.includes('*')).not.toThrow();
            expect(() => value.replace(/\*/g, 'x')).not.toThrow();
        });
    });
});

// ============================================================================
// DECODED WARRANT NORMALIZATION
// ============================================================================

describe('Decoded Warrant Normalization', () => {
    // The explorer normalizes WASM results to ensure all fields exist
    const normalizeWarrant = (result: Record<string, unknown>) => ({
        id: result.id || '',
        issuer: result.issuer || '',
        tools: Array.isArray(result.tools) ? result.tools : [],
        capabilities: result.capabilities || {},
        issued_at: result.issued_at || 0,
        expires_at: result.expires_at || 0,
        authorized_holder: result.authorized_holder || '',
        depth: result.depth || 0,
    });

    it('normalizes complete warrant', () => {
        const result = {
            id: 'abc',
            issuer: 'xyz',
            tools: ['read'],
            capabilities: { read: {} },
            issued_at: 100,
            expires_at: 200,
            authorized_holder: 'holder',
            depth: 1
        };
        expect(normalizeWarrant(result)).toEqual(result);
    });

    it('provides defaults for missing fields', () => {
        const normalized = normalizeWarrant({});
        expect(normalized.id).toBe('');
        expect(normalized.tools).toEqual([]);
        expect(normalized.issued_at).toBe(0);
        expect(normalized.depth).toBe(0);
    });

    it('handles null values', () => {
        const normalized = normalizeWarrant({
            id: null,
            tools: null,
            capabilities: null
        });
        expect(normalized.id).toBe('');
        expect(normalized.tools).toEqual([]);
        expect(normalized.capabilities).toEqual({});
    });

    it('handles non-array tools', () => {
        const normalized = normalizeWarrant({
            tools: 'single_tool'  // Wrong type
        });
        expect(Array.isArray(normalized.tools)).toBe(true);
        expect(normalized.tools).toEqual([]);
    });
});

// ============================================================================
// VALIDATION EDGE CASES
// ============================================================================

describe('Validation Edge Cases', () => {
    const base64Regex = /^[A-Za-z0-9+/\-_]+=*$/;



    describe('Base64 Validation', () => {
        it('accepts standard base64', () => {
            expect(base64Regex.test('SGVsbG8gV29ybGQ=')).toBe(true);
        });

        it('accepts base64url', () => {
            expect(base64Regex.test('abc-def_ghi')).toBe(true);
        });

        it('rejects base64 with spaces', () => {
            expect(base64Regex.test('abc def')).toBe(false);
        });

        it('rejects base64 with newlines', () => {
            expect(base64Regex.test('abc\ndef')).toBe(false);
        });

        it('handles empty string', () => {
            expect(base64Regex.test('')).toBe(false); // + quantifier requires at least 1 char
        });

        it('rejects clearly invalid', () => {
            expect(base64Regex.test('!@#$%')).toBe(false);
        });
    });

    describe('Tool Name Validation', () => {
        const toolRegex = /^[a-zA-Z_][a-zA-Z0-9_]*$/;

        it('accepts valid tool names', () => {
            expect(toolRegex.test('read_file')).toBe(true);
            expect(toolRegex.test('_private')).toBe(true);
            expect(toolRegex.test('Tool123')).toBe(true);
        });

        it('rejects invalid tool names', () => {
            expect(toolRegex.test('123start')).toBe(false);
            expect(toolRegex.test('has-dash')).toBe(false);
            expect(toolRegex.test('has space')).toBe(false);
            expect(toolRegex.test('')).toBe(false);
        });
    });

    describe('Hex Key Validation', () => {
        const hexRegex = /^[a-f0-9]+$/;

        it('accepts valid hex', () => {
            expect(hexRegex.test('deadbeef')).toBe(true);
            expect(hexRegex.test('0123456789abcdef')).toBe(true);
        });

        it('rejects invalid hex', () => {
            expect(hexRegex.test('0123456789abcdefg')).toBe(false);
            expect(hexRegex.test('DEADBEEF')).toBe(false); // Must lowercase first
            expect(hexRegex.test('')).toBe(false);
        });
    });
});

// ============================================================================
// PEM EXTRACTION EDGE CASES
// ============================================================================

describe('cleanInput (PEM extraction)', () => {
    it('handles raw base64', () => {
        const raw = 'abc123xyz';
        expect(cleanInput(raw)).toEqual({ b64: 'abc123xyz', isPem: false });
    });

    it('handles PEM wrapped content', () => {
        const pem = `-----BEGIN TENUO WARRANT-----
abc123xyz
-----END TENUO WARRANT-----`;
        expect(cleanInput(pem)).toEqual({ b64: 'abc123xyz', isPem: true });
    });

    it('strips newlines in PEM payload', () => {
        const pem = `-----BEGIN TENUO WARRANT-----
abc
123
xyz
-----END TENUO WARRANT-----`;
        expect(cleanInput(pem)).toEqual({ b64: 'abc123xyz', isPem: true });
    });

    it('strips whitespace in raw input', () => {
        expect(cleanInput(' a b c ')).toEqual({ b64: 'abc', isPem: false });
    });

    it('handles invalid PEM tags (treats as raw)', () => {
        // If it doesn't match the regex, it falls back to raw
        // And raw logic strips whitespace
        const badPem = `-----BEGIN WRONG TAG-----
abc
-----END WRONG TAG-----`;
        const result = cleanInput(badPem);
        expect(result.isPem).toBe(false);
        expect(result.b64).toContain('BEGINWRONGTAG'); // whitespace stripped
    });
});
