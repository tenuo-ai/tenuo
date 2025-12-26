import { describe, it, expect } from 'vitest';

/**
 * Constraint Parsing Tests
 * 
 * These tests verify that constraint parsing logic correctly handles
 * various constraint formats from decoded warrants.
 */

type ParsedConstraint = {
    type: 'pattern' | 'exact' | 'range' | 'oneof' | 'unknown';
    pythonCode: string;
    rustCode: string;
    exampleValue: string | number;
    warning?: string;
};

// Constraint parsing function extracted from CodeGenerator in App.tsx
const parseConstraint = (_key: string, value: unknown): ParsedConstraint => {
    if (typeof value === 'object' && value !== null) {
        const v = value as Record<string, unknown>;

        // Pattern constraint: { pattern: "docs/*" }
        if (v.pattern && typeof v.pattern === 'string') {
            const pattern = v.pattern;
            return {
                type: 'pattern',
                pythonCode: `Pattern("${pattern}")`,
                rustCode: `Constraint::Pattern(Pattern::new("${pattern}")?)`,
                exampleValue: pattern.replace(/\*/g, 'example').replace(/\?/g, 'x')
            };
        }

        // Exact constraint: { exact: "value" }
        if (v.exact !== undefined) {
            const exact = String(v.exact);
            return {
                type: 'exact',
                pythonCode: `Exact("${exact}")`,
                rustCode: `Constraint::Exact("${exact}".to_string())`,
                exampleValue: exact
            };
        }

        // Range constraint: { min: 0, max: 100 } or { max: 100 }
        if (v.min !== undefined || v.max !== undefined) {
            const min = v.min as number | undefined;
            const max = v.max as number | undefined;
            let pythonCode: string;
            let rustCode: string;
            if (min !== undefined && max !== undefined) {
                pythonCode = `Range(min_value=${min}, max_value=${max})`;
                rustCode = `Constraint::Range(Range::new(Some(${min}), Some(${max})))`;
            } else if (max !== undefined) {
                pythonCode = `Range.max_value(${max})`;
                rustCode = `Constraint::Range(Range::max(${max}))`;
            } else {
                pythonCode = `Range.min_value(${min})`;
                rustCode = `Constraint::Range(Range::min(${min}))`;
            }
            return {
                type: 'range',
                pythonCode,
                rustCode,
                exampleValue: max !== undefined ? Math.floor(max / 2) : (min !== undefined ? min + 10 : 50)
            };
        }

        // OneOf constraint: { oneof: ["a", "b"] }
        if (v.oneof || v.values) {
            const rawVal = v.oneof || v.values;
            let values: string[];
            if (Array.isArray(rawVal)) {
                values = rawVal.map(String);
            } else if (typeof rawVal === 'string') {
                values = rawVal.split(',').map(s => s.trim()).filter(Boolean);
            } else {
                values = [String(rawVal)];
            }
            if (values.length === 0) values = ['value'];
            return {
                type: 'oneof',
                pythonCode: `OneOf([${values.map(x => `"${x}"`).join(', ')}])`,
                rustCode: `Constraint::OneOf(vec![${values.map(x => `"${x}".to_string()`).join(', ')}])`,
                exampleValue: values[0] || 'value'
            };
        }
    }

    // String value - check if pattern
    if (typeof value === 'string') {
        if (value.includes('*') || value.includes('?')) {
            return {
                type: 'pattern',
                pythonCode: `Pattern("${value}")`,
                rustCode: `Constraint::Pattern(Pattern::new("${value}")?)`,
                exampleValue: value.replace(/\*/g, 'example').replace(/\?/g, 'x')
            };
        }
        return {
            type: 'exact',
            pythonCode: `Exact("${value}")`,
            rustCode: `Constraint::Exact("${value}".to_string())`,
            exampleValue: value
        };
    }

    // Number - assume range max
    if (typeof value === 'number') {
        return {
            type: 'range',
            pythonCode: `Range.max_value(${value})`,
            rustCode: `Constraint::Range(Range::max(${value}))`,
            exampleValue: Math.floor(value / 2)
        };
    }

    // Unknown - fallback
    const strVal = typeof value === 'object' ? JSON.stringify(value) : String(value);
    return {
        type: 'unknown',
        pythonCode: `Pattern("*")  # TODO: Unknown constraint type - ${strVal.slice(0, 50)}`,
        rustCode: `Constraint::Pattern(Pattern::new("*")?)  // TODO: Unknown constraint - ${strVal.slice(0, 50)}`,
        exampleValue: 'value',
        warning: `Unrecognized constraint format: ${strVal.slice(0, 100)}`
    };
};

describe('Constraint Parsing', () => {
    describe('Pattern Constraints', () => {
        it('parses object pattern format', () => {
            const result = parseConstraint('path', { pattern: 'docs/*' });

            expect(result.type).toBe('pattern');
            expect(result.pythonCode).toBe('Pattern("docs/*")');
            expect(result.rustCode).toContain('Pattern::new("docs/*")');
            expect(result.exampleValue).toBe('docs/example');
        });

        it('parses string with glob as pattern', () => {
            const result = parseConstraint('path', 'data/*.txt');

            expect(result.type).toBe('pattern');
            expect(result.pythonCode).toBe('Pattern("data/*.txt")');
        });

        it('handles ? wildcard in pattern', () => {
            const result = parseConstraint('name', { pattern: 'file?.txt' });

            expect(result.exampleValue).toBe('filex.txt');
        });
    });

    describe('Exact Constraints', () => {
        it('parses object exact format', () => {
            const result = parseConstraint('method', { exact: 'GET' });

            expect(result.type).toBe('exact');
            expect(result.pythonCode).toBe('Exact("GET")');
            expect(result.rustCode).toContain('"GET".to_string()');
            expect(result.exampleValue).toBe('GET');
        });

        it('parses plain string as exact', () => {
            const result = parseConstraint('method', 'POST');

            expect(result.type).toBe('exact');
            expect(result.pythonCode).toBe('Exact("POST")');
        });
    });

    describe('Range Constraints', () => {
        it('parses min and max range', () => {
            const result = parseConstraint('amount', { min: 0, max: 1000 });

            expect(result.type).toBe('range');
            expect(result.pythonCode).toBe('Range(min_value=0, max_value=1000)');
            expect(result.exampleValue).toBe(500);
        });

        it('parses max-only range', () => {
            const result = parseConstraint('size', { max: 100 });

            expect(result.type).toBe('range');
            expect(result.pythonCode).toBe('Range.max_value(100)');
            expect(result.exampleValue).toBe(50);
        });

        it('parses min-only range', () => {
            const result = parseConstraint('count', { min: 5 });

            expect(result.type).toBe('range');
            expect(result.pythonCode).toBe('Range.min_value(5)');
            expect(result.exampleValue).toBe(15);
        });

        it('parses plain number as range max', () => {
            const result = parseConstraint('limit', 200);

            expect(result.type).toBe('range');
            expect(result.pythonCode).toBe('Range.max_value(200)');
        });
    });

    describe('OneOf Constraints', () => {
        it('parses oneof array format', () => {
            const result = parseConstraint('status', { oneof: ['active', 'pending'] });

            expect(result.type).toBe('oneof');
            expect(result.pythonCode).toBe('OneOf(["active", "pending"])');
            expect(result.exampleValue).toBe('active');
        });

        it('parses values array format', () => {
            const result = parseConstraint('type', { values: ['a', 'b', 'c'] });

            expect(result.type).toBe('oneof');
            expect(result.pythonCode).toContain('"a"');
            expect(result.pythonCode).toContain('"b"');
            expect(result.pythonCode).toContain('"c"');
        });

        it('parses comma-separated string', () => {
            const result = parseConstraint('role', { oneof: 'admin,user,guest' });

            expect(result.type).toBe('oneof');
            expect(result.pythonCode).toBe('OneOf(["admin", "user", "guest"])');
        });

        it('handles empty oneof array', () => {
            const result = parseConstraint('empty', { oneof: [] });

            expect(result.type).toBe('oneof');
            expect(result.exampleValue).toBe('value');
        });
    });

    describe('Unknown Constraints', () => {
        it('returns unknown for unrecognized object', () => {
            const result = parseConstraint('weird', { custom: 'value', other: 123 });

            expect(result.type).toBe('unknown');
            expect(result.warning).toContain('Unrecognized');
            expect(result.pythonCode).toContain('# TODO');
        });

        it('returns unknown for boolean', () => {
            const result = parseConstraint('flag', true);

            expect(result.type).toBe('unknown');
        });
    });
});
