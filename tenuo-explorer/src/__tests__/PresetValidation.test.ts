import { describe, it, expect } from 'vitest';

/**
 * Preset Import Validation Tests
 * 
 * These tests verify that preset import properly validates and filters incoming data.
 * This is a security feature to prevent malformed JSON from corrupting state.
 */

// Type definition matching App.tsx
interface Preset {
    id: string;
    name: string;
    warrant: string;
    tool: string;
    args: string;
    rootKey: string;
}

// Validation function extracted from App.tsx handleImport logic
const validatePreset = (p: unknown): p is Preset => {
    return (
        p !== null &&
        typeof p === 'object' &&
        typeof (p as Preset).id === 'string' && (p as Preset).id.length > 0 &&
        typeof (p as Preset).name === 'string' && (p as Preset).name.length > 0 &&
        typeof (p as Preset).warrant === 'string' && (p as Preset).warrant.length > 0 &&
        (typeof (p as Preset).tool === 'string' || (p as Preset).tool === undefined) &&
        (typeof (p as Preset).args === 'string' || (p as Preset).args === undefined) &&
        (typeof (p as Preset).rootKey === 'string' || (p as Preset).rootKey === undefined)
    );
};

const filterValidPresets = (imported: unknown[]): Preset[] => {
    return imported.filter(validatePreset);
};

describe('Preset Import Validation', () => {
    describe('Required Fields', () => {
        it('accepts preset with all required fields', () => {
            const preset = {
                id: 'abc123',
                name: 'Test Preset',
                warrant: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFZDI1NTE5In0...',
                tool: 'read_file',
                args: '{"path": "/data/test.txt"}',
                rootKey: 'f32e74b5...'
            };

            expect(validatePreset(preset)).toBe(true);
        });

        it('rejects preset without id', () => {
            const preset = {
                name: 'Test Preset',
                warrant: 'eyJ0eXAi...'
            };

            expect(validatePreset(preset)).toBe(false);
        });

        it('rejects preset without name', () => {
            const preset = {
                id: 'abc123',
                warrant: 'eyJ0eXAi...'
            };

            expect(validatePreset(preset)).toBe(false);
        });

        it('rejects preset without warrant', () => {
            const preset = {
                id: 'abc123',
                name: 'Test Preset'
            };

            expect(validatePreset(preset)).toBe(false);
        });

        it('rejects preset with empty id', () => {
            const preset = {
                id: '',
                name: 'Test Preset',
                warrant: 'eyJ0eXAi...'
            };

            expect(validatePreset(preset)).toBe(false);
        });

        it('rejects preset with empty name', () => {
            const preset = {
                id: 'abc123',
                name: '',
                warrant: 'eyJ0eXAi...'
            };

            expect(validatePreset(preset)).toBe(false);
        });

        it('rejects preset with empty warrant', () => {
            const preset = {
                id: 'abc123',
                name: 'Test Preset',
                warrant: ''
            };

            expect(validatePreset(preset)).toBe(false);
        });
    });

    describe('Optional Fields', () => {
        it('accepts preset without tool', () => {
            const preset = {
                id: 'abc123',
                name: 'Test Preset',
                warrant: 'eyJ0eXAi...'
            };

            expect(validatePreset(preset)).toBe(true);
        });

        it('accepts preset without args', () => {
            const preset = {
                id: 'abc123',
                name: 'Test Preset',
                warrant: 'eyJ0eXAi...',
                tool: 'read_file'
            };

            expect(validatePreset(preset)).toBe(true);
        });

        it('accepts preset without rootKey', () => {
            const preset = {
                id: 'abc123',
                name: 'Test Preset',
                warrant: 'eyJ0eXAi...',
                tool: 'read_file',
                args: '{}'
            };

            expect(validatePreset(preset)).toBe(true);
        });
    });

    describe('Type Validation', () => {
        it('rejects null', () => {
            expect(validatePreset(null)).toBe(false);
        });

        it('rejects undefined', () => {
            expect(validatePreset(undefined)).toBe(false);
        });

        it('rejects string', () => {
            expect(validatePreset('not a preset')).toBe(false);
        });

        it('rejects number', () => {
            expect(validatePreset(42)).toBe(false);
        });

        it('rejects array', () => {
            expect(validatePreset(['id', 'name', 'warrant'])).toBe(false);
        });

        it('rejects preset with numeric id', () => {
            const preset = {
                id: 123,
                name: 'Test Preset',
                warrant: 'eyJ0eXAi...'
            };

            expect(validatePreset(preset)).toBe(false);
        });
    });

    describe('Array Filtering', () => {
        it('filters out invalid presets from array', () => {
            const imported = [
                { id: 'a', name: 'Valid', warrant: 'abc' },
                { id: '', name: 'Invalid ID', warrant: 'abc' },
                { id: 'b', name: 'Valid 2', warrant: 'def' },
                null,
                { id: 'c', name: '', warrant: 'ghi' },
                'not an object'
            ];

            const valid = filterValidPresets(imported);

            expect(valid).toHaveLength(2);
            expect(valid[0].id).toBe('a');
            expect(valid[1].id).toBe('b');
        });

        it('returns empty array when all presets invalid', () => {
            const imported = [
                { name: 'Missing ID' },
                { id: 'a' },
                null
            ];

            const valid = filterValidPresets(imported);

            expect(valid).toHaveLength(0);
        });

        it('handles empty array', () => {
            const valid = filterValidPresets([]);
            expect(valid).toHaveLength(0);
        });
    });
});
