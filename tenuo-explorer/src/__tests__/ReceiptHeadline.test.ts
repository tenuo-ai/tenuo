import { describe, expect, it } from 'vitest';
import { receiptHeadline } from '../App';

/** A denial made in observe mode (receipt key 16) ran; it must not read as a block. */
describe('receiptHeadline', () => {
  it('labels an allow', () => {
    expect(receiptHeadline({ outcome: 'allow', action: 'read_file' })).toBe('✅ ALLOW · read_file');
  });

  it('labels an enforced deny, with or without key 16 decoded', () => {
    expect(receiptHeadline({ outcome: 'deny', action: 'read_file' })).toBe('🚫 DENY · read_file');
    expect(receiptHeadline({ outcome: 'deny', action: 'read_file', mode: 'enforce' })).toBe('🚫 DENY · read_file');
  });
  it('labels an allow made while observing', () => {
    expect(receiptHeadline({ outcome: 'allow', action: 'read_file', mode: 'observe' })).toBe(
      '✅ ALLOW (observe mode) · read_file',
    );
  });

  it('labels an observed deny as not enforced', () => {
    const headline = receiptHeadline({ outcome: 'deny', action: 'read_file', mode: 'observe' });
    expect(headline).toContain('OBSERVED DENY (not enforced)');
    expect(headline).not.toContain('🚫');
  });
});
