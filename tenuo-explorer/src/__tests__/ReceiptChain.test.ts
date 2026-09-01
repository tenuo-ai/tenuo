import { describe, expect, it } from 'vitest';
import { analyzeReceiptChain, type ReceiptRow } from '../App';

/**
 * The chain link only pays off if something resolves it. These pin the two
 * cases that matter: a receipt withheld from a stream, and a stream that looks
 * intact only because two separate ones were concatenated.
 */

const row = (
  line: number,
  digest: string,
  prev?: string,
  request_id = `req-${line}`,
): Pick<ReceiptRow, 'line' | 'digest' | 'payload'> => ({
  line,
  digest,
  payload: {
    authentic: true,
    outcome: 'allow',
    action: 'read_file',
    request_id,
    ...(prev ? { prev_receipt_hash: prev } : {}),
  },
});

describe('analyzeReceiptChain', () => {
  it('reports no breaks when every link resolves', () => {
    const { breaks, roots } = analyzeReceiptChain([
      row(1, 'aaa'),
      row(2, 'bbb', 'aaa'),
      row(3, 'ccc', 'bbb'),
    ]);

    expect(breaks).toHaveLength(0);
    expect(roots).toHaveLength(1);
  });

  it('detects a receipt withheld from the middle of a stream', () => {
    // 'bbb' is absent; its successor now points at nothing.
    const { breaks } = analyzeReceiptChain([row(1, 'aaa'), row(2, 'ccc', 'bbb')]);

    expect(breaks).toHaveLength(1);
    expect(breaks[0].payload.request_id).toBe('req-2');
  });

  it('detects a withheld receipt at the head of a stream', () => {
    const { breaks } = analyzeReceiptChain([row(1, 'bbb', 'aaa')]);

    expect(breaks).toHaveLength(1);
  });

  it('flags merged streams even though every link resolves', () => {
    // Two predecessorless receipts: links are intact, but this is two streams.
    const { breaks, roots } = analyzeReceiptChain([
      row(1, 'aaa'),
      row(2, 'bbb', 'aaa'),
      row(3, 'xxx'),
    ]);

    expect(breaks).toHaveLength(0);
    expect(roots).toHaveLength(2);
  });

  it('treats an empty stream as having nothing to resolve', () => {
    const { breaks, roots } = analyzeReceiptChain([]);

    expect(breaks).toHaveLength(0);
    expect(roots).toHaveLength(0);
  });

  it('does not care what order receipts were pasted in', () => {
    const forward = analyzeReceiptChain([row(1, 'aaa'), row(2, 'bbb', 'aaa')]);
    const reversed = analyzeReceiptChain([row(2, 'bbb', 'aaa'), row(1, 'aaa')]);

    expect(forward.breaks).toHaveLength(0);
    expect(reversed.breaks).toHaveLength(0);
  });
});
