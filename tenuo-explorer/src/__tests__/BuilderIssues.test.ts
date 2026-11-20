import { describe, expect, it } from 'vitest';
import { builderIssues } from '../App';

type Row = { key: string; type: 'range' | 'pattern' | 'url_safe' | 'oneof'; value: string };
const tool = (name: string, constraints: Row[]) => ({ name, constraints });

describe('builderIssues', () => {
  it('blocks an inverted range instead of letting it be dropped', () => {
    const { rows } = builderIssues([tool('transfer', [{ key: 'amount', type: 'range', value: '1000-0' }])], 600);
    expect(rows['0-0']).toBe('Min cannot be greater than max');
  });

  it('passes the Limited Spend template as shipped', () => {
    const issues = builderIssues([tool('transfer', [{ key: 'amount', type: 'range', value: '0-1000' }])], 600);
    expect(issues).toEqual({ rows: {}, form: [] });
  });

  it('blocks rows that would otherwise be omitted from the config', () => {
    const { rows } = builderIssues([
      tool('transfer', [
        { key: '', type: 'range', value: '0-10' },
        { key: 'amount', type: 'range', value: '' },
        { key: 'amount', type: 'range', value: '5' },
      ]),
      tool('', [{ key: 'path', type: 'pattern', value: 'docs/*' }]),
      tool('transfer', []),
    ], 600);
    expect(rows).toEqual({
      '0-0': 'Argument name is required',
      '0-1': 'Value is required',
      '0-2': 'Duplicate argument "amount"',
      '1': 'Tool name is required',
      '2': 'Duplicate tool "transfer"',
    });
  });

  it('allows an empty UrlSafe value, which means the default protections', () => {
    expect(builderIssues([tool('fetch', [{ key: 'url', type: 'url_safe', value: '' }])], 60).rows).toEqual({});
  });

  it('reports form-level problems', () => {
    expect(builderIssues([tool('', [])], 0).form).toEqual([
      'TTL must be a positive whole number of seconds',
      'Add at least one tool',
    ]);
  });
});
