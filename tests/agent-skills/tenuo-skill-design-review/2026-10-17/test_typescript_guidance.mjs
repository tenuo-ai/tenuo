// Run with NODE_ENV=test and the path to a project containing the resolved SDK.
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import test from 'node:test';

const require = createRequire(path.resolve(process.argv[2], 'package.json'));
const { createTenuo, exact, range } = await import(pathToFileURL(require.resolve('@tenuo/core')));
const tenuo = createTenuo({ root: createTenuo.devRoot() });
const scope = ceiling => ({ pay_invoice: {
  invoice_id: exact('inv-123'), bank_account: exact('approved-bank'),
  amount_cents: range({min: 1, max: ceiling}),
} });
const args = {invoice_id: 'inv-123', bank_account: 'approved-bank', amount_cents: 20000};

test('top-level empty capability map is rejected', () => {
  assert.throws(() => tenuo.session({allow: {}, ttlSeconds: 60}), /at least one capability/);
});

test('per-tool empty policy permits arbitrary arguments', () => {
  const session = tenuo.session({allow: {ping: {}}, ttlSeconds: 60});
  assert.equal(tenuo.explain(session, 'ping', {unexpected: 'anything'}).outcome, 'allow');
});

test('inspect and explain expose terminal narrower-child diagnostics', () => {
  const parent = tenuo.session({allow: scope(50000), ttlSeconds: 60, maxDepth: 2});
  const child = tenuo.narrow(parent, scope(25000), {ttlSeconds: 30, terminal: true});
  assert.equal(child.inspect().depth, 1);
  assert.equal(child.inspect().terminal, true);
  assert.equal(child.inspect().canAuthorize, true);
  assert.deepEqual(child.inspect().tools, ['pay_invoice']);
  assert.equal(tenuo.explain(child, 'pay_invoice', args).outcome, 'allow');
  assert.equal(tenuo.explain(child, 'pay_invoice', {...args, amount_cents: 40000}).outcome, 'deny');
  assert.equal(tenuo.explain(parent, 'pay_invoice', {...args, amount_cents: 40000}).outcome, 'allow');
});

test('holder-approved destination cannot be changed by argument selection', () => {
  const session = tenuo.session({allow: scope(50000), ttlSeconds: 60});
  assert.equal(tenuo.explain(session, 'pay_invoice', {...args, bank_account: 'attacker-bank'}).outcome, 'deny');
});

test('terminal session cannot create another child', () => {
  const parent = tenuo.session({allow: scope(50000), ttlSeconds: 60});
  const child = tenuo.narrow(parent, scope(25000), {terminal: true});
  assert.throws(() => tenuo.narrow(child, scope(10000)), /terminal|depth/i);
});
