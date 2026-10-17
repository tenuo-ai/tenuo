import {afterEach, describe, expect, it, vi} from 'vitest';
import {createRequire} from 'node:module';
import {createPrivateKey, sign, verify, createPublicKey} from 'node:crypto';
import {createTenuo, exact, range, type Session, type PresentedCall} from '@tenuo/core';
import {createPaymentService} from './payment.js';

// Test-only low-level signer bypasses present()'s local authorization preflight.
const wasm = createRequire(import.meta.url)('../node_modules/@tenuo/core/dist/generated/tenuo_wasm.js');
const args = {recipient: 'merchant', amount: 200};
function setup() {
  const issuer = createTenuo({root: createTenuo.issuerKeyFromBytes(createTenuo.generateIssuerKey())});
  const holderKey = createTenuo.generateHolderKey();
  const caller = createTenuo({trustedRoots: [issuer.issuerPublicKey()]});
  const issued = issuer.session({allow: {'payment.transfer': {recipient: exact('merchant'), amount: range({min: 1, max: 300})}}, holder: createTenuo.publicKeyFromHolderKey(holderKey), ttlSeconds: 120, maxDepth: 2});
  const session = caller.sessionFromWire({warrant: issued.toWire(), holderKey});
  return {issuer, holderKey, caller, session, service: createPaymentService(issuer.issuerPublicKey())};
}
function rawProof(session: Session, holderKey: Uint8Array, values = args, tool = 'payment.transfer'): PresentedCall {
  const context = wasm.SdkContext.fromTrustedRoots([createTenuo.publicKeyFromHolderKey(holderKey).hex]);
  const raw = wasm.SdkSession.fromChain(session.toWire(), holderKey);
  try { return context.signMeta(raw, tool, JSON.stringify(values), Math.floor(Date.now()/1000), null); }
  finally {raw.free(); context.free();}
}
async function denied(service: ReturnType<typeof createPaymentService>, proof: PresentedCall | undefined, code: string, values = args) {
  await expect(service.executeTransfer(values.recipient, values.amount, proof)).rejects.toMatchObject(code === 'Missing authority' ? {message: code} : {code});
  expect(service.calls).toHaveLength(0);
}
afterEach(() => {vi.useRealTimers(); vi.restoreAllMocks();});

it('application issuer → holder → public presentation → independently configured verifier → one effect', async () => {
  const f = setup();
  const proof = f.caller.present(f.session, 'payment.transfer', args);
  expect(Object.keys(proof).sort()).toEqual(['signature', 'warrant']);
  expect(await f.service.executeTransfer(args.recipient, args.amount, JSON.parse(JSON.stringify(proof)))).toEqual({...args, status: 'sent'});
  expect(f.service.calls).toEqual([args]);
});
it('missing authority: zero effects', async () => {const f = setup(); await denied(f.service, undefined, 'Missing authority');});
it('untrusted issuer: zero effects', async () => {const f = setup(), other = setup(); await denied(f.service, rawProof(other.session, other.holderKey), 'TENUO_UNTRUSTED_ROOT');});
it('wrong holder proof: zero effects', async () => {
  const f = setup(), other = setup();
  // A valid proof from another holder is presented beside the victim warrant.
  const victim = rawProof(f.session, f.holderKey), attacker = rawProof(other.session, other.holderKey);
  await denied(f.service, {...victim, signature: attacker.signature}, 'TENUO_INVALID_POP');
});
it('expired warrant with fresh holder proof: zero effects', async () => {
  const f = setup(); vi.useFakeTimers(); vi.setSystemTime((f.session.inspect().expiresAt + 10)*1000);
  await denied(f.service, rawProof(f.session, f.holderKey), 'TENUO_WARRANT_EXPIRED');
});
it('wrong capability: zero effects', async () => {
  const f = setup();
  const wrong = f.issuer.session({allow: {'payment.refund': {recipient: exact('merchant'), amount: range({max: 300})}}, holder: createTenuo.publicKeyFromHolderKey(f.holderKey), ttlSeconds: 120});
  await denied(f.service, rawProof(wrong, f.holderKey), 'TENUO_TOOL_NOT_AUTHORIZED');
});
it.each([{recipient:'attacker',amount:200}, {recipient:'merchant',amount:301}])('warrant constraint denial for %j: zero effects', async values => {
  const f = setup(); await denied(f.service, rawProof(f.session, f.holderKey, values), 'TENUO_CONSTRAINT_VIOLATION', values);
});
it('host ceiling independently caps a broader trusted warrant', async () => {
  const f = setup(); const broad = f.issuer.session({allow: {'payment.transfer': {recipient: exact('attacker'), amount: range({max: 999})}}, holder: createTenuo.publicKeyFromHolderKey(f.holderKey), ttlSeconds: 120});
  const values = {recipient:'attacker', amount:600};
  await denied(f.service, rawProof(broad,f.holderKey,values), 'TENUO_CONSTRAINT_VIOLATION', values);
});
it.each([0,-1,1.5,NaN,Infinity,Number.MAX_SAFE_INTEGER+1])('rejects non-domain amount %s before effect', async amount => {
  const f=setup(); await expect(f.service.executeTransfer('merchant',amount,rawProof(f.session,f.holderKey))).rejects.toThrow('Invalid transfer arguments'); expect(f.service.calls).toHaveLength(0);
});

// Test-only wire mutation keeps every field except amount.max unchanged, then
// uses the legitimate parent holder to sign the malicious child. This is not
// a broken-signature fixture and never enters application request data as a key.
function widenChild(token: string, parentKey: Uint8Array, parentPublic: string): string {
  const wire=Buffer.from(token,'base64url');
  const start=wire[2]===0x58?4:5, length=start===4?wire[3]:wire.readUInt16BE(3);
  const payload=wire.subarray(start,start+length);
  const old=Buffer.from('636d6178f95a40','hex'); // CBOR "max", half-float 200
  const offset=payload.indexOf(old); expect(offset).toBeGreaterThanOrEqual(0);
  payload.writeUInt16BE(0x5e40,offset+5); // 400, same CBOR width
  const message=Buffer.concat([Buffer.from('tenuo-warrant-v1'),Buffer.from([1]),payload]);
  const key=createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),Buffer.from(parentKey)]),format:'der',type:'pkcs8'});
  const signature=sign(null,message,key); signature.copy(wire,wire.length-64);
  const publicKey=createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(parentPublic,'hex')]),format:'der',type:'spki'});
  expect(verify(null,message,publicKey,signature)).toBe(true);
  return wire.toString('base64url');
}
it('narrow child succeeds with root-only trust; wider signed child and omitted chain produce zero effects', async () => {
  const f=setup(), childKey=createTenuo.generateHolderKey();
  const child=f.caller.narrow(f.session,{amount:range({min:1,max:200}),recipient:exact('merchant')},{holder:createTenuo.publicKeyFromHolderKey(childKey),ttlSeconds:60,terminal:true});
  const childSession=f.caller.sessionFromWire({warrant:child.toWire(),holderKey:childKey});
  const proof=rawProof(childSession,childKey);
  await f.service.executeTransfer('merchant',200,proof); expect(f.service.calls).toEqual([args]);
  const chain=child.toWire();
  const wider=widenChild(chain[1],f.holderKey,createTenuo.publicKeyFromHolderKey(f.holderKey).hex);
  // Construct transport without calling a local authorizer or import verifier.
  const stack=Buffer.from(proof.warrant,'base64url'); const original=Buffer.from(chain[1],'base64url');
  const offset=stack.indexOf(original); expect(offset).toBeGreaterThanOrEqual(0);
  Buffer.from(wider,'base64url').copy(stack,offset);
  const forgedProof={...proof,warrant:stack.toString('base64url')};
  await expect(createPaymentService(f.issuer.issuerPublicKey()).executeTransfer('merchant',200,forgedProof)).rejects.toThrow(/range expanded.*400.*300/);
  await denied(createPaymentService(f.issuer.issuerPublicKey()),forgedProof,'TENUO_TOOL_NOT_AUTHORIZED');
  const context=wasm.SdkContext.fromTrustedRoots([f.issuer.issuerPublicKey().hex]), leaf=wasm.SdkSession.fromWire(chain[1],childKey);
  const noChain=context.signMeta(leaf,'payment.transfer',JSON.stringify(args),Math.floor(Date.now()/1000),null);
  leaf.free();context.free();
  await denied(createPaymentService(f.issuer.issuerPublicKey()),noChain,'TENUO_UNTRUSTED_ROOT');
  expect(() => f.caller.narrow(f.session,{amount:range({max:400})},{holder:createTenuo.publicKeyFromHolderKey(childKey)})).toThrow(/range expanded|parent|attenuat/i);
});
it('original defining module cannot construct or invoke the raw payment client', async () => {
  const original=await import('./payment.js');
  expect(Reflect.get(original,'PaymentClient')).toBeUndefined(); expect(Reflect.get(original,'client')).toBeUndefined();
  expect(() => Reflect.construct(Reflect.get(original,'PaymentClient'),[])).toThrow(TypeError);
  expect(() => Reflect.get(original,'client').transfer('merchant',200)).toThrow(TypeError);
  expect(() => Reflect.get(original,'executeTransfer')('merchant',200)).toThrow(TypeError);
  const f=setup(); expect(f.service.calls).toEqual([]);
  // @ts-expect-error Original raw client no longer exists at its defining module.
  const removed: typeof import('./payment.js').PaymentClient = undefined;
  void removed;
});
