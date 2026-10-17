import {it, expect} from 'vitest';
import {createRequire} from 'node:module';
import {createTenuo,exact,range} from '@tenuo/core';
import {createPaymentService} from '../src/payment.js';
const wasm=createRequire(import.meta.url)('../node_modules/@tenuo/core/dist/generated/tenuo_wasm.js');
function flow(){
 const issuer=createTenuo({root:createTenuo.issuerKeyFromBytes(createTenuo.generateIssuerKey())});
 const holder=createTenuo.generateHolderKey();
 const session=issuer.session({allow:{'payment.transfer':{recipient:exact('merchant'),amount:range({min:1,max:400})}},holder:createTenuo.publicKeyFromHolderKey(holder),ttlSeconds:60});
 const raw=wasm.SdkSession.fromChain(session.toWire(),holder);
 const context=wasm.SdkContext.fromTrustedRoots([issuer.issuerPublicKey().hex]);
 const sign=(recipient:string,amount:number)=>context.signMeta(raw,'payment.transfer',JSON.stringify({recipient,amount}),Math.floor(Date.now()/1000),null);
 return {issuer,service:createPaymentService(issuer.issuerPublicKey()),sign};
}
it('independent allow after receiver denials',async()=>{
 const f=flow();
 for(const [recipient,amount] of [['other-vendor',381],['merchant',401]] as const){
  await expect(f.service.executeTransfer(recipient,amount,f.sign(recipient,amount))).rejects.toMatchObject({code:'TENUO_CONSTRAINT_VIOLATION'});
  expect(f.service.calls).toEqual([]);
 }
 const proof=f.sign('merchant',381);
 await expect(f.service.executeTransfer('merchant',380,proof)).rejects.toMatchObject({code:'TENUO_INVALID_POP'});
 expect(f.service.calls).toEqual([]);
 await f.service.executeTransfer('merchant',381,proof);
 expect(f.service.calls).toEqual([{recipient:'merchant',amount:381}]);
});
it('original exports are inaccessible at defining module',async()=>{
 const m=await import('../src/payment.js');
 for(const name of ['PaymentClient','client','executeTransfer']) expect(Reflect.get(m,name)).toBeUndefined();
});
it('returned record cannot mutate protected effect state',async()=>{
 const f=flow();
 await f.service.executeTransfer('merchant',381,f.sign('merchant',381));
 const snapshot=f.service.calls as Array<{recipient:string,amount:number}>;
 expect(()=>snapshot[0].amount=999).toThrow();
 snapshot.length=0;
 expect(f.service.calls).toEqual([{recipient:'merchant',amount:381}]);
});

it('wrong key signs the exact victim challenge and reaches receiver',async()=>{
 const {createPrivateKey,createPublicKey,sign,verify}=await import('node:crypto');
 const issuer=createTenuo({root:createTenuo.issuerKeyFromBytes(createTenuo.generateIssuerKey())});
 const holder=createTenuo.generateHolderKey(), wrong=createTenuo.generateHolderKey();
 const session=issuer.session({allow:{'payment.transfer':{recipient:exact('merchant'),amount:range({max:400})}},holder:createTenuo.publicKeyFromHolderKey(holder),ttlSeconds:60});
 const raw=wasm.SdkSession.fromChain(session.toWire(),holder);
 const context=wasm.SdkContext.fromTrustedRoots([issuer.issuerPublicKey().hex]);
 const now=Math.floor(Date.now()/1000), values={recipient:'merchant',amount:200};
 const good=context.signMeta(raw,'payment.transfer',JSON.stringify(values),now,null);
 const uint=(major:number,n:number):Buffer=>{
  if(n<24)return Buffer.from([(major<<5)|n]);
  if(n<256)return Buffer.from([(major<<5)|24,n]);
  const b=Buffer.alloc(5);b[0]=(major<<5)|26;b.writeUInt32BE(n,1);return b;
 };
 const cbor=(x:unknown):Buffer=>{
  if(typeof x==='string'){const b=Buffer.from(x);return Buffer.concat([uint(3,b.length),b]);}
  if(typeof x==='number')return uint(0,x);
  if(Array.isArray(x))return Buffer.concat([uint(4,x.length),...x.map(cbor)]);
  throw new Error('unsupported test-only CBOR value');
 };
 const id=session.inspect().warrantIds[0].replace('tnu_wrt_','');
 const message=Buffer.concat([Buffer.from('tenuo-warrant-v1tenuo-pop-v1'),cbor([id,'payment.transfer',[['amount',200],['recipient','merchant']],Math.floor(now/30)*30])]);
 const pk=createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(createTenuo.publicKeyFromHolderKey(holder).hex,'hex')]),format:'der',type:'spki'});
 expect(verify(null,message,pk,Buffer.from(good.signature,'base64url'))).toBe(true);
 const wrongPk=createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),Buffer.from(wrong)]),format:'der',type:'pkcs8'});
 const proof={...good,signature:sign(null,message,wrongPk).toString('base64url')};
 const service=createPaymentService(issuer.issuerPublicKey());
 await expect(service.executeTransfer('merchant',200,proof)).rejects.toMatchObject({code:'TENUO_INVALID_POP'});
 expect(service.calls).toEqual([]);
});
