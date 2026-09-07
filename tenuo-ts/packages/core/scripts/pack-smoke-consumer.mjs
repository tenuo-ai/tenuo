import {
  createTenuo,
  range,
  under,
} from "@tenuo/core";

const issuerSecret = createTenuo.generateIssuerKey();
const tenuo = createTenuo({
  root: createTenuo.issuerKeyFromBytes(issuerSecret),
});

const readFile = tenuo.tool(
  { execute: async ({ path }) => path },
  { capability: "read_file", allow: { path: under("/data") } },
);
const pay = tenuo.tool(
  { execute: async ({ amount }) => amount },
  { capability: "pay", allow: { amount: range({ min: 1, max: 100 }) } },
);

const session = tenuo.session({
  tools: [readFile, pay],
  ttlSeconds: 600,
});

const got = await tenuo.withSession(session, () =>
  readFile.execute({ path: "/data/q3.pdf" }),
);
if (got !== "/data/q3.pdf") {
  throw new Error("unexpected execute result: " + got);
}

const paid = await tenuo.withSession(session, () => pay.execute({ amount: 25 }));
if (paid !== 25) {
  throw new Error("unexpected range allow: " + paid);
}

await tenuo.withSession(session, () => pay.execute({ amount: 250 })).then(
  () => {
    throw new Error("range deny must not execute");
  },
  (error) => {
    if (error?.code !== "TENUO_CONSTRAINT_VIOLATION") {
      throw new Error("unexpected range deny: " + error);
    }
  },
);

const explained = tenuo.explain(session, "read_file", { path: "/data/q3.pdf" });
if (explained.outcome !== "allow") {
  throw new Error("unexpected explain: " + JSON.stringify(explained));
}

const workerKey = createTenuo.generateHolderKey();
const issued = tenuo.session({
  allow: { read_file: { path: under("/data") } },
  holder: createTenuo.publicKeyFromHolderKey(workerKey),
});
if (issued.inspect().canAuthorize !== false) {
  throw new Error("issued session must be wire-only");
}
if (tenuo.explain(issued, "read_file", { path: "/data/q3.pdf" }).outcome !== "allow") {
  throw new Error("explain on a wire-only session must still decide");
}

const worker = createTenuo({ trustedRoots: [tenuo.issuerPublicKey()] });
const mine = worker.sessionFromWire({
  warrant: issued.toWire(),
  holderKey: workerKey,
});
const presented = worker.present(mine, "read_file", { path: "/data/q3.pdf" });
const verified = await tenuo.verify(presented, "read_file", { path: "/data/q3.pdf" }, {
  allow: { path: under("/data") },
});
if (verified.path !== "/data/q3.pdf") {
  throw new Error("unexpected present/verify: " + JSON.stringify(verified));
}

const orchestratorKey = createTenuo.generateHolderKey();
const issuerHanded = tenuo.session({
  kind: "issuer",
  issuableTools: ["read_file"],
  constraintBounds: { path: under("/data") },
  holder: createTenuo.publicKeyFromHolderKey(orchestratorKey),
  ttlSeconds: 600,
});
const orchestrator = createTenuo({ trustedRoots: [tenuo.issuerPublicKey()] });
const issuer = orchestrator.sessionFromWire({
  warrant: issuerHanded.toWire(),
  holderKey: orchestratorKey,
});
const childKey = createTenuo.generateHolderKey();
const child = orchestrator.issue(issuer, {
  allow: { read_file: { path: under("/data/reports") } },
  holder: createTenuo.publicKeyFromHolderKey(childKey),
  ttlSeconds: 60,
});
const childSession = worker.sessionFromWire({
  warrant: child.toWire(),
  holderKey: childKey,
});
const childRead = worker.tool(
  { execute: async ({ path }) => path },
  { capability: "read_file", allow: {} },
);
const report = await childRead.execute({ path: "/data/reports/q3.pdf" }, { session: childSession });
if (report !== "/data/reports/q3.pdf") {
  throw new Error("unexpected issued execute: " + report);
}

const receipts = [];
await readFile.execute(
  { path: "/data/q3.pdf" },
  { session, requestId: "smoke-1", onReceipt: (receipt) => receipts.push(receipt) },
);
if (receipts.length !== 1) {
  throw new Error("expected one receipt");
}
const receipt = createTenuo.verifyReceipt(receipts[0]);
if (receipt.outcome !== "allow" || receipt.authentic !== true || receipt.requestId !== "smoke-1") {
  throw new Error("unexpected receipt: " + JSON.stringify(receipt));
}

const call = tenuo.mcp.attach(session, "read_file", { path: "/data/q3.pdf" });
const mcpVerified = await tenuo.mcp.verify(call.name, call.arguments, call._meta, {
  allow: { path: under("/data") },
});
if (mcpVerified.path !== "/data/q3.pdf") {
  throw new Error("unexpected mcp verify: " + JSON.stringify(mcpVerified));
}

console.log("pack smoke ok");
