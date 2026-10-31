import { createRequire } from "node:module";
import { describe, expect, it } from "vitest";
import { approvalRequirement, inspectApprovalGate } from "../src/index.ts";

const require = createRequire(import.meta.url);
const wasm = require("../src/generated/tenuo_wasm.js") as {
  create_warrant_from_config: (config: unknown) => {
    warrant_b64: string; error?: string; holder_private_key_hex: string;
  };
};

const mint = (constraint: unknown, approval_gates?: unknown) =>
  wasm.create_warrant_from_config({
    tools: { exec: { command: constraint } }, ttl: 60,
    ...(approval_gates === undefined ? {} : { approval_gates }),
  });

describe("legacy WASM Shlex builder fails closed", () => {
  it("preserves optional messages for whole-tool and per-argument gates", () => {
    for (const args of [null, { command: "all" }]) {
      const result = mint({ shlex: { allow: ["cat"] } }, {
        exec: { args, message: "  Confirm execution  " },
      });
      expect(result.error).toBeFalsy();
      expect(inspectApprovalGate(result.warrant_b64, "exec").message).toBe("Confirm execution");
    }
    for (const message of [true, 123, [], {}]) {
      expect(mint({ shlex: { allow: ["cat"] } }, { exec: { args: null, message } }).error).toBeTruthy();
    }
  });

  it("inherits parent gates and rejects supplied delegation approval policy", () => {
    const parent = wasm.create_warrant_from_config({
      tools: { exec: { command: { shlex: { allow: ["cat"] } } } }, ttl: 600,
      approval_gates: { exec: { args: null, message: "Parent approval" } },
    });
    expect(parent.error).toBeFalsy();
    const config = {
      tools: { exec: { command: { shlex: { allow: ["cat"] } } } }, ttl: 30,
      parent_warrant_b64: parent.warrant_b64, signing_key_hex: parent.holder_private_key_hex,
    };
    const child = wasm.create_warrant_from_config(config);
    expect(child.error).toBeFalsy();
    expect(inspectApprovalGate(child.warrant_b64, "exec")).toMatchObject({
      kind: "whole_tool", message: "Parent approval",
    });
    for (const policy of [
      { approval_gates: { exec: false } },
      { approval_gates: { exec: { args: null } } },
      { required_approvers: [] }, { min_approvals: 1 },
    ]) {
      const result = wasm.create_warrant_from_config({ ...config, ...policy });
      expect(result.error).toBeTruthy();
      expect(result.warrant_b64).toBe("");
    }
  });
  it("rejects malformed allow lists and unsupported options in both forms", () => {
    for (const options of [
      { allow: [] }, { allow: "cat" }, { allow: ["cat", 42] },
      { allow: [""] }, { allow: ["cat"], allowed: ["grep"] },
      { allow: ["cat"], within: "/work" }, { allow: ["cat"], withn: "/work" },
    ]) {
      for (const constraint of [{ shlex: options }, { type: "Shlex", ...options }]) {
        const result = mint(constraint);
        expect(result.error).toBeTruthy();
        expect(result.warrant_b64).toBe("");
      }
    }
    expect(mint({ pattern: "*", shlex: { allow: [42] } }).error).toBeTruthy();
    expect(mint({ type: "Shlex", pattern: "*", allow: ["cat"] }).error).toBeTruthy();
  });

  it("never silently drops a malformed approval gate or nested constraint", () => {
    for (const gates of [
      { exec: false },
      { exec: { args: [] } },
      { safe: { args: null }, exec: { argz: null } },
      { exec: { args: { command: { exempt: { all: [
        { pattern: "*" }, { shlex: { allow: ["cat", 42] } },
      ] } } } } },
      { exec: { args: { command: { exempt: { min: 0, shlex: { allow: [42] } } } } } },
    ]) {
      const result = mint({ shlex: { allow: ["cat"] } }, gates);
      expect(result.error).toBeTruthy();
      expect(result.warrant_b64).toBe("");
    }
  });

  it("preserves valid Shlex approval exemptions for canonical and alias forms", () => {
    for (const constraint of [{ shlex: { allow: ["cat"] } }, { type: "Shlex", allowed: ["cat"] }]) {
      const result = mint(constraint, {
        exec: { args: { command: { exempt: { shlex: { allow: ["cat"] } } } } },
      });
      expect(result.error).toBeFalsy();
      expect(approvalRequirement(result.warrant_b64, "exec", { command: "cat a.txt" }).status).toBe("exempt");
    }
  });
});
