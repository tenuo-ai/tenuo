import {it, expect} from "vitest";
import {PaymentClient, client, executeTransfer} from "./payment.js";
it("application transfer", () => {
  client.calls.length = 0;
  expect(executeTransfer("merchant", 200).status).toBe("sent");
  expect(client.calls).toEqual([{recipient: "merchant", amount: 200}]);
});
it("raw client", () => {
  const raw = new PaymentClient();
  raw.transfer("merchant", 200);
  expect(raw.calls).toHaveLength(1);
});
