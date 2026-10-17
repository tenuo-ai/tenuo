import {createTenuo, exact, range, type PresentedCall, type PublicKeyHandle} from '@tenuo/core';

export type Transfer = Readonly<{recipient: string; amount: number}>;
export type TransferResult = Transfer & {readonly status: 'sent'};

/** Trusted service construction. Pass only independently provisioned issuer public keys. */
export function createPaymentService(issuer: PublicKeyHandle) {
  // Copy the root so later mutation of configuration cannot alter trust.
  const verifier = createTenuo({trustedRoots: [createTenuo.publicKeyFromHex(issuer.hex)]});
  const records: Transfer[] = [];
  return Object.freeze({
    get calls(): readonly Transfer[] { return records.map(call => Object.freeze({...call})); },
    async executeTransfer(recipient: string, amount: number, authority?: PresentedCall): Promise<TransferResult> {
      if (!authority) throw new Error('Missing authority');
      // Amounts are integer minor currency units; no rounding, coercion, or unit conversion.
      if (typeof recipient !== 'string' || !Number.isSafeInteger(amount) || amount <= 0) {
        throw new Error('Invalid transfer arguments');
      }
      const authorized = await verifier.verify(authority, 'payment.transfer', {recipient, amount}, {
        allow: {recipient: exact('merchant'), amount: range({min: 1, max: 500})},
      });
      // Execute precisely the verifier's snapshot, never the original mutable input.
      const transfer = Object.freeze({recipient: authorized.recipient as string, amount: authorized.amount as number});
      records.push(transfer); // Isolated fake effect; no payment network or credentials.
      return {...transfer, status: 'sent'};
    },
  });
}
