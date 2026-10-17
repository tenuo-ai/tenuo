export class PaymentClient {
  readonly calls: Array<{recipient: string; amount: number}> = [];
  transfer(recipient: string, amount: number) {
    this.calls.push({recipient, amount});
    return {recipient, amount, status: "sent"};
  }
}
export const client = new PaymentClient();
export function executeTransfer(recipient: string, amount: number) {
  return client.transfer(recipient, amount);
}
