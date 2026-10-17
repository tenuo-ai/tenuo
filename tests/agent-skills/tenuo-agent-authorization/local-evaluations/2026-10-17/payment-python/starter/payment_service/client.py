class PaymentClient:
    def __init__(self):
        self.calls = []

    def transfer(self, recipient: str, amount: int) -> dict:
        self.calls.append((recipient, amount))
        return {"recipient": recipient, "amount": amount, "status": "sent"}


client = PaymentClient()


def execute_transfer(recipient: str, amount: int) -> dict:
    return client.transfer(recipient, amount)
