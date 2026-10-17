from payment_service import PaymentClient, client, execute_transfer


def test_application_transfer():
    client.calls.clear()
    assert execute_transfer("merchant", 200)["status"] == "sent"
    assert client.calls == [("merchant", 200)]


def test_payment_client():
    raw = PaymentClient()
    raw.transfer("merchant", 200)
    assert raw.calls == [("merchant", 200)]
