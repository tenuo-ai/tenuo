use payment_service_eval::{
    execute_transfer, issue_transfer, present, PaymentService, Presentation, Transfer,
};
use tenuo::{SigningKey, Warrant};
fn raw(chain: &[Warrant], holder: &SigningKey, request: &Transfer) -> Presentation {
    use tenuo::args;
    let values =
        args! {"recipient" => request.recipient.clone(), "amount" => request.amount as i64};
    Presentation {
        chain: chain
            .iter()
            .map(|w| tenuo::wire::encode(w).unwrap())
            .collect(),
        proof: chain
            .last()
            .unwrap()
            .sign(holder, "payment.transfer", &values)
            .unwrap(),
    }
}
#[test]
fn independent_receiving_boundary() {
    let issuer = SigningKey::generate();
    let holder = SigningKey::generate();
    let warrant = issue_transfer(&issuer, holder.public_key(), "independent-vendor", 725).unwrap();
    let mut service = PaymentService::new(issuer.public_key());
    for (recipient, amount) in [("other-vendor", 724), ("independent-vendor", 726)] {
        let request = Transfer {
            recipient: recipient.into(),
            amount,
        };
        let proof = raw(&[warrant.clone()], &holder, &request);
        assert!(execute_transfer(&mut service, request, Some(&proof)).is_err());
        assert!(service.calls().is_empty());
    }
    let request = Transfer {
        recipient: "independent-vendor".into(),
        amount: 724,
    };
    let proof = present(&[warrant.clone()], &holder, &request).unwrap();
    let changed = Transfer {
        amount: 723,
        ..request.clone()
    };
    assert!(service.transfer(changed, Some(&proof)).is_err());
    assert!(service.calls().is_empty());
    service.transfer(request.clone(), Some(&proof)).unwrap();
    assert_eq!(service.calls(), &[("independent-vendor".to_owned(), 724)]);
    let mut other = PaymentService::new(SigningKey::generate().public_key());
    assert!(other.transfer(request, Some(&proof)).is_err());
    assert!(other.calls().is_empty());
}
