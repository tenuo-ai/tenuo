//! Development demonstration only: issuer and holder keys are ephemeral and co-located.
use payment_service_eval::{execute_transfer, issue_transfer, present, PaymentService, Transfer};
use tenuo::SigningKey;
fn main() {
    let issuer = SigningKey::generate();
    let holder = SigningKey::generate();
    let warrant = issue_transfer(&issuer, holder.public_key(), "merchant", 500).unwrap();
    let mut service = PaymentService::new(issuer.public_key());
    println!("Task warrant: payment.transfer(recipient=merchant, amount<=500), TTL<=300s");
    let allowed = Transfer {
        recipient: "merchant".into(),
        amount: 200,
    };
    let authority = present(&[warrant.clone()], &holder, &allowed).unwrap();
    execute_transfer(&mut service, allowed, Some(&authority)).unwrap();
    println!("Allowed amount=200: effect count={}", service.calls().len());
    let before = service.calls().len();
    let denied = Transfer {
        recipient: "merchant".into(),
        amount: 501,
    };
    let authority = present(&[warrant], &holder, &denied).unwrap();
    let result = execute_transfer(&mut service, denied, Some(&authority));
    assert!(result.is_err());
    assert_eq!(service.calls().len(), before);
    println!(
        "Denied amount=501: {result:?}; new effects={}",
        service.calls().len() - before
    );
}
