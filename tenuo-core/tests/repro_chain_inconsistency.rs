use std::time::Duration;
use tenuo_core::{
    crypto::SigningKey,
    warrant::{Warrant, WarrantType, TrustLevel},
    planes::Authorizer,
};

#[test]
fn repro_verify_chain_mixed_types() {
    let issuer_kp = SigningKey::generate();
    let holder_kp = SigningKey::generate();

    // 1. Create an ISSUER warrant (Root)
    // This represents a root of trust that can issue warrants.
    let root_warrant = Warrant::builder()
        .r#type(WarrantType::Issuer)
        .issuable_tools(vec!["read_file".to_string()])
        .trust_ceiling(TrustLevel::System)
        .max_issue_depth(5)
        .ttl(Duration::from_secs(3600))
        .authorized_holder(issuer_kp.public_key())
        .build(&issuer_kp)
        .unwrap();

    // 2. Issue an EXECUTION warrant from the Root
    // The issuer uses their key (issuer_kp) to sign the new warrant.
    let execution_warrant = root_warrant
        .issue_execution_warrant()
        .unwrap()
        .tool("read_file")
        .trust_level(TrustLevel::System) // <= trust_ceiling
        .ttl(Duration::from_secs(600))
        .authorized_holder(holder_kp.public_key())
        .build(&issuer_kp, &issuer_kp) // Signer is the holder of the root warrant
        .unwrap();

    // 3. Verify the chain [root, execution]
    let authorizer = Authorizer::new()
        .with_trusted_root(issuer_kp.public_key());

    let chain = vec![root_warrant, execution_warrant];
    let result = authorizer.verify_chain(&chain);

    // If my hypothesis is correct, this will fail with MonotonicityViolation
    assert!(result.is_ok(), "verify_chain failed: {:?}", result.err());
}
