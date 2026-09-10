//! Holder runtime: persist identity, bind a warrant, drain receipts.
//!
//! ```text
//! cargo run --example sdk_runtime --features sdk,receipts
//! ```

use std::time::Duration;
use tenuo::sdk::prelude::*;
use tenuo::{args, constraints, EvidencePolicy};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!("tenuo-runtime-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let key_path = dir.join("holder.key");

    let identity = PersistentIdentity::load_or_generate(&key_path)?;
    let restarted = PersistentIdentity::load_or_generate(&key_path)?;
    assert_eq!(identity.public_key(), restarted.public_key());

    let issuer = SigningKey::generate();
    let warrant = Warrant::builder()
        .capability(
            "read_file",
            constraints! { "path" => Pattern::new("/data/*")? },
        )
        .holder(identity.public_key())
        .ttl(Duration::from_secs(300))
        .build(&issuer)?;

    let runtime = Runtime::builder()
        .identity(identity)
        .trusted_roots(vec![issuer.public_key()])
        .evidence_policy(EvidencePolicy::BestEffort)
        .ttl_fallback(Duration::from_secs(600))
        .build()?;

    let empty_srl = tenuo::SignedRevocationList::builder()
        .version(1)
        .build(&issuer)?;
    runtime.apply_signed_revocation_list_now(empty_srl)?;

    let session = runtime.session_from_warrant(warrant)?;
    let allowed = Call::owned("read_file", args! { "path" => "/data/report.csv" })?;
    let result = session.guard(&allowed, |_| Ok::<_, std::io::Error>("read"))?;
    assert_eq!(result.into_inner(), "read");

    let receipts = session.drain_receipts();
    assert_eq!(receipts.len(), 1);
    assert_eq!(session.acknowledge_receipts(1), 1);
    assert!(session.drain_receipts().is_empty());

    println!(
        "runtime session authorized; drained {} receipt",
        receipts.len()
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
