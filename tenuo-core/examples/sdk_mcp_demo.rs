//! Section 16 validation target: holder-sign → `_meta.tenuo` → received-verify.
//!
//! This is the MCP hop without embedding an MCP SDK. Protocol handling stays
//! in the caller's library; Tenuo only encodes and verifies.
//!
//! ```text
//! cargo run --example sdk_mcp_demo --features sdk,mcp-transport
//! ```

use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use tenuo::approval_gate::{encode_approval_gate_map, ApprovalGateMap, ToolApprovalGate};
use tenuo::args;
use tenuo::sdk::prelude::*;
use tenuo::sdk::transport::mcp_meta::{decode_meta, encode_meta_from_authorized, strip_tenuo};

fn main() {
    println!("Tenuo SDK — MCP hop demo\n");

    let issuer = SigningKey::generate();
    let holder = SigningKey::generate();
    let approver = SigningKey::generate();

    let (client, authority) = Tenuo::local()
        .trusted_root(issuer.public_key())
        .chain(vec![mint_read(&issuer, &holder)])
        .signer(holder.clone())
        .revocation(RevocationMode::TtlOnly {
            max_lifetime: Duration::from_secs(3600),
        })
        .build()
        .expect("client");

    let server = Tenuo::enforcement()
        .trusted_root(issuer.public_key())
        .revocation(RevocationMode::TtlOnly {
            max_lifetime: Duration::from_secs(3600),
        })
        .build()
        .expect("server");

    hop_allow(&client, &authority, &server);
    hop_constraint_deny(&client, &authority);
    hop_missing_meta(&server);
    hop_approval_retry(&issuer, &holder, &approver, &server);

    println!("done. ObservingGuard is assessment, not enforcement.");
}

fn mint_read(issuer: &SigningKey, holder: &SigningKey) -> Warrant {
    let mut constraints = ConstraintSet::new();
    constraints.insert("path", Pattern::new("/data/*").unwrap());
    Warrant::builder()
        .capability("read_file", constraints)
        .holder(holder.public_key())
        .ttl(Duration::from_secs(300))
        .build(issuer)
        .expect("mint read_file")
}

fn mint_sensitive(issuer: &SigningKey, holder: &SigningKey, approver: &SigningKey) -> Warrant {
    let mut gates = ApprovalGateMap::new();
    gates.insert("export_report".into(), ToolApprovalGate::whole_tool());
    Warrant::builder()
        .capability("export_report", ConstraintSet::new())
        .holder(holder.public_key())
        .ttl(Duration::from_secs(300))
        .required_approvers(vec![approver.public_key()])
        .min_approvals(1)
        .extension(
            "tenuo.approval_gates",
            encode_approval_gate_map(&gates).unwrap(),
        )
        .build(issuer)
        .expect("mint export_report")
}

fn hop_allow(client: &Guard, authority: &PresentedAuthority, server: &Guard) {
    println!("1. holder-sign → encode _meta → server guard_received");
    let args = args! { "path" => "/data/report.txt" };
    let call = Call::borrowed("read_file", &args);
    let envelope = client
        .guard(authority, &call, |authorized| {
            let tenuo_meta = encode_meta_from_authorized(authorized).expect("encode");
            Ok::<_, &str>(json!({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "name": "read_file",
                    "arguments": { "path": "/data/report.txt" },
                    "_meta": { "tenuo": tenuo_meta }
                }
            }))
        })
        .expect("client allow");

    let mut meta = envelope.value["params"]["_meta"].clone();
    let owned = decode_meta(&meta["tenuo"]).expect("decode");
    strip_tenuo(&mut meta);
    assert!(
        meta.get("tenuo").is_none(),
        "tenuo key stripped after decode"
    );

    let received = owned.as_received().expect("received");
    let projection = VerifiedProjection::identical(args);
    let inbound = Call::from_transport("read_file", &projection);
    let _allowed = server
        .guard_received(&received, &inbound, |_| {
            println!("   server allowed read_file path=/data/report.txt");
            Ok::<_, &str>(())
        })
        .expect("server allow");
}

fn hop_constraint_deny(client: &Guard, authority: &PresentedAuthority) {
    println!("2. constraint deny (client never encodes a forged allow)");
    let args = args! { "path" => "/etc/passwd" };
    let call = Call::borrowed("read_file", &args);
    match client.guard(authority, &call, |_| Ok::<_, &str>(())) {
        Err(GuardError::Denied(denial)) => {
            println!("   denied [{}] — operation did not run", denial.code());
        }
        Ok(_) => panic!("expected constraint deny"),
        Err(GuardError::Operation(_)) => panic!("operation must not run"),
    }
}

fn hop_missing_meta(server: &Guard) {
    println!("3. missing _meta is an observe finding, and still runs");
    let args = args! { "path" => "/data/report.txt" };
    let call = Call::borrowed("read_file", &args);
    let observed = server
        .observe_until(chrono::Utc::now() + chrono::Duration::hours(1))
        .observe(PresentedRequest::Missing, &call, || {
            println!("   tool ran under observe (would-deny: no authority)");
            Ok::<_, &str>(())
        })
        .expect("observe");
    println!(
        "   outcome=would-deny-no-authority observe_only={}",
        observed.observation.is_observe_only()
    );
}

fn hop_approval_retry(
    issuer: &SigningKey,
    holder: &SigningKey,
    approver: &SigningKey,
    server: &Guard,
) {
    println!("4. approval required → resolve_approvals → retry → server verifies");
    let mut authorizer = tenuo::Authorizer::new();
    authorizer.add_trusted_root(issuer.public_key());
    let provider: Arc<dyn ApprovalProvider> =
        Arc::new(LocalApprovalSigner::new(approver.clone(), "approver@local"));
    let client = Guard::builder()
        .authorizer(authorizer)
        .revocation(RevocationMode::TtlOnly {
            max_lifetime: Duration::from_secs(3600),
        })
        .approval_provider(provider)
        .build()
        .expect("gated client");
    let authority = PresentedAuthority::new(
        vec![mint_sensitive(issuer, holder, approver)],
        Arc::new(LocalSigner::new(holder.clone())),
    )
    .expect("authority");
    let args = args! {};
    let call = Call::borrowed("export_report", &args);

    let first = client.guard(&authority, &call, |_| Ok::<_, &str>(()));
    let request = match first {
        Err(GuardError::Denied(denial)) if denial.needs_approval() => {
            println!("   first attempt: {}", denial.code());
            denial.approval_request().cloned().expect("core request")
        }
        Err(GuardError::Denied(denial)) => {
            panic!("expected approval-required, got {}", denial.code())
        }
        Ok(_) => panic!("expected approval-required"),
        Err(GuardError::Operation(_)) => panic!("operation must not run"),
    };

    let approvals = client.resolve_approvals(&request).expect("provider");
    let attempt = AuthorizationAttempt::with_approvals(&call, &approvals);
    let envelope = client
        .guard_attempt(&authority, attempt, |authorized| {
            encode_meta_from_authorized(authorized).map_err(|_| "encode")
        })
        .expect("retry allow");

    let owned = decode_meta(&envelope.value).expect("decode approvals");
    let received = owned.as_received().expect("received");
    let projection = VerifiedProjection::identical(args);
    let inbound = Call::from_transport("export_report", &projection);
    let _approved = server
        .guard_received(&received, &inbound, |_| {
            println!("   server allowed export_report with carried approvals");
            Ok::<_, &str>(())
        })
        .expect("server approval hop");
}
