//! `HeartbeatConfig` must stay constructible with a struct literal from
//! outside the crate, using exactly the fields it had in 0.3.2.
//!
//! Adding a public field breaks every downstream literal that lists all
//! fields, which a patch release must not do. If this test stops compiling,
//! pass the new value to the loop as an argument (as
//! `start_heartbeat_loop_with_status` does) instead of adding a field.

#![cfg(feature = "server")]

use std::sync::Arc;

use tenuo::crypto::SigningKey;
use tenuo::heartbeat::{
    start_heartbeat_loop_with_status, ConnectionState, ControlPlaneStatus, EnvironmentInfo,
    HeartbeatConfig,
};
use tokio::sync::RwLock;

fn config_with_0_3_2_fields(control_plane_url: String) -> HeartbeatConfig {
    HeartbeatConfig {
        control_plane_url,
        api_key: "tc_test".to_string(),
        authorizer_name: "compat".to_string(),
        authorizer_type: "sidecar".to_string(),
        version: "0.3.2".to_string(),
        interval_secs: 30,
        authorizer: None,
        trusted_root: None,
        audit_batch_size: 100,
        audit_flush_interval_secs: 10,
        environment: EnvironmentInfo::default(),
        metrics: None,
        signing_key: SigningKey::generate(),
        id_notify: None,
        agent_id: None,
        connect_token: None,
        revocation_tracker: None,
    }
}

#[tokio::test]
async fn status_is_reported_through_the_loop_argument() {
    // Nothing listens here, so registration fails and the loop stops when
    // told to; the caller's status handle must see that.
    let config = config_with_0_3_2_fields("http://127.0.0.1:9".to_string());
    let status: Arc<ControlPlaneStatus> = Arc::default();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(start_heartbeat_loop_with_status(
        config,
        None,
        Arc::new(RwLock::new(None)),
        Some(stop_rx),
        status.clone(),
    ));
    let _ = stop_tx.send(());
    tokio::time::timeout(std::time::Duration::from_secs(30), task)
        .await
        .expect("heartbeat loop did not stop")
        .unwrap();
    assert_eq!(status.state(), ConnectionState::Stopped);
}
