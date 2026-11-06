//! Bind an MCP Tasks (SEP-2663) task to the warrant that created it.
//!
//! A server may answer `tools/call` with a task handle and serve the rest of
//! the work through `tasks/get`, `tasks/update` and `tasks/cancel`. The
//! extension leaves authorization of those calls to each server. Here the
//! answer is the warrant that authorized the creating call.
//!
//! [`TaskBinding::for_created_task`] records the task id, the creating
//! warrant id and its holder. [`verify_task_request`] then admits a `tasks/*`
//! request only when its `_meta.tenuo` envelope:
//!
//! - carries a warrant chain the authorizer accepts (trust, expiry,
//!   revocation) that contains the creating warrant, with the same holder;
//! - proves possession over the method name and the request params without
//!   `_meta`, so `taskId` and `inputResponses` are covered.
//!
//! An unknown task and a task bound elsewhere fail the same way, so a caller
//! cannot probe which ids exist. Replay detection and binding storage stay
//! with the SDK: [`TaskAccess::signature`] is the nonce to record.

use std::fmt;

use crate::constraints::ConstraintValue;
use crate::crypto::{PublicKey, Signature};
use crate::error::Error;
use crate::meta_envelope::{args_from_json, decode_meta_parts, MetaError};
use crate::planes::Authorizer;
use crate::warrant::{Warrant, POP_TIMESTAMP_WINDOW_SECS};

/// SEP-2663 request methods that address an existing task by `taskId`.
pub const TASK_METHODS: [&str; 3] = ["tasks/get", "tasks/update", "tasks/cancel"];

/// The authority a task was created under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskBinding {
    pub task_id: String,
    /// Display form of the creating warrant's id.
    pub warrant_id: String,
    /// The creating warrant's authorized holder.
    pub holder: PublicKey,
    /// Unix seconds. The creating warrant expires here, so the binding can
    /// never match afterwards and stores may drop it.
    pub expires_at: i64,
}

impl TaskBinding {
    /// Binding for a task created under `leaf`, the last warrant of the
    /// chain that authorized the creating `tools/call`.
    pub fn for_created_task(task_id: impl Into<String>, leaf: &Warrant) -> Self {
        Self {
            task_id: task_id.into(),
            warrant_id: leaf.id().to_string(),
            holder: leaf.authorized_holder().clone(),
            expires_at: leaf.expires_at().timestamp(),
        }
    }
}

/// An admitted task request.
#[derive(Debug, Clone)]
pub struct TaskAccess {
    pub task_id: String,
    /// Display form of the presented leaf warrant's id.
    pub warrant_id: String,
    /// The holder proof. Record it in a nonce store to reject replays.
    pub signature: Signature,
}

/// Why a task request was not admitted.
#[derive(Debug)]
pub enum TaskAccessError {
    /// The method is not one of [`TASK_METHODS`].
    InvalidMethod,
    /// The signed params have no string `taskId`.
    MissingTaskId,
    /// The envelope or params could not be read.
    Envelope(MetaError),
    /// The authorizer rejected the warrant chain.
    Warrant(Error),
    /// The proof does not cover this method and these params.
    InvalidPop,
    /// No binding, or the binding names another warrant or holder.
    NotAccessible,
}

impl fmt::Display for TaskAccessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMethod => write!(f, "not a task method"),
            Self::MissingTaskId => write!(f, "task request is missing taskId"),
            Self::Envelope(err) => write!(f, "{err}"),
            Self::Warrant(err) => write!(f, "{err}"),
            Self::InvalidPop => write!(
                f,
                "PoP does not cover this task request; sign the method name and the \
                 request params without _meta with the warrant holder's key"
            ),
            Self::NotAccessible => write!(f, "task is not accessible with this warrant"),
        }
    }
}

impl std::error::Error for TaskAccessError {}

impl TaskAccessError {
    /// Stable transport category, matching [`MetaError::code`] where they overlap.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidMethod => "invalid_method",
            Self::MissingTaskId => "invalid_arguments",
            Self::Envelope(err) => err.code(),
            Self::Warrant(_) => "invalid_warrant",
            Self::InvalidPop => "invalid_pop",
            Self::NotAccessible => "task_not_accessible",
        }
    }

    /// JSON-RPC error code for the denial.
    pub fn jsonrpc_code(&self) -> i64 {
        match self {
            Self::InvalidMethod => -32601,
            Self::MissingTaskId => -32602,
            Self::Envelope(MetaError::PayloadTooLarge | MetaError::InvalidArguments(_)) => -32602,
            _ => -32001,
        }
    }
}

/// Admit or deny a `tasks/*` request.
///
/// `params_json` is the request params without `_meta`. `warrant` and
/// `signature` are the `_meta.tenuo` fields. `binding` is what the server
/// stored for the `taskId` in `params_json`, if anything. `now` is unix
/// seconds.
///
/// Checks run in order: method, envelope, warrant chain, proof, binding.
/// Replay is the caller's: record [`TaskAccess::signature`].
pub fn verify_task_request(
    authorizer: &Authorizer,
    method: &str,
    params_json: &str,
    warrant: &str,
    signature: &str,
    binding: Option<&TaskBinding>,
    now: i64,
) -> Result<TaskAccess, TaskAccessError> {
    if !TASK_METHODS.contains(&method) {
        return Err(TaskAccessError::InvalidMethod);
    }
    let decoded = decode_meta_parts(warrant, signature, &[]).map_err(TaskAccessError::Envelope)?;
    let params = args_from_json(params_json).map_err(TaskAccessError::Envelope)?;
    let task_id = match params.get("taskId") {
        Some(ConstraintValue::String(id)) if !id.is_empty() => id.clone(),
        _ => return Err(TaskAccessError::MissingTaskId),
    };
    let leaf = decoded
        .warrants
        .last()
        .ok_or(TaskAccessError::Envelope(MetaError::EmptyChain))?;

    authorizer
        .verify_chain_as_of(&decoded.warrants, now)
        .map_err(TaskAccessError::Warrant)?;

    match leaf.verify_pop_as_of(
        method,
        &params,
        Some(&decoded.signature),
        POP_TIMESTAMP_WINDOW_SECS,
        1,
        now,
    ) {
        Ok(()) => {}
        Err(Error::SignatureInvalid(_)) => return Err(TaskAccessError::InvalidPop),
        Err(err) => return Err(TaskAccessError::Warrant(err)),
    }

    let bound = binding.is_some_and(|b| {
        b.task_id == task_id
            && b.holder == *leaf.authorized_holder()
            && decoded
                .warrants
                .iter()
                .any(|w| w.id().to_string() == b.warrant_id)
    });
    if !bound {
        return Err(TaskAccessError::NotAccessible);
    }

    Ok(TaskAccess {
        task_id,
        warrant_id: leaf.id().to_string(),
        signature: decoded.signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SigningKey;
    use crate::meta_envelope::sign_meta;
    use std::time::Duration;

    struct Fixture {
        authorizer: Authorizer,
        issuer: SigningKey,
        holder: SigningKey,
        warrant: Warrant,
        now: i64,
    }

    fn fixture() -> Fixture {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let warrant = Warrant::builder()
            .capability("crunch", crate::constraints::ConstraintSet::new())
            .ttl(Duration::from_secs(600))
            .holder(holder.public_key())
            .build(&issuer)
            .unwrap();
        let authorizer = Authorizer::new().with_trusted_root(issuer.public_key());
        Fixture {
            authorizer,
            issuer,
            holder,
            warrant,
            now: chrono::Utc::now().timestamp(),
        }
    }

    fn sign(
        chain: &[Warrant],
        key: &SigningKey,
        method: &str,
        params: &str,
        now: i64,
    ) -> (String, String) {
        let meta = sign_meta(chain, key, method, params, now, &[]).unwrap();
        (meta.warrant, meta.signature)
    }

    fn verify(
        f: &Fixture,
        method: &str,
        params: &str,
        envelope: &(String, String),
        binding: Option<&TaskBinding>,
    ) -> Result<TaskAccess, TaskAccessError> {
        verify_task_request(
            &f.authorizer,
            method,
            params,
            &envelope.0,
            &envelope.1,
            binding,
            f.now,
        )
    }

    const PARAMS: &str = r#"{"taskId":"t1"}"#;

    #[test]
    fn creating_warrant_is_admitted() {
        let f = fixture();
        let binding = TaskBinding::for_created_task("t1", &f.warrant);
        for method in TASK_METHODS {
            let env = sign(
                std::slice::from_ref(&f.warrant),
                &f.holder,
                method,
                PARAMS,
                f.now,
            );
            let access = verify(&f, method, PARAMS, &env, Some(&binding)).unwrap();
            assert_eq!(access.task_id, "t1");
            assert_eq!(access.warrant_id, f.warrant.id().to_string());
        }
    }

    #[test]
    fn proof_is_bound_to_method_and_params() {
        let f = fixture();
        let binding = TaskBinding::for_created_task("t1", &f.warrant);
        let env = sign(
            std::slice::from_ref(&f.warrant),
            &f.holder,
            "tasks/get",
            PARAMS,
            f.now,
        );
        let err = verify(&f, "tasks/cancel", PARAMS, &env, Some(&binding)).unwrap_err();
        assert_eq!(err.code(), "invalid_pop");

        let update = r#"{"taskId":"t1","inputResponses":{"k":{"action":"accept"}}}"#;
        let tampered = r#"{"taskId":"t1","inputResponses":{"k":{"action":"decline"}}}"#;
        let env = sign(
            std::slice::from_ref(&f.warrant),
            &f.holder,
            "tasks/update",
            update,
            f.now,
        );
        assert!(verify(&f, "tasks/update", update, &env, Some(&binding)).is_ok());
        let err = verify(&f, "tasks/update", tampered, &env, Some(&binding)).unwrap_err();
        assert_eq!(err.code(), "invalid_pop");
    }

    #[test]
    fn unknown_and_foreign_tasks_look_the_same() {
        let f = fixture();
        let other_key = SigningKey::generate();
        let other = Warrant::builder()
            .capability("crunch", crate::constraints::ConstraintSet::new())
            .ttl(Duration::from_secs(600))
            .holder(other_key.public_key())
            .build(&f.issuer)
            .unwrap();
        let binding = TaskBinding::for_created_task("t1", &f.warrant);
        let env = sign(&[other], &other_key, "tasks/get", PARAMS, f.now);
        let foreign = verify(&f, "tasks/get", PARAMS, &env, Some(&binding)).unwrap_err();
        let unknown = verify(&f, "tasks/get", PARAMS, &env, None).unwrap_err();
        assert_eq!(foreign.code(), "task_not_accessible");
        assert_eq!(foreign.to_string(), unknown.to_string());
    }

    #[test]
    fn binding_for_another_task_id_does_not_match() {
        let f = fixture();
        let binding = TaskBinding::for_created_task("t2", &f.warrant);
        let env = sign(
            std::slice::from_ref(&f.warrant),
            &f.holder,
            "tasks/get",
            PARAMS,
            f.now,
        );
        let err = verify(&f, "tasks/get", PARAMS, &env, Some(&binding)).unwrap_err();
        assert_eq!(err.code(), "task_not_accessible");
    }

    #[test]
    fn untrusted_issuer_is_rejected() {
        let f = fixture();
        let binding = TaskBinding::for_created_task("t1", &f.warrant);
        let env = sign(
            std::slice::from_ref(&f.warrant),
            &f.holder,
            "tasks/get",
            PARAMS,
            f.now,
        );
        let other = Authorizer::new().with_trusted_root(SigningKey::generate().public_key());
        let err = verify_task_request(
            &other,
            "tasks/get",
            PARAMS,
            &env.0,
            &env.1,
            Some(&binding),
            f.now,
        )
        .unwrap_err();
        assert_eq!(err.code(), "invalid_warrant");
    }

    #[test]
    fn expired_warrant_is_rejected() {
        let f = fixture();
        let binding = TaskBinding::for_created_task("t1", &f.warrant);
        let later = binding.expires_at + 3600;
        let env = sign(
            std::slice::from_ref(&f.warrant),
            &f.holder,
            "tasks/get",
            PARAMS,
            later,
        );
        let err = verify_task_request(
            &f.authorizer,
            "tasks/get",
            PARAMS,
            &env.0,
            &env.1,
            Some(&binding),
            later,
        )
        .unwrap_err();
        assert_eq!(err.code(), "invalid_warrant");
    }

    #[test]
    fn request_shape_errors() {
        let f = fixture();
        let env = sign(
            std::slice::from_ref(&f.warrant),
            &f.holder,
            "tasks/get",
            "{}",
            f.now,
        );
        assert_eq!(
            verify(&f, "tasks/list", "{}", &env, None)
                .unwrap_err()
                .jsonrpc_code(),
            -32601
        );
        assert_eq!(
            verify(&f, "tasks/get", "{}", &env, None)
                .unwrap_err()
                .jsonrpc_code(),
            -32602
        );
    }
}
