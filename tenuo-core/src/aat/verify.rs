//! The chain verification algorithm of Section 8, steps 1 to 7i, in order.

use super::constraint::{self, Tools};
use super::jose::{self, Jwk, AAT_TYP, POP_TYP};
use super::json::{self, Json, Obj};
use super::{deny, Denied, TrustAnchor, Verified, VerifyOptions};

const AAT_TYPE: &str = "attenuating_agent_token";

/// One verified token of the chain.
struct Token {
    claims: Obj,
    tools: Tools,
    jti: String,
    iat: i128,
    exp: i128,
    del_depth: i128,
    del_max_depth: i128,
    /// `cnf.jwk`: the key that signs the next token, or the PoP for the leaf.
    holder: Jwk,
}

pub(super) fn verify_chain(
    chain: &[&str],
    pop: &str,
    anchors: &[TrustAnchor],
    tool: &str,
    args_json: &str,
    opts: &mut VerifyOptions<'_>,
) -> Result<Verified, Denied> {
    let limits = opts.limits;
    let now = i128::from(opts.now);

    // 1, 2
    let root_compact = *chain.first().ok_or_else(|| deny("1", "empty chain"))?;
    if chain
        .iter()
        .any(|token| token.len() > limits.max_token_size)
    {
        return Err(deny("2a", "a token exceeds MAX_TOKEN_SIZE"));
    }
    if chain.iter().map(|token| token.len()).sum::<usize>() > limits.max_chain_size {
        return Err(deny("2b", "chain exceeds MAX_CHAIN_SIZE"));
    }
    // Untrusted until each signature verifies; used only to refuse a chain
    // that presents one token twice.
    let mut seen = std::collections::HashSet::new();
    for token in chain {
        let jti = jose::unverified_jti(token)
            .ok_or_else(|| deny("2c", "a string-valued jti cannot be extracted"))?;
        if !seen.insert(jti) {
            return Err(deny("2c", "duplicate jti in chain"));
        }
    }

    // 3: root
    let (root_claims, anchor) = verify_root_signature(root_compact, anchors)?;
    let root = verify_root(root_claims, anchor, now, opts)?;
    let issuer = anchor.issuer.clone();

    // 4: adjacent pairs
    let mut tokens = vec![root];
    for i in 1..chain.len() {
        let child = verify_derived(chain[i], chain[i - 1], &tokens[i - 1], now, opts)?;
        tokens.push(child);
    }

    // 5, 6: leaf
    let leaf = &tokens[tokens.len() - 1];
    if i128::try_from(chain.len()).ok() != Some(leaf.del_depth + 1) {
        return Err(deny("5", "chain length is not leaf.del_depth + 1"));
    }
    // 6a holds for every token already: steps 3m and 4n require exactly one
    // attenuating_agent_token entry.
    let map = leaf
        .tools
        .get(tool)
        .ok_or_else(|| deny("6b", format!("tool {tool:?} is not authorized")))?;
    let args = json::parse(args_json).ok_or_else(|| deny("6b", "arguments are not JSON"))?;
    if args.duplicate {
        return Err(deny("6b", "arguments contain a duplicate JSON member name"));
    }
    if args.value.as_obj().is_none() {
        return Err(deny("6b", "arguments are not a JSON object"));
    }
    let args = args.value;
    if args.has_inadmissible_number() {
        return Err(deny("6b", "an argument number is not admissible"));
    }
    if let Json::Obj(members) = &args {
        constraint::check_arguments(map, members)?;
    }

    // 6c: every token that carries aud must name this enforcement point. A
    // derived token can add or narrow the restriction, never remove one.
    let mut any_aud = false;
    for (i, token) in tokens.iter().enumerate() {
        let Some(aud) = token.claims.get("aud") else {
            continue;
        };
        any_aud = true;
        let named = match aud {
            Json::Str(one) => one == opts.audience,
            Json::Arr(many) if many.iter().all(|v| v.as_str().is_some()) => {
                many.iter().any(|v| v.as_str() == Some(opts.audience))
            }
            _ => {
                return Err(deny(
                    "6c",
                    format!("token {i} aud is not a string or an array of strings"),
                ))
            }
        };
        if !named {
            return Err(deny(
                "6c",
                format!("token {i} aud does not identify this enforcement point"),
            ));
        }
    }
    if opts.require_chain_aud && !any_aud {
        return Err(deny(
            "6c",
            "chain audience is required but no token carries aud",
        ));
    }

    // 7: proof of possession
    let leaf_compact = chain[chain.len() - 1];
    let pop = jose::verify(pop, Some(&leaf.holder), POP_TYP, "7a", "7b")?;
    let pop_jti = non_empty_str(&pop, "jti")
        .ok_or_else(|| deny("7c", "PoP jti is missing or not a non-empty string"))?;
    let (Some(aat_id), Some(aat_hash), Some(aat_tool)) = (
        non_empty_str(&pop, "aat_id"),
        non_empty_str(&pop, "aat_hash"),
        non_empty_str(&pop, "aat_tool"),
    ) else {
        return Err(deny(
            "7c",
            "PoP aat_id, aat_hash or aat_tool is missing or not a non-empty string",
        ));
    };
    let pop_iat = pop
        .get("iat")
        .and_then(Json::as_int)
        .ok_or_else(|| deny("7c", "PoP iat is missing or not a NumericDate"))?;
    let hta = pop
        .get("hta")
        .filter(|hta| hta.as_obj().is_some())
        .ok_or_else(|| deny("7c", "PoP hta is missing or not an object"))?;
    if aat_id != leaf.jti {
        return Err(deny("7c", "aat_id is not the leaf jti"));
    }
    if aat_hash != jose::sha256_b64u(jose::signing_input(leaf_compact)) {
        return Err(deny("7c", "aat_hash does not match the presented leaf"));
    }
    match pop.get("aat_aud") {
        None | Some(Json::Null) => {
            if opts.require_pop_aud {
                return Err(deny("7d", "aat_aud is required but absent"));
            }
        }
        Some(aud) => {
            if aud.as_str() != Some(opts.audience) {
                return Err(deny(
                    "7d",
                    "aat_aud does not identify this enforcement point",
                ));
            }
        }
    }
    if aat_tool != tool {
        return Err(deny("7e", "aat_tool is not the tool being invoked"));
    }
    if hta.has_inadmissible_number() {
        return Err(deny("7f", "a number in the PoP hta is not admissible"));
    }
    if !hta.jcs_eq(&args) {
        return Err(deny("7f", "hta does not equal the arguments"));
    }
    let window = i128::from(limits.pop_window);
    if pop_iat < now.saturating_sub(window) {
        return Err(deny("7g", "PoP iat is older than the clock window"));
    }
    if pop_iat > now.saturating_add(window) {
        return Err(deny(
            "7g",
            "PoP iat is further in the future than the clock window",
        ));
    }
    if let Some(expected) = opts.nonce {
        if pop.get("nonce").and_then(Json::as_str) != Some(expected) {
            return Err(deny(
                "7h",
                "nonce is required but absent or not issued by this enforcement point",
            ));
        }
    }
    if let Some(store) = opts.replay.as_deref_mut() {
        // Last, so that only a PoP that passed every other check is recorded.
        if !store.record(pop_jti) {
            return Err(deny("7i", "PoP jti was already accepted"));
        }
    }

    let holder = leaf
        .holder
        .key()
        .ok_or_else(|| deny("7b", "leaf cnf.jwk is not a usable key"))?;
    Ok(Verified {
        issuer,
        token_ids: tokens.into_iter().map(|t| t.jti).collect(),
        holder,
    })
}

/// Steps 3a and 3b: the root verifies under some trust anchor's key.
fn verify_root_signature<'a>(
    root: &str,
    anchors: &'a [TrustAnchor],
) -> Result<(Obj, &'a TrustAnchor), Denied> {
    let mut last = deny("3b", "no trust anchor is configured");
    for anchor in anchors {
        match jose::verify(root, Some(&Jwk::from_key(&anchor.key)), AAT_TYP, "3a", "3b") {
            Ok(claims) => return Ok((claims, anchor)),
            Err(denied) => last = denied,
        }
    }
    Err(last)
}

/// Steps 3b (after the signature) to 3n.
fn verify_root(
    claims: Obj,
    anchor: &TrustAnchor,
    now: i128,
    opts: &VerifyOptions<'_>,
) -> Result<Token, Denied> {
    let limits = opts.limits;
    let (Some(iat), Some(exp)) = (int(&claims, "iat"), int(&claims, "exp")) else {
        return Err(deny(
            "3b",
            "root iat or exp is missing or not a NumericDate",
        ));
    };
    if int(&claims, "del_depth") != Some(0) {
        return Err(deny("3c", "root del_depth is not the integer 0"));
    }
    if claims.contains("par_hash") {
        return Err(deny("3d", "root carries par_hash"));
    }
    if exp <= now {
        return Err(deny("3e", "root is expired"));
    }
    if iat > now.saturating_add(limits.max_iat_skew.into()) {
        return Err(deny("3f", "root iat is beyond now + MAX_IAT_SKEW"));
    }
    if exp <= iat {
        return Err(deny("3g", "root exp is not after iat"));
    }
    if exp > iat.saturating_add(limits.max_token_lifetime.into()) {
        return Err(deny("3h", "root lifetime exceeds MAX_TOKEN_LIFETIME"));
    }
    let del_max_depth = int(&claims, "del_max_depth")
        .filter(|depth| (0..=i128::from(limits.max_delegation_depth)).contains(depth))
        .ok_or_else(|| {
            deny(
                "3i",
                "root del_max_depth is missing, not a non-negative integer, or exceeds MAX_DELEGATION_DEPTH",
            )
        })?;
    let jti = non_empty_str(&claims, "jti")
        .ok_or_else(|| deny("3j", "root jti is missing or not a non-empty string"))?
        .to_owned();
    let iss = claims.get("iss").and_then(Json::as_str);
    if !iss.is_some_and(is_uri) || iss != Some(anchor.issuer.as_str()) {
        return Err(deny(
            "3k",
            "root iss is not a URI or does not match the verifying trust anchor",
        ));
    }
    let holder = holder_key(&claims, "3l")?;
    let entry = aat_entry(&claims, true, "3m")?;
    let tools = constraint::decode_tools(entry, limits.max_constraint_depth, "3n")?;
    Ok(Token {
        claims,
        tools,
        jti,
        iat,
        exp,
        del_depth: 0,
        del_max_depth,
        holder,
    })
}

/// Step 4 for one adjacent pair.
fn verify_derived(
    compact: &str,
    parent_compact: &str,
    parent: &Token,
    now: i128,
    opts: &VerifyOptions<'_>,
) -> Result<Token, Denied> {
    let limits = opts.limits;
    let claims = jose::verify(compact, Some(&parent.holder), AAT_TYP, "4a", "4b")?;
    let jti = non_empty_str(&claims, "jti")
        .ok_or_else(|| deny("4b1", "jti is missing or not a non-empty string"))?
        .to_owned();
    let holder = holder_key(&claims, "4b2")?;
    if claims
        .get("authorization_details")
        .and_then(Json::as_arr)
        .is_none()
    {
        return Err(deny(
            "4b3",
            "authorization_details is missing or not an array",
        ));
    }
    let non_negative = |name| int(&claims, name).filter(|n| *n >= 0);
    let (Some(del_depth), Some(del_max_depth)) =
        (non_negative("del_depth"), non_negative("del_max_depth"))
    else {
        return Err(deny(
            "4b4",
            "del_depth or del_max_depth is missing or not a non-negative integer",
        ));
    };
    let string = |name| claims.get(name).and_then(Json::as_str);
    let (Some(iss), Some(par_hash)) = (string("iss"), string("par_hash")) else {
        return Err(deny("4b5", "iss or par_hash is missing or not a string"));
    };
    let (Some(iat), Some(exp)) = (int(&claims, "iat"), int(&claims, "exp")) else {
        return Err(deny("4b5", "iat or exp is missing or not a NumericDate"));
    };
    if iss != parent.holder.thumbprint_uri() {
        return Err(deny(
            "4c",
            "iss is not the thumbprint URI of parent.cnf.jwk",
        ));
    }
    if del_depth != parent.del_depth + 1 {
        return Err(deny("4d", "del_depth is not parent.del_depth + 1"));
    }
    if del_depth > parent.del_max_depth {
        return Err(deny("4e", "del_depth exceeds parent.del_max_depth"));
    }
    if del_depth > i128::from(limits.max_delegation_depth) {
        return Err(deny("4f", "del_depth exceeds MAX_DELEGATION_DEPTH"));
    }
    if del_max_depth > parent.del_max_depth {
        return Err(deny("4g", "del_max_depth exceeds parent.del_max_depth"));
    }
    if exp > parent.exp {
        return Err(deny("4h", "exp is after parent.exp"));
    }
    if exp <= now {
        return Err(deny("4i", "token is expired"));
    }
    if iat < parent.iat {
        return Err(deny("4j", "iat is before parent.iat"));
    }
    if iat > now.saturating_add(limits.max_iat_skew.into()) {
        return Err(deny("4k", "iat is beyond now + MAX_IAT_SKEW"));
    }
    if exp <= iat {
        return Err(deny("4l", "exp is not after iat"));
    }
    if del_depth > del_max_depth {
        return Err(deny("4m", "del_depth exceeds del_max_depth"));
    }
    let entry = aat_entry(&claims, false, "4n")?;
    let tools = constraint::decode_tools(entry, limits.max_constraint_depth, "4o")?;
    constraint::check_attenuation(&parent.tools, &tools)?;
    if par_hash != jose::sha256_b64u(jose::signing_input(parent_compact)) {
        return Err(deny("4q", "par_hash does not match the parent token"));
    }
    Ok(Token {
        claims,
        tools,
        jti,
        iat,
        exp,
        del_depth,
        del_max_depth,
        holder,
    })
}

/// Steps 3l and 4b2: `cnf.jwk` is a public Ed25519 key.
fn holder_key(claims: &Obj, step: &'static str) -> Result<Jwk, Denied> {
    let jwk = jose::cnf_jwk(claims);
    let holder = Jwk::from_json(jwk).ok_or_else(|| deny(step, "cnf.jwk is missing or invalid"))?;
    if jwk
        .and_then(Json::as_obj)
        .is_some_and(|jwk| jwk.contains("d"))
    {
        return Err(deny(step, "cnf.jwk contains the private key parameter d"));
    }
    Ok(holder)
}

/// Steps 3m and 4n: exactly one `attenuating_agent_token` entry, whose `tools`
/// is an object of objects. Entries of other types are ignored (Section 3.3).
fn aat_entry<'a>(claims: &'a Obj, non_empty: bool, step: &'static str) -> Result<&'a Obj, Denied> {
    let details = claims
        .get("authorization_details")
        .and_then(Json::as_arr)
        .filter(|details| !(non_empty && details.is_empty()))
        .ok_or_else(|| deny(step, "authorization_details is not a non-empty array"))?;
    let mut entries = details
        .iter()
        .filter_map(Json::as_obj)
        .filter(|entry| entry.get("type").and_then(Json::as_str) == Some(AAT_TYPE));
    let (Some(entry), None) = (entries.next(), entries.next()) else {
        return Err(deny(step, "not exactly one attenuating_agent_token entry"));
    };
    let tools = entry.get("tools").and_then(Json::as_obj).ok_or_else(|| {
        deny(
            step,
            "the attenuating_agent_token entry has no tools object",
        )
    })?;
    if tools.iter().any(|(_, map)| map.as_obj().is_none()) {
        return Err(deny(step, "a tools value is not a constraint-map object"));
    }
    Ok(tools)
}

fn int(claims: &Obj, name: &str) -> Option<i128> {
    claims.get(name).and_then(Json::as_int)
}

fn non_empty_str<'a>(claims: &'a Obj, name: &str) -> Option<&'a str> {
    claims
        .get(name)
        .and_then(Json::as_str)
        .filter(|s| !s.is_empty())
}

/// A string that starts with a URI scheme (RFC 3986 Section 3.1).
fn is_uri(text: &str) -> bool {
    let Some((scheme, _)) = text.split_once(':') else {
        return false;
    };
    let mut chars = scheme.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'))
}
