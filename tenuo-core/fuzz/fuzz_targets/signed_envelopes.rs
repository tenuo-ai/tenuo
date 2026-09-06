#![no_main]

use libfuzzer_sys::fuzz_target;
use tenuo::approval::SignedApproval;
use tenuo::{Receipt, RevocationRequest, SignedRevocationList};

fuzz_target!(|data: &[u8]| {
    if let Ok(request) = RevocationRequest::from_bytes(data) {
        let _ = request.verify_signature();
    }
    if let Ok(list) = SignedRevocationList::from_bytes(data) {
        let _ = list.to_bytes();
    }
    if let Ok(approval) = ciborium::from_reader::<SignedApproval, _>(data) {
        let _ = approval.verify();
    }
    if let Ok(receipt) = ciborium::from_reader::<Receipt, _>(data) {
        let _ = receipt.verify_signature();
    }
});
