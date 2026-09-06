#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = tenuo::wire::decode(data);
    let _ = tenuo::wire::decode_stack(data);

    if let Ok(text) = std::str::from_utf8(data) {
        let _ = tenuo::wire::decode_base64(text);
        let _ = tenuo::wire::decode_pem_chain(text);
    }
});
