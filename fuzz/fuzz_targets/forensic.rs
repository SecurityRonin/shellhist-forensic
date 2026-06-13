#![no_main]
//! Full detect → parse → audit pipeline over arbitrary bytes — must never panic.
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let entries = shellhist_core::parse_auto(data, None);
    let _ = shellhist_forensic::audit(&entries);
});
