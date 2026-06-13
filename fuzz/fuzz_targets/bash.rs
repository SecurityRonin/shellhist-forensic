#![no_main]
//! bash history parse over arbitrary bytes — must never panic.
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let _ = shellhist_core::bash::parse(data);
});
