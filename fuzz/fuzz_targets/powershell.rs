#![no_main]
//! powershell history parse over arbitrary bytes — must never panic.
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let _ = shellhist_core::powershell::parse(data);
});
