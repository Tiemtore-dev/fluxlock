// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    if let Some(code) = fluxlock_lib::autofill::host_relay::maybe_run_native_host_from_env() {
        std::process::exit(code);
    }
    fluxlock_lib::run();
}
