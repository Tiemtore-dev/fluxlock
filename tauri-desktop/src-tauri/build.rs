fn main() {
    // ═══ macOS: Compile Objective-C biometric helper (Touch ID / Face ID) ═══
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os == "macos" || target_os == "ios" {
        cc::Build::new()
            .file("objc/biometric.m")
            .flag("-fobjc-arc") // Automatic Reference Counting
            .flag("-Wno-unused-parameter")
            .compile("biometric_objc");

        // Link LocalAuthentication.framework (Touch ID / Face ID)
        println!("cargo:rustc-link-lib=framework=LocalAuthentication");
        // Link Security.framework (SecItem* / SecAccessControl for Secure Enclave keychain)
        println!("cargo:rustc-link-lib=framework=Security");
    }

    tauri_build::build()
}
