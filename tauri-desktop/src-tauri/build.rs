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

    #[cfg(target_os = "macos")]
    if target_os == "macos" {
        compile_biometric_compatibility();
    }

    tauri_build::build()
}

#[cfg(target_os = "macos")]
fn compile_biometric_compatibility() {
    use std::{env, path::PathBuf, process::Command};

    fn xcrun(args: &[&str]) -> PathBuf {
        let output = Command::new("xcrun")
            .args(args)
            .output()
            .expect("run xcrun");
        assert!(
            output.status.success(),
            "xcrun failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        PathBuf::from(
            String::from_utf8(output.stdout)
                .expect("xcrun output")
                .trim(),
        )
    }

    let source = "swift/BiometricCompatibility.swift";
    println!("cargo:rerun-if-changed={source}");
    println!("cargo:rerun-if-env-changed=DEVELOPER_DIR");
    let target = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("aarch64") => "arm64-apple-macosx11.0",
        Ok("x86_64") => "x86_64-apple-macosx10.15",
        _ => panic!("Unsupported macOS architecture"),
    };
    let sdk = xcrun(&["--sdk", "macosx", "--show-sdk-path"]);
    let compiler = xcrun(&["--sdk", "macosx", "--find", "swiftc"]);
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo output directory"));
    let object = out.join("BiometricCompatibility.o");
    let result = Command::new(&compiler)
        .args([
            "-target",
            target,
            "-parse-as-library",
            "-emit-object",
            "-O",
            "-sdk",
        ])
        .arg(&sdk)
        .arg("-module-cache-path")
        .arg(out.join("swift-module-cache"))
        .arg(source)
        .arg("-o")
        .arg(&object)
        .status()
        .expect("run swiftc");
    assert!(
        result.success(),
        "Could not compile the macOS Touch ID compatibility module"
    );
    let runtime = compiler
        .parent()
        .and_then(|bin| bin.parent())
        .expect("Swift toolchain")
        .join("lib/swift/macosx");
    println!("cargo:rustc-link-search=native={}", runtime.display());
    println!(
        "cargo:rustc-link-search=native={}",
        sdk.join("usr/lib/swift").display()
    );
    println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/lib/swift");
    cc::Build::new()
        .object(object)
        .compile("biometric_compatibility");
}
