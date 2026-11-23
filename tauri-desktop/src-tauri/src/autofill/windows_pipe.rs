//! Kept independent of Tauri so the actual Windows ACL code can be type-checked
//! from other development platforms, as well as compiled in the desktop app.
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::{LocalFree, HLOCAL},
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
        },
    },
};

pub(super) fn create(path: &str, first: bool) -> Result<NamedPipeServer, String> {
    let sddl: Vec<u16> = "D:P(A;;GA;;;OW)\0".encode_utf16().collect();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
        .map_err(|e| e.to_string())?;
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: false.into(),
    };
    let result = unsafe {
        ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(
                path,
                &attributes as *const _ as *mut std::ffi::c_void,
            )
    }
    .map_err(|e| e.to_string());
    unsafe {
        let _ = LocalFree(HLOCAL(descriptor.0));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[tokio::test]
    async fn owner_can_connect_and_another_first_instance_is_rejected() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = format!(r"\\.\pipe\fluxlock-acl-test-{}-{nonce}", std::process::id());
        let mut server = create(&path, true).unwrap();
        assert!(create(&path, true).is_err());
        let mut client = tokio::net::windows::named_pipe::ClientOptions::new()
            .open(&path)
            .unwrap();
        server.connect().await.unwrap();
        client.write_all(b"test").await.unwrap();
        let mut data = [0; 4];
        server.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"test");
    }
}
