//! Deliberately has no vault, crypto-key, database or shell dependencies.
use std::{io, path::PathBuf};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
const MAX: usize = 65536;

fn endpoint() -> io::Result<String> {
    let test = cfg!(debug_assertions) && option_env!("FLUXLOCK_TEST_BUILD").is_some();
    let storage = if test {
        "SecureVault Test"
    } else {
        "SecureVault"
    };
    #[cfg(windows)]
    {
        let local = std::env::var("LOCALAPPDATA").map_err(io::Error::other)?;
        // Names include the per-account app-data path; the server enforces a private ACL.
        return Ok(format!(
            r"\\.\pipe\fluxlock-autofill-{}",
            stable_id(&format!("{local}/{storage}"))
        ));
    }
    #[cfg(not(windows))]
    {
        let home = std::env::var("HOME").map_err(io::Error::other)?;
        let root = if cfg!(target_os = "macos") {
            PathBuf::from(home)
                .join("Library/Application Support")
                .join(storage)
        } else {
            PathBuf::from(home).join(".local/share").join(storage)
        };
        Ok(root
            .join("browser-ipc/channel.sock")
            .to_string_lossy()
            .into_owned())
    }
}
#[cfg(windows)]
fn stable_id(s: &str) -> String {
    // This is only a name, never an authentication mechanism.
    let mut hash = 0xcbf29ce484222325u64;
    for b in s.bytes() {
        hash = (hash ^ b as u64).wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}
async fn frame<R: AsyncRead + Unpin>(reader: &mut R, native: bool) -> io::Result<Vec<u8>> {
    let mut header = [0; 4];
    reader.read_exact(&mut header).await?;
    let len = if native {
        u32::from_ne_bytes(header)
    } else {
        u32::from_be_bytes(header)
    } as usize;
    if len == 0 || len > MAX {
        return Err(io::Error::other("Invalid frame size"));
    }
    let mut data = vec![0; len];
    reader.read_exact(&mut data).await?;
    let value: serde_json::Value = serde_json::from_slice(&data).map_err(io::Error::other)?;
    let object = value
        .as_object()
        .ok_or_else(|| io::Error::other("Invalid envelope"))?;
    if object.len() != 2 || value["version"] != 2 || !value["frame"].is_string() {
        return Err(io::Error::other("Invalid envelope"));
    }
    Ok(data)
}
async fn send<W: AsyncWrite + Unpin>(writer: &mut W, data: &[u8], native: bool) -> io::Result<()> {
    let header = if native {
        (data.len() as u32).to_ne_bytes()
    } else {
        (data.len() as u32).to_be_bytes()
    };
    writer.write_all(&header).await?;
    writer.write_all(data).await?;
    writer.flush().await
}
#[tokio::main(flavor = "current_thread")]
async fn main() -> io::Result<()> {
    // Chrome supplies the calling extension origin. A spoofed argument does not
    // bypass Noise pinning and native authentication in the desktop process.
    let caller = std::env::args()
        .nth(1)
        .ok_or_else(|| io::Error::other("Browser origin required"))?;
    let authority = caller
        .strip_prefix("chrome-extension://")
        .ok_or_else(|| io::Error::other("Invalid browser origin"))?;
    let id = authority.strip_suffix('/').unwrap_or(authority);
    if id.len() != 32 || !id.bytes().all(|b| (b'a'..=b'p').contains(&b)) {
        return Err(io::Error::other("Invalid extension ID"));
    }
    #[cfg(unix)]
    let stream = tokio::net::UnixStream::connect(endpoint()?).await?;
    #[cfg(windows)]
    let stream = tokio::net::windows::named_pipe::ClientOptions::new().open(endpoint()?)?;
    let (mut read, mut write) = tokio::io::split(stream);
    let input = async {
        let mut stdin = tokio::io::stdin();
        loop {
            let data = frame(&mut stdin, true).await?;
            send(&mut write, &data, false).await?;
        }
    };
    let output = async {
        let mut stdout = tokio::io::stdout();
        loop {
            let data = frame(&mut read, false).await?;
            send(&mut stdout, &data, true).await?;
        }
    };
    tokio::select! { r=input=>r, r=output=>r }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn relay_translates_frame_byte_order_and_rejects_unknown_envelopes() {
        let data = br#"{"version":2,"frame":"opaque-ciphertext"}"#;
        let (mut a, mut b) = tokio::io::duplex(1024);
        send(&mut a, data, true).await.unwrap();
        assert_eq!(frame(&mut b, true).await.unwrap(), data);
        send(&mut a, data, false).await.unwrap();
        assert_eq!(frame(&mut b, false).await.unwrap(), data);
        let wrong = br#"{"version":2,"frame":"x","command":"decrypt_all"}"#;
        send(&mut a, wrong, true).await.unwrap();
        assert!(frame(&mut b, true).await.is_err());
        let legacy = br#"{"version":1,"frame":"old-classical-packet"}"#;
        send(&mut a, legacy, true).await.unwrap();
        assert!(frame(&mut b, true).await.is_err());
    }
    #[tokio::test]
    async fn relay_refuses_unbounded_frame_before_allocation() {
        let (mut a, mut b) = tokio::io::duplex(16);
        a.write_all(&((MAX + 1) as u32).to_ne_bytes())
            .await
            .unwrap();
        assert!(frame(&mut b, true).await.is_err());
    }
}
