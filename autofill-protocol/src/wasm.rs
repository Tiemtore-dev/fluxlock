//! Minimal bounded WASM ABI. The only host import is Web Crypto randomness.
use super::*;
use std::cell::RefCell;
use zeroize::Zeroize;
#[link(wasm_import_module = "fluxlock")]
extern "C" {
    fn random_fill(ptr: *mut u8, len: usize) -> i32;
}
pub(super) fn random(bytes: &mut [u8]) -> Result<(), snow::Error> {
    // The import receives a valid slice in this module's linear memory.
    if unsafe { random_fill(bytes.as_mut_ptr(), bytes.len()) } == 1 {
        Ok(())
    } else {
        Err(snow::Error::Rng)
    }
}
struct State {
    input: Box<[u8; MAX_FRAME]>,
    output: Zeroizing<Vec<u8>>,
    handshake: Option<Handshake>,
    transport: Option<snow::TransportState>,
}
thread_local! { static STATE: RefCell<State> = RefCell::new(State { input: Box::new([0;MAX_FRAME]), output: Zeroizing::new(Vec::new()), handshake: None, transport: None }); }
#[no_mangle]
pub extern "C" fn input_ptr() -> *mut u8 {
    STATE.with(|s| s.borrow_mut().input.as_mut_ptr())
}
#[no_mangle]
pub extern "C" fn output_ptr() -> *const u8 {
    STATE.with(|s| s.borrow().output.as_ptr())
}
#[no_mangle]
pub extern "C" fn output_len() -> usize {
    STATE.with(|s| s.borrow().output.len())
}
#[no_mangle]
pub extern "C" fn clear() {
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        s.input.zeroize();
        s.output.zeroize();
        s.handshake = None;
        s.transport = None;
    });
}
#[no_mangle]
pub extern "C" fn execute(op: u32, len: usize) -> i32 {
    if len > MAX_FRAME {
        clear();
        return 0;
    }
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        s.output.zeroize();
        let data = Zeroizing::new(s.input[..len].to_vec());
        s.input.zeroize();
        let result: Result<Vec<u8>, String> = (|| match op {
            0 => {
                let key: &[u8; IDENTITY_SIZE] =
                    data.as_slice().try_into().map_err(|_| "Identity size")?;
                let pending = handshake(key, true)?;
                let own_identity =
                    identity_id(&pending.signing.as_ref().ok_or("Identity absent")?.public());
                s.handshake = Some(pending);
                s.transport = None;
                Ok(own_identity.to_vec())
            }
            1 => {
                let mut out = vec![0; MAX_HANDSHAKE];
                let n = s
                    .handshake
                    .as_mut()
                    .ok_or("Handshake absent")?
                    .write_message(&data, &mut out)
                    .map_err(|_| "Handshake write")?;
                out.truncate(n);
                Ok(out)
            }
            2 => {
                let mut out = vec![0; MAX_HANDSHAKE];
                let n = s
                    .handshake
                    .as_mut()
                    .ok_or("Handshake absent")?
                    .read_message(&data, &mut out)
                    .map_err(|_| "Handshake read")?;
                out.truncate(n);
                Ok(out)
            }
            3 => Ok(s
                .handshake
                .as_ref()
                .ok_or("Handshake absent")?
                .remote_identity()
                .ok_or("Peer absent")?
                .to_vec()),
            4 => {
                let hash = s
                    .handshake
                    .as_ref()
                    .ok_or("Handshake absent")?
                    .get_handshake_hash();
                if hash.len() != 64 {
                    return Err("PQ handshake unfinished".into());
                }
                Ok(fingerprint(hash).into_bytes())
            }
            5 => {
                s.transport = Some(
                    s.handshake
                        .take()
                        .ok_or("Handshake absent")?
                        .into_transport_mode()
                        .map_err(|_| "Handshake unfinished")?,
                );
                Ok(Vec::new())
            }
            6 => encrypt(s.transport.as_mut().ok_or("Channel absent")?, &data),
            7 => Ok(decrypt(s.transport.as_mut().ok_or("Channel absent")?, &data)?.to_vec()),
            _ => Err("Unknown operation".into()),
        })();
        match result {
            Ok(v) => {
                s.output = Zeroizing::new(v);
                1
            }
            Err(_) => {
                s.handshake = None;
                s.transport = None;
                0
            }
        }
    })
}
