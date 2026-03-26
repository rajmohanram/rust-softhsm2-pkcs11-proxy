//! PKCS#11 proxy client library.
//!
//! This cdylib exports the standard PKCS#11 C API. Applications (such as
//! OpenBao) load it via `dlopen` and call `C_GetFunctionList` to discover
//! available functions. Every call is serialized to protobuf and forwarded
//! over TLS-PSK to the proxy server daemon.

mod deserialize;
mod functions;
mod serialize;
mod state;

use std::sync::Once;

use cryptoki_sys::*;

static INIT_TRACING: Once = Once::new();

/// Initialize the tracing subscriber (once only, idempotent).
///
/// Log level is resolved from (first wins):
/// 1. `PKCS11_PROXY_LOG_LEVEL` env var
/// 2. `RUST_LOG` env var
/// 3. Default: `info`
fn init_tracing() {
    INIT_TRACING.call_once(|| {
        let filter = std::env::var("PKCS11_PROXY_LOG_LEVEL")
            .ok()
            .and_then(|v| tracing_subscriber::EnvFilter::try_new(&v).ok())
            .or_else(|| tracing_subscriber::EnvFilter::try_from_default_env().ok())
            .unwrap_or_else(|| tracing_subscriber::EnvFilter::new("info"));

        let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
    });
}

/// The static PKCS#11 function list returned to callers of `C_GetFunctionList`.
static mut FUNCTION_LIST: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    version: CK_VERSION {
        major: 2,
        minor: 40,
    },
    C_Initialize: Some(functions::C_Initialize),
    C_Finalize: Some(functions::C_Finalize),
    C_GetInfo: None,
    C_GetFunctionList: Some(C_GetFunctionList),
    C_GetSlotList: Some(functions::C_GetSlotList),
    C_GetSlotInfo: Some(functions::C_GetSlotInfo),
    C_GetTokenInfo: Some(functions::C_GetTokenInfo),
    C_GetMechanismList: Some(functions::C_GetMechanismList),
    C_GetMechanismInfo: Some(functions::C_GetMechanismInfo),
    C_InitToken: None,
    C_InitPIN: None,
    C_SetPIN: None,
    C_OpenSession: Some(functions::C_OpenSession),
    C_CloseSession: Some(functions::C_CloseSession),
    C_CloseAllSessions: None,
    C_GetSessionInfo: None,
    C_GetOperationState: None,
    C_SetOperationState: None,
    C_Login: Some(functions::C_Login),
    C_Logout: Some(functions::C_Logout),
    C_CreateObject: None,
    C_CopyObject: None,
    C_DestroyObject: None,
    C_GetObjectSize: None,
    C_GetAttributeValue: Some(functions::C_GetAttributeValue),
    C_SetAttributeValue: None,
    C_FindObjectsInit: Some(functions::C_FindObjectsInit),
    C_FindObjects: Some(functions::C_FindObjects),
    C_FindObjectsFinal: Some(functions::C_FindObjectsFinal),
    C_EncryptInit: Some(functions::C_EncryptInit),
    C_Encrypt: Some(functions::C_Encrypt),
    C_EncryptUpdate: None,
    C_EncryptFinal: None,
    C_DecryptInit: Some(functions::C_DecryptInit),
    C_Decrypt: Some(functions::C_Decrypt),
    C_DecryptUpdate: None,
    C_DecryptFinal: None,
    C_DigestInit: None,
    C_Digest: None,
    C_DigestUpdate: None,
    C_DigestKey: None,
    C_DigestFinal: None,
    C_SignInit: None,
    C_Sign: None,
    C_SignUpdate: None,
    C_SignFinal: None,
    C_SignRecoverInit: None,
    C_SignRecover: None,
    C_VerifyInit: None,
    C_Verify: None,
    C_VerifyUpdate: None,
    C_VerifyFinal: None,
    C_VerifyRecoverInit: None,
    C_VerifyRecover: None,
    C_DigestEncryptUpdate: None,
    C_DecryptDigestUpdate: None,
    C_SignEncryptUpdate: None,
    C_DecryptVerifyUpdate: None,
    C_GenerateKey: Some(functions::C_GenerateKey),
    C_GenerateKeyPair: Some(functions::C_GenerateKeyPair),
    C_WrapKey: None,
    C_UnwrapKey: None,
    C_DeriveKey: None,
    C_SeedRandom: None,
    C_GenerateRandom: Some(functions::C_GenerateRandom),
    C_GetFunctionStatus: None,
    C_CancelFunction: None,
    C_WaitForSlotEvent: None,
};

/// Entry point for PKCS#11 consumers. Returns a pointer to the function list.
///
/// # Safety
///
/// `pp_function_list` must be a valid, non-null pointer to a `CK_FUNCTION_LIST_PTR`.
#[no_mangle]
pub unsafe extern "C" fn C_GetFunctionList(pp_function_list: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    init_tracing();

    if pp_function_list.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    unsafe {
        *pp_function_list = std::ptr::addr_of_mut!(FUNCTION_LIST);
    }

    CKR_OK
}
