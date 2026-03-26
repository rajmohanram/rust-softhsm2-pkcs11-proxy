//! Individual PKCS#11 C function implementations.
//!
//! Each function has the exact C signature from the PKCS#11 v2.40 spec,
//! builds the corresponding protobuf `Request`, sends it to the proxy server,
//! and writes output parameters from the `Response`.

#![allow(non_snake_case)]

use cryptoki_sys::*;
use tracing::{debug, error, info};

use pkcs11_common::protocol;
use pkcs11_common::protocol::request::Call;
use pkcs11_common::protocol::response::Call as RespCall;

use crate::deserialize;
use crate::serialize;
use crate::state;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Safely copy bytes from a raw C pointer into a Vec.
unsafe fn ptr_to_vec(ptr: *const u8, len: CK_ULONG) -> Vec<u8> {
    if ptr.is_null() || len == 0 {
        Vec::new()
    } else {
        std::slice::from_raw_parts(ptr, len as usize).to_vec()
    }
}

/// Helper: send a request and return the response call variant, or CKR_DEVICE_ERROR.
fn do_call(call: Call) -> Result<RespCall, CK_RV> {
    debug!("do_call: {:?}", std::mem::discriminant(&call));
    let request = protocol::Request { call: Some(call) };
    match state::send_request(&request) {
        Ok(resp) => resp.call.ok_or(CKR_DEVICE_ERROR),
        Err(e) => {
            error!("RPC failed: {e}");
            Err(CKR_DEVICE_ERROR)
        }
    }
}

// ---------------------------------------------------------------------------
// C_Initialize
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn C_Initialize(_init_args: CK_VOID_PTR) -> CK_RV {
    crate::init_tracing();
    info!("C_Initialize called");

    match do_call(Call::Initialize(protocol::InitializeRequest {})) {
        Ok(RespCall::Initialize(r)) => {
            let rv = r.rv as CK_RV;
            info!("C_Initialize completed (rv=0x{:x})", rv);
            rv
        }
        _ => CKR_DEVICE_ERROR,
    }
}

// ---------------------------------------------------------------------------
// C_Finalize
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn C_Finalize(_reserved: CK_VOID_PTR) -> CK_RV {
    info!("C_Finalize called");
    let result = match do_call(Call::Finalize(protocol::FinalizeRequest {})) {
        Ok(RespCall::Finalize(r)) => r.rv as CK_RV,
        _ => CKR_DEVICE_ERROR,
    };
    state::disconnect();
    info!("C_Finalize completed (rv=0x{:x})", result);
    result
}

// ---------------------------------------------------------------------------
// C_GetSlotList
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn C_GetSlotList(
    token_present: CK_BBOOL,
    slot_list: CK_SLOT_ID_PTR,
    count: CK_ULONG_PTR,
) -> CK_RV {
    if count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    let req = protocol::GetSlotListRequest {
        token_present: token_present != 0,
    };

    match do_call(Call::GetSlotList(req)) {
        Ok(RespCall::GetSlotList(r)) => {
            let rv = r.rv as CK_RV;
            if rv != CKR_OK {
                return rv;
            }

            let ids = &r.slot_ids;
            let required = ids.len() as CK_ULONG;

            if slot_list.is_null() {
                unsafe { *count = required };
                return CKR_OK;
            }

            let available = unsafe { *count };
            if available < required {
                unsafe { *count = required };
                return CKR_BUFFER_TOO_SMALL;
            }

            debug!("C_GetSlotList received {} slot IDs: {:?}", ids.len(), ids);
            for (i, &id) in ids.iter().enumerate() {
                debug!("  writing slot_list[{}] = {}", i, id);
                unsafe { *slot_list.add(i) = id as CK_SLOT_ID };
            }
            unsafe { *count = required };
            CKR_OK
        }
        _ => CKR_DEVICE_ERROR,
    }
}

// ---------------------------------------------------------------------------
// C_GetSlotInfo
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn C_GetSlotInfo(slot_id: CK_SLOT_ID, info: CK_SLOT_INFO_PTR) -> CK_RV {
    if info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    let req = protocol::GetSlotInfoRequest { slot_id };

    match do_call(Call::GetSlotInfo(req)) {
        Ok(RespCall::GetSlotInfo(r)) => {
            let rv = r.rv as CK_RV;
            if rv != CKR_OK {
                return rv;
            }
            if let Some(si) = r.info {
                let out = unsafe { &mut *info };
                copy_padded_string(&si.slot_description, &mut out.slotDescription);
                copy_padded_string(&si.manufacturer_id, &mut out.manufacturerID);
                out.flags = si.flags;
                out.hardwareVersion = CK_VERSION {
                    major: si.hardware_version_major as u8,
                    minor: si.hardware_version_minor as u8,
                };
                out.firmwareVersion = CK_VERSION {
                    major: si.firmware_version_major as u8,
                    minor: si.firmware_version_minor as u8,
                };
            }
            CKR_OK
        }
        _ => CKR_DEVICE_ERROR,
    }
}

// ---------------------------------------------------------------------------
// C_GetTokenInfo
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn C_GetTokenInfo(slot_id: CK_SLOT_ID, info: CK_TOKEN_INFO_PTR) -> CK_RV {
    if info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    let req = protocol::GetTokenInfoRequest { slot_id };

    match do_call(Call::GetTokenInfo(req)) {
        Ok(RespCall::GetTokenInfo(r)) => {
            let rv = r.rv as CK_RV;
            if rv != CKR_OK {
                return rv;
            }
            if let Some(ti) = r.info {
                let out = unsafe { &mut *info };
                copy_padded_string(&ti.label, &mut out.label);
                copy_padded_string(&ti.manufacturer_id, &mut out.manufacturerID);
                copy_padded_string(&ti.model, &mut out.model);
                copy_padded_string(&ti.serial_number, &mut out.serialNumber);
                out.flags = ti.flags;
                out.ulMaxSessionCount = ti.max_session_count;
                out.ulSessionCount = ti.session_count;
                out.ulMaxRwSessionCount = ti.max_rw_session_count;
                out.ulRwSessionCount = ti.rw_session_count;
                out.ulMaxPinLen = ti.max_pin_len;
                out.ulMinPinLen = ti.min_pin_len;
                out.ulTotalPublicMemory = ti.total_public_memory;
                out.ulFreePublicMemory = ti.free_public_memory;
                out.ulTotalPrivateMemory = ti.total_private_memory;
                out.ulFreePrivateMemory = ti.free_private_memory;
                out.hardwareVersion = CK_VERSION {
                    major: ti.hardware_version_major as u8,
                    minor: ti.hardware_version_minor as u8,
                };
                out.firmwareVersion = CK_VERSION {
                    major: ti.firmware_version_major as u8,
                    minor: ti.firmware_version_minor as u8,
                };
                // utcTime is a 16-byte space-padded field.
                copy_padded_string(&ti.utc_time, &mut out.utcTime);
            }
            CKR_OK
        }
        _ => CKR_DEVICE_ERROR,
    }
}

// ---------------------------------------------------------------------------
// C_GetMechanismList
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn C_GetMechanismList(
    slot_id: CK_SLOT_ID,
    mechanism_list: CK_MECHANISM_TYPE_PTR,
    count: CK_ULONG_PTR,
) -> CK_RV {
    if count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    let req = protocol::GetMechanismListRequest { slot_id };

    match do_call(Call::GetMechanismList(req)) {
        Ok(RespCall::GetMechanismList(r)) => {
            let rv = r.rv as CK_RV;
            if rv != CKR_OK {
                return rv;
            }

            let types = &r.mechanism_types;
            let required = types.len() as CK_ULONG;

            if mechanism_list.is_null() {
                unsafe { *count = required };
                return CKR_OK;
            }

            let available = unsafe { *count };
            if available < required {
                unsafe { *count = required };
                return CKR_BUFFER_TOO_SMALL;
            }

            for (i, &mt) in types.iter().enumerate() {
                unsafe { *mechanism_list.add(i) = mt as CK_MECHANISM_TYPE };
            }
            unsafe { *count = required };
            CKR_OK
        }
        _ => CKR_DEVICE_ERROR,
    }
}

// ---------------------------------------------------------------------------
// C_GetMechanismInfo
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn C_GetMechanismInfo(
    slot_id: CK_SLOT_ID,
    mechanism_type: CK_MECHANISM_TYPE,
    info: CK_MECHANISM_INFO_PTR,
) -> CK_RV {
    if info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    let req = protocol::GetMechanismInfoRequest {
        slot_id,
        mechanism_type,
    };

    match do_call(Call::GetMechanismInfo(req)) {
        Ok(RespCall::GetMechanismInfo(r)) => {
            let rv = r.rv as CK_RV;
            if rv != CKR_OK {
                return rv;
            }
            if let Some(mi) = r.info {
                let out = unsafe { &mut *info };
                out.ulMinKeySize = mi.min_key_size;
                out.ulMaxKeySize = mi.max_key_size;
                out.flags = mi.flags;
            }
            CKR_OK
        }
        _ => CKR_DEVICE_ERROR,
    }
}

// ---------------------------------------------------------------------------
// C_OpenSession
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn C_OpenSession(
    slot_id: CK_SLOT_ID,
    flags: CK_FLAGS,
    _application: CK_VOID_PTR,
    _notify: CK_NOTIFY,
    session_handle: CK_SESSION_HANDLE_PTR,
) -> CK_RV {
    if session_handle.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    let req = protocol::OpenSessionRequest { slot_id, flags };

    match do_call(Call::OpenSession(req)) {
        Ok(RespCall::OpenSession(r)) => {
            let rv = r.rv as CK_RV;
            if rv == CKR_OK {
                unsafe { *session_handle = r.session_handle };
            }
            rv
        }
        _ => CKR_DEVICE_ERROR,
    }
}

// ---------------------------------------------------------------------------
// C_CloseSession
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn C_CloseSession(session_handle: CK_SESSION_HANDLE) -> CK_RV {
    let req = protocol::CloseSessionRequest { session_handle };

    match do_call(Call::CloseSession(req)) {
        Ok(RespCall::CloseSession(r)) => r.rv as CK_RV,
        _ => CKR_DEVICE_ERROR,
    }
}

// ---------------------------------------------------------------------------
// C_Login
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn C_Login(
    session_handle: CK_SESSION_HANDLE,
    user_type: CK_USER_TYPE,
    pin: CK_UTF8CHAR_PTR,
    pin_len: CK_ULONG,
) -> CK_RV {
    let pin_bytes = unsafe { ptr_to_vec(pin, pin_len) };

    let req = protocol::LoginRequest {
        session_handle,
        user_type,
        pin: pin_bytes,
    };

    match do_call(Call::Login(req)) {
        Ok(RespCall::Login(r)) => r.rv as CK_RV,
        _ => CKR_DEVICE_ERROR,
    }
}

// ---------------------------------------------------------------------------
// C_Logout
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn C_Logout(session_handle: CK_SESSION_HANDLE) -> CK_RV {
    let req = protocol::LogoutRequest { session_handle };

    match do_call(Call::Logout(req)) {
        Ok(RespCall::Logout(r)) => r.rv as CK_RV,
        _ => CKR_DEVICE_ERROR,
    }
}

// ---------------------------------------------------------------------------
// C_FindObjectsInit
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn C_FindObjectsInit(
    session_handle: CK_SESSION_HANDLE,
    template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> CK_RV {
    let attrs = if template.is_null() || count == 0 {
        Vec::new()
    } else {
        unsafe { serialize::serialize_attributes(template, count) }
    };

    let req = protocol::FindObjectsInitRequest {
        session_handle,
        template: attrs,
    };

    match do_call(Call::FindObjectsInit(req)) {
        Ok(RespCall::FindObjectsInit(r)) => r.rv as CK_RV,
        _ => CKR_DEVICE_ERROR,
    }
}

// ---------------------------------------------------------------------------
// C_FindObjects
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn C_FindObjects(
    session_handle: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE_PTR,
    max_object_count: CK_ULONG,
    object_count: CK_ULONG_PTR,
) -> CK_RV {
    if object.is_null() || object_count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    let req = protocol::FindObjectsRequest {
        session_handle,
        max_object_count: max_object_count as u32,
    };

    match do_call(Call::FindObjects(req)) {
        Ok(RespCall::FindObjects(r)) => {
            let rv = r.rv as CK_RV;
            if rv != CKR_OK {
                return rv;
            }

            let handles = &r.object_handles;
            let n = std::cmp::min(handles.len(), max_object_count as usize);
            for (i, &h) in handles.iter().enumerate().take(n) {
                unsafe { *object.add(i) = h as CK_OBJECT_HANDLE };
            }
            unsafe { *object_count = n as CK_ULONG };
            CKR_OK
        }
        _ => CKR_DEVICE_ERROR,
    }
}

// ---------------------------------------------------------------------------
// C_FindObjectsFinal
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn C_FindObjectsFinal(session_handle: CK_SESSION_HANDLE) -> CK_RV {
    let req = protocol::FindObjectsFinalRequest { session_handle };

    match do_call(Call::FindObjectsFinal(req)) {
        Ok(RespCall::FindObjectsFinal(r)) => r.rv as CK_RV,
        _ => CKR_DEVICE_ERROR,
    }
}

// ---------------------------------------------------------------------------
// C_GetAttributeValue
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn C_GetAttributeValue(
    session_handle: CK_SESSION_HANDLE,
    object_handle: CK_OBJECT_HANDLE,
    template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> CK_RV {
    if template.is_null() || count == 0 {
        return CKR_ARGUMENTS_BAD;
    }

    let attrs = unsafe { serialize::serialize_attributes(template, count) };

    let req = protocol::GetAttributeValueRequest {
        session_handle,
        object_handle,
        template: attrs,
    };

    match do_call(Call::GetAttributeValue(req)) {
        Ok(RespCall::GetAttributeValue(r)) => {
            let rv = r.rv as CK_RV;
            // Write back even on CKR_ATTRIBUTE_TYPE_INVALID etc. so that
            // the caller can inspect ulValueLen for each attribute.
            unsafe {
                deserialize::write_attributes(&r.template, template, count);
            }
            rv
        }
        _ => CKR_DEVICE_ERROR,
    }
}

// ---------------------------------------------------------------------------
// C_EncryptInit
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn C_EncryptInit(
    session_handle: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    key_handle: CK_OBJECT_HANDLE,
) -> CK_RV {
    debug!(
        "C_EncryptInit(session={}, key={})",
        session_handle, key_handle
    );
    if mechanism.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    let mech = unsafe { serialize::serialize_mechanism(mechanism) };
    let req = protocol::EncryptInitRequest {
        session_handle,
        mechanism: Some(mech),
        key_handle,
    };

    match do_call(Call::EncryptInit(req)) {
        Ok(RespCall::EncryptInit(r)) => r.rv as CK_RV,
        _ => CKR_DEVICE_ERROR,
    }
}

// ---------------------------------------------------------------------------
// C_Encrypt
// ---------------------------------------------------------------------------

/// Cached encryption result for the two-call pattern.
/// PKCS#11 callers may call C_Encrypt(null) to get the size, then again with a buffer.
/// But the server-side operation is consumed on the first real encrypt, so we cache.
static ENCRYPT_CACHE: parking_lot::Mutex<Option<Vec<u8>>> = parking_lot::Mutex::new(None);

pub unsafe extern "C" fn C_Encrypt(
    session_handle: CK_SESSION_HANDLE,
    data: CK_BYTE_PTR,
    data_len: CK_ULONG,
    encrypted_data: CK_BYTE_PTR,
    encrypted_data_len: CK_ULONG_PTR,
) -> CK_RV {
    debug!(
        "C_Encrypt(session={}, data_len={}, out_null={})",
        session_handle,
        data_len,
        encrypted_data.is_null()
    );
    if encrypted_data_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    // If we have a cached result from a previous size-query call, use it.
    if encrypted_data.is_null() {
        // Size query: do the actual encrypt, cache result, return size.
        let plaintext = unsafe { ptr_to_vec(data, data_len) };

        let req = protocol::EncryptRequest {
            session_handle,
            plaintext,
        };

        match do_call(Call::Encrypt(req)) {
            Ok(RespCall::Encrypt(r)) => {
                let rv = r.rv as CK_RV;
                if rv != CKR_OK {
                    // Do NOT cache the result on error.
                    return rv;
                }
                unsafe { *encrypted_data_len = r.ciphertext.len() as CK_ULONG };
                *ENCRYPT_CACHE.lock() = Some(r.ciphertext);
                CKR_OK
            }
            _ => CKR_DEVICE_ERROR,
        }
    } else {
        // Data call: use cached result if available, otherwise do a fresh encrypt.
        let cached = ENCRYPT_CACHE.lock().take();
        let ciphertext = if let Some(c) = cached {
            c
        } else {
            let plaintext = unsafe { ptr_to_vec(data, data_len) };

            let req = protocol::EncryptRequest {
                session_handle,
                plaintext,
            };

            match do_call(Call::Encrypt(req)) {
                Ok(RespCall::Encrypt(r)) if r.rv as CK_RV == CKR_OK => r.ciphertext,
                Ok(RespCall::Encrypt(r)) => return r.rv as CK_RV,
                _ => return CKR_DEVICE_ERROR,
            }
        };

        unsafe { deserialize::write_to_buffer(&ciphertext, encrypted_data, encrypted_data_len) }
    }
}

// ---------------------------------------------------------------------------
// C_DecryptInit
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn C_DecryptInit(
    session_handle: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    key_handle: CK_OBJECT_HANDLE,
) -> CK_RV {
    debug!(
        "C_DecryptInit(session={}, key={})",
        session_handle, key_handle
    );
    if mechanism.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    let mech = unsafe { serialize::serialize_mechanism(mechanism) };
    let req = protocol::DecryptInitRequest {
        session_handle,
        mechanism: Some(mech),
        key_handle,
    };

    match do_call(Call::DecryptInit(req)) {
        Ok(RespCall::DecryptInit(r)) => r.rv as CK_RV,
        _ => CKR_DEVICE_ERROR,
    }
}

// ---------------------------------------------------------------------------
// C_Decrypt
// ---------------------------------------------------------------------------

static DECRYPT_CACHE: parking_lot::Mutex<Option<Vec<u8>>> = parking_lot::Mutex::new(None);

pub unsafe extern "C" fn C_Decrypt(
    session_handle: CK_SESSION_HANDLE,
    encrypted_data: CK_BYTE_PTR,
    encrypted_data_len: CK_ULONG,
    data: CK_BYTE_PTR,
    data_len: CK_ULONG_PTR,
) -> CK_RV {
    debug!(
        "C_Decrypt(session={}, enc_len={}, out_null={})",
        session_handle,
        encrypted_data_len,
        data.is_null()
    );
    if data_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    if data.is_null() {
        // Size query: do the actual decrypt, cache result, return size.
        let ciphertext = unsafe { ptr_to_vec(encrypted_data, encrypted_data_len) };

        let req = protocol::DecryptRequest {
            session_handle,
            ciphertext,
        };

        match do_call(Call::Decrypt(req)) {
            Ok(RespCall::Decrypt(r)) => {
                let rv = r.rv as CK_RV;
                if rv != CKR_OK {
                    // Do NOT cache the result on error.
                    return rv;
                }
                unsafe { *data_len = r.plaintext.len() as CK_ULONG };
                *DECRYPT_CACHE.lock() = Some(r.plaintext);
                CKR_OK
            }
            _ => CKR_DEVICE_ERROR,
        }
    } else {
        // Data call: use cached result if available.
        let cached = DECRYPT_CACHE.lock().take();
        let plaintext = if let Some(p) = cached {
            p
        } else {
            let ciphertext = unsafe { ptr_to_vec(encrypted_data, encrypted_data_len) };

            let req = protocol::DecryptRequest {
                session_handle,
                ciphertext,
            };

            match do_call(Call::Decrypt(req)) {
                Ok(RespCall::Decrypt(r)) if r.rv as CK_RV == CKR_OK => r.plaintext,
                Ok(RespCall::Decrypt(r)) => return r.rv as CK_RV,
                _ => return CKR_DEVICE_ERROR,
            }
        };

        unsafe { deserialize::write_to_buffer(&plaintext, data, data_len) }
    }
}

// ---------------------------------------------------------------------------
// C_GenerateKey
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn C_GenerateKey(
    session_handle: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
    key_handle: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    if mechanism.is_null() || key_handle.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    let mech = unsafe { serialize::serialize_mechanism(mechanism) };
    let attrs = if template.is_null() || count == 0 {
        Vec::new()
    } else {
        unsafe { serialize::serialize_attributes(template, count) }
    };

    let req = protocol::GenerateKeyRequest {
        session_handle,
        mechanism: Some(mech),
        template: attrs,
    };

    match do_call(Call::GenerateKey(req)) {
        Ok(RespCall::GenerateKey(r)) => {
            let rv = r.rv as CK_RV;
            if rv == CKR_OK {
                unsafe { *key_handle = r.key_handle };
            }
            rv
        }
        _ => CKR_DEVICE_ERROR,
    }
}

// ---------------------------------------------------------------------------
// C_GenerateKeyPair
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn C_GenerateKeyPair(
    session_handle: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    public_key_template: CK_ATTRIBUTE_PTR,
    public_key_attribute_count: CK_ULONG,
    private_key_template: CK_ATTRIBUTE_PTR,
    private_key_attribute_count: CK_ULONG,
    public_key_handle: CK_OBJECT_HANDLE_PTR,
    private_key_handle: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    if mechanism.is_null() || public_key_handle.is_null() || private_key_handle.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    let mech = unsafe { serialize::serialize_mechanism(mechanism) };

    let pub_attrs = if public_key_template.is_null() || public_key_attribute_count == 0 {
        Vec::new()
    } else {
        unsafe { serialize::serialize_attributes(public_key_template, public_key_attribute_count) }
    };

    let priv_attrs = if private_key_template.is_null() || private_key_attribute_count == 0 {
        Vec::new()
    } else {
        unsafe {
            serialize::serialize_attributes(private_key_template, private_key_attribute_count)
        }
    };

    let req = protocol::GenerateKeyPairRequest {
        session_handle,
        mechanism: Some(mech),
        public_key_template: pub_attrs,
        private_key_template: priv_attrs,
    };

    match do_call(Call::GenerateKeyPair(req)) {
        Ok(RespCall::GenerateKeyPair(r)) => {
            let rv = r.rv as CK_RV;
            if rv == CKR_OK {
                unsafe {
                    *public_key_handle = r.public_key_handle;
                    *private_key_handle = r.private_key_handle;
                }
            }
            rv
        }
        _ => CKR_DEVICE_ERROR,
    }
}

// ---------------------------------------------------------------------------
// C_GenerateRandom
// ---------------------------------------------------------------------------

pub unsafe extern "C" fn C_GenerateRandom(
    session: CK_SESSION_HANDLE,
    random_data: CK_BYTE_PTR,
    random_len: CK_ULONG,
) -> CK_RV {
    if random_data.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    match do_call(Call::GenerateRandom(protocol::GenerateRandomRequest {
        session_handle: session,
        length: random_len,
    })) {
        Ok(RespCall::GenerateRandom(r)) => {
            if r.rv == CKR_OK && !r.data.is_empty() {
                let n = std::cmp::min(r.data.len(), random_len as usize);
                unsafe {
                    std::ptr::copy_nonoverlapping(r.data.as_ptr(), random_data, n);
                }
            }
            r.rv as CK_RV
        }
        _ => CKR_DEVICE_ERROR,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Copy a string into a fixed-size, space-padded `CK_UTF8CHAR` array (no NUL
/// terminator) as required by the PKCS#11 spec for info structures.
fn copy_padded_string(src: &str, dst: &mut [CK_UTF8CHAR]) {
    // Fill with spaces first.
    for b in dst.iter_mut() {
        *b = b' ';
    }
    let bytes = src.as_bytes();
    let n = std::cmp::min(bytes.len(), dst.len());
    dst[..n].copy_from_slice(&bytes[..n]);
}
