//! Core dispatch logic.
//!
//! Receives a deserialized protobuf [`Request`], calls the corresponding
//! PKCS#11 function on the real module via raw `cryptoki-sys` FFI, and
//! returns a protobuf [`Response`].

use std::sync::OnceLock;

use tracing::{debug, info, warn};

use pkcs11_common::protocol::*;

use crate::session_map::SessionMap;

// ---------------------------------------------------------------------------
// Helper macros
// ---------------------------------------------------------------------------

/// Helper macro to extract a function pointer from the CK_FUNCTION_LIST,
/// returning CKR_FUNCTION_NOT_SUPPORTED if the function is None.
macro_rules! get_fn {
    ($fl:expr, $func:ident, $resp_variant:ident, $resp_type:ident { $($defaults:tt)* }) => {
        match (*$fl).$func {
            Some(f) => f,
            None => {
                return response::Call::$resp_variant($resp_type {
                    rv: cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED,
                    $($defaults)*
                });
            }
        }
    };
}

/// Helper macro to resolve a proxy session handle to a real session handle,
/// returning CKR_SESSION_HANDLE_INVALID if the handle is not found.
macro_rules! resolve_session {
    ($session_map:expr, $handle:expr, $resp_variant:ident, $resp_type:ident { $($defaults:tt)* }) => {
        match $session_map.get($handle) {
            Some(h) => h,
            None => {
                return response::Call::$resp_variant($resp_type {
                    rv: cryptoki_sys::CKR_SESSION_HANDLE_INVALID,
                    $($defaults)*
                });
            }
        }
    };
}

// ---------------------------------------------------------------------------
// Raw function-list accessor
// ---------------------------------------------------------------------------

/// Wrapper to allow `OnceLock` to store the raw pointer (which is neither
/// `Send` nor `Sync` by default). The pointer is obtained from a loaded
/// PKCS#11 module and remains valid for the process lifetime.
struct FuncListPtr(*mut cryptoki_sys::CK_FUNCTION_LIST);
// Safety: the pointer refers to a static function table inside a loaded
// shared library that outlives the process. It is only ever read after
// initialization.
unsafe impl Send for FuncListPtr {}
unsafe impl Sync for FuncListPtr {}

static FUNCTION_LIST: OnceLock<FuncListPtr> = OnceLock::new();

/// Obtain the raw `CK_FUNCTION_LIST` pointer previously stored via
/// [`set_function_list`].
pub fn get_function_list() -> *mut cryptoki_sys::CK_FUNCTION_LIST {
    FUNCTION_LIST
        .get()
        .map(|w| w.0)
        .unwrap_or(std::ptr::null_mut())
}

/// Set the raw function list pointer. Called once from `main.rs` after
/// resolving `C_GetFunctionList` from the loaded PKCS#11 shared library.
pub fn set_function_list(ptr: *mut cryptoki_sys::CK_FUNCTION_LIST) {
    let _ = FUNCTION_LIST.set(FuncListPtr(ptr));
}

// ---------------------------------------------------------------------------
// Mechanism reconstruction helpers
// ---------------------------------------------------------------------------

/// Result of building a CK_MECHANISM with its backing parameter data.
///
/// The `_backing_*` fields keep the heap-allocated parameter data alive so
/// that the pointers inside `mechanism` remain valid.
struct MechanismWithBacking {
    mechanism: cryptoki_sys::CK_MECHANISM,
    // These fields exist solely to keep the pointed-to memory alive.
    _backing_gcm_iv: Option<Vec<u8>>,
    _backing_gcm_aad: Option<Vec<u8>>,
    _backing_gcm_params: Option<Box<cryptoki_sys::CK_GCM_PARAMS>>,
    _backing_oaep_source: Option<Vec<u8>>,
    _backing_oaep_params: Option<Box<cryptoki_sys::CK_RSA_PKCS_OAEP_PARAMS>>,
    _backing_pss_params: Option<Box<cryptoki_sys::CK_RSA_PKCS_PSS_PARAMS>>,
    _backing_raw: Option<Vec<u8>>,
}

fn build_mechanism(proto_mech: &Mechanism) -> MechanismWithBacking {
    let mech_type = proto_mech.mechanism_type as cryptoki_sys::CK_MECHANISM_TYPE;

    let mut result = MechanismWithBacking {
        mechanism: cryptoki_sys::CK_MECHANISM {
            mechanism: mech_type,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        },
        _backing_gcm_iv: None,
        _backing_gcm_aad: None,
        _backing_gcm_params: None,
        _backing_oaep_source: None,
        _backing_oaep_params: None,
        _backing_pss_params: None,
        _backing_raw: None,
    };

    match &proto_mech.params {
        Some(mechanism::Params::Gcm(gcm)) => {
            let mut iv_data = gcm.iv.clone();
            let mut aad_data = gcm.aad.clone();

            let gcm_params = Box::new(cryptoki_sys::CK_GCM_PARAMS {
                pIv: iv_data.as_mut_ptr(),
                ulIvLen: iv_data.len() as cryptoki_sys::CK_ULONG,
                ulIvBits: gcm.iv_bits as cryptoki_sys::CK_ULONG,
                pAAD: aad_data.as_mut_ptr(),
                ulAADLen: aad_data.len() as cryptoki_sys::CK_ULONG,
                ulTagBits: gcm.tag_bits as cryptoki_sys::CK_ULONG,
            });

            result.mechanism.pParameter =
                &*gcm_params as *const cryptoki_sys::CK_GCM_PARAMS as *mut std::ffi::c_void;
            result.mechanism.ulParameterLen =
                std::mem::size_of::<cryptoki_sys::CK_GCM_PARAMS>() as cryptoki_sys::CK_ULONG;

            // Store backing data to keep it alive.
            result._backing_gcm_iv = Some(iv_data);
            result._backing_gcm_aad = Some(aad_data);
            result._backing_gcm_params = Some(gcm_params);

            // IMPORTANT: The GCM params struct contains pointers into the
            // iv_data and aad_data Vecs. After moving the Vecs into the
            // result struct the heap allocations don't move, so the pointers
            // remain valid. However, to be completely safe we must update
            // the pointers after the move. We do this below.
            //
            // Actually, Vec::clone() returns a new heap allocation. Storing
            // the Vec in the struct doesn't move the heap data — only the
            // (ptr, len, cap) triple on the stack moves. So the pointers
            // captured above into the GCM params struct are still valid.
            // No fixup needed.
        }
        Some(mechanism::Params::RsaOaep(oaep)) => {
            let mut source_data = oaep.source_data.clone();

            let oaep_params = Box::new(cryptoki_sys::CK_RSA_PKCS_OAEP_PARAMS {
                hashAlg: oaep.hash_alg as cryptoki_sys::CK_MECHANISM_TYPE,
                mgf: oaep.mgf as cryptoki_sys::CK_RSA_PKCS_MGF_TYPE,
                source: oaep.source_type as cryptoki_sys::CK_RSA_PKCS_OAEP_SOURCE_TYPE,
                pSourceData: if source_data.is_empty() {
                    std::ptr::null_mut()
                } else {
                    source_data.as_mut_ptr() as *mut std::ffi::c_void
                },
                ulSourceDataLen: source_data.len() as cryptoki_sys::CK_ULONG,
            });

            result.mechanism.pParameter = &*oaep_params
                as *const cryptoki_sys::CK_RSA_PKCS_OAEP_PARAMS
                as *mut std::ffi::c_void;
            result.mechanism.ulParameterLen = std::mem::size_of::<
                cryptoki_sys::CK_RSA_PKCS_OAEP_PARAMS,
            >() as cryptoki_sys::CK_ULONG;

            result._backing_oaep_source = Some(source_data);
            result._backing_oaep_params = Some(oaep_params);
        }
        Some(mechanism::Params::RsaPss(pss)) => {
            let pss_params = Box::new(cryptoki_sys::CK_RSA_PKCS_PSS_PARAMS {
                hashAlg: pss.hash_alg as cryptoki_sys::CK_MECHANISM_TYPE,
                mgf: pss.mgf as cryptoki_sys::CK_RSA_PKCS_MGF_TYPE,
                sLen: pss.salt_len as cryptoki_sys::CK_ULONG,
            });

            result.mechanism.pParameter = &*pss_params
                as *const cryptoki_sys::CK_RSA_PKCS_PSS_PARAMS
                as *mut std::ffi::c_void;
            result.mechanism.ulParameterLen = std::mem::size_of::<
                cryptoki_sys::CK_RSA_PKCS_PSS_PARAMS,
            >() as cryptoki_sys::CK_ULONG;

            result._backing_pss_params = Some(pss_params);
        }
        Some(mechanism::Params::Raw(raw_bytes)) => {
            let mut raw = raw_bytes.clone();
            if !raw.is_empty() {
                result.mechanism.pParameter = raw.as_mut_ptr() as *mut std::ffi::c_void;
                result.mechanism.ulParameterLen = raw.len() as cryptoki_sys::CK_ULONG;
            }
            result._backing_raw = Some(raw);
        }
        None => {
            // No parameters — pParameter stays null.
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Attribute conversion helpers
// ---------------------------------------------------------------------------

fn proto_attrs_to_ck(attrs: &[Attribute]) -> Vec<cryptoki_sys::CK_ATTRIBUTE> {
    attrs
        .iter()
        .map(|a| cryptoki_sys::CK_ATTRIBUTE {
            type_: a.attr_type as cryptoki_sys::CK_ATTRIBUTE_TYPE,
            pValue: if a.value.is_empty() {
                std::ptr::null_mut()
            } else {
                a.value.as_ptr() as *mut std::ffi::c_void
            },
            ulValueLen: a.value.len() as cryptoki_sys::CK_ULONG,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// Dispatch a single protobuf [`Request`] and return the corresponding
/// [`Response`].
pub fn dispatch(session_map: &SessionMap, request: Request) -> Response {
    let fl = get_function_list();

    let call = match request.call {
        Some(c) => c,
        None => {
            warn!("received request with no call variant set");
            return Response { call: None };
        }
    };

    let response_call = match call {
        request::Call::Initialize(_req) => {
            info!("C_Initialize (no-op, already initialized)");
            // The server initializes the module at startup; just return OK.
            response::Call::Initialize(InitializeResponse {
                rv: cryptoki_sys::CKR_OK,
            })
        }

        request::Call::Finalize(_req) => {
            info!("C_Finalize (no-op on server)");
            // Don't actually finalize — other clients may be connected.
            response::Call::Finalize(FinalizeResponse {
                rv: cryptoki_sys::CKR_OK,
            })
        }

        request::Call::GetSlotList(req) => {
            debug!(token_present = req.token_present, "C_GetSlotList");
            handle_get_slot_list(fl, req)
        }

        request::Call::GetSlotInfo(req) => {
            debug!(slot = req.slot_id, "C_GetSlotInfo");
            handle_get_slot_info(fl, req)
        }

        request::Call::GetTokenInfo(req) => {
            debug!(slot = req.slot_id, "C_GetTokenInfo");
            handle_get_token_info(fl, req)
        }

        request::Call::GetMechanismList(req) => {
            debug!(slot = req.slot_id, "C_GetMechanismList");
            handle_get_mechanism_list(fl, req)
        }

        request::Call::GetMechanismInfo(req) => {
            debug!(
                slot = req.slot_id,
                mech = req.mechanism_type,
                "C_GetMechanismInfo"
            );
            handle_get_mechanism_info(fl, req)
        }

        request::Call::OpenSession(req) => {
            info!(slot = req.slot_id, "C_OpenSession");
            handle_open_session(fl, session_map, req)
        }

        request::Call::CloseSession(req) => {
            info!(session = req.session_handle, "C_CloseSession");
            handle_close_session(fl, session_map, req)
        }

        request::Call::Login(req) => {
            info!(
                session = req.session_handle,
                user_type = req.user_type,
                "C_Login"
            );
            handle_login(fl, session_map, req)
        }

        request::Call::Logout(req) => {
            info!(session = req.session_handle, "C_Logout");
            handle_logout(fl, session_map, req)
        }

        request::Call::FindObjectsInit(req) => {
            debug!(session = req.session_handle, "C_FindObjectsInit");
            handle_find_objects_init(fl, session_map, req)
        }

        request::Call::FindObjects(req) => {
            debug!(session = req.session_handle, "C_FindObjects");
            handle_find_objects(fl, session_map, req)
        }

        request::Call::FindObjectsFinal(req) => {
            debug!(session = req.session_handle, "C_FindObjectsFinal");
            handle_find_objects_final(fl, session_map, req)
        }

        request::Call::GetAttributeValue(req) => {
            debug!(
                session = req.session_handle,
                object = req.object_handle,
                "C_GetAttributeValue"
            );
            handle_get_attribute_value(fl, session_map, req)
        }

        request::Call::EncryptInit(req) => {
            info!(
                session = req.session_handle,
                mechanism = req
                    .mechanism
                    .as_ref()
                    .map(|m| m.mechanism_type)
                    .unwrap_or(0),
                "C_EncryptInit"
            );
            handle_encrypt_init(fl, session_map, req)
        }

        request::Call::Encrypt(req) => {
            debug!(session = req.session_handle, "C_Encrypt");
            handle_encrypt(fl, session_map, req)
        }

        request::Call::DecryptInit(req) => {
            info!(
                session = req.session_handle,
                mechanism = req
                    .mechanism
                    .as_ref()
                    .map(|m| m.mechanism_type)
                    .unwrap_or(0),
                "C_DecryptInit"
            );
            handle_decrypt_init(fl, session_map, req)
        }

        request::Call::Decrypt(req) => {
            debug!(session = req.session_handle, "C_Decrypt");
            handle_decrypt(fl, session_map, req)
        }

        request::Call::GenerateKey(req) => {
            info!(session = req.session_handle, "C_GenerateKey");
            handle_generate_key(fl, session_map, req)
        }

        request::Call::GenerateKeyPair(req) => {
            info!(session = req.session_handle, "C_GenerateKeyPair");
            handle_generate_key_pair(fl, session_map, req)
        }

        request::Call::GenerateRandom(req) => {
            debug!(
                session = req.session_handle,
                length = req.length,
                "C_GenerateRandom"
            );
            handle_generate_random(fl, session_map, req)
        }
    };

    Response {
        call: Some(response_call),
    }
}

// ---------------------------------------------------------------------------
// Individual handlers
// ---------------------------------------------------------------------------

fn handle_get_slot_list(
    fl: *mut cryptoki_sys::CK_FUNCTION_LIST,
    req: GetSlotListRequest,
) -> response::Call {
    let token_present = if req.token_present {
        cryptoki_sys::CK_TRUE
    } else {
        cryptoki_sys::CK_FALSE
    };

    unsafe {
        let c_get_slot_list = get_fn!(
            fl,
            C_GetSlotList,
            GetSlotList,
            GetSlotListResponse { slot_ids: vec![] }
        );

        // First call to get count.
        let mut count: cryptoki_sys::CK_ULONG = 0;
        let rv = c_get_slot_list(token_present, std::ptr::null_mut(), &mut count);
        if rv != cryptoki_sys::CKR_OK {
            warn!(
                rv = format_args!("0x{rv:x}"),
                "C_GetSlotList failed (count query)"
            );
            return response::Call::GetSlotList(GetSlotListResponse {
                rv: rv as u64,
                slot_ids: vec![],
            });
        }

        // Second call to get the list.
        let mut slot_ids = vec![0 as cryptoki_sys::CK_SLOT_ID; count as usize];
        let rv = c_get_slot_list(token_present, slot_ids.as_mut_ptr(), &mut count);
        slot_ids.truncate(count as usize);

        let result_ids: Vec<u64> = slot_ids.to_vec();
        debug!(count = result_ids.len(), slots = ?result_ids, "C_GetSlotList result");
        response::Call::GetSlotList(GetSlotListResponse {
            rv: rv as u64,
            slot_ids: result_ids,
        })
    }
}

fn handle_get_slot_info(
    fl: *mut cryptoki_sys::CK_FUNCTION_LIST,
    req: GetSlotInfoRequest,
) -> response::Call {
    unsafe {
        let c_get_slot_info = get_fn!(
            fl,
            C_GetSlotInfo,
            GetSlotInfo,
            GetSlotInfoResponse { info: None }
        );

        let mut info: cryptoki_sys::CK_SLOT_INFO = std::mem::zeroed();
        let rv = c_get_slot_info(req.slot_id as cryptoki_sys::CK_SLOT_ID, &mut info);

        let proto_info = if rv == cryptoki_sys::CKR_OK {
            Some(SlotInfo {
                slot_description: ck_utf8_to_string(&info.slotDescription),
                manufacturer_id: ck_utf8_to_string(&info.manufacturerID),
                flags: info.flags,
                hardware_version_major: info.hardwareVersion.major as u32,
                hardware_version_minor: info.hardwareVersion.minor as u32,
                firmware_version_major: info.firmwareVersion.major as u32,
                firmware_version_minor: info.firmwareVersion.minor as u32,
            })
        } else {
            warn!(
                rv = format_args!("0x{rv:x}"),
                slot = req.slot_id,
                "C_GetSlotInfo failed"
            );
            None
        };

        response::Call::GetSlotInfo(GetSlotInfoResponse {
            rv,
            info: proto_info,
        })
    }
}

fn handle_get_token_info(
    fl: *mut cryptoki_sys::CK_FUNCTION_LIST,
    req: GetTokenInfoRequest,
) -> response::Call {
    unsafe {
        let c_get_token_info = get_fn!(
            fl,
            C_GetTokenInfo,
            GetTokenInfo,
            GetTokenInfoResponse { info: None }
        );

        let mut info: cryptoki_sys::CK_TOKEN_INFO = std::mem::zeroed();
        let rv = c_get_token_info(req.slot_id as cryptoki_sys::CK_SLOT_ID, &mut info);

        let proto_info = if rv == cryptoki_sys::CKR_OK {
            Some(TokenInfo {
                label: ck_utf8_to_string(&info.label),
                manufacturer_id: ck_utf8_to_string(&info.manufacturerID),
                model: ck_utf8_to_string(&info.model),
                serial_number: ck_utf8_to_string(&info.serialNumber),
                flags: info.flags,
                max_session_count: info.ulMaxSessionCount,
                session_count: info.ulSessionCount,
                max_rw_session_count: info.ulMaxRwSessionCount,
                rw_session_count: info.ulRwSessionCount,
                max_pin_len: info.ulMaxPinLen,
                min_pin_len: info.ulMinPinLen,
                total_public_memory: info.ulTotalPublicMemory,
                free_public_memory: info.ulFreePublicMemory,
                total_private_memory: info.ulTotalPrivateMemory,
                free_private_memory: info.ulFreePrivateMemory,
                hardware_version_major: info.hardwareVersion.major as u32,
                hardware_version_minor: info.hardwareVersion.minor as u32,
                firmware_version_major: info.firmwareVersion.major as u32,
                firmware_version_minor: info.firmwareVersion.minor as u32,
                utc_time: ck_utf8_to_string(&info.utcTime),
            })
        } else {
            warn!(
                rv = format_args!("0x{rv:x}"),
                slot = req.slot_id,
                "C_GetTokenInfo failed"
            );
            None
        };

        response::Call::GetTokenInfo(GetTokenInfoResponse {
            rv,
            info: proto_info,
        })
    }
}

fn handle_get_mechanism_list(
    fl: *mut cryptoki_sys::CK_FUNCTION_LIST,
    req: GetMechanismListRequest,
) -> response::Call {
    unsafe {
        let c_get_mechanism_list = get_fn!(
            fl,
            C_GetMechanismList,
            GetMechanismList,
            GetMechanismListResponse {
                mechanism_types: vec![],
            }
        );

        let slot_id = req.slot_id as cryptoki_sys::CK_SLOT_ID;

        // First call to get count.
        let mut count: cryptoki_sys::CK_ULONG = 0;
        let rv = c_get_mechanism_list(slot_id, std::ptr::null_mut(), &mut count);
        if rv != cryptoki_sys::CKR_OK {
            warn!(
                rv = format_args!("0x{rv:x}"),
                slot = req.slot_id,
                "C_GetMechanismList failed (count query)"
            );
            return response::Call::GetMechanismList(GetMechanismListResponse {
                rv: rv as u64,
                mechanism_types: vec![],
            });
        }

        // Second call to get the list.
        let mut mechs = vec![0 as cryptoki_sys::CK_MECHANISM_TYPE; count as usize];
        let rv = c_get_mechanism_list(slot_id, mechs.as_mut_ptr(), &mut count);
        mechs.truncate(count as usize);

        response::Call::GetMechanismList(GetMechanismListResponse {
            rv: rv as u64,
            mechanism_types: mechs.into_iter().collect(),
        })
    }
}

fn handle_get_mechanism_info(
    fl: *mut cryptoki_sys::CK_FUNCTION_LIST,
    req: GetMechanismInfoRequest,
) -> response::Call {
    unsafe {
        let c_get_mechanism_info = get_fn!(
            fl,
            C_GetMechanismInfo,
            GetMechanismInfo,
            GetMechanismInfoResponse { info: None }
        );

        let mut info: cryptoki_sys::CK_MECHANISM_INFO = std::mem::zeroed();
        let rv = c_get_mechanism_info(
            req.slot_id as cryptoki_sys::CK_SLOT_ID,
            req.mechanism_type as cryptoki_sys::CK_MECHANISM_TYPE,
            &mut info,
        );

        let proto_info = if rv == cryptoki_sys::CKR_OK {
            Some(MechanismInfo {
                min_key_size: info.ulMinKeySize,
                max_key_size: info.ulMaxKeySize,
                flags: info.flags,
            })
        } else {
            warn!(
                rv = format_args!("0x{rv:x}"),
                slot = req.slot_id,
                mech = req.mechanism_type,
                "C_GetMechanismInfo failed"
            );
            None
        };

        response::Call::GetMechanismInfo(GetMechanismInfoResponse {
            rv,
            info: proto_info,
        })
    }
}

fn handle_open_session(
    fl: *mut cryptoki_sys::CK_FUNCTION_LIST,
    session_map: &SessionMap,
    req: OpenSessionRequest,
) -> response::Call {
    unsafe {
        let c_open_session = get_fn!(
            fl,
            C_OpenSession,
            OpenSession,
            OpenSessionResponse { session_handle: 0 }
        );

        let mut real_handle: cryptoki_sys::CK_SESSION_HANDLE = 0;
        let rv = c_open_session(
            req.slot_id as cryptoki_sys::CK_SLOT_ID,
            req.flags as cryptoki_sys::CK_FLAGS,
            std::ptr::null_mut(), // pApplication
            None,                 // Notify callback
            &mut real_handle,
        );

        if rv != cryptoki_sys::CKR_OK {
            warn!(
                rv = format_args!("0x{rv:x}"),
                slot = req.slot_id,
                "C_OpenSession failed"
            );
        }

        let proxy_handle = if rv == cryptoki_sys::CKR_OK {
            session_map.create(real_handle as u64)
        } else {
            0
        };

        response::Call::OpenSession(OpenSessionResponse {
            rv: rv as u64,
            session_handle: proxy_handle,
        })
    }
}

fn handle_close_session(
    fl: *mut cryptoki_sys::CK_FUNCTION_LIST,
    session_map: &SessionMap,
    req: CloseSessionRequest,
) -> response::Call {
    let real_handle = resolve_session!(
        session_map,
        req.session_handle,
        CloseSession,
        CloseSessionResponse {}
    );

    unsafe {
        let c_close_session = get_fn!(fl, C_CloseSession, CloseSession, CloseSessionResponse {});

        let rv = c_close_session(real_handle as cryptoki_sys::CK_SESSION_HANDLE);
        if rv == cryptoki_sys::CKR_OK {
            session_map.remove(req.session_handle);
        } else {
            warn!(
                rv = format_args!("0x{rv:x}"),
                session = req.session_handle,
                "C_CloseSession failed"
            );
        }

        response::Call::CloseSession(CloseSessionResponse { rv })
    }
}

fn handle_login(
    fl: *mut cryptoki_sys::CK_FUNCTION_LIST,
    session_map: &SessionMap,
    req: LoginRequest,
) -> response::Call {
    let real_handle = resolve_session!(session_map, req.session_handle, Login, LoginResponse {});

    unsafe {
        let c_login = get_fn!(fl, C_Login, Login, LoginResponse {});

        let pin = req.pin.clone();
        let rv = c_login(
            real_handle as cryptoki_sys::CK_SESSION_HANDLE,
            req.user_type as cryptoki_sys::CK_USER_TYPE,
            pin.as_ptr() as *mut cryptoki_sys::CK_UTF8CHAR,
            pin.len() as cryptoki_sys::CK_ULONG,
        );

        if rv != cryptoki_sys::CKR_OK {
            warn!(
                rv = format_args!("0x{rv:x}"),
                session = req.session_handle,
                "C_Login failed"
            );
        }

        response::Call::Login(LoginResponse { rv })
    }
}

fn handle_logout(
    fl: *mut cryptoki_sys::CK_FUNCTION_LIST,
    session_map: &SessionMap,
    req: LogoutRequest,
) -> response::Call {
    let real_handle = resolve_session!(session_map, req.session_handle, Logout, LogoutResponse {});

    unsafe {
        let c_logout = get_fn!(fl, C_Logout, Logout, LogoutResponse {});

        let rv = c_logout(real_handle as cryptoki_sys::CK_SESSION_HANDLE);
        if rv != cryptoki_sys::CKR_OK {
            warn!(
                rv = format_args!("0x{rv:x}"),
                session = req.session_handle,
                "C_Logout failed"
            );
        }
        response::Call::Logout(LogoutResponse { rv })
    }
}

fn handle_find_objects_init(
    fl: *mut cryptoki_sys::CK_FUNCTION_LIST,
    session_map: &SessionMap,
    req: FindObjectsInitRequest,
) -> response::Call {
    let real_handle = resolve_session!(
        session_map,
        req.session_handle,
        FindObjectsInit,
        FindObjectsInitResponse {}
    );

    unsafe {
        let c_find_objects_init = get_fn!(
            fl,
            C_FindObjectsInit,
            FindObjectsInit,
            FindObjectsInitResponse {}
        );

        let mut ck_attrs = proto_attrs_to_ck(&req.template);
        let rv = c_find_objects_init(
            real_handle as cryptoki_sys::CK_SESSION_HANDLE,
            if ck_attrs.is_empty() {
                std::ptr::null_mut()
            } else {
                ck_attrs.as_mut_ptr()
            },
            ck_attrs.len() as cryptoki_sys::CK_ULONG,
        );

        if rv != cryptoki_sys::CKR_OK {
            warn!(
                rv = format_args!("0x{rv:x}"),
                session = req.session_handle,
                "C_FindObjectsInit failed"
            );
        }

        response::Call::FindObjectsInit(FindObjectsInitResponse { rv: rv as u64 })
    }
}

fn handle_find_objects(
    fl: *mut cryptoki_sys::CK_FUNCTION_LIST,
    session_map: &SessionMap,
    req: FindObjectsRequest,
) -> response::Call {
    let real_handle = resolve_session!(
        session_map,
        req.session_handle,
        FindObjects,
        FindObjectsResponse {
            object_handles: vec![],
        }
    );

    unsafe {
        let c_find_objects = get_fn!(
            fl,
            C_FindObjects,
            FindObjects,
            FindObjectsResponse {
                object_handles: vec![],
            }
        );

        let max_count = req.max_object_count as usize;
        let mut handles = vec![0 as cryptoki_sys::CK_OBJECT_HANDLE; max_count];
        let mut found_count: cryptoki_sys::CK_ULONG = 0;

        let rv = c_find_objects(
            real_handle as cryptoki_sys::CK_SESSION_HANDLE,
            handles.as_mut_ptr(),
            max_count as cryptoki_sys::CK_ULONG,
            &mut found_count,
        );

        handles.truncate(found_count as usize);

        response::Call::FindObjects(FindObjectsResponse {
            rv: rv as u64,
            object_handles: handles.into_iter().collect(),
        })
    }
}

fn handle_find_objects_final(
    fl: *mut cryptoki_sys::CK_FUNCTION_LIST,
    session_map: &SessionMap,
    req: FindObjectsFinalRequest,
) -> response::Call {
    let real_handle = resolve_session!(
        session_map,
        req.session_handle,
        FindObjectsFinal,
        FindObjectsFinalResponse {}
    );

    unsafe {
        let c_find_objects_final = get_fn!(
            fl,
            C_FindObjectsFinal,
            FindObjectsFinal,
            FindObjectsFinalResponse {}
        );

        let rv = c_find_objects_final(real_handle as cryptoki_sys::CK_SESSION_HANDLE);
        response::Call::FindObjectsFinal(FindObjectsFinalResponse { rv })
    }
}

fn handle_get_attribute_value(
    fl: *mut cryptoki_sys::CK_FUNCTION_LIST,
    session_map: &SessionMap,
    req: GetAttributeValueRequest,
) -> response::Call {
    let real_handle = resolve_session!(
        session_map,
        req.session_handle,
        GetAttributeValue,
        GetAttributeValueResponse { template: vec![] }
    );

    unsafe {
        let c_get_attribute_value = get_fn!(
            fl,
            C_GetAttributeValue,
            GetAttributeValue,
            GetAttributeValueResponse { template: vec![] }
        );

        // Phase 1: Query attribute sizes.
        let mut ck_attrs: Vec<cryptoki_sys::CK_ATTRIBUTE> = req
            .template
            .iter()
            .map(|a| cryptoki_sys::CK_ATTRIBUTE {
                type_: a.attr_type as cryptoki_sys::CK_ATTRIBUTE_TYPE,
                pValue: std::ptr::null_mut(),
                ulValueLen: 0,
            })
            .collect();

        let rv = c_get_attribute_value(
            real_handle as cryptoki_sys::CK_SESSION_HANDLE,
            req.object_handle as cryptoki_sys::CK_OBJECT_HANDLE,
            ck_attrs.as_mut_ptr(),
            ck_attrs.len() as cryptoki_sys::CK_ULONG,
        );

        // If any attribute is unavailable, rv may be CKR_ATTRIBUTE_TYPE_INVALID
        // or CKR_ATTRIBUTE_SENSITIVE, but we still proceed to read the ones
        // that are available.
        if rv != cryptoki_sys::CKR_OK
            && rv != cryptoki_sys::CKR_ATTRIBUTE_TYPE_INVALID
            && rv != cryptoki_sys::CKR_ATTRIBUTE_SENSITIVE
        {
            warn!(
                rv = format_args!("0x{rv:x}"),
                session = req.session_handle,
                object = req.object_handle,
                "C_GetAttributeValue failed"
            );
            return response::Call::GetAttributeValue(GetAttributeValueResponse {
                rv,
                template: vec![],
            });
        }

        // Phase 2: Allocate buffers and read values.
        let mut buffers: Vec<Vec<u8>> = ck_attrs
            .iter()
            .map(|a| {
                if a.ulValueLen != cryptoki_sys::CK_UNAVAILABLE_INFORMATION && a.ulValueLen > 0 {
                    vec![0u8; a.ulValueLen as usize]
                } else {
                    Vec::new()
                }
            })
            .collect();

        for (ck_attr, buf) in ck_attrs.iter_mut().zip(buffers.iter_mut()) {
            if !buf.is_empty() {
                ck_attr.pValue = buf.as_mut_ptr() as *mut std::ffi::c_void;
                ck_attr.ulValueLen = buf.len() as cryptoki_sys::CK_ULONG;
            }
        }

        let rv2 = c_get_attribute_value(
            real_handle as cryptoki_sys::CK_SESSION_HANDLE,
            req.object_handle as cryptoki_sys::CK_OBJECT_HANDLE,
            ck_attrs.as_mut_ptr(),
            ck_attrs.len() as cryptoki_sys::CK_ULONG,
        );

        // Build response template.
        let result_attrs: Vec<Attribute> = ck_attrs
            .iter()
            .zip(buffers.iter())
            .zip(req.template.iter())
            .map(|((ck, buf), orig)| {
                let value = if ck.ulValueLen == cryptoki_sys::CK_UNAVAILABLE_INFORMATION
                    || ck.pValue.is_null()
                {
                    Vec::new()
                } else {
                    buf[..ck.ulValueLen as usize].to_vec()
                };
                Attribute {
                    attr_type: orig.attr_type,
                    value,
                }
            })
            .collect();

        response::Call::GetAttributeValue(GetAttributeValueResponse {
            rv: rv2,
            template: result_attrs,
        })
    }
}

fn handle_encrypt_init(
    fl: *mut cryptoki_sys::CK_FUNCTION_LIST,
    session_map: &SessionMap,
    req: EncryptInitRequest,
) -> response::Call {
    let real_handle = resolve_session!(
        session_map,
        req.session_handle,
        EncryptInit,
        EncryptInitResponse {}
    );

    let proto_mech = match &req.mechanism {
        Some(m) => m,
        None => {
            return response::Call::EncryptInit(EncryptInitResponse {
                rv: cryptoki_sys::CKR_MECHANISM_INVALID,
            });
        }
    };

    let mut mech_with_backing = build_mechanism(proto_mech);

    unsafe {
        let c_encrypt_init = get_fn!(fl, C_EncryptInit, EncryptInit, EncryptInitResponse {});

        let rv = c_encrypt_init(
            real_handle as cryptoki_sys::CK_SESSION_HANDLE,
            &mut mech_with_backing.mechanism,
            req.key_handle as cryptoki_sys::CK_OBJECT_HANDLE,
        );

        if rv != cryptoki_sys::CKR_OK {
            warn!(
                rv = format_args!("0x{rv:x}"),
                session = req.session_handle,
                "C_EncryptInit failed"
            );
        }

        response::Call::EncryptInit(EncryptInitResponse { rv: rv as u64 })
    }
}

fn handle_encrypt(
    fl: *mut cryptoki_sys::CK_FUNCTION_LIST,
    session_map: &SessionMap,
    req: EncryptRequest,
) -> response::Call {
    let real_handle = resolve_session!(
        session_map,
        req.session_handle,
        Encrypt,
        EncryptResponse { ciphertext: vec![] }
    );

    unsafe {
        let c_encrypt = get_fn!(
            fl,
            C_Encrypt,
            Encrypt,
            EncryptResponse { ciphertext: vec![] }
        );

        let mut plaintext = req.plaintext.clone();

        // Allocate generously: plaintext + 256 bytes for tag/padding overhead.
        let mut out_len: cryptoki_sys::CK_ULONG = (plaintext.len() + 256) as cryptoki_sys::CK_ULONG;
        let mut ciphertext = vec![0u8; out_len as usize];

        let rv = c_encrypt(
            real_handle as cryptoki_sys::CK_SESSION_HANDLE,
            plaintext.as_mut_ptr(),
            plaintext.len() as cryptoki_sys::CK_ULONG,
            ciphertext.as_mut_ptr(),
            &mut out_len,
        );

        if rv != cryptoki_sys::CKR_OK {
            warn!(
                rv = format_args!("0x{rv:x}"),
                session = req.session_handle,
                "C_Encrypt failed"
            );
        }

        ciphertext.truncate(out_len as usize);

        response::Call::Encrypt(EncryptResponse {
            rv: rv as u64,
            ciphertext,
        })
    }
}

fn handle_decrypt_init(
    fl: *mut cryptoki_sys::CK_FUNCTION_LIST,
    session_map: &SessionMap,
    req: DecryptInitRequest,
) -> response::Call {
    let real_handle = resolve_session!(
        session_map,
        req.session_handle,
        DecryptInit,
        DecryptInitResponse {}
    );

    let proto_mech = match &req.mechanism {
        Some(m) => m,
        None => {
            return response::Call::DecryptInit(DecryptInitResponse {
                rv: cryptoki_sys::CKR_MECHANISM_INVALID,
            });
        }
    };

    let mut mech_with_backing = build_mechanism(proto_mech);

    unsafe {
        let c_decrypt_init = get_fn!(fl, C_DecryptInit, DecryptInit, DecryptInitResponse {});

        let rv = c_decrypt_init(
            real_handle as cryptoki_sys::CK_SESSION_HANDLE,
            &mut mech_with_backing.mechanism,
            req.key_handle as cryptoki_sys::CK_OBJECT_HANDLE,
        );

        if rv != cryptoki_sys::CKR_OK {
            warn!(
                rv = format_args!("0x{rv:x}"),
                session = req.session_handle,
                "C_DecryptInit failed"
            );
        }

        response::Call::DecryptInit(DecryptInitResponse { rv: rv as u64 })
    }
}

fn handle_decrypt(
    fl: *mut cryptoki_sys::CK_FUNCTION_LIST,
    session_map: &SessionMap,
    req: DecryptRequest,
) -> response::Call {
    let real_handle = resolve_session!(
        session_map,
        req.session_handle,
        Decrypt,
        DecryptResponse { plaintext: vec![] }
    );

    unsafe {
        let c_decrypt = get_fn!(
            fl,
            C_Decrypt,
            Decrypt,
            DecryptResponse { plaintext: vec![] }
        );

        let mut ciphertext = req.ciphertext.clone();

        // Allocate generously: ciphertext size is an upper bound for plaintext.
        let mut out_len: cryptoki_sys::CK_ULONG =
            (ciphertext.len() + 256) as cryptoki_sys::CK_ULONG;
        let mut plaintext = vec![0u8; out_len as usize];
        let rv = c_decrypt(
            real_handle as cryptoki_sys::CK_SESSION_HANDLE,
            ciphertext.as_mut_ptr(),
            ciphertext.len() as cryptoki_sys::CK_ULONG,
            plaintext.as_mut_ptr(),
            &mut out_len,
        );

        if rv != cryptoki_sys::CKR_OK {
            warn!(
                rv = format_args!("0x{rv:x}"),
                session = req.session_handle,
                "C_Decrypt failed"
            );
        }

        plaintext.truncate(out_len as usize);

        response::Call::Decrypt(DecryptResponse {
            rv: rv as u64,
            plaintext,
        })
    }
}

fn handle_generate_key(
    fl: *mut cryptoki_sys::CK_FUNCTION_LIST,
    session_map: &SessionMap,
    req: GenerateKeyRequest,
) -> response::Call {
    let real_handle = resolve_session!(
        session_map,
        req.session_handle,
        GenerateKey,
        GenerateKeyResponse { key_handle: 0 }
    );

    let proto_mech = match &req.mechanism {
        Some(m) => m,
        None => {
            return response::Call::GenerateKey(GenerateKeyResponse {
                rv: cryptoki_sys::CKR_MECHANISM_INVALID,
                key_handle: 0,
            });
        }
    };

    let mut mech_with_backing = build_mechanism(proto_mech);
    let mut ck_attrs = proto_attrs_to_ck(&req.template);

    unsafe {
        let c_generate_key = get_fn!(
            fl,
            C_GenerateKey,
            GenerateKey,
            GenerateKeyResponse { key_handle: 0 }
        );

        let mut key_handle: cryptoki_sys::CK_OBJECT_HANDLE = 0;
        let rv = c_generate_key(
            real_handle as cryptoki_sys::CK_SESSION_HANDLE,
            &mut mech_with_backing.mechanism,
            if ck_attrs.is_empty() {
                std::ptr::null_mut()
            } else {
                ck_attrs.as_mut_ptr()
            },
            ck_attrs.len() as cryptoki_sys::CK_ULONG,
            &mut key_handle,
        );

        if rv != cryptoki_sys::CKR_OK {
            warn!(
                rv = format_args!("0x{rv:x}"),
                session = req.session_handle,
                "C_GenerateKey failed"
            );
        }

        response::Call::GenerateKey(GenerateKeyResponse {
            rv: rv as u64,
            key_handle: key_handle as u64,
        })
    }
}

fn handle_generate_key_pair(
    fl: *mut cryptoki_sys::CK_FUNCTION_LIST,
    session_map: &SessionMap,
    req: GenerateKeyPairRequest,
) -> response::Call {
    let real_handle = resolve_session!(
        session_map,
        req.session_handle,
        GenerateKeyPair,
        GenerateKeyPairResponse {
            public_key_handle: 0,
            private_key_handle: 0,
        }
    );

    let proto_mech = match &req.mechanism {
        Some(m) => m,
        None => {
            return response::Call::GenerateKeyPair(GenerateKeyPairResponse {
                rv: cryptoki_sys::CKR_MECHANISM_INVALID,
                public_key_handle: 0,
                private_key_handle: 0,
            });
        }
    };

    let mut mech_with_backing = build_mechanism(proto_mech);
    let mut pub_attrs = proto_attrs_to_ck(&req.public_key_template);
    let mut priv_attrs = proto_attrs_to_ck(&req.private_key_template);

    unsafe {
        let c_generate_key_pair = get_fn!(
            fl,
            C_GenerateKeyPair,
            GenerateKeyPair,
            GenerateKeyPairResponse {
                public_key_handle: 0,
                private_key_handle: 0,
            }
        );

        let mut pub_handle: cryptoki_sys::CK_OBJECT_HANDLE = 0;
        let mut priv_handle: cryptoki_sys::CK_OBJECT_HANDLE = 0;

        let rv = c_generate_key_pair(
            real_handle as cryptoki_sys::CK_SESSION_HANDLE,
            &mut mech_with_backing.mechanism,
            if pub_attrs.is_empty() {
                std::ptr::null_mut()
            } else {
                pub_attrs.as_mut_ptr()
            },
            pub_attrs.len() as cryptoki_sys::CK_ULONG,
            if priv_attrs.is_empty() {
                std::ptr::null_mut()
            } else {
                priv_attrs.as_mut_ptr()
            },
            priv_attrs.len() as cryptoki_sys::CK_ULONG,
            &mut pub_handle,
            &mut priv_handle,
        );

        if rv != cryptoki_sys::CKR_OK {
            warn!(
                rv = format_args!("0x{rv:x}"),
                session = req.session_handle,
                "C_GenerateKeyPair failed"
            );
        }

        response::Call::GenerateKeyPair(GenerateKeyPairResponse {
            rv: rv as u64,
            public_key_handle: pub_handle as u64,
            private_key_handle: priv_handle as u64,
        })
    }
}

fn handle_generate_random(
    fl: *mut cryptoki_sys::CK_FUNCTION_LIST,
    session_map: &SessionMap,
    req: GenerateRandomRequest,
) -> response::Call {
    let real_session = resolve_session!(
        session_map,
        req.session_handle,
        GenerateRandom,
        GenerateRandomResponse { data: vec![] }
    );

    unsafe {
        let c_generate_random = get_fn!(
            fl,
            C_GenerateRandom,
            GenerateRandom,
            GenerateRandomResponse { data: vec![] }
        );

        let len = req.length as usize;
        let mut buf = vec![0u8; len];
        let rv = c_generate_random(
            real_session as cryptoki_sys::CK_SESSION_HANDLE,
            buf.as_mut_ptr(),
            len as cryptoki_sys::CK_ULONG,
        );

        if rv != cryptoki_sys::CKR_OK {
            warn!(
                rv = format_args!("0x{rv:x}"),
                session = req.session_handle,
                "C_GenerateRandom failed"
            );
        }

        response::Call::GenerateRandom(GenerateRandomResponse {
            rv,
            data: if rv == cryptoki_sys::CKR_OK {
                buf
            } else {
                vec![]
            },
        })
    }
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

/// Convert a fixed-size PKCS#11 UTF-8 padded character array to a trimmed
/// Rust `String`.
fn ck_utf8_to_string(buf: &[u8]) -> String {
    String::from_utf8_lossy(buf).trim_end().to_string()
}
