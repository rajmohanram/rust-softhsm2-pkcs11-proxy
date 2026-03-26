//! Serialization helpers: convert raw CK_* C types to protobuf messages.

use cryptoki_sys::*;

use pkcs11_common::protocol;

/// Convert a `CK_MECHANISM` pointer to a protobuf `Mechanism`.
///
/// # Safety
///
/// - `mech` must be a valid, non-null pointer to a `CK_MECHANISM`.
/// - For mechanisms with known parameter structs (GCM, OAEP, PSS), the
///   `pParameter` field must point to a correctly-sized and initialized
///   struct and any embedded pointers (e.g. `pIv`, `pAAD`) must be valid
///   for their declared lengths.
pub unsafe fn serialize_mechanism(mech: *const CK_MECHANISM) -> protocol::Mechanism {
    let mech = unsafe { &*mech };
    let mechanism_type = mech.mechanism;

    let params = if mech.pParameter.is_null() || mech.ulParameterLen == 0 {
        None
    } else {
        match mechanism_type {
            CKM_AES_GCM => {
                let p = unsafe { &*(mech.pParameter as *const CK_GCM_PARAMS) };
                let iv = if p.pIv.is_null() || p.ulIvLen == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(p.pIv, p.ulIvLen as usize) }.to_vec()
                };
                let aad = if p.pAAD.is_null() || p.ulAADLen == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(p.pAAD, p.ulAADLen as usize) }.to_vec()
                };
                Some(protocol::mechanism::Params::Gcm(protocol::GcmParams {
                    iv,
                    iv_bits: p.ulIvBits as u32,
                    aad,
                    tag_bits: p.ulTagBits as u32,
                }))
            }
            CKM_RSA_PKCS_OAEP => {
                let p = unsafe { &*(mech.pParameter as *const CK_RSA_PKCS_OAEP_PARAMS) };
                let source_data = if p.pSourceData.is_null() || p.ulSourceDataLen == 0 {
                    Vec::new()
                } else {
                    unsafe {
                        std::slice::from_raw_parts(
                            p.pSourceData as *const u8,
                            p.ulSourceDataLen as usize,
                        )
                    }
                    .to_vec()
                };
                Some(protocol::mechanism::Params::RsaOaep(
                    protocol::RsaOaepParams {
                        hash_alg: p.hashAlg,
                        mgf: p.mgf,
                        source_type: p.source,
                        source_data,
                    },
                ))
            }
            CKM_RSA_PKCS_PSS
            | CKM_SHA1_RSA_PKCS_PSS
            | CKM_SHA256_RSA_PKCS_PSS
            | CKM_SHA384_RSA_PKCS_PSS
            | CKM_SHA512_RSA_PKCS_PSS => {
                let p = unsafe { &*(mech.pParameter as *const CK_RSA_PKCS_PSS_PARAMS) };
                Some(protocol::mechanism::Params::RsaPss(
                    protocol::RsaPssParams {
                        hash_alg: p.hashAlg,
                        mgf: p.mgf,
                        salt_len: p.sLen,
                    },
                ))
            }
            _ => {
                // Fallback: raw byte copy of the parameter block.
                let raw = unsafe {
                    std::slice::from_raw_parts(
                        mech.pParameter as *const u8,
                        mech.ulParameterLen as usize,
                    )
                }
                .to_vec();
                Some(protocol::mechanism::Params::Raw(raw))
            }
        }
    };

    protocol::Mechanism {
        mechanism_type,
        params,
    }
}

/// Convert a C `CK_ATTRIBUTE` template array to a vector of protobuf `Attribute` messages.
///
/// # Safety
///
/// - `template` must be a valid pointer to `count` consecutive `CK_ATTRIBUTE` structs.
/// - Each attribute's `pValue` (if non-null) must be valid for `ulValueLen` bytes.
pub unsafe fn serialize_attributes(
    template: *const CK_ATTRIBUTE,
    count: u64,
) -> Vec<protocol::Attribute> {
    let mut attrs = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let attr = unsafe { &*template.add(i) };
        let value = if attr.pValue.is_null() || attr.ulValueLen == 0 {
            Vec::new()
        } else {
            unsafe {
                std::slice::from_raw_parts(attr.pValue as *const u8, attr.ulValueLen as usize)
            }
            .to_vec()
        };
        attrs.push(protocol::Attribute {
            attr_type: attr.type_,
            value,
        });
    }
    attrs
}
