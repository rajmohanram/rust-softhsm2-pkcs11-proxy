//! Deserialization helpers: write protobuf response data back into C output
//! buffers provided by the PKCS#11 caller.

use cryptoki_sys::*;

use pkcs11_common::protocol;

/// Write `data` into a caller-supplied buffer.
///
/// Follows the PKCS#11 convention:
/// - If `out_ptr` is null, only write the required length to `*out_len`.
/// - If the buffer is too small, set `*out_len` to the required length and
///   return `CKR_BUFFER_TOO_SMALL`.
/// - Otherwise copy the data and set `*out_len` to the actual length.
///
/// # Safety
///
/// `out_len` must be a valid, non-null pointer. If `out_ptr` is non-null it
/// must point to a buffer of at least `*out_len` bytes.
pub unsafe fn write_to_buffer(data: &[u8], out_ptr: *mut CK_BYTE, out_len: *mut CK_ULONG) -> CK_RV {
    let required = data.len() as CK_ULONG;

    if out_ptr.is_null() {
        // Caller is querying the required size.
        unsafe { *out_len = required };
        return CKR_OK;
    }

    let available = unsafe { *out_len };
    if available < required {
        unsafe { *out_len = required };
        return CKR_BUFFER_TOO_SMALL;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(data.as_ptr(), out_ptr, data.len());
        *out_len = required;
    }

    CKR_OK
}

/// Write protobuf `Attribute` values back into the caller's `CK_ATTRIBUTE`
/// template.
///
/// # Safety
///
/// - `template` must point to `count` consecutive, writable `CK_ATTRIBUTE` structs.
/// - Each attribute's `pValue` (if non-null) must be valid for `ulValueLen` bytes.
pub unsafe fn write_attributes(
    attrs: &[protocol::Attribute],
    template: *mut CK_ATTRIBUTE,
    count: u64,
) {
    let n = std::cmp::min(attrs.len(), count as usize);
    for (i, src) in attrs.iter().enumerate().take(n) {
        let dst = unsafe { &mut *template.add(i) };

        // Always report the true length.
        dst.ulValueLen = src.value.len() as CK_ULONG;

        if !dst.pValue.is_null() && !src.value.is_empty() {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    src.value.as_ptr(),
                    dst.pValue as *mut u8,
                    src.value.len(),
                );
            }
        }
    }
}
