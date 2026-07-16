//! ML-KEM encapsulation and AES Key Wrap for CRMF key archival.

use crate::{DogtagError, DogtagResult};

/// Result of an ML-KEM encapsulation.
pub struct KemEncapsulation {
    /// KEM ciphertext — sent to the KRA alongside the wrapped key.
    pub ciphertext: Vec<u8>,
    /// Shared secret — used as the AES-KWP key to wrap the private key.
    pub shared_secret: Vec<u8>,
}

/// ML-KEM encapsulate against a transport cert's SPKI DER.
///
/// Calls `EVP_PKEY_encapsulate` via FFI (the `openssl` crate 0.10.x
/// doesn't expose KEM operations yet). Returns the KEM ciphertext and
/// the derived shared secret.
pub fn ml_kem_encapsulate(transport_pub_key_der: &[u8]) -> DogtagResult<KemEncapsulation> {
    unsafe {
        let mut ptr = transport_pub_key_der.as_ptr();
        let evp_pkey = openssl_sys::d2i_PUBKEY(
            std::ptr::null_mut(),
            &mut ptr,
            transport_pub_key_der.len() as std::os::raw::c_long,
        );
        if evp_pkey.is_null() {
            return Err(DogtagError::KraError("d2i_PUBKEY failed for transport key".into()));
        }

        let ctx = openssl_sys::EVP_PKEY_CTX_new(evp_pkey, std::ptr::null_mut());
        if ctx.is_null() {
            openssl_sys::EVP_PKEY_free(evp_pkey);
            return Err(DogtagError::KraError("EVP_PKEY_CTX_new failed".into()));
        }

        let rc = openssl_sys::EVP_PKEY_encapsulate_init(ctx, std::ptr::null());
        if rc <= 0 {
            openssl_sys::EVP_PKEY_CTX_free(ctx);
            openssl_sys::EVP_PKEY_free(evp_pkey);
            return Err(DogtagError::KraError(
                "EVP_PKEY_encapsulate_init failed".into(),
            ));
        }

        // Query output sizes
        let mut ct_len: usize = 0;
        let mut ss_len: usize = 0;
        let rc = openssl_sys::EVP_PKEY_encapsulate(
            ctx,
            std::ptr::null_mut(),
            &mut ct_len,
            std::ptr::null_mut(),
            &mut ss_len,
        );
        if rc <= 0 {
            openssl_sys::EVP_PKEY_CTX_free(ctx);
            openssl_sys::EVP_PKEY_free(evp_pkey);
            return Err(DogtagError::KraError(
                "EVP_PKEY_encapsulate size query failed".into(),
            ));
        }

        let mut ciphertext = vec![0u8; ct_len];
        let mut shared_secret = vec![0u8; ss_len];

        let rc = openssl_sys::EVP_PKEY_encapsulate(
            ctx,
            ciphertext.as_mut_ptr(),
            &mut ct_len,
            shared_secret.as_mut_ptr(),
            &mut ss_len,
        );
        openssl_sys::EVP_PKEY_CTX_free(ctx);
        openssl_sys::EVP_PKEY_free(evp_pkey);

        if rc <= 0 {
            return Err(DogtagError::KraError(
                "EVP_PKEY_encapsulate failed".into(),
            ));
        }

        ciphertext.truncate(ct_len);
        shared_secret.truncate(ss_len);

        tracing::info!(
            ct_len = ciphertext.len(),
            ss_len = shared_secret.len(),
            "ML-KEM encapsulation complete"
        );

        Ok(KemEncapsulation {
            ciphertext,
            shared_secret,
        })
    }
}

/// AES Key Wrap with Padding (RFC 5649) — wraps `plaintext` under `kek`.
pub fn aes_kwp_wrap(kek: &[u8], plaintext: &[u8]) -> DogtagResult<Vec<u8>> {
    unsafe {
        let cipher_name = match kek.len() {
            16 => c"AES-128-WRAP-PAD",
            24 => c"AES-192-WRAP-PAD",
            32 => c"AES-256-WRAP-PAD",
            _ => {
                return Err(DogtagError::KraError(format!(
                    "Invalid KEK length {} (expected 16, 24, or 32)",
                    kek.len()
                )))
            }
        };

        let cipher = openssl_sys::EVP_CIPHER_fetch(
            std::ptr::null_mut(),
            cipher_name.as_ptr(),
            std::ptr::null(),
        );
        if cipher.is_null() {
            return Err(DogtagError::KraError(
                "AES-KWP cipher not available".into(),
            ));
        }

        let ctx = openssl_sys::EVP_CIPHER_CTX_new();
        if ctx.is_null() {
            openssl_sys::EVP_CIPHER_free(cipher as *mut _);
            return Err(DogtagError::KraError(
                "EVP_CIPHER_CTX_new failed".into(),
            ));
        }

        openssl_sys::EVP_CIPHER_CTX_set_flags(
            ctx,
            openssl_sys::EVP_CIPHER_CTX_FLAG_WRAP_ALLOW,
        );

        let rc = openssl_sys::EVP_EncryptInit_ex(
            ctx,
            cipher,
            std::ptr::null_mut(),
            kek.as_ptr(),
            std::ptr::null(),
        );
        // cipher ref now held by ctx; free our fetch ref
        openssl_sys::EVP_CIPHER_free(cipher as *mut _);
        if rc != 1 {
            openssl_sys::EVP_CIPHER_CTX_free(ctx);
            return Err(DogtagError::KraError("EVP_EncryptInit_ex failed".into()));
        }

        let max_out = plaintext.len() + 32;
        let mut output = vec![0u8; max_out];
        let mut out_len: i32 = 0;

        let rc = openssl_sys::EVP_EncryptUpdate(
            ctx,
            output.as_mut_ptr(),
            &mut out_len,
            plaintext.as_ptr(),
            plaintext.len() as i32,
        );
        if rc != 1 {
            openssl_sys::EVP_CIPHER_CTX_free(ctx);
            return Err(DogtagError::KraError("EVP_EncryptUpdate failed".into()));
        }

        let mut final_len: i32 = 0;
        let rc = openssl_sys::EVP_EncryptFinal_ex(
            ctx,
            output.as_mut_ptr().add(out_len as usize),
            &mut final_len,
        );
        openssl_sys::EVP_CIPHER_CTX_free(ctx);

        if rc != 1 {
            return Err(DogtagError::KraError("EVP_EncryptFinal_ex failed".into()));
        }

        let total = (out_len + final_len) as usize;
        output.truncate(total);

        tracing::debug!(
            kek_len = kek.len(),
            plaintext_len = plaintext.len(),
            wrapped_len = total,
            "AES-KWP wrap complete"
        );

        Ok(output)
    }
}
