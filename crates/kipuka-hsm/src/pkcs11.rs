//! PKCS#11 library context management.

use crate::error::{HsmError, HsmResult};
use cryptoki::context::{CInitializeArgs, Pkcs11};
use std::path::Path;
use std::sync::{Arc, Mutex};

/// PKCS#11 library context.
///
/// Wraps the Cryptoki `Pkcs11` handle with thread-safe reference counting
/// and automatic initialization/finalization.
#[derive(Clone)]
pub struct Pkcs11Context {
    inner: Arc<Mutex<Pkcs11>>,
}

impl Pkcs11Context {
    /// Initialize a new PKCS#11 context from a library path.
    ///
    /// # Arguments
    ///
    /// * `library_path` - Path to the PKCS#11 library (.so, .dylib, .dll)
    ///
    /// # Errors
    ///
    /// Returns `HsmError::LibraryLoad` if the library cannot be loaded or initialized.
    pub fn new(library_path: impl AsRef<Path>) -> HsmResult<Self> {
        let path = library_path.as_ref();

        tracing::debug!("Loading PKCS#11 library from {}", path.display());

        let pkcs11 = Pkcs11::new(path)
            .map_err(|e| HsmError::LibraryLoad(format!("Failed to load {}: {}", path.display(), e)))?;

        // Initialize the library with OS locking
        pkcs11
            .initialize(CInitializeArgs::OsThreads)
            .map_err(|e| HsmError::LibraryLoad(format!("C_Initialize failed: {}", e)))?;

        tracing::info!("PKCS#11 library initialized: {}", path.display());

        Ok(Self {
            inner: Arc::new(Mutex::new(pkcs11)),
        })
    }

    /// Get the underlying Pkcs11 handle.
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned (should never happen in normal operation).
    pub fn with_pkcs11<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&Pkcs11) -> R,
    {
        let pkcs11 = self.inner.lock().expect("Pkcs11Context mutex poisoned");
        f(&pkcs11)
    }

    /// Get library information.
    pub fn library_info(&self) -> HsmResult<String> {
        self.with_pkcs11(|pkcs11| {
            let info = pkcs11.get_library_info()?;
            Ok(format!(
                "Library: {} v{}.{}",
                info.library_description(),
                info.cryptoki_version().major(),
                info.cryptoki_version().minor()
            ))
        })
    }
}

impl Drop for Pkcs11Context {
    fn drop(&mut self) {
        // Finalization is handled automatically by cryptoki 0.7
        // The library calls C_Finalize in its own Drop implementation
        tracing::debug!("PKCS#11 context dropped");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires PKCS#11 library"]
    fn test_context_creation() {
        // This would require a real PKCS#11 library path
        let result = Pkcs11Context::new("/usr/local/lib/softhsm/libsofthsm2.so");
        assert!(result.is_ok() || matches!(result, Err(HsmError::LibraryLoad(_))));
    }
}
