//! Session handle mapping.
//!
//! Maps client-facing proxy session handles (u64) to real CK_SESSION_HANDLE
//! values returned by the underlying PKCS#11 module.  The mapping is
//! thread-safe, protected by a [`parking_lot::RwLock`].

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::RwLock;

/// Thread-safe bidirectional mapping between proxy session handles and the
/// real CK_SESSION_HANDLE values from the PKCS#11 module.
pub struct SessionMap {
    /// Next proxy handle to allocate.
    next_id: AtomicU64,
    /// proxy_handle -> real_handle
    proxy_to_real: RwLock<HashMap<u64, u64>>,
    /// real_handle -> proxy_handle (for cleanup)
    real_to_proxy: RwLock<HashMap<u64, u64>>,
}

impl SessionMap {
    /// Create a new, empty session map.
    pub fn new() -> Self {
        Self {
            // Start at 1 so that 0 is never a valid proxy handle.
            next_id: AtomicU64::new(1),
            proxy_to_real: RwLock::new(HashMap::new()),
            real_to_proxy: RwLock::new(HashMap::new()),
        }
    }

    /// Register a real session handle and return the corresponding proxy handle.
    pub fn create(&self, real_handle: u64) -> u64 {
        let proxy_handle = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.proxy_to_real.write().insert(proxy_handle, real_handle);
        self.real_to_proxy.write().insert(real_handle, proxy_handle);
        proxy_handle
    }

    /// Resolve a proxy handle to the underlying real session handle.
    pub fn get(&self, proxy_handle: u64) -> Option<u64> {
        self.proxy_to_real.read().get(&proxy_handle).copied()
    }

    /// Remove a session mapping by proxy handle and return the real handle.
    pub fn remove(&self, proxy_handle: u64) -> Option<u64> {
        let real = self.proxy_to_real.write().remove(&proxy_handle);
        if let Some(r) = real {
            self.real_to_proxy.write().remove(&r);
        }
        real
    }

    /// Return all real session handles currently tracked (used for cleanup on
    /// connection drop).
    pub fn all_real_handles(&self) -> Vec<u64> {
        self.proxy_to_real.read().values().copied().collect()
    }

    /// Remove all entries from the map.
    pub fn clear(&self) {
        self.proxy_to_real.write().clear();
        self.real_to_proxy.write().clear();
    }
}
