//! Support for statistics.

use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

/// Represents the traffic statistics.
#[derive(Clone, Debug)]
pub struct Traffic {
    size: Arc<AtomicUsize>,
    count: Arc<AtomicUsize>,
}

impl Traffic {
    /// Creates a new `Traffic`.
    pub fn new() -> Traffic {
        Traffic {
            size: Arc::new(AtomicUsize::new(0)),
            count: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Returns the data size of the traffic.
    pub fn size(&self) -> Arc<AtomicUsize> {
        self.size.clone()
    }

    /// Returns the packet count of the traffic.
    pub fn count(&self) -> Arc<AtomicUsize> {
        self.count.clone()
    }
}
