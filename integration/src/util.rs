//! Utilities for the integration tests
use std::future::Future;

use tokio::runtime::Handle;

/// Block the current runtime on a given future
pub fn block_rt<T, F: Future<Output = T>>(future: F) -> T {
    let handle = Handle::current();
    handle.block_on(future)
}
