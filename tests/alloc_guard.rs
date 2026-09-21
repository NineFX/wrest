//! Guards the leak class that handle counting cannot see.
//!
//! `CallbackContext::into_raw()` hands an `Arc<RequestState>` to WinHTTP
//! and relies on the `HANDLE_CLOSING` callback to reclaim it.  A missed
//! reclaim leaks heap, not a kernel handle, so `GetProcessHandleCount`
//! stays flat while the process grows.
//!
//! This is its own test binary because `#[global_allocator]` applies to a
//! whole binary, and counting every allocation in the main suite would
//! slow it down for no benefit.
//!
//! The measurement is live allocations, not bytes: one leaked `Arc` per
//! request is one allocation that never returns, which shows as a count
//! rising with iterations rather than settling.

#![cfg(native_winhttp)]
#![expect(clippy::tests_outside_test_module)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};
use std::time::Duration;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use wrest::Client;

/// Live allocations: incremented on alloc, decremented on dealloc.
static LIVE: AtomicIsize = AtomicIsize::new(0);

/// Iterations per measured loop, and the growth allowed across them.
///
/// One leaked allocation per iteration would be `ITERATIONS`; the
/// allowance absorbs genuine steady-state drift well below that.
const ITERATIONS: usize = 200;
const ALLOWED_GROWTH: isize = 50;

struct CountingAllocator;

// SAFETY: every method forwards to `System`, which is a correct
// allocator; the counters do not affect the returned pointers.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: delegated to the system allocator with the caller's layout.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            LIVE.fetch_add(1, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(1, Ordering::Relaxed);
        // SAFETY: delegated; `ptr`/`layout` are the caller's contract.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // Reallocation keeps the live count unchanged: one block in, one
        // block out.
        // SAFETY: delegated; arguments are the caller's contract.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn live_allocations() -> isize {
    LIVE.load(Ordering::Relaxed)
}

/// A completed request must not leave allocations behind.
///
/// Reaching a steady state is the signal: caches and pools legitimately
/// grow during warmup, but a per-request leak keeps growing after it.
#[tokio::test]
async fn request_cycle_reaches_a_steady_state() {
    const WARMUP: usize = 50;

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/alloc"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("client should build");
    let url = format!("{}/alloc", server.uri());

    // Warm up so pools and caches have settled before measuring.
    for _ in 0..WARMUP {
        let resp = client.get(&url).send().await.expect("warmup request");
        let _ = resp.text().await.expect("warmup body");
    }

    let before = live_allocations();
    for _ in 0..ITERATIONS {
        let resp = client
            .get(&url)
            .send()
            .await
            .expect("request should succeed");
        let _ = resp.text().await.expect("body should read");
    }
    let after = live_allocations();

    let growth = after.saturating_sub(before);
    assert!(
        growth < ALLOWED_GROWTH,
        "live allocations grew by {growth} over {ITERATIONS} requests ({before} -> {after})"
    );
}

/// Abandoned responses must not leave allocations behind either.
///
/// Dropping a response early is the path where the callback context is
/// reclaimed by the closing handshake rather than by normal completion.
#[tokio::test]
async fn abandoned_responses_reach_a_steady_state() {
    const WARMUP: usize = 50;

    let body = "x".repeat(256 * 1024);
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/alloc-abandon"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&server)
        .await;

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("client should build");
    let url = format!("{}/alloc-abandon", server.uri());

    for _ in 0..WARMUP {
        drop(client.get(&url).send().await.expect("warmup request"));
    }

    let before = live_allocations();
    for _ in 0..ITERATIONS {
        drop(
            client
                .get(&url)
                .send()
                .await
                .expect("request should succeed"),
        );
    }
    let after = live_allocations();

    let growth = after.saturating_sub(before);
    assert!(
        growth < ALLOWED_GROWTH,
        "live allocations grew by {growth} over {ITERATIONS} abandoned responses \
         ({before} -> {after})"
    );
}
