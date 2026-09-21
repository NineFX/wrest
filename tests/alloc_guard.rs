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
//! request is one allocation that never returns. Absolute counts cannot
//! be asserted -- pools and caches retain memory legitimately -- so what
//! is measured is whether growth decays across successive batches.

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

/// A leak shows as growth that does not decay.
///
/// Absolute counts are meaningless here: connection pools, tokio and
/// wiremock all retain memory legitimately, and the figure never settles
/// at a knowable constant. What distinguishes a leak is the *shape* —
/// caches warm and their growth falls away, while one leaked allocation
/// per request keeps growing at the same rate forever.
///
/// So this measures successive equal batches and requires the growth to
/// decay. It is a single test on purpose: the counter is process-global,
/// and two tests running concurrently in one binary measure each other.
#[tokio::test]
#[ignore = "resource measurement: slow, and run in CI via --ignored"]
async fn allocation_growth_decays() {
    const WARMUP: usize = 100;
    const BATCH: usize = 200;

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

    // Half the batches read the body, half abandon it: the abandoned path
    // reclaims the callback context through the closing handshake rather
    // than normal completion.
    async fn batch(client: &Client, url: &str, n: usize, read_body: bool) {
        for i in 0..n {
            let resp = client
                .get(url)
                .send()
                .await
                .expect("request should succeed");
            if read_body || i % 2 == 0 {
                let _ = resp.text().await.expect("body should read");
            } else {
                drop(resp);
            }
        }
    }

    batch(&client, &url, WARMUP, true).await;

    let mut growth = Vec::new();
    for _ in 0..3 {
        let before = live_allocations();
        batch(&client, &url, BATCH, false).await;
        growth.push(live_allocations().saturating_sub(before));
    }

    // Printed so the numbers are visible in CI, which runs this with
    // --nocapture; a threshold alone would hide the trend.
    println!("live-allocation growth per {BATCH}-request batch: {growth:?}");

    let first = growth[0];
    let last = growth[2];
    assert!(
        last < first,
        "allocation growth is not decaying across batches ({growth:?}); \
         a per-request leak grows at a constant rate"
    );
    assert!(
        last < BATCH.cast_signed(),
        "last batch grew by {last} over {BATCH} requests, at least one allocation each ({growth:?})"
    );
}
