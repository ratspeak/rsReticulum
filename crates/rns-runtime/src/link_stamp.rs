//! Stamped link requests for initiators (RNS/Link.py:300-395@1.6.0): the cost
//! is the one the destination announced, recalled from Transport, and keys are
//! ground off the async runtime under `lr_stamp_timeout`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use rns_link::link::Link;
use rns_link::stamp::{LinkRequestStamper, LinkStampError, LinkStampPolicy};
use rns_transport::messages::{TransportMessage, TransportQuery, TransportQueryResponse};
use tokio::sync::{Semaphore, mpsc, oneshot};

const RECALL_TIMEOUT: Duration = Duration::from_secs(5);

/// The link request switches of the process stamp policy.
pub fn link_stamp_policy() -> LinkStampPolicy {
    let policy = crate::destination_stamper::policy();
    LinkStampPolicy {
        stamp_lrs: policy.stamp_lrs,
        always_stamp_lrs: policy.always_stamp_lrs,
        lr_cost: policy.lr_cost,
        timeout: Duration::try_from_secs_f64(policy.lr_stamp_timeout).unwrap_or(Duration::MAX),
    }
}

/// Python `Identity.recall_link_cost` through Transport; `None` when the
/// destination is unknown, announced no cost, or Transport does not answer.
pub async fn recall_link_cost(
    transport_tx: &mpsc::Sender<TransportMessage>,
    destination_hash: [u8; 16],
) -> Option<f64> {
    let (response_tx, response_rx) = oneshot::channel();
    let query = async {
        transport_tx
            .send(TransportMessage::Rpc {
                query: TransportQuery::RecallLinkCost {
                    dest: destination_hash,
                },
                response_tx,
            })
            .await
            .ok()?;
        match response_rx.await {
            Ok(TransportQueryResponse::FloatResult(cost)) => cost,
            _ => None,
        }
    };
    tokio::time::timeout(RECALL_TIMEOUT, query)
        .await
        .ok()
        .flatten()
}

// Python grinds on an unbounded thread per link; bound concurrent grinds to the CPUs.
fn grind_permits() -> Arc<Semaphore> {
    static PERMITS: OnceLock<Arc<Semaphore>> = OnceLock::new();
    PERMITS
        .get_or_init(|| {
            let cpus = std::thread::available_parallelism().map_or(1, usize::from);
            Arc::new(Semaphore::new(cpus))
        })
        .clone()
}

struct CancelOnDrop(Arc<AtomicBool>);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// The MTU a new link request to `destination_hash` signals (Link.py:392-397@1.6.0):
/// the next-hop interface's hardware MTU when discovery is on and that interface
/// autoconfigures or fixes its MTU, otherwise the base MTU.
pub async fn signalled_link_mtu(
    transport_tx: &mpsc::Sender<TransportMessage>,
    destination_hash: [u8; 16],
) -> u32 {
    let base = rns_wire::constants::MTU as u32;
    let discovery =
        crate::reticulum::get_instance().is_none_or(|handle| handle.link_mtu_discovery());
    if !discovery {
        return base;
    }
    let (response_tx, response_rx) = oneshot::channel();
    let query = async {
        transport_tx
            .send(TransportMessage::Rpc {
                query: TransportQuery::GetNextHopHardwareMtu {
                    dest: destination_hash,
                },
                response_tx,
            })
            .await
            .ok()?;
        match response_rx.await {
            Ok(TransportQueryResponse::IntResult(mtu)) => u32::try_from(mtu).ok(),
            _ => None,
        }
    };
    tokio::time::timeout(RECALL_TIMEOUT, query)
        .await
        .ok()
        .flatten()
        .filter(|mtu| *mtu != 0)
        .unwrap_or(base)
}

/// Create an initiator Link whose request carries the stamp upstream would
/// send to `destination_hash` and the MTU it would signal. Dropping the future
/// cancels the grind.
pub async fn new_initiator(
    transport_tx: &mpsc::Sender<TransportMessage>,
    destination_hash: [u8; 16],
    hops: u8,
) -> Result<(Link, Vec<u8>), LinkStampError> {
    let policy = link_stamp_policy();
    let recalled = if policy.stamp_lrs {
        recall_link_cost(transport_tx, destination_hash).await
    } else {
        None
    };
    let Some(cost) = policy.request_cost(recalled) else {
        let mtu = signalled_link_mtu(transport_tx, destination_hash).await;
        return Ok(Link::new_initiator_with_keys(
            destination_hash,
            hops,
            rns_link::handshake::EphemeralKeys::generate(),
            mtu,
        ));
    };
    let mtu = signalled_link_mtu(transport_tx, destination_hash).await;
    let _permit = grind_permits().acquire_owned().await.ok();
    let ctl = policy.control(cost);
    let _cancel = CancelOnDrop(ctl.cancel.clone());
    let started = std::time::Instant::now();
    let result = tokio::task::spawn_blocking(move || {
        Link::new_stamped_initiator(destination_hash, hops, Some(cost), &ctl, mtu)
    })
    .await
    .map_err(|_| LinkStampError::Stopped)?;
    match &result {
        Ok(_) => tracing::debug!(
            destination = %hex::encode(destination_hash),
            cost,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "generated link request stamp"
        ),
        Err(error) => tracing::info!(
            destination = %hex::encode(destination_hash),
            cost,
            %error,
            "link request stamp generation failed"
        ),
    }
    result
}

/// A stamper for synchronous Link owners on a multi-threaded runtime: link
/// costs are recalled from Transport by blocking in place. Elsewhere no cost
/// is recalled and requests are stamped only under `always_stamp_lrs`.
pub fn blocking_stamper(transport_tx: mpsc::Sender<TransportMessage>) -> LinkRequestStamper {
    LinkRequestStamper::new(
        link_stamp_policy(),
        Arc::new(move |destination_hash: &[u8; 16]| {
            let handle = tokio::runtime::Handle::try_current().ok()?;
            if handle.runtime_flavor() != tokio::runtime::RuntimeFlavor::MultiThread {
                return None;
            }
            let destination_hash = *destination_hash;
            tokio::task::block_in_place(|| {
                handle.block_on(recall_link_cost(&transport_tx, destination_hash))
            })
        }),
    )
}
