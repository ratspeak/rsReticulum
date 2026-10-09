//! Private bounds for desktop GATT setup and Windows address resolution.

use std::{fmt::Display, future::Future, time::Duration};

const OPERATION_TIMEOUT: Duration = Duration::from_secs(10);

pub(super) async fn operation<T, E: Display>(
    label: &str,
    future: impl Future<Output = Result<T, E>>,
) -> Result<T, String> {
    tokio::time::timeout(OPERATION_TIMEOUT, future)
        .await
        .map_err(|_| format!("{label}: timed out"))?
        .map_err(|error| format!("{label}: {error}"))
}

/// Cancels an in-flight setup when its interface generation ends. The caller
/// retains the peripheral in the teardown registry until cleanup completes.
pub(super) async fn while_current<T>(
    future: impl Future<Output = Result<T, String>>,
    current: impl Fn() -> bool,
) -> Result<T, String> {
    tokio::pin!(future);
    let mut tick = tokio::time::interval(Duration::from_millis(50));
    loop {
        if !current() {
            return Err("BLE connection cancelled".into());
        }
        tokio::select! {
            biased;
            _ = tick.tick() => {},
            result = &mut future => {
                return if current() { result } else { Err("BLE connection cancelled".into()) };
            }
        }
    }
}

#[cfg(any(target_os = "windows", test))]
pub(super) fn known_address(value: &str) -> Option<btleplug::api::BDAddr> {
    let address: btleplug::api::BDAddr = value.parse().ok()?;
    // Neither sentinel can identify an explicitly selected device.
    (!matches!(
        address.to_string().as_str(),
        "00:00:00:00:00:00" | "FF:FF:FF:FF:FF:FF"
    ))
    .then_some(address)
}

#[cfg(any(target_os = "windows", test))]
pub(super) async fn resolve_address<T, E: Display, F: Future<Output = Result<T, E>>>(
    cached: Option<T>,
    address: &str,
    add: impl FnOnce(btleplug::api::BDAddr) -> F,
) -> Result<T, String> {
    if let Some(peripheral) = cached {
        return Ok(peripheral);
    }
    let address = known_address(address).ok_or("No valid configured BLE address")?;
    operation("Resolve BLE address", add(address)).await
}

/// Keep the existing desktop ceiling; only shrink writes when the negotiated
/// ATT MTU requires it. Unknown/invalid MTUs use BLE's mandatory baseline.
pub(super) fn write_payload(mtu: u16) -> usize {
    if mtu < 23 {
        20
    } else {
        usize::from(mtu - 3).min(182)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    #[tokio::test]
    async fn cached_device_does_not_attempt_address_creation() {
        let result = resolve_address(Some(7), "platform-id", |_| async {
            panic!("must not add a cached peripheral");
            #[allow(unreachable_code)]
            Ok::<_, String>(8)
        })
        .await;
        assert_eq!(result, Ok(7));
    }

    #[tokio::test]
    async fn only_explicit_addresses_can_create_peripherals() {
        for invalid in [
            "",
            "RNode One",
            "1234",
            "00:00:00:00:00:00",
            "FF:FF:FF:FF:FF:FF",
            "AE34CD04-9854-4E64-8870-D58631FBBCC4",
        ] {
            assert!(
                resolve_address::<(), String, _>(None, invalid, |_| async {
                    panic!("invalid target reached the platform");
                    #[allow(unreachable_code)]
                    Ok(())
                })
                .await
                .is_err()
            );
        }
        assert_eq!(
            resolve_address(None, "aa:bb:cc:dd:ee:01", |address| async move {
                Ok::<_, String>(address.to_string())
            })
            .await
            .unwrap(),
            "AA:BB:CC:DD:EE:01"
        );
        assert!(
            resolve_address::<(), _, _>(None, "AA:BB:CC:DD:EE:01", |_| async {
                Err("adapter unavailable")
            })
            .await
            .unwrap_err()
            .contains("adapter unavailable")
        );
    }

    struct DropFlag(Arc<AtomicBool>);
    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn unavailable_device_is_bounded_and_releases_pending_work() {
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = DropFlag(dropped.clone());
        let result = resolve_address::<(), String, _>(None, "AA:BB:CC:DD:EE:01", |_| async move {
            let _guard = guard;
            std::future::pending().await
        })
        .await;
        assert!(result.unwrap_err().contains("timed out"));
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[tokio::test(start_paused = true)]
    async fn generation_change_cancels_pending_setup_before_timeout() {
        let active = Arc::new(AtomicBool::new(true));
        let stop = active.clone();
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = DropFlag(dropped.clone());
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(75)).await;
            stop.store(false, Ordering::SeqCst);
        });
        let start = tokio::time::Instant::now();
        let result: Result<(), String> = while_current(
            async move {
                let _guard = guard;
                std::future::pending().await
            },
            || active.load(Ordering::SeqCst),
        )
        .await;
        assert!(result.unwrap_err().contains("cancelled"));
        assert!(start.elapsed() < Duration::from_secs(1));
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn negotiated_mtu_never_exceeds_existing_write_ceiling() {
        for (mtu, expected) in [
            (0, 20),
            (22, 20),
            (23, 20),
            (100, 97),
            (185, 182),
            (247, 182),
        ] {
            assert_eq!(write_payload(mtu), expected);
        }
    }
}
