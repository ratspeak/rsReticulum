use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::Notify;
use tokio::task::JoinHandle;

/// Privacy-safe classification used only to select an interface's shutdown path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InterfaceKind {
    Standard,
    #[cfg(feature = "ble")]
    BlePeer,
    #[cfg(feature = "ble")]
    BleRNode,
    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    RNode,
    #[cfg(feature = "serial")]
    RNodeMulti,
    #[cfg(target_os = "android")]
    AndroidUsbRNode,
}

/// Closed set of teardown strategies. Compatibility strategies remain
/// transitional until every RNode spawn path supplies an exact driver handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InterfaceShutdownStrategy {
    Abort,
    #[cfg(feature = "ble")]
    StopBlePeer,
    #[cfg(feature = "ble")]
    StopBleRNodeCompatibility,
    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    StopRNodeCompatibility,
    #[cfg(target_os = "android")]
    StopAndroidUsbRNodeCompatibility,
}

impl InterfaceKind {
    pub(crate) fn shutdown_strategy(self) -> InterfaceShutdownStrategy {
        match self {
            Self::Standard => InterfaceShutdownStrategy::Abort,
            #[cfg(feature = "ble")]
            Self::BlePeer => InterfaceShutdownStrategy::StopBlePeer,
            #[cfg(feature = "ble")]
            Self::BleRNode => InterfaceShutdownStrategy::StopBleRNodeCompatibility,
            #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
            Self::RNode => InterfaceShutdownStrategy::StopRNodeCompatibility,
            #[cfg(feature = "serial")]
            Self::RNodeMulti => InterfaceShutdownStrategy::Abort,
            #[cfg(target_os = "android")]
            Self::AndroidUsbRNode => InterfaceShutdownStrategy::StopAndroidUsbRNodeCompatibility,
        }
    }
}

#[derive(Clone, Default)]
pub(crate) struct InterfaceRegistry {
    inner: Arc<RegistryInner>,
}

#[derive(Default)]
struct RegistryInner {
    next_owner: AtomicU64,
    records: Mutex<HashMap<u64, InterfaceRecord>>,
    changed: Notify,
}

struct InterfaceRecord {
    owner: u64,
    kind: InterfaceKind,
    strategy: InterfaceShutdownStrategy,
    task: Option<JoinHandle<()>>,
    online: Option<Arc<std::sync::atomic::AtomicBool>>,
    // R6c will populate this from observed RNode spawn paths. R6b deliberately
    // leaves it empty and preserves the compatibility shutdown routes.
    _driver: Option<rns_interface::rnode::RNodeDriverHandle>,
    state: RecordState,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum RecordState {
    Pending { cancel_requested: bool },
    Active,
    Stopping,
}

impl RegistryInner {
    fn next_owner(&self) -> u64 {
        // Zero remains a sentinel and is never issued, including after wrap.
        loop {
            let owner = self
                .next_owner
                .fetch_add(1, Ordering::Relaxed)
                .wrapping_add(1);
            if owner != 0 {
                return owner;
            }
        }
    }

    fn remove_exact(&self, id: u64, owner: u64) {
        let mut records = self
            .records
            .lock()
            .expect("interface registry mutex poisoned");
        if records.get(&id).is_some_and(|record| record.owner == owner) {
            records.remove(&id);
            drop(records);
            self.changed.notify_waiters();
        }
    }
}

impl InterfaceRegistry {
    #[cfg(test)]
    pub(crate) fn reserve(
        &self,
        id: u64,
        kind: InterfaceKind,
        task: JoinHandle<()>,
        driver: Option<rns_interface::rnode::RNodeDriverHandle>,
    ) -> Result<InterfaceRegistration, RejectedInterfaceRegistration> {
        self.reserve_with_online(id, kind, task, driver, None)
    }

    pub(crate) fn reserve_with_online(
        &self,
        id: u64,
        kind: InterfaceKind,
        task: JoinHandle<()>,
        driver: Option<rns_interface::rnode::RNodeDriverHandle>,
        online: Option<Arc<std::sync::atomic::AtomicBool>>,
    ) -> Result<InterfaceRegistration, RejectedInterfaceRegistration> {
        let owner = self.inner.next_owner();
        let mut records = self
            .inner
            .records
            .lock()
            .expect("interface registry mutex poisoned");
        if records.contains_key(&id) {
            return Err(RejectedInterfaceRegistration {
                task: Some(task),
                _driver: driver,
            });
        }
        records.insert(
            id,
            InterfaceRecord {
                owner,
                kind,
                strategy: kind.shutdown_strategy(),
                task: None,
                online,
                _driver: None,
                state: RecordState::Pending {
                    cancel_requested: false,
                },
            },
        );
        drop(records);
        Ok(InterfaceRegistration {
            registry: self.clone(),
            id,
            owner,
            task: Some(task),
            driver,
            committed: false,
        })
    }

    pub(crate) fn begin_shutdown(&self, id: u64) -> ShutdownStart {
        let mut records = self
            .inner
            .records
            .lock()
            .expect("interface registry mutex poisoned");
        let Some(record) = records.get_mut(&id) else {
            let owner = self.inner.next_owner();
            records.insert(
                id,
                InterfaceRecord {
                    owner,
                    kind: InterfaceKind::Standard,
                    strategy: InterfaceShutdownStrategy::Abort,
                    task: None,
                    online: None,
                    _driver: None,
                    state: RecordState::Stopping,
                },
            );
            return ShutdownStart::Acquired(InterfaceShutdown {
                registry: self.clone(),
                id,
                owner,
                kind: InterfaceKind::Standard,
                strategy: InterfaceShutdownStrategy::Abort,
                task: None,
                online: None,
                _driver: None,
                control_owner: None,
                finished: false,
            });
        };
        match record.state {
            RecordState::Pending {
                ref mut cancel_requested,
            } => {
                *cancel_requested = true;
                let owner = record.owner;
                drop(records);
                self.inner.changed.notify_waiters();
                ShutdownStart::RegistrationPending { owner }
            }
            RecordState::Stopping => ShutdownStart::AlreadyStopping {
                owner: record.owner,
            },
            RecordState::Active => {
                record.state = RecordState::Stopping;
                ShutdownStart::Acquired(InterfaceShutdown {
                    registry: self.clone(),
                    id,
                    owner: record.owner,
                    kind: record.kind,
                    strategy: record.strategy,
                    task: record.task.take(),
                    online: record.online.clone(),
                    // R6b does not consume the future exact driver handle.
                    _driver: record._driver.clone(),
                    control_owner: Some(record.owner),
                    finished: false,
                })
            }
        }
    }

    pub(crate) fn begin_shutdown_exact(&self, id: u64, owner: u64) -> ExactShutdownStart {
        let mut records = self
            .inner
            .records
            .lock()
            .expect("interface registry mutex poisoned");
        let Some(record) = records.get_mut(&id) else {
            return ExactShutdownStart::NotOwned;
        };
        if record.owner != owner {
            return ExactShutdownStart::NotOwned;
        }
        match record.state {
            RecordState::Active => {
                record.state = RecordState::Stopping;
                ExactShutdownStart::Acquired(InterfaceShutdown {
                    registry: self.clone(),
                    id,
                    owner: record.owner,
                    kind: record.kind,
                    strategy: record.strategy,
                    task: record.task.take(),
                    online: record.online.clone(),
                    _driver: record._driver.clone(),
                    control_owner: Some(record.owner),
                    finished: false,
                })
            }
            RecordState::Stopping => ExactShutdownStart::AlreadyStopping,
            RecordState::Pending { .. } => ExactShutdownStart::NotOwned,
        }
    }

    pub(crate) async fn wait_for_any_cancel_requested(&self, tokens: &[(u64, u64)]) {
        loop {
            let changed = self.inner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let cancelled = {
                let records = self
                    .inner
                    .records
                    .lock()
                    .expect("interface registry mutex poisoned");
                tokens.iter().any(|(id, owner)| {
                    let Some(record) = records.get(id) else {
                        return true;
                    };
                    if record.owner != *owner {
                        return true;
                    }
                    matches!(
                        record.state,
                        RecordState::Pending {
                            cancel_requested: true
                        } | RecordState::Stopping
                    )
                })
            };
            if cancelled {
                return;
            }
            changed.await;
        }
    }

    pub(crate) async fn wait_until_not_owner(&self, id: u64, owner: u64) {
        loop {
            let changed = self.inner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self
                .inner
                .records
                .lock()
                .expect("interface registry mutex poisoned")
                .get(&id)
                .is_none_or(|record| record.owner != owner)
            {
                return;
            }
            changed.await;
        }
    }

    pub(crate) fn commit_batch(
        &self,
        mut registrations: Vec<InterfaceRegistration>,
    ) -> Result<(), Vec<InterfaceRegistration>> {
        let mut records = self
            .inner
            .records
            .lock()
            .expect("interface registry mutex poisoned");
        let valid = registrations.iter().all(|registration| {
            Arc::ptr_eq(&self.inner, &registration.registry.inner)
                && records.get(&registration.id).is_some_and(|record| {
                    record.owner == registration.owner
                        && record.state
                            == (RecordState::Pending {
                                cancel_requested: false,
                            })
                })
        });
        if !valid {
            drop(records);
            return Err(registrations);
        }

        for registration in &mut registrations {
            let record = records
                .get_mut(&registration.id)
                .expect("batch reservation was validated");
            record.task = registration.task.take();
            record._driver = registration.driver.take();
            record.state = RecordState::Active;
            registration.committed = true;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.inner
            .records
            .lock()
            .expect("interface registry mutex poisoned")
            .len()
    }

    #[cfg(test)]
    fn owner_for_test(&self, id: u64) -> Option<u64> {
        self.inner
            .records
            .lock()
            .expect("interface registry mutex poisoned")
            .get(&id)
            .map(|record| record.owner)
    }
}

pub(crate) struct InterfaceRegistration {
    registry: InterfaceRegistry,
    id: u64,
    owner: u64,
    task: Option<JoinHandle<()>>,
    driver: Option<rns_interface::rnode::RNodeDriverHandle>,
    committed: bool,
}

impl InterfaceRegistration {
    pub(crate) fn owner(&self) -> u64 {
        self.owner
    }

    pub(crate) fn commit(mut self) -> Result<(), Self> {
        let mut records = self
            .registry
            .inner
            .records
            .lock()
            .expect("interface registry mutex poisoned");
        let Some(record) = records.get_mut(&self.id) else {
            drop(records);
            return Err(self);
        };
        if record.owner != self.owner
            || record.state
                != (RecordState::Pending {
                    cancel_requested: false,
                })
        {
            drop(records);
            return Err(self);
        }

        let task = self.task.take().expect("pending registration owns a task");
        let driver = self.driver.take();
        record.task = Some(task);
        record._driver = driver;
        record.state = RecordState::Active;
        self.committed = true;
        Ok(())
    }

    pub(crate) async fn rollback(mut self) {
        self.stop_task_and_wait().await;
        self.release();
    }

    pub(crate) async fn stop_task_and_wait(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
    }

    pub(crate) fn release(mut self) {
        self.registry.inner.remove_exact(self.id, self.owner);
        self.committed = true;
    }
}

impl Drop for InterfaceRegistration {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
        // Cancellation cannot await the aborted task. Keep the reservation as
        // a fail-closed tombstone so the ID cannot be reused before join proof.
    }
}

pub(crate) struct RejectedInterfaceRegistration {
    task: Option<JoinHandle<()>>,
    _driver: Option<rns_interface::rnode::RNodeDriverHandle>,
}

impl std::fmt::Debug for RejectedInterfaceRegistration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RejectedInterfaceRegistration")
    }
}

impl RejectedInterfaceRegistration {
    pub(crate) async fn abort_and_wait(mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
    }
}

impl Drop for RejectedInterfaceRegistration {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

pub(crate) enum ShutdownStart {
    Acquired(InterfaceShutdown),
    RegistrationPending { owner: u64 },
    AlreadyStopping { owner: u64 },
}

pub(crate) enum ExactShutdownStart {
    Acquired(InterfaceShutdown),
    AlreadyStopping,
    NotOwned,
}

pub(crate) struct InterfaceShutdown {
    registry: InterfaceRegistry,
    id: u64,
    owner: u64,
    kind: InterfaceKind,
    strategy: InterfaceShutdownStrategy,
    task: Option<JoinHandle<()>>,
    online: Option<Arc<std::sync::atomic::AtomicBool>>,
    _driver: Option<rns_interface::rnode::RNodeDriverHandle>,
    control_owner: Option<u64>,
    finished: bool,
}

impl InterfaceShutdown {
    pub(crate) fn kind(&self) -> InterfaceKind {
        self.kind
    }

    pub(crate) fn strategy(&self) -> InterfaceShutdownStrategy {
        self.strategy
    }

    pub(crate) fn control_owner(&self) -> Option<u64> {
        self.control_owner
    }

    pub(crate) fn mark_offline(&self) {
        if let Some(online) = &self.online {
            online.store(false, Ordering::SeqCst);
        }
    }

    pub(crate) async fn stop_task_and_wait(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
    }

    pub(crate) fn finish(mut self) {
        self.registry.inner.remove_exact(self.id, self.owner);
        self.finished = true;
    }
}

impl Drop for InterfaceShutdown {
    fn drop(&mut self) {
        // Never abort from Drop. In particular, an Android USB owner may be
        // inside its ordered Java-release sequence. Public teardown runs in a
        // cancellation-independent worker; if that worker panics, retaining
        // the Stopping tombstone and detaching the task is the fail-closed
        // fallback.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::sync::oneshot;

    fn pending_task() -> JoinHandle<()> {
        tokio::spawn(std::future::pending())
    }

    #[tokio::test]
    async fn registries_isolate_overlapping_interface_ids() {
        let first = InterfaceRegistry::default();
        let second = InterfaceRegistry::default();

        let first_registration = first
            .reserve(7, InterfaceKind::Standard, pending_task(), None)
            .expect("first reservation");
        let second_registration = second
            .reserve(7, InterfaceKind::Standard, pending_task(), None)
            .expect("second reservation");

        assert_eq!(first.len(), 1);
        assert_eq!(second.len(), 1);
        first_registration.rollback().await;
        assert_eq!(first.len(), 0);
        assert_eq!(second.len(), 1);
        second_registration.rollback().await;
    }

    #[tokio::test]
    async fn duplicate_and_rollback_abort_incoming_tasks_without_replacement() {
        struct Dropped(Arc<AtomicBool>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        let registry = InterfaceRegistry::default();
        let first = registry
            .reserve(11, InterfaceKind::Standard, pending_task(), None)
            .expect("first reservation");
        let first_owner = first.owner();
        let duplicate_dropped = Arc::new(AtomicBool::new(false));
        let duplicate_flag = duplicate_dropped.clone();
        let duplicate_task = tokio::spawn(async move {
            let _dropped = Dropped(duplicate_flag);
            std::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;

        let duplicate = match registry.reserve(11, InterfaceKind::Standard, duplicate_task, None) {
            Ok(_) => panic!("duplicate must be rejected"),
            Err(duplicate) => duplicate,
        };
        duplicate.abort_and_wait().await;
        assert!(duplicate_dropped.load(Ordering::Acquire));
        assert_eq!(registry.owner_for_test(11), Some(first_owner));

        first.rollback().await;
        assert_eq!(registry.len(), 0);
    }

    #[tokio::test]
    async fn stale_removal_token_cannot_remove_reused_id() {
        let registry = InterfaceRegistry::default();
        let first = registry
            .reserve(19, InterfaceKind::Standard, pending_task(), None)
            .expect("first reservation");
        let stale_owner = first.owner();
        first.rollback().await;

        let second = registry
            .reserve(19, InterfaceKind::Standard, pending_task(), None)
            .expect("second reservation");
        let current_owner = second.owner();
        assert_ne!(stale_owner, current_owner);

        registry.inner.remove_exact(19, stale_owner);
        assert_eq!(registry.owner_for_test(19), Some(current_owner));
        second.rollback().await;
    }

    #[tokio::test]
    async fn pending_teardown_cancels_commit_and_releases_only_after_joined_rollback() {
        let registry = InterfaceRegistry::default();
        let registration = registry
            .reserve(23, InterfaceKind::Standard, pending_task(), None)
            .expect("reservation");

        assert!(matches!(
            registry.begin_shutdown(23),
            ShutdownStart::RegistrationPending { .. }
        ));
        let registration = registration
            .commit()
            .expect_err("cancel-requested pending registration must not commit");
        assert_eq!(registry.len(), 1);
        registration.rollback().await;
        assert_eq!(registry.len(), 0);
    }

    #[tokio::test]
    async fn normal_shutdown_waiters_do_not_attach_to_reused_ids() {
        let pending_registry = InterfaceRegistry::default();
        let pending = pending_registry
            .reserve(25, InterfaceKind::Standard, pending_task(), None)
            .expect("pending owner A");
        let ShutdownStart::RegistrationPending {
            owner: pending_owner,
        } = pending_registry.begin_shutdown(25)
        else {
            panic!("pending shutdown must retain owner A");
        };
        pending.rollback().await;
        let pending_replacement = pending_registry
            .reserve(25, InterfaceKind::Standard, pending_task(), None)
            .expect("pending owner B");
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            pending_registry.wait_until_not_owner(25, pending_owner),
        )
        .await
        .expect("pending waiter must return after owner A is replaced by B");
        pending_replacement.rollback().await;

        let stopping_registry = InterfaceRegistry::default();
        let active = stopping_registry
            .reserve(27, InterfaceKind::Standard, pending_task(), None)
            .expect("active owner A");
        assert!(active.commit().is_ok());
        let ShutdownStart::Acquired(mut shutdown) = stopping_registry.begin_shutdown(27) else {
            panic!("active owner A must yield shutdown ownership");
        };
        let ShutdownStart::AlreadyStopping {
            owner: stopping_owner,
        } = stopping_registry.begin_shutdown(27)
        else {
            panic!("second shutdown must retain stopping owner A");
        };
        shutdown.stop_task_and_wait().await;
        shutdown.finish();
        let stopping_replacement = stopping_registry
            .reserve(27, InterfaceKind::Standard, pending_task(), None)
            .expect("stopping owner B");
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            stopping_registry.wait_until_not_owner(27, stopping_owner),
        )
        .await
        .expect("stopping waiter must return after owner A is replaced by B");
        stopping_replacement.rollback().await;
    }

    #[tokio::test]
    async fn pending_and_stopping_drop_keep_ids_fail_closed() {
        let pending_registry = InterfaceRegistry::default();
        let pending = pending_registry
            .reserve(29, InterfaceKind::Standard, pending_task(), None)
            .expect("pending reservation");
        drop(pending);
        let rejected =
            match pending_registry.reserve(29, InterfaceKind::Standard, pending_task(), None) {
                Ok(_) => panic!("dropped Pending owner must block same-ID reuse"),
                Err(rejected) => rejected,
            };
        rejected.abort_and_wait().await;

        let stopping_registry = InterfaceRegistry::default();
        let task_release = Arc::new(Notify::new());
        let task_release_clone = task_release.clone();
        let (completed_tx, completed_rx) = oneshot::channel();
        let registration = stopping_registry
            .reserve(
                31,
                InterfaceKind::Standard,
                tokio::spawn(async move {
                    task_release_clone.notified().await;
                    let _ = completed_tx.send(());
                }),
                None,
            )
            .expect("stopping reservation");
        assert!(registration.commit().is_ok(), "commit");
        let ShutdownStart::Acquired(shutdown) = stopping_registry.begin_shutdown(31) else {
            panic!("active registration must yield shutdown ownership");
        };
        drop(shutdown);

        let rejected =
            match stopping_registry.reserve(31, InterfaceKind::Standard, pending_task(), None) {
                Ok(_) => panic!("dropped Stopping owner must block same-ID reuse"),
                Err(rejected) => rejected,
            };
        rejected.abort_and_wait().await;
        task_release.notify_one();
        tokio::time::timeout(std::time::Duration::from_secs(1), completed_rx)
            .await
            .expect("InterfaceShutdown Drop must not abort the owned task")
            .expect("completion sender");
    }

    #[tokio::test]
    async fn missing_shutdown_installs_owner_tombstone_until_explicit_finish() {
        let registry = InterfaceRegistry::default();
        let ShutdownStart::Acquired(shutdown) = registry.begin_shutdown(37) else {
            panic!("missing ID must install an orphan shutdown tombstone");
        };
        assert!(shutdown.control_owner().is_none());

        let rejected = match registry.reserve(37, InterfaceKind::Standard, pending_task(), None) {
            Ok(_) => panic!("orphan cleanup tombstone must block same-ID reuse"),
            Err(rejected) => rejected,
        };
        rejected.abort_and_wait().await;
        shutdown.finish();

        let replacement = registry
            .reserve(37, InterfaceKind::Standard, pending_task(), None)
            .expect("explicit finish releases orphan tombstone");
        replacement.rollback().await;
    }

    #[test]
    fn kinds_keep_their_shutdown_strategies() {
        assert_eq!(
            InterfaceKind::Standard.shutdown_strategy(),
            InterfaceShutdownStrategy::Abort
        );
        #[cfg(feature = "serial")]
        assert_eq!(
            InterfaceKind::RNodeMulti.shutdown_strategy(),
            InterfaceShutdownStrategy::Abort
        );
        #[cfg(feature = "ble")]
        {
            assert_eq!(
                InterfaceKind::BlePeer.shutdown_strategy(),
                InterfaceShutdownStrategy::StopBlePeer
            );
            assert_eq!(
                InterfaceKind::BleRNode.shutdown_strategy(),
                InterfaceShutdownStrategy::StopBleRNodeCompatibility
            );
        }
        #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
        assert_eq!(
            InterfaceKind::RNode.shutdown_strategy(),
            InterfaceShutdownStrategy::StopRNodeCompatibility
        );
        #[cfg(target_os = "android")]
        assert_eq!(
            InterfaceKind::AndroidUsbRNode.shutdown_strategy(),
            InterfaceShutdownStrategy::StopAndroidUsbRNodeCompatibility
        );
    }
}
