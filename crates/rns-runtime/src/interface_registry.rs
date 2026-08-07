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

/// Closed set of teardown strategies owned by one runtime-local registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InterfaceShutdownStrategy {
    Abort,
    #[cfg(feature = "ble")]
    StopBlePeer,
    #[cfg(any(
        feature = "serial",
        feature = "rnode-tcp",
        feature = "ble",
        target_os = "android"
    ))]
    ExactRNodeDriver,
}

impl InterfaceKind {
    pub(crate) fn shutdown_strategy(self) -> InterfaceShutdownStrategy {
        match self {
            Self::Standard => InterfaceShutdownStrategy::Abort,
            #[cfg(feature = "ble")]
            Self::BlePeer => InterfaceShutdownStrategy::StopBlePeer,
            #[cfg(feature = "ble")]
            Self::BleRNode => InterfaceShutdownStrategy::ExactRNodeDriver,
            #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
            Self::RNode => InterfaceShutdownStrategy::ExactRNodeDriver,
            #[cfg(feature = "serial")]
            Self::RNodeMulti => InterfaceShutdownStrategy::Abort,
            #[cfg(target_os = "android")]
            Self::AndroidUsbRNode => InterfaceShutdownStrategy::ExactRNodeDriver,
        }
    }

    fn requires_exact_driver(self) -> bool {
        match self {
            #[cfg(feature = "ble")]
            Self::BleRNode => true,
            #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
            Self::RNode => true,
            #[cfg(target_os = "android")]
            Self::AndroidUsbRNode => true,
            _ => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InterfaceRegistrationRejection {
    Duplicate,
    InvalidDriverOwnership,
    Draining,
    Closed,
}

/// Closed, registry-local failures for exact RNode observation lookup.
#[allow(clippy::enum_variant_names)] // The shared API contract uses these exact classifications.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RNodeObservationLookupError {
    NotFound,
    NotRNode,
    NotActive,
}

#[derive(Clone, Default)]
pub(crate) struct InterfaceRegistry {
    inner: Arc<RegistryInner>,
}

struct RegistryInner {
    next_owner: AtomicU64,
    state: Mutex<RegistryState>,
    changed: Notify,
}

struct RegistryState {
    admission: RegistryAdmission,
    in_flight_spawns: usize,
    records: HashMap<u64, InterfaceRecord>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RegistryAdmission {
    Open,
    Draining,
    Closed,
}

impl Default for RegistryInner {
    fn default() -> Self {
        Self {
            next_owner: AtomicU64::new(0),
            state: Mutex::new(RegistryState {
                admission: RegistryAdmission::Open,
                in_flight_spawns: 0,
                records: HashMap::new(),
            }),
            changed: Notify::new(),
        }
    }
}

struct InterfaceRecord {
    owner: u64,
    kind: InterfaceKind,
    strategy: InterfaceShutdownStrategy,
    task: Option<JoinHandle<()>>,
    online: Option<Arc<std::sync::atomic::AtomicBool>>,
    driver: Option<rns_interface::rnode::RNodeDriverHandle>,
    state: RecordState,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum RecordState {
    Pending {
        cancel_requested: bool,
        abandoned: bool,
    },
    Active,
    Stopping,
    Abandoned,
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
        let mut state = self
            .state
            .lock()
            .expect("interface registry mutex poisoned");
        if state
            .records
            .get(&id)
            .is_some_and(|record| record.owner == owner)
        {
            state.records.remove(&id);
            drop(state);
            self.changed.notify_waiters();
        }
    }
}

impl InterfaceRegistry {
    pub(crate) fn is_open(&self) -> bool {
        self.inner
            .state
            .lock()
            .expect("interface registry mutex poisoned")
            .admission
            == RegistryAdmission::Open
    }

    /// Subscribe to one active exact RNode without transferring lifecycle
    /// ownership or exposing its shutdown handle.
    pub(crate) fn observe_active_rnode(
        &self,
        id: u64,
    ) -> Result<rns_interface::rnode::RNodeDriverSubscription, RNodeObservationLookupError> {
        let subscription = {
            let state = self
                .inner
                .state
                .lock()
                .expect("interface registry mutex poisoned");
            let record = state
                .records
                .get(&id)
                .ok_or(RNodeObservationLookupError::NotFound)?;
            if !record.kind.requires_exact_driver() {
                return Err(RNodeObservationLookupError::NotRNode);
            }
            if record.state != RecordState::Active {
                return Err(RNodeObservationLookupError::NotActive);
            }
            record
                .driver
                .as_ref()
                .ok_or(RNodeObservationLookupError::NotActive)?
                .watch()
        };
        Ok(subscription)
    }

    /// Acquire lifecycle ownership before beginning a physical interface
    /// spawn. The permit spans spawn plus registration/rollback, closing the
    /// otherwise unavoidable gap before an interface has an ID reservation.
    pub(crate) fn acquire_spawn_permit(&self) -> Result<InterfaceSpawnPermit, RegistryAdmission> {
        let mut state = self
            .inner
            .state
            .lock()
            .expect("interface registry mutex poisoned");
        if state.admission != RegistryAdmission::Open {
            return Err(state.admission);
        }
        state.in_flight_spawns = state
            .in_flight_spawns
            .checked_add(1)
            .expect("interface spawn permit count overflowed");
        Ok(InterfaceSpawnPermit {
            registry: self.clone(),
            released: false,
        })
    }

    pub(crate) async fn wait_for_spawn_permits(&self) {
        loop {
            let changed = self.inner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self
                .inner
                .state
                .lock()
                .expect("interface registry mutex poisoned")
                .in_flight_spawns
                == 0
            {
                return;
            }
            changed.await;
        }
    }

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
        if kind.requires_exact_driver() != driver.is_some() {
            return Err(RejectedInterfaceRegistration {
                task: Some(task),
                driver,
                reason: InterfaceRegistrationRejection::InvalidDriverOwnership,
            });
        }
        let owner = self.inner.next_owner();
        let mut state = self
            .inner
            .state
            .lock()
            .expect("interface registry mutex poisoned");
        let admission_rejection = match state.admission {
            RegistryAdmission::Open => None,
            RegistryAdmission::Draining => Some(InterfaceRegistrationRejection::Draining),
            RegistryAdmission::Closed => Some(InterfaceRegistrationRejection::Closed),
        };
        if let Some(reason) = admission_rejection {
            return Err(RejectedInterfaceRegistration {
                task: Some(task),
                driver,
                reason,
            });
        }
        if state.records.contains_key(&id) {
            return Err(RejectedInterfaceRegistration {
                task: Some(task),
                driver,
                reason: InterfaceRegistrationRejection::Duplicate,
            });
        }
        state.records.insert(
            id,
            InterfaceRecord {
                owner,
                kind,
                strategy: kind.shutdown_strategy(),
                task: None,
                online,
                driver: None,
                state: RecordState::Pending {
                    cancel_requested: false,
                    abandoned: false,
                },
            },
        );
        drop(state);
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
        let mut state = self
            .inner
            .state
            .lock()
            .expect("interface registry mutex poisoned");
        let Some(record) = state.records.get_mut(&id) else {
            if state.admission != RegistryAdmission::Open {
                return ShutdownStart::RegistryDraining;
            }
            let owner = self.inner.next_owner();
            state.records.insert(
                id,
                InterfaceRecord {
                    owner,
                    kind: InterfaceKind::Standard,
                    strategy: InterfaceShutdownStrategy::Abort,
                    task: None,
                    online: None,
                    driver: None,
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
                driver: None,
                control_owner: None,
                finished: false,
            });
        };
        match record.state {
            RecordState::Pending {
                ref mut cancel_requested,
                ..
            } => {
                *cancel_requested = true;
                let owner = record.owner;
                drop(state);
                self.inner.changed.notify_waiters();
                ShutdownStart::RegistrationPending { owner }
            }
            RecordState::Stopping | RecordState::Abandoned => ShutdownStart::AlreadyStopping {
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
                    driver: record.driver.take(),
                    control_owner: Some(record.owner),
                    finished: false,
                })
            }
        }
    }

    pub(crate) fn begin_shutdown_exact(&self, id: u64, owner: u64) -> ExactShutdownStart {
        let mut state = self
            .inner
            .state
            .lock()
            .expect("interface registry mutex poisoned");
        let Some(record) = state.records.get_mut(&id) else {
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
                    driver: record.driver.take(),
                    control_owner: Some(record.owner),
                    finished: false,
                })
            }
            RecordState::Stopping | RecordState::Abandoned => ExactShutdownStart::AlreadyStopping,
            RecordState::Pending { .. } => ExactShutdownStart::NotOwned,
        }
    }

    pub(crate) async fn wait_for_any_cancel_requested(&self, tokens: &[(u64, u64)]) {
        loop {
            let changed = self.inner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let cancelled = {
                let state = self
                    .inner
                    .state
                    .lock()
                    .expect("interface registry mutex poisoned");
                tokens.iter().any(|(id, owner)| {
                    let Some(record) = state.records.get(id) else {
                        return true;
                    };
                    if record.owner != *owner {
                        return true;
                    }
                    matches!(
                        record.state,
                        RecordState::Pending {
                            cancel_requested: true,
                            ..
                        } | RecordState::Stopping
                            | RecordState::Abandoned
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
                .state
                .lock()
                .expect("interface registry mutex poisoned")
                .records
                .get(&id)
                .is_none_or(|record| record.owner != owner)
            {
                return;
            }
            changed.await;
        }
    }

    /// Wait until a cleanup owner disappears, or claim a Pending registration
    /// whose task cleanup completed after its transaction future was dropped.
    pub(crate) async fn wait_or_claim_abandoned(&self, id: u64, owner: u64) -> Option<(u64, u64)> {
        loop {
            let changed = self.inner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let abandoned = {
                let state = self
                    .inner
                    .state
                    .lock()
                    .expect("interface registry mutex poisoned");
                let record = state.records.get(&id)?;
                if record.owner != owner {
                    return None;
                }
                record.state == RecordState::Abandoned
            };
            if abandoned {
                return Some((id, owner));
            }
            changed.await;
        }
    }

    fn mark_abandoned_pending(&self, id: u64, owner: u64) {
        let mut state = self
            .inner
            .state
            .lock()
            .expect("interface registry mutex poisoned");
        let admission = state.admission;
        let Some(record) = state.records.get_mut(&id) else {
            return;
        };
        if record.owner != owner {
            return;
        }
        if let RecordState::Pending { abandoned, .. } = &mut record.state {
            *abandoned = true;
            if admission != RegistryAdmission::Open {
                record.state = RecordState::Abandoned;
            }
            drop(state);
            self.inner.changed.notify_waiters();
        }
    }

    fn mark_abandoned_shutdown(&self, id: u64, owner: u64) {
        let mut state = self
            .inner
            .state
            .lock()
            .expect("interface registry mutex poisoned");
        let Some(record) = state.records.get_mut(&id) else {
            return;
        };
        if record.owner == owner && record.state == RecordState::Stopping {
            record.state = RecordState::Abandoned;
            drop(state);
            self.inner.changed.notify_waiters();
        }
    }

    pub(crate) fn finish_abandoned(&self, id: u64, owner: u64) {
        self.inner.remove_exact(id, owner);
    }

    pub(crate) fn commit_batch(
        &self,
        mut registrations: Vec<InterfaceRegistration>,
    ) -> Result<(), Vec<InterfaceRegistration>> {
        let mut state = self
            .inner
            .state
            .lock()
            .expect("interface registry mutex poisoned");
        if state.admission != RegistryAdmission::Open {
            drop(state);
            return Err(registrations);
        }
        let valid = registrations.iter().all(|registration| {
            Arc::ptr_eq(&self.inner, &registration.registry.inner)
                && state.records.get(&registration.id).is_some_and(|record| {
                    record.owner == registration.owner
                        && record.state
                            == (RecordState::Pending {
                                cancel_requested: false,
                                abandoned: false,
                            })
                })
        });
        if !valid {
            drop(state);
            return Err(registrations);
        }

        for registration in &mut registrations {
            let record = state
                .records
                .get_mut(&registration.id)
                .expect("batch reservation was validated");
            record.task = registration.task.take();
            record.driver = registration.driver.take();
            record.state = RecordState::Active;
            registration.committed = true;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.inner
            .state
            .lock()
            .expect("interface registry mutex poisoned")
            .records
            .len()
    }

    #[cfg(test)]
    fn owner_for_test(&self, id: u64) -> Option<u64> {
        self.inner
            .state
            .lock()
            .expect("interface registry mutex poisoned")
            .records
            .get(&id)
            .map(|record| record.owner)
    }

    /// Atomically close admission and lease every active interface to the
    /// runtime-wide drain coordinator. Pending registrations are cancelled
    /// under the same lock, so a concurrent commit cannot cross the drain
    /// boundary.
    pub(crate) fn begin_drain(&self) -> DrainStart {
        let mut state = self
            .inner
            .state
            .lock()
            .expect("interface registry mutex poisoned");
        match state.admission {
            RegistryAdmission::Draining => return DrainStart::AlreadyDraining,
            RegistryAdmission::Closed => return DrainStart::Closed,
            RegistryAdmission::Open => state.admission = RegistryAdmission::Draining,
        }

        let mut shutdowns = Vec::new();
        let mut waiters = Vec::new();
        let mut abandoned_registrations = Vec::new();
        for (&id, record) in &mut state.records {
            if let Some(online) = &record.online {
                online.store(false, Ordering::SeqCst);
            }
            match &mut record.state {
                RecordState::Pending {
                    cancel_requested,
                    abandoned,
                } => {
                    *cancel_requested = true;
                    if *abandoned {
                        record.state = RecordState::Abandoned;
                        abandoned_registrations.push((id, record.owner));
                    } else {
                        waiters.push((id, record.owner));
                    }
                }
                RecordState::Active => {
                    record.state = RecordState::Stopping;
                    shutdowns.push(InterfaceShutdown {
                        registry: self.clone(),
                        id,
                        owner: record.owner,
                        kind: record.kind,
                        strategy: record.strategy,
                        task: record.task.take(),
                        online: record.online.clone(),
                        driver: record.driver.take(),
                        control_owner: Some(record.owner),
                        finished: false,
                    });
                }
                RecordState::Stopping => waiters.push((id, record.owner)),
                RecordState::Abandoned => abandoned_registrations.push((id, record.owner)),
            }
        }
        drop(state);
        self.inner.changed.notify_waiters();
        DrainStart::Acquired(InterfaceDrain {
            shutdowns,
            waiters,
            abandoned_registrations,
        })
    }

    /// Finish the one-way runtime lifecycle. This is called only after the
    /// transport actor has persisted and stopped, so any remaining entries
    /// are shutdown-only tombstones and can no longer race ID reuse.
    fn try_finish_drain(&self, expected: &[(u64, u64)]) -> Result<(), ()> {
        let mut state = self
            .inner
            .state
            .lock()
            .expect("interface registry mutex poisoned");
        let exact_shutdown_leases = state.records.len() == expected.len()
            && expected.iter().all(|(id, owner)| {
                state.records.get(id).is_some_and(|record| {
                    record.owner == *owner
                        && record.state == RecordState::Stopping
                        && record.task.is_none()
                        && record.driver.is_none()
                })
            });
        if !exact_shutdown_leases || state.in_flight_spawns != 0 {
            return Err(());
        }
        state.admission = RegistryAdmission::Closed;
        state.records.clear();
        drop(state);
        self.inner.changed.notify_waiters();
        Ok(())
    }

    pub(crate) async fn finish_drain_when_owned(&self, expected: &[(u64, u64)]) {
        loop {
            let changed = self.inner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.try_finish_drain(expected).is_ok() {
                return;
            }
            changed.await;
        }
    }

    #[cfg(test)]
    pub(crate) fn admission_for_test(&self) -> RegistryAdmission {
        self.inner
            .state
            .lock()
            .expect("interface registry mutex poisoned")
            .admission
    }
}

pub(crate) struct InterfaceSpawnPermit {
    registry: InterfaceRegistry,
    released: bool,
}

impl InterfaceSpawnPermit {
    fn release(&mut self) {
        if self.released {
            return;
        }
        let mut state = self
            .registry
            .inner
            .state
            .lock()
            .expect("interface registry mutex poisoned");
        state.in_flight_spawns = state
            .in_flight_spawns
            .checked_sub(1)
            .expect("interface spawn permit count underflowed");
        self.released = true;
        drop(state);
        self.registry.inner.changed.notify_waiters();
    }
}

impl Drop for InterfaceSpawnPermit {
    fn drop(&mut self) {
        self.release();
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
        let mut state = self
            .registry
            .inner
            .state
            .lock()
            .expect("interface registry mutex poisoned");
        if state.admission != RegistryAdmission::Open {
            drop(state);
            return Err(self);
        }
        let Some(record) = state.records.get_mut(&self.id) else {
            drop(state);
            return Err(self);
        };
        if record.owner != self.owner
            || record.state
                != (RecordState::Pending {
                    cancel_requested: false,
                    abandoned: false,
                })
        {
            drop(state);
            return Err(self);
        }

        let task = self.task.take().expect("pending registration owns a task");
        let driver = self.driver.take();
        record.task = Some(task);
        record.driver = driver;
        record.state = RecordState::Active;
        self.committed = true;
        Ok(())
    }

    pub(crate) async fn rollback(mut self) {
        self.stop_task_and_wait().await;
        self.release();
    }

    pub(crate) async fn stop_task_and_wait(&mut self) {
        stop_owned_task(&mut self.task, &mut self.driver, Some(self.id)).await;
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
        let registry = self.registry.clone();
        let id = self.id;
        let owner = self.owner;
        let mut task = self.task.take();
        let mut driver = self.driver.take();
        if task.is_none() && driver.is_none() {
            registry.mark_abandoned_pending(id, owner);
            return;
        }
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                stop_owned_task(&mut task, &mut driver, Some(id)).await;
                registry.mark_abandoned_pending(id, owner);
            });
        } else if let Some(driver) = driver.take() {
            driver.request_shutdown();
        } else if let Some(task) = task.take() {
            task.abort();
        }
        // The exact owner remains fail-closed until the detached cleanup has
        // joined the task. During a runtime drain the coordinator claims the
        // resulting Abandoned record and orders any possible actor rollback.
    }
}

pub(crate) struct RejectedInterfaceRegistration {
    task: Option<JoinHandle<()>>,
    driver: Option<rns_interface::rnode::RNodeDriverHandle>,
    reason: InterfaceRegistrationRejection,
}

impl std::fmt::Debug for RejectedInterfaceRegistration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RejectedInterfaceRegistration")
            .field("reason", &self.reason)
            .finish_non_exhaustive()
    }
}

impl RejectedInterfaceRegistration {
    pub(crate) fn reason(&self) -> InterfaceRegistrationRejection {
        self.reason
    }

    pub(crate) async fn stop_and_wait(mut self) {
        stop_owned_task(&mut self.task, &mut self.driver, None).await;
    }
}

impl Drop for RejectedInterfaceRegistration {
    fn drop(&mut self) {
        if let Some(driver) = self.driver.take() {
            driver.request_shutdown();
        } else if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

pub(crate) enum ShutdownStart {
    Acquired(InterfaceShutdown),
    RegistrationPending { owner: u64 },
    AlreadyStopping { owner: u64 },
    RegistryDraining,
}

pub(crate) enum ExactShutdownStart {
    Acquired(InterfaceShutdown),
    AlreadyStopping,
    NotOwned,
}

pub(crate) enum DrainStart {
    Acquired(InterfaceDrain),
    AlreadyDraining,
    Closed,
}

pub(crate) struct InterfaceDrain {
    shutdowns: Vec<InterfaceShutdown>,
    waiters: Vec<InterfaceOwnerToken>,
    abandoned_registrations: Vec<InterfaceOwnerToken>,
}

pub(crate) type InterfaceOwnerToken = (u64, u64);
pub(crate) type InterfaceDrainParts = (
    Vec<InterfaceShutdown>,
    Vec<InterfaceOwnerToken>,
    Vec<InterfaceOwnerToken>,
);

impl InterfaceDrain {
    pub(crate) fn into_parts(self) -> InterfaceDrainParts {
        (self.shutdowns, self.waiters, self.abandoned_registrations)
    }
}

pub(crate) struct InterfaceShutdown {
    registry: InterfaceRegistry,
    id: u64,
    owner: u64,
    kind: InterfaceKind,
    strategy: InterfaceShutdownStrategy,
    task: Option<JoinHandle<()>>,
    online: Option<Arc<std::sync::atomic::AtomicBool>>,
    driver: Option<rns_interface::rnode::RNodeDriverHandle>,
    control_owner: Option<u64>,
    finished: bool,
}

impl InterfaceShutdown {
    pub(crate) fn token(&self) -> (u64, u64) {
        (self.id, self.owner)
    }

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
        stop_owned_task(&mut self.task, &mut self.driver, Some(self.id)).await;
    }

    /// Signal exact RNode owners before joining any one interface. Standard
    /// tasks have no cooperative stop primitive and are aborted by the join
    /// phase instead.
    pub(crate) fn request_driver_shutdown(&self) {
        if let Some(driver) = &self.driver {
            driver.request_shutdown();
        }
    }

    /// Stop this interface within the runtime drain's one absolute deadline.
    /// Returns false when the graceful exact-driver join exceeded the shared
    /// budget and the task had to be aborted.
    pub(crate) async fn stop_task_until(&mut self, deadline: tokio::time::Instant) -> bool {
        let graceful = if let Some(driver) = self.driver.take() {
            driver.request_shutdown();
            true
        } else {
            false
        };
        let Some(mut task) = self.task.take() else {
            return true;
        };
        if graceful && tokio::time::timeout_at(deadline, &mut task).await.is_ok() {
            return true;
        }
        if graceful {
            tracing::warn!(
                interface_id = self.id,
                "exact RNode driver did not stop before the runtime drain deadline; aborting task"
            );
        }
        task.abort();
        let _ = task.await;
        !graceful
    }

    pub(crate) fn finish(mut self) {
        self.registry.inner.remove_exact(self.id, self.owner);
        self.finished = true;
    }
}

impl Drop for InterfaceShutdown {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let registry = self.registry.clone();
        let id = self.id;
        let owner = self.owner;
        let mut task = self.task.take();
        let mut driver = self.driver.take();
        if task.is_none() && driver.is_none() {
            registry.mark_abandoned_shutdown(id, owner);
            return;
        }
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                stop_owned_task(&mut task, &mut driver, Some(id)).await;
                registry.mark_abandoned_shutdown(id, owner);
            });
        } else if let Some(driver) = driver.take() {
            driver.request_shutdown();
        } else if let Some(task) = task.take() {
            task.abort();
        }
        // The Stopping tombstone remains fail-closed until the detached task
        // join completes. A later runtime drain claims Abandoned and orders
        // the possible actor deregistration before closing permanently.
    }
}

const EXACT_RNODE_SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(10);

async fn stop_owned_task(
    task: &mut Option<JoinHandle<()>>,
    driver: &mut Option<rns_interface::rnode::RNodeDriverHandle>,
    id: Option<u64>,
) {
    let graceful = if let Some(driver) = driver.take() {
        driver.request_shutdown();
        true
    } else {
        false
    };
    let Some(mut task) = task.take() else {
        return;
    };
    if graceful {
        if tokio::time::timeout(EXACT_RNODE_SHUTDOWN_GRACE, &mut task)
            .await
            .is_ok()
        {
            return;
        }
        tracing::warn!(
            interface_id = ?id,
            grace_ms = EXACT_RNODE_SHUTDOWN_GRACE.as_millis(),
            "exact RNode driver did not stop before the bounded join deadline; aborting task"
        );
    }
    task.abort();
    let _ = task.await;
}

pub(crate) async fn stop_unregistered_task(
    task: JoinHandle<()>,
    driver: Option<rns_interface::rnode::RNodeDriverHandle>,
) {
    let mut task = Some(task);
    let mut driver = driver;
    stop_owned_task(&mut task, &mut driver, None).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::sync::oneshot;

    fn pending_task() -> JoinHandle<()> {
        tokio::spawn(std::future::pending())
    }

    fn assert_registry_mutex_is_available(registry: &InterfaceRegistry) {
        let state = registry
            .inner
            .state
            .try_lock()
            .expect("observation lookup must release the registry mutex");
        drop(state);
    }

    async fn assert_non_rnode_kind_is_rejected(kind: InterfaceKind, id: u64) {
        let registry = InterfaceRegistry::default();
        assert!(matches!(
            registry.observe_active_rnode(id),
            Err(RNodeObservationLookupError::NotFound)
        ));
        assert_registry_mutex_is_available(&registry);

        let registration = registry
            .reserve(id, kind, pending_task(), None)
            .expect("non-RNode reservation");
        assert!(matches!(
            registry.observe_active_rnode(id),
            Err(RNodeObservationLookupError::NotRNode)
        ));
        assert_registry_mutex_is_available(&registry);

        assert!(registration.commit().is_ok(), "commit non-RNode record");
        assert!(matches!(
            registry.observe_active_rnode(id),
            Err(RNodeObservationLookupError::NotRNode)
        ));
        assert_registry_mutex_is_available(&registry);

        let ShutdownStart::Acquired(mut shutdown) = registry.begin_shutdown(id) else {
            panic!("active non-RNode record must yield shutdown ownership");
        };
        assert!(matches!(
            registry.observe_active_rnode(id),
            Err(RNodeObservationLookupError::NotRNode)
        ));
        assert_registry_mutex_is_available(&registry);
        shutdown.stop_task_and_wait().await;
        shutdown.finish();
    }

    #[tokio::test]
    async fn observation_lookup_rejects_missing_and_non_exact_kinds_without_holding_lock() {
        assert_non_rnode_kind_is_rejected(InterfaceKind::Standard, 1_001).await;
        #[cfg(feature = "serial")]
        assert_non_rnode_kind_is_rejected(InterfaceKind::RNodeMulti, 1_002).await;
        #[cfg(feature = "ble")]
        assert_non_rnode_kind_is_rejected(InterfaceKind::BlePeer, 1_003).await;
    }

    #[cfg(feature = "rnode-tcp")]
    #[tokio::test]
    async fn observation_lookup_exposes_only_active_exact_rnode_and_releases_lock() {
        use std::io::Read;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("tcp://{}", listener.local_addr().unwrap());
        let peer = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut buffer = [0_u8; 512];
            loop {
                match stream.read(&mut buffer) {
                    Ok(0) => return,
                    Ok(_) => {}
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::Interrupted
                                | std::io::ErrorKind::WouldBlock
                                | std::io::ErrorKind::TimedOut
                        ) =>
                    {
                        panic!("timed out waiting for exact RNode shutdown: {error}");
                    }
                    Err(error) => panic!("RNode peer read failed: {error}"),
                }
            }
        });

        let id = 1_005;
        let (transport_tx, _transport_rx) = tokio::sync::mpsc::channel(4);
        let spawned = rns_interface::rnode::spawn_rnode_interface_with_driver(
            rns_interface::rnode::RNodeConfig::new("observed-rnode", &endpoint),
            id,
            transport_tx,
        )
        .await
        .expect("spawn observed RNode");
        let registry = InterfaceRegistry::default();
        let registration = registry
            .reserve(
                id,
                InterfaceKind::RNode,
                spawned.interface.read_task,
                Some(spawned.driver),
            )
            .expect("reserve observed RNode");

        assert!(matches!(
            registry.observe_active_rnode(id),
            Err(RNodeObservationLookupError::NotActive)
        ));
        assert_registry_mutex_is_available(&registry);

        assert!(registration.commit().is_ok(), "commit observed RNode");
        let subscription = registry
            .observe_active_rnode(id)
            .expect("active exact RNode must be observable");
        assert_eq!(
            subscription.snapshot().transport,
            rns_interface::rnode::RNodeTransportClass::Tcp
        );
        assert_registry_mutex_is_available(&registry);

        let ShutdownStart::Acquired(mut shutdown) = registry.begin_shutdown(id) else {
            panic!("active exact RNode must yield shutdown ownership");
        };
        assert!(matches!(
            registry.observe_active_rnode(id),
            Err(RNodeObservationLookupError::NotActive)
        ));
        assert_registry_mutex_is_available(&registry);

        {
            let mut state = registry.inner.state.lock().unwrap();
            state.records.get_mut(&id).unwrap().state = RecordState::Abandoned;
        }
        assert!(matches!(
            registry.observe_active_rnode(id),
            Err(RNodeObservationLookupError::NotActive)
        ));
        assert_registry_mutex_is_available(&registry);

        {
            let mut state = registry.inner.state.lock().unwrap();
            state.records.get_mut(&id).unwrap().state = RecordState::Active;
        }
        assert!(matches!(
            registry.observe_active_rnode(id),
            Err(RNodeObservationLookupError::NotActive)
        ));
        assert_registry_mutex_is_available(&registry);

        shutdown.stop_task_and_wait().await;
        shutdown.finish();
        peer.join().unwrap();
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
        duplicate.stop_and_wait().await;
        assert!(duplicate_dropped.load(Ordering::Acquire));
        assert_eq!(registry.owner_for_test(11), Some(first_owner));

        first.rollback().await;
        assert_eq!(registry.len(), 0);
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[tokio::test]
    async fn exact_kind_without_driver_is_rejected_and_joined() {
        struct Dropped(Arc<AtomicBool>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        let registry = InterfaceRegistry::default();
        let dropped = Arc::new(AtomicBool::new(false));
        let task_dropped = dropped.clone();
        let task = tokio::spawn(async move {
            let _dropped = Dropped(task_dropped);
            std::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;

        let rejected = match registry.reserve(13, InterfaceKind::RNode, task, None) {
            Ok(_) => panic!("exact RNode kind must require an exact driver"),
            Err(rejected) => rejected,
        };
        assert_eq!(
            rejected.reason(),
            InterfaceRegistrationRejection::InvalidDriverOwnership
        );
        rejected.stop_and_wait().await;
        assert!(dropped.load(Ordering::Acquire));
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
        rejected.stop_and_wait().await;

        let stopping_registry = InterfaceRegistry::default();
        struct Dropped(Arc<AtomicBool>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        let task_dropped = Arc::new(AtomicBool::new(false));
        let task_dropped_clone = task_dropped.clone();
        let (started_tx, started_rx) = oneshot::channel();
        let registration = stopping_registry
            .reserve(
                31,
                InterfaceKind::Standard,
                tokio::spawn(async move {
                    let _dropped = Dropped(task_dropped_clone);
                    let _ = started_tx.send(());
                    std::future::pending::<()>().await;
                }),
                None,
            )
            .expect("stopping reservation");
        started_rx.await.expect("owned task started");
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
        rejected.stop_and_wait().await;
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !task_dropped.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dropped shutdown cleanup must join the owned task");
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
        rejected.stop_and_wait().await;
        shutdown.finish();

        let replacement = registry
            .reserve(37, InterfaceKind::Standard, pending_task(), None)
            .expect("explicit finish releases orphan tombstone");
        replacement.rollback().await;
    }

    #[tokio::test]
    async fn drain_closes_admission_and_waits_for_pre_spawn_permits() {
        let registry = InterfaceRegistry::default();
        let permit = registry
            .acquire_spawn_permit()
            .expect("open registry grants a pre-spawn permit");

        let DrainStart::Acquired(drain) = registry.begin_drain() else {
            panic!("first drain owns the transition");
        };
        assert_eq!(registry.admission_for_test(), RegistryAdmission::Draining);
        let (shutdowns, waiters, abandoned) = drain.into_parts();
        assert!(shutdowns.is_empty());
        assert!(waiters.is_empty());
        assert!(abandoned.is_empty());

        let rejected = match registry.reserve(41, InterfaceKind::Standard, pending_task(), None) {
            Ok(_) => panic!("draining registry must reject a newly spawned interface"),
            Err(rejected) => rejected,
        };
        assert_eq!(rejected.reason(), InterfaceRegistrationRejection::Draining);
        rejected.stop_and_wait().await;

        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(20),
                registry.wait_for_spawn_permits(),
            )
            .await
            .is_err(),
            "drain must wait while physical spawn ownership is outstanding"
        );
        drop(permit);
        registry.wait_for_spawn_permits().await;
        registry.finish_drain_when_owned(&[]).await;
        assert_eq!(registry.admission_for_test(), RegistryAdmission::Closed);

        let rejected = match registry.reserve(43, InterfaceKind::Standard, pending_task(), None) {
            Ok(_) => panic!("closed registry must never reopen"),
            Err(rejected) => rejected,
        };
        assert_eq!(rejected.reason(), InterfaceRegistrationRejection::Closed);
        rejected.stop_and_wait().await;
        assert!(matches!(
            registry.begin_shutdown(99),
            ShutdownStart::RegistryDraining
        ));
    }

    #[tokio::test]
    async fn drain_cancels_pending_and_exactly_leases_active_records() {
        let registry = InterfaceRegistry::default();
        let pending_online = Arc::new(AtomicBool::new(true));
        let pending = registry
            .reserve_with_online(
                45,
                InterfaceKind::Standard,
                pending_task(),
                None,
                Some(pending_online.clone()),
            )
            .expect("pending reservation");
        let active_online = Arc::new(AtomicBool::new(true));
        let active = registry
            .reserve_with_online(
                47,
                InterfaceKind::Standard,
                pending_task(),
                None,
                Some(active_online.clone()),
            )
            .expect("active reservation");
        assert!(active.commit().is_ok(), "commit active record");

        let DrainStart::Acquired(drain) = registry.begin_drain() else {
            panic!("first drain owns the transition");
        };
        assert!(!pending_online.load(Ordering::SeqCst));
        assert!(!active_online.load(Ordering::SeqCst));
        let (mut shutdowns, waiters, abandoned) = drain.into_parts();
        assert_eq!(shutdowns.len(), 1);
        assert_eq!(waiters.len(), 1);
        assert!(abandoned.is_empty());

        let pending = pending
            .commit()
            .expect_err("drain-cancelled pending record cannot commit");
        pending.rollback().await;
        registry
            .wait_until_not_owner(waiters[0].0, waiters[0].1)
            .await;

        let token = shutdowns[0].token();
        shutdowns[0]
            .stop_task_until(tokio::time::Instant::now() + std::time::Duration::from_secs(1))
            .await;
        registry.finish_drain_when_owned(&[token]).await;
        drop(shutdowns);
        assert_eq!(registry.admission_for_test(), RegistryAdmission::Closed);
        assert_eq!(registry.len(), 0);
    }

    #[tokio::test]
    async fn abandoned_pending_owner_is_joined_then_claimed_by_drain() {
        struct Dropped(Arc<AtomicBool>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        let registry = InterfaceRegistry::default();
        let dropped = Arc::new(AtomicBool::new(false));
        let dropped_in_task = dropped.clone();
        let (started_tx, started_rx) = oneshot::channel();
        let registration = registry
            .reserve(
                49,
                InterfaceKind::Standard,
                tokio::spawn(async move {
                    let _dropped = Dropped(dropped_in_task);
                    let _ = started_tx.send(());
                    std::future::pending::<()>().await;
                }),
                None,
            )
            .expect("pending owner");
        let owner = registration.owner();
        started_rx.await.expect("task started");
        drop(registration);
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !dropped.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("abandoned task cleanup joined");

        let DrainStart::Acquired(drain) = registry.begin_drain() else {
            panic!("drain acquired");
        };
        let (shutdowns, waiters, abandoned) = drain.into_parts();
        assert!(shutdowns.is_empty());
        assert!(waiters.is_empty());
        assert_eq!(abandoned, vec![(49, owner)]);
        registry.finish_abandoned(49, owner);
        registry.finish_drain_when_owned(&[]).await;
        assert_eq!(registry.admission_for_test(), RegistryAdmission::Closed);
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
                InterfaceShutdownStrategy::ExactRNodeDriver
            );
        }
        #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
        assert_eq!(
            InterfaceKind::RNode.shutdown_strategy(),
            InterfaceShutdownStrategy::ExactRNodeDriver
        );
        #[cfg(target_os = "android")]
        assert_eq!(
            InterfaceKind::AndroidUsbRNode.shutdown_strategy(),
            InterfaceShutdownStrategy::ExactRNodeDriver
        );
    }
}
