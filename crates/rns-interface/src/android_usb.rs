//! USB serial RNode over Android USB-C OTG via JNI to `UsbManager`. 115200 8N1.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::{mpsc, watch};

use crate::android_usb_lifecycle::{
    OwnedUsbIo, UsbConnectionCleanup, UsbConnectionLifecycle, UsbInboundOutcome, UsbInboundState,
    UsbIoEvent, UsbLeaseTable, UsbReadDrainOutcome, UsbReadResult, UsbReaderBackend,
    UsbShutdownReport, UsbTransferError, UsbTxPumpExit, UsbWriterBackend, drain_usb_reader_tail,
    forward_usb_read_chunk, run_usb_rnode_startup, run_usb_tx_pump, spawn_owned_usb_io,
};
#[cfg(test)]
use crate::kiss;
use crate::rnode::{
    self, RNodeDriverShutdown, RNodeRuntimeReason, RNodeTransportClass, SpawnedRNodeInterface,
};
use crate::rnode_protocol::RNodeProtocolTarget;
use crate::traits::{
    InterfaceDirection, InterfaceError, InterfaceHandle, InterfaceId, InterfaceMode,
};
use rns_transport::messages::TransportMessage;

pub const BAUD_RATE: u32 = 115_200;
const USB_WRITE_QUEUE: usize = 64;
const USB_READ_QUEUE: usize = 64;
const USB_WRITE_TIMEOUT_MS: i32 = 1_000;
const USB_READ_TIMEOUT_MS: i32 = 100;
const USB_DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_millis(USB_WRITE_TIMEOUT_MS as u64);
const USB_STARTUP_ACK_DEADLINE: Duration = Duration::from_secs(2);
const USB_DETACH_ACK_DEADLINE: Duration = Duration::from_millis(500);
const USB_WORKER_JOIN_DEADLINE: Duration = Duration::from_millis(1_250);

/// USB VIDs of serial chipsets commonly used by RNode hardware.
pub const KNOWN_VIDS: &[(u16, &str)] = &[
    (0x0403, "FTDI"),
    (0x10C4, "Silicon Labs CP210x"),
    (0x1A86, "WCH CH340/CH341"),
    (0x0525, "CDC-ACM (Netchip)"),
    (0x2E8A, "Raspberry Pi Pico / RP2040"),
    (0x303A, "Espressif ESP32-S3"),
    (0x239A, "Adafruit"),
    (0x1915, "Nordic Semiconductor NRF52840"),
];

#[derive(Clone, Debug)]
enum AndroidUsbShutdownStatus {
    Running,
    Complete(Arc<UsbShutdownReport>),
}

#[derive(Clone)]
struct AndroidUsbStopHandle {
    stop_tx: mpsc::Sender<()>,
    status: watch::Receiver<AndroidUsbShutdownStatus>,
}

type AndroidUsbRNodeStopRegistry = Mutex<HashMap<InterfaceId, AndroidUsbStopHandle>>;

fn android_usb_rnode_stop_registry() -> &'static AndroidUsbRNodeStopRegistry {
    static REGISTRY: OnceLock<AndroidUsbRNodeStopRegistry> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

struct AndroidUsbRNodeStopRegistryGuard {
    id: InterfaceId,
    stop_tx: mpsc::Sender<()>,
    status: watch::Receiver<AndroidUsbShutdownStatus>,
}

impl Drop for AndroidUsbRNodeStopRegistryGuard {
    fn drop(&mut self) {
        if matches!(
            self.status.borrow().clone(),
            AndroidUsbShutdownStatus::Complete(report) if report.is_quarantined()
        ) {
            // Preserve the exact-ID failed outcome. The device-name
            // quarantine separately blocks a competing reopen.
            return;
        }
        let mut registry = android_usb_rnode_stop_registry()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let owns_entry = registry
            .get(&self.id)
            .is_some_and(|registered| registered.stop_tx.same_channel(&self.stop_tx));
        if owns_entry {
            registry.remove(&self.id);
        }
    }
}

fn register_android_usb_rnode_stop(
    id: InterfaceId,
    stop_tx: mpsc::Sender<()>,
    status: watch::Receiver<AndroidUsbShutdownStatus>,
) -> AndroidUsbRNodeStopRegistryGuard {
    let guard_status = status.clone();
    android_usb_rnode_stop_registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(
            id,
            AndroidUsbStopHandle {
                stop_tx: stop_tx.clone(),
                status,
            },
        );
    AndroidUsbRNodeStopRegistryGuard {
        id,
        stop_tx,
        status: guard_status,
    }
}

fn request_android_usb_rnode_stop(id: InterfaceId) -> Option<AndroidUsbStopHandle> {
    let stop_handle = android_usb_rnode_stop_registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&id)
        .cloned();
    let Some(stop_handle) = stop_handle else {
        tracing::debug!(id, "Android USB RNode stop requested for unknown interface");
        return None;
    };
    match stop_handle.stop_tx.try_send(()) {
        Ok(()) => tracing::info!(id, "Android USB RNode stop signal sent"),
        Err(mpsc::error::TrySendError::Full(_)) => {
            tracing::debug!(id, "Android USB RNode stop signal already pending")
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            tracing::debug!(id, "Android USB RNode stop signal receiver already closed")
        }
    }
    Some(stop_handle)
}

/// Compatibility stop request for the currently registered Android USB RNode.
///
/// New owners should retain [`crate::rnode::RNodeDriverHandle`] and call
/// [`crate::rnode::RNodeDriverHandle::request_shutdown`] so later ID reuse
/// cannot redirect the request. The acknowledged compatibility form below
/// remains available to existing runtime callers.
pub fn stop_android_usb_rnode_interface(id: InterfaceId) {
    let _ = request_android_usb_rnode_stop(id);
}

/// Request stop and wait until the JNI workers have joined and Java ownership
/// is either safely closed or explicitly quarantined. Idempotent; unknown ids
/// have already left the interface registry.
pub async fn stop_android_usb_rnode_interface_and_wait(id: InterfaceId) -> Result<(), String> {
    let Some(mut stop_handle) = request_android_usb_rnode_stop(id) else {
        return Ok(());
    };
    loop {
        match stop_handle.status.borrow().clone() {
            AndroidUsbShutdownStatus::Running => {}
            AndroidUsbShutdownStatus::Complete(report) => {
                return report.as_result();
            }
        }
        if stop_handle.status.changed().await.is_err() {
            return Err("Android USB owner ended without a shutdown outcome".into());
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UsbSerialDevice {
    pub device_name: String,
    pub vid: u16,
    pub pid: u16,
    pub chipset: String,
    pub manufacturer: String,
    pub product: String,
}

#[derive(Debug, Clone)]
pub struct AndroidUsbConfig {
    pub name: String,
    pub device_name: String,
    pub baud_rate: u32,
    pub frequency: u32,
    pub bandwidth: u32,
    pub spreading_factor: u8,
    pub coding_rate: u8,
    pub tx_power: u8,
    pub mode: InterfaceMode,
    /// Gate each TX on the radio's CMD_READY. Python default: off.
    pub flow_control: bool,
    /// Short-term airtime cap, percent (0.0..=100.0). `None` = unlimited.
    pub st_alock: Option<f32>,
    /// Long-term airtime cap, percent (0.0..=100.0). `None` = unlimited.
    pub lt_alock: Option<f32>,
}

impl AndroidUsbConfig {
    pub fn new(name: &str, device_name: &str) -> Self {
        Self {
            name: name.to_string(),
            device_name: device_name.to_string(),
            baud_rate: BAUD_RATE,
            frequency: 915_000_000,
            bandwidth: 125_000,
            spreading_factor: 8,
            coding_rate: 6,
            tx_power: 17,
            mode: InterfaceMode::Full,
            flow_control: false,
            st_alock: None,
            lt_alock: None,
        }
    }

    /// Validate RF and airtime settings before opening the physical device.
    pub fn validate(&self) -> Result<(), rnode::RNodeConfigValidationError> {
        rnode_config_from_android_usb_config(self).validate()
    }
}

fn rnode_config_from_android_usb_config(config: &AndroidUsbConfig) -> rnode::RNodeConfig {
    let mut rnode = rnode::RNodeConfig::new(&config.name, &config.device_name);
    rnode.baud_rate = config.baud_rate;
    rnode.frequency = config.frequency;
    rnode.bandwidth = config.bandwidth;
    rnode.spreading_factor = config.spreading_factor;
    rnode.coding_rate = config.coding_rate;
    rnode.tx_power = config.tx_power;
    rnode.mode = config.mode;
    rnode.flow_control = config.flow_control;
    rnode.st_alock = config.st_alock;
    rnode.lt_alock = config.lt_alock;
    rnode
}

use jni::JavaVM;
use jni::objects::{GlobalRef, JObject, JValue};

static JAVA_VM: OnceLock<JavaVM> = OnceLock::new();
static APP_CONTEXT: OnceLock<GlobalRef> = OnceLock::new();

/// Stash JavaVM (wired from `JNI_OnLoad`); Application context fetched lazily
/// via `ActivityThread.currentApplication()` so callers don't thread it through.
pub fn init_vm(vm: JavaVM) {
    let _ = JAVA_VM.set(vm);
}

/// Shared JavaVM accessor (e.g. `auto.rs::get_link_local_addrs_android`).
/// `None` until `init_vm` has run.
pub fn java_vm() -> Option<&'static JavaVM> {
    JAVA_VM.get()
}

fn with_env<F, R>(f: F) -> Result<R, String>
where
    F: FnOnce(&jni::JNIEnv) -> Result<R, String>,
{
    let vm = JAVA_VM.get().ok_or("JavaVM not initialized for USB")?;
    let env = vm
        .attach_current_thread()
        .map_err(|e| format!("JNI: {e}"))?;
    f(&env)
}

/// Lazily resolve the Application context; cached after first resolution.
fn ensure_app_context(env: &jni::JNIEnv) -> Result<&'static GlobalRef, String> {
    if let Some(ctx) = APP_CONTEXT.get() {
        return Ok(ctx);
    }
    let activity_thread = env
        .find_class("android/app/ActivityThread")
        .map_err(|e| format!("ActivityThread class: {e}"))?;
    let app = env
        .call_static_method(
            activity_thread,
            "currentApplication",
            "()Landroid/app/Application;",
            &[],
        )
        .map_err(|e| format!("currentApplication: {e}"))?
        .l()
        .map_err(|e| format!("currentApplication object: {e}"))?;
    if app.is_null() {
        return Err("ActivityThread.currentApplication() returned null".into());
    }
    let global = env
        .new_global_ref(app)
        .map_err(|e| format!("new_global_ref(application): {e}"))?;
    let _ = APP_CONTEXT.set(global);
    APP_CONTEXT
        .get()
        .ok_or_else(|| "APP_CONTEXT race".to_string())
}

pub async fn enumerate_usb_devices() -> Result<Vec<UsbSerialDevice>, String> {
    tokio::task::spawn_blocking(|| {
        with_env(|env| {
            let ctx = ensure_app_context(env)?;
            let usb_str = env.new_string("usb").map_err(|e| format!("{e}"))?;
            let usb_mgr = env
                .call_method(
                    ctx.as_obj(),
                    "getSystemService",
                    "(Ljava/lang/String;)Ljava/lang/Object;",
                    &[JValue::Object(usb_str.into())],
                )
                .map_err(|e| format!("{e}"))?
                .l()
                .map_err(|e| format!("{e}"))?;

            let device_map = env
                .call_method(usb_mgr, "getDeviceList", "()Ljava/util/HashMap;", &[])
                .map_err(|e| format!("{e}"))?
                .l()
                .map_err(|e| format!("{e}"))?;
            let values = env
                .call_method(device_map, "values", "()Ljava/util/Collection;", &[])
                .map_err(|e| format!("{e}"))?
                .l()
                .map_err(|e| format!("{e}"))?;
            let iter = env
                .call_method(values, "iterator", "()Ljava/util/Iterator;", &[])
                .map_err(|e| format!("{e}"))?
                .l()
                .map_err(|e| format!("{e}"))?;

            let mut devices = Vec::new();
            loop {
                let has_next = env
                    .call_method(iter, "hasNext", "()Z", &[])
                    .map_err(|e| format!("{e}"))?
                    .z()
                    .map_err(|e| format!("{e}"))?;
                if !has_next {
                    break;
                }

                let device = env
                    .call_method(iter, "next", "()Ljava/lang/Object;", &[])
                    .map_err(|e| format!("{e}"))?
                    .l()
                    .map_err(|e| format!("{e}"))?;
                let vid = env
                    .call_method(device, "getVendorId", "()I", &[])
                    .map_err(|e| format!("{e}"))?
                    .i()
                    .map_err(|e| format!("{e}"))? as u16;
                let pid = env
                    .call_method(device, "getProductId", "()I", &[])
                    .map_err(|e| format!("{e}"))?
                    .i()
                    .map_err(|e| format!("{e}"))? as u16;
                let name_js = env
                    .call_method(device, "getDeviceName", "()Ljava/lang/String;", &[])
                    .map_err(|e| format!("{e}"))?
                    .l()
                    .map_err(|e| format!("{e}"))?;
                let name: String = env
                    .get_string(name_js.into())
                    .map(|s| s.into())
                    .unwrap_or_default();

                let chipset = KNOWN_VIDS
                    .iter()
                    .find(|(v, _)| *v == vid)
                    .map(|(_, n)| n.to_string())
                    .unwrap_or_default();

                if !chipset.is_empty() {
                    devices.push(UsbSerialDevice {
                        device_name: name,
                        vid,
                        pid,
                        chipset,
                        manufacturer: String::new(),
                        product: String::new(),
                    });
                }
            }
            Ok(devices)
        })
    })
    .await
    .map_err(|e| format!("{e}"))?
}

pub async fn request_usb_permission(device_name: &str) -> Result<bool, String> {
    let dev_name = device_name.to_string();
    tokio::task::spawn_blocking(move || {
        with_env(|env| {
            let ctx = ensure_app_context(env)?;
            let usb_str = env.new_string("usb").map_err(|e| format!("{e}"))?;
            let usb_mgr = env
                .call_method(
                    ctx.as_obj(),
                    "getSystemService",
                    "(Ljava/lang/String;)Ljava/lang/Object;",
                    &[JValue::Object(usb_str.into())],
                )
                .map_err(|e| format!("{e}"))?
                .l()
                .map_err(|e| format!("{e}"))?;

            let device_map = env
                .call_method(usb_mgr, "getDeviceList", "()Ljava/util/HashMap;", &[])
                .map_err(|e| format!("{e}"))?
                .l()
                .map_err(|e| format!("{e}"))?;
            let key = env.new_string(&dev_name).map_err(|e| format!("{e}"))?;
            let device = env
                .call_method(
                    device_map,
                    "get",
                    "(Ljava/lang/Object;)Ljava/lang/Object;",
                    &[JValue::Object(key.into())],
                )
                .map_err(|e| format!("{e}"))?
                .l()
                .map_err(|e| format!("{e}"))?;

            if device.is_null() {
                return Err(format!("USB device not found: {dev_name}"));
            }

            env.call_method(
                usb_mgr,
                "hasPermission",
                "(Landroid/hardware/usb/UsbDevice;)Z",
                &[JValue::Object(device)],
            )
            .map_err(|e| format!("{e}"))?
            .z()
            .map_err(|e| format!("{e}"))
        })
    })
    .await
    .map_err(|e| format!("{e}"))?
}

fn clear_pending_jni_exception(env: &jni::JNIEnv) {
    if env.exception_check().unwrap_or(false) {
        let _ = env.exception_clear();
    }
}

fn jni_failure(env: &jni::JNIEnv, context: &str, error: impl std::fmt::Display) -> String {
    clear_pending_jni_exception(env);
    format!("{context}: {error}")
}

struct JniUsbConnectionOwner {
    connection: Option<GlobalRef>,
    data_interface: Option<GlobalRef>,
    interface_claimed: bool,
    device_name: String,
    lease_phase: JniUsbLeasePhase,
}

struct JniUsbWriter {
    connection: Option<GlobalRef>,
    endpoint: Option<GlobalRef>,
}

struct JniUsbReader {
    connection: Option<GlobalRef>,
    endpoint: Option<GlobalRef>,
}

struct PendingAndroidUsbOpen {
    resources: Option<(JniUsbConnectionOwner, JniUsbWriter, JniUsbReader)>,
}

impl PendingAndroidUsbOpen {
    fn new(resources: (JniUsbConnectionOwner, JniUsbWriter, JniUsbReader)) -> Self {
        Self {
            resources: Some(resources),
        }
    }

    fn into_resources(
        mut self,
    ) -> Result<(JniUsbConnectionOwner, JniUsbWriter, JniUsbReader), String> {
        self.resources
            .take()
            .ok_or_else(|| "Android USB open handoff was already consumed".into())
    }
}

impl Drop for PendingAndroidUsbOpen {
    fn drop(&mut self) {
        let Some((owner, writer, reader)) = self.resources.take() else {
            return;
        };
        drop(reader);
        drop(writer);
        let error = cleanup_failed_android_usb_open(
            owner,
            "Android USB open result receiver was cancelled".into(),
        );
        tracing::warn!(error = %error, "cleaned up abandoned Android USB open");
    }
}

#[derive(Clone, Copy)]
enum JniUsbLeasePhase {
    Opening,
    Active,
}

struct JniUsbQuarantinedSession {
    _owner: Option<JniUsbConnectionOwner>,
    _reason: String,
}

type AndroidUsbLeaseRegistry = Mutex<UsbLeaseTable<JniUsbQuarantinedSession>>;

fn android_usb_lease_registry() -> &'static AndroidUsbLeaseRegistry {
    static REGISTRY: OnceLock<AndroidUsbLeaseRegistry> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(UsbLeaseTable::default()))
}

fn reserve_android_usb_opening(device_name: &str) -> Result<(), String> {
    android_usb_lease_registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .reserve_opening(device_name)
}

fn activate_android_usb_lease(owner: &mut JniUsbConnectionOwner) -> Result<(), String> {
    android_usb_lease_registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .activate(&owner.device_name)?;
    owner.lease_phase = JniUsbLeasePhase::Active;
    Ok(())
}

fn release_android_usb_lease(device_name: &str, phase: JniUsbLeasePhase) -> Result<(), String> {
    let mut leases = android_usb_lease_registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match phase {
        JniUsbLeasePhase::Opening => leases.release_opening(device_name),
        JniUsbLeasePhase::Active => leases.release_active(device_name),
    }
}

fn retain_android_usb_owner(owner: JniUsbConnectionOwner, reason: String) {
    let device_name = owner.device_name.clone();
    android_usb_lease_registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .quarantine(
            &device_name,
            JniUsbQuarantinedSession {
                _owner: Some(owner),
                _reason: reason.clone(),
            },
        );
    tracing::error!(
        device_name = %device_name,
        reason = %reason,
        "Android USB ownership quarantined; reopen is blocked for this process"
    );
}

fn retain_android_usb_unproven_session(device_name: &str, reason: String) {
    android_usb_lease_registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .quarantine(
            device_name,
            JniUsbQuarantinedSession {
                _owner: None,
                _reason: reason.clone(),
            },
        );
    tracing::error!(
        device_name = %device_name,
        reason = %reason,
        "Android USB open state is unproven; device permanently quarantined"
    );
}

fn drop_worker_global_refs_attached(
    connection: &mut Option<GlobalRef>,
    endpoint: &mut Option<GlobalRef>,
) {
    let connection = connection.take();
    let endpoint = endpoint.take();
    if let Some(vm) = JAVA_VM.get()
        && let Ok(env) = vm.attach_current_thread()
    {
        drop(endpoint);
        drop(connection);
        drop(env);
        return;
    }
    drop(endpoint);
    drop(connection);
}

impl Drop for JniUsbWriter {
    fn drop(&mut self) {
        drop_worker_global_refs_attached(&mut self.connection, &mut self.endpoint);
    }
}

impl Drop for JniUsbReader {
    fn drop(&mut self) {
        drop_worker_global_refs_attached(&mut self.connection, &mut self.endpoint);
    }
}

impl UsbWriterBackend for JniUsbWriter {
    fn transfer(&mut self, bytes: &[u8], timeout: Duration) -> Result<i32, UsbTransferError> {
        let vm = JAVA_VM.get().ok_or_else(|| {
            UsbTransferError::Backend("JavaVM not initialized for USB write".into())
        })?;
        let env = vm
            .attach_current_thread()
            .map_err(|error| UsbTransferError::Backend(format!("JNI attach: {error}")))?;
        let connection = self.connection.as_ref().ok_or_else(|| {
            UsbTransferError::Backend("USB writer connection already released".into())
        })?;
        let endpoint = self.endpoint.as_ref().ok_or_else(|| {
            UsbTransferError::Backend("USB writer endpoint already released".into())
        })?;
        let length = i32::try_from(bytes.len()).map_err(|_| {
            UsbTransferError::Backend(format!(
                "USB write length {} exceeds Android's signed limit",
                bytes.len()
            ))
        })?;
        let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
        if timeout_ms <= 0 {
            return Err(UsbTransferError::Backend(
                "USB write timeout budget is below one millisecond".into(),
            ));
        }
        let buffer = env.byte_array_from_slice(bytes).map_err(|error| {
            UsbTransferError::Backend(jni_failure(&env, "USB write buffer allocation", error))
        })?;
        let value = env
            .call_method(
                connection.as_obj(),
                "bulkTransfer",
                "(Landroid/hardware/usb/UsbEndpoint;[BII)I",
                &[
                    JValue::Object(endpoint.as_obj()),
                    JValue::Object(buffer.into()),
                    JValue::Int(length),
                    JValue::Int(timeout_ms),
                ],
            )
            .map_err(|error| {
                UsbTransferError::Backend(jni_failure(&env, "USB bulk write", error))
            })?;
        value.i().map_err(|_| {
            clear_pending_jni_exception(&env);
            UsbTransferError::WrongReturnType
        })
    }
}

impl UsbReaderBackend for JniUsbReader {
    fn read(&mut self) -> Result<UsbReadResult, String> {
        with_env(|env| {
            const READ_SIZE: i32 = 1_024;
            let connection = self
                .connection
                .as_ref()
                .ok_or("USB reader connection already released")?;
            let endpoint = self
                .endpoint
                .as_ref()
                .ok_or("USB reader endpoint already released")?;
            let buffer = env
                .new_byte_array(READ_SIZE)
                .map_err(|error| jni_failure(env, "USB read buffer allocation", error))?;
            let value = env
                .call_method(
                    connection.as_obj(),
                    "bulkTransfer",
                    "(Landroid/hardware/usb/UsbEndpoint;[BII)I",
                    &[
                        JValue::Object(endpoint.as_obj()),
                        JValue::Object(buffer.into()),
                        JValue::Int(READ_SIZE),
                        JValue::Int(USB_READ_TIMEOUT_MS),
                    ],
                )
                .map_err(|error| jni_failure(env, "USB bulk read", error))?;
            let read = value
                .i()
                .map_err(|error| jni_failure(env, "USB bulk read result", error))?;
            if read <= 0 {
                return Ok(UsbReadResult::Idle);
            }
            if read > READ_SIZE {
                return Err(format!(
                    "USB bulk read returned invalid length {read} (capacity {READ_SIZE})"
                ));
            }
            let bytes = env
                .convert_byte_array(buffer)
                .map_err(|error| jni_failure(env, "USB read buffer conversion", error))?;
            Ok(UsbReadResult::Data(bytes[..read as usize].to_vec()))
        })
    }
}

impl UsbConnectionLifecycle for JniUsbConnectionOwner {
    fn release_and_close(mut self) -> UsbConnectionCleanup<Self> {
        let Some(vm) = JAVA_VM.get() else {
            let error = "JavaVM not initialized for USB cleanup".to_string();
            return UsbConnectionCleanup::Unclosed {
                owner: self,
                release_interface: Err(error.clone()),
                close_connection: error,
            };
        };
        let env = match vm.attach_current_thread() {
            Ok(env) => env,
            Err(error) => {
                let error = format!("JNI cleanup attach: {error}");
                return UsbConnectionCleanup::Unclosed {
                    owner: self,
                    release_interface: Err(error.clone()),
                    close_connection: error,
                };
            }
        };
        let Some(connection) = self.connection.as_ref() else {
            let error = "USB owner connection already released".to_string();
            return UsbConnectionCleanup::Unclosed {
                owner: self,
                release_interface: Err(error.clone()),
                close_connection: error,
            };
        };
        let release_interface = if self.interface_claimed {
            match self.data_interface.as_ref() {
                Some(data_interface) => env
                    .call_method(
                        connection.as_obj(),
                        "releaseInterface",
                        "(Landroid/hardware/usb/UsbInterface;)Z",
                        &[JValue::Object(data_interface.as_obj())],
                    )
                    .map_err(|error| jni_failure(&env, "releaseInterface", error))
                    .and_then(|value| {
                        value
                            .z()
                            .map_err(|error| jni_failure(&env, "releaseInterface result", error))
                    })
                    .and_then(|released| {
                        released
                            .then_some(())
                            .ok_or_else(|| "Java releaseInterface returned false".into())
                    }),
                None => Err("claimed USB interface reference is missing".into()),
            }
        } else {
            Ok(())
        };
        // close is unconditional, including releaseInterface(false/error).
        let close_connection = env
            .call_method(connection.as_obj(), "close", "()V", &[])
            .map(|_| ())
            .map_err(|error| jni_failure(&env, "UsbDeviceConnection.close", error));

        if let Err(close_connection) = close_connection {
            drop(env);
            return UsbConnectionCleanup::Unclosed {
                owner: self,
                release_interface,
                close_connection,
            };
        }

        let lease_release = release_android_usb_lease(&self.device_name, self.lease_phase);
        let release_interface = match (release_interface, lease_release) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(release), Ok(())) => Err(release),
            (Ok(()), Err(lease)) => {
                retain_android_usb_unproven_session(
                    &self.device_name,
                    format!("closed connection but failed to release lease: {lease}"),
                );
                Err(format!("lease release: {lease}"))
            }
            (Err(release), Err(lease)) => {
                retain_android_usb_unproven_session(
                    &self.device_name,
                    format!("closed connection but failed to release lease: {lease}"),
                );
                Err(format!("{release}; lease release: {lease}"))
            }
        };

        // The joined workers have already dropped their temporary refs. Only
        // a proven close releases the canonical refs, and does so while this
        // cleanup thread is still JNI-attached.
        let data_interface = self.data_interface.take();
        let connection = self.connection.take();
        drop(data_interface);
        drop(connection);
        drop(env);
        UsbConnectionCleanup::Closed { release_interface }
    }

    fn retain_quarantined(self) {
        retain_android_usb_owner(self, "USB closure was not proven".into());
    }
}

fn cleanup_failed_android_usb_open(owner: JniUsbConnectionOwner, setup_error: String) -> String {
    match owner.release_and_close() {
        UsbConnectionCleanup::Closed { release_interface } => match release_interface {
            Ok(()) => setup_error,
            Err(cleanup) => format!("{setup_error}; cleanup: {cleanup}"),
        },
        UsbConnectionCleanup::Unclosed {
            owner,
            release_interface,
            close_connection,
        } => {
            let cleanup = match release_interface {
                Ok(()) => close_connection,
                Err(release) => format!("{release}; close: {close_connection}"),
            };
            retain_android_usb_owner(owner, format!("USB setup cleanup failed: {cleanup}"));
            format!("{setup_error}; cleanup unproven: {cleanup}")
        }
    }
}

fn open_usb_serial_attached(
    dev_name: &str,
    baud_rate: u32,
) -> Result<(JniUsbConnectionOwner, JniUsbWriter, JniUsbReader), String> {
    let result = with_env(|env| {
        let ctx = ensure_app_context(env)?;
        let usb_str = env
            .new_string("usb")
            .map_err(|error| jni_failure(env, "USB service string", error))?;
        let usb_mgr = env
            .call_method(
                ctx.as_obj(),
                "getSystemService",
                "(Ljava/lang/String;)Ljava/lang/Object;",
                &[JValue::Object(usb_str.into())],
            )
            .map_err(|error| jni_failure(env, "getSystemService(usb)", error))?
            .l()
            .map_err(|error| jni_failure(env, "USB manager object", error))?;
        let device_map = env
            .call_method(usb_mgr, "getDeviceList", "()Ljava/util/HashMap;", &[])
            .map_err(|error| jni_failure(env, "getDeviceList", error))?
            .l()
            .map_err(|error| jni_failure(env, "USB device map", error))?;
        let key = env
            .new_string(dev_name)
            .map_err(|error| jni_failure(env, "USB device-name string", error))?;
        let device = env
            .call_method(
                device_map,
                "get",
                "(Ljava/lang/Object;)Ljava/lang/Object;",
                &[JValue::Object(key.into())],
            )
            .map_err(|error| jni_failure(env, "USB device lookup", error))?
            .l()
            .map_err(|error| jni_failure(env, "USB device object", error))?;
        if device.is_null() {
            return Err(format!("USB device not found: {dev_name}"));
        }

        let connection = env
            .call_method(
                usb_mgr,
                "openDevice",
                "(Landroid/hardware/usb/UsbDevice;)Landroid/hardware/usb/UsbDeviceConnection;",
                &[JValue::Object(device)],
            )
            .map_err(|error| jni_failure(env, "openDevice", error))?
            .l()
            .map_err(|error| jni_failure(env, "USB connection object", error))?;
        if connection.is_null() {
            return Err("Failed to open USB device (permission denied?)".into());
        }

        let connection_ref = match env.new_global_ref(connection) {
            Ok(connection_ref) => connection_ref,
            Err(error) => {
                let allocation = jni_failure(env, "USB connection global reference", error);
                let close = env
                    .call_method(connection, "close", "()V", &[])
                    .map(|_| ())
                    .map_err(|error| {
                        jni_failure(env, "UsbDeviceConnection.close after open", error)
                    });
                match close {
                    Ok(()) => {
                        let _ = release_android_usb_lease(dev_name, JniUsbLeasePhase::Opening);
                        return Err(allocation);
                    }
                    Err(close) => {
                        retain_android_usb_unproven_session(
                            dev_name,
                            format!("{allocation}; {close}"),
                        );
                        return Err(format!("{allocation}; cleanup unproven: {close}"));
                    }
                }
            }
        };
        let mut owner = JniUsbConnectionOwner {
            connection: Some(connection_ref),
            data_interface: None,
            interface_claimed: false,
            device_name: dev_name.to_string(),
            lease_phase: JniUsbLeasePhase::Opening,
        };

        let setup = (|| -> Result<(GlobalRef, GlobalRef), String> {
            // CDC-Data (0x0A) or vendor-specific (0xFF), with a matched
            // IN/OUT endpoint pair from one interface.
            let iface_count = env
                .call_method(device, "getInterfaceCount", "()I", &[])
                .map_err(|error| jni_failure(env, "getInterfaceCount", error))?
                .i()
                .map_err(|error| jni_failure(env, "USB interface count", error))?;
            let mut data_iface = JObject::null();
            let mut ep_in = JObject::null();
            let mut ep_out = JObject::null();
            for interface_index in 0..iface_count {
                let interface = env
                    .call_method(
                        device,
                        "getInterface",
                        "(I)Landroid/hardware/usb/UsbInterface;",
                        &[JValue::Int(interface_index)],
                    )
                    .map_err(|error| jni_failure(env, "getInterface", error))?
                    .l()
                    .map_err(|error| jni_failure(env, "USB interface object", error))?;
                let class = env
                    .call_method(interface, "getInterfaceClass", "()I", &[])
                    .map_err(|error| jni_failure(env, "getInterfaceClass", error))?
                    .i()
                    .map_err(|error| jni_failure(env, "USB interface class", error))?;
                if class != 0x0A && class != 0xFF {
                    continue;
                }

                let endpoint_count = env
                    .call_method(interface, "getEndpointCount", "()I", &[])
                    .map_err(|error| jni_failure(env, "getEndpointCount", error))?
                    .i()
                    .map_err(|error| jni_failure(env, "USB endpoint count", error))?;
                let mut candidate_in = JObject::null();
                let mut candidate_out = JObject::null();
                for endpoint_index in 0..endpoint_count {
                    let endpoint = env
                        .call_method(
                            interface,
                            "getEndpoint",
                            "(I)Landroid/hardware/usb/UsbEndpoint;",
                            &[JValue::Int(endpoint_index)],
                        )
                        .map_err(|error| jni_failure(env, "getEndpoint", error))?
                        .l()
                        .map_err(|error| jni_failure(env, "USB endpoint object", error))?;
                    let direction = env
                        .call_method(endpoint, "getDirection", "()I", &[])
                        .map_err(|error| jni_failure(env, "getEndpointDirection", error))?
                        .i()
                        .map_err(|error| jni_failure(env, "USB endpoint direction", error))?;
                    if direction == 0x80 {
                        candidate_in = endpoint;
                    } else {
                        candidate_out = endpoint;
                    }
                }
                if !candidate_in.is_null() && !candidate_out.is_null() {
                    data_iface = interface;
                    ep_in = candidate_in;
                    ep_out = candidate_out;
                    break;
                }
            }
            if data_iface.is_null() {
                return Err("No CDC-ACM interface found".into());
            }

            owner.data_interface = Some(
                env.new_global_ref(data_iface)
                    .map_err(|error| jni_failure(env, "USB interface global reference", error))?,
            );
            let claimed = env
                .call_method(
                    connection,
                    "claimInterface",
                    "(Landroid/hardware/usb/UsbInterface;Z)Z",
                    &[JValue::Object(data_iface), JValue::Bool(1)],
                )
                .map_err(|error| jni_failure(env, "claimInterface", error))?
                .z()
                .map_err(|error| jni_failure(env, "claimInterface result", error))?;
            if !claimed {
                return Err("Java claimInterface returned false".into());
            }
            owner.interface_claimed = true;

            // CDC SET_LINE_CODING remains best-effort for vendor chipsets.
            let mut line_coding = [0u8; 7];
            line_coding[0..4].copy_from_slice(&baud_rate.to_le_bytes());
            line_coding[6] = 8;
            if let Ok(line_coding_array) = env.byte_array_from_slice(&line_coding) {
                let _ = env.call_method(
                    connection,
                    "controlTransfer",
                    "(IIII[BII)I",
                    &[
                        JValue::Int(0x21),
                        JValue::Int(0x20),
                        JValue::Int(0),
                        JValue::Int(0),
                        JValue::Object(line_coding_array.into()),
                        JValue::Int(7),
                        JValue::Int(USB_WRITE_TIMEOUT_MS),
                    ],
                );
            }
            clear_pending_jni_exception(env);

            let input_endpoint = env
                .new_global_ref(ep_in)
                .map_err(|error| jni_failure(env, "USB input endpoint global reference", error))?;
            let output_endpoint = env
                .new_global_ref(ep_out)
                .map_err(|error| jni_failure(env, "USB output endpoint global reference", error))?;
            Ok((input_endpoint, output_endpoint))
        })();

        let (input_endpoint, output_endpoint) = match setup {
            Ok(endpoints) => endpoints,
            Err(error) => return Err(cleanup_failed_android_usb_open(owner, error)),
        };
        let connection = match owner.connection.as_ref() {
            Some(connection) => connection.clone(),
            None => {
                return Err(cleanup_failed_android_usb_open(
                    owner,
                    "USB owner connection disappeared during setup".into(),
                ));
            }
        };
        if let Err(error) = activate_android_usb_lease(&mut owner) {
            return Err(cleanup_failed_android_usb_open(owner, error));
        }
        Ok((
            owner,
            JniUsbWriter {
                connection: Some(connection.clone()),
                endpoint: Some(output_endpoint),
            },
            JniUsbReader {
                connection: Some(connection),
                endpoint: Some(input_endpoint),
            },
        ))
    });

    if result.is_err() {
        // Pre-open failures leave the reservation in Opening. Managed
        // post-open cleanup has already released or quarantined it.
        let _ = release_android_usb_lease(dev_name, JniUsbLeasePhase::Opening);
    }
    result
}

/// Open the device and claim its CDC data interface. The returned owner is the
/// only component allowed to release the interface and close the connection;
/// its read/write workers hold temporary global references only until joined.
async fn open_usb_serial(
    device_name: &str,
    baud_rate: u32,
) -> Result<(OwnedUsbIo<JniUsbConnectionOwner>, Arc<AtomicBool>), InterfaceError> {
    reserve_android_usb_opening(device_name).map_err(InterfaceError::SendFailed)?;
    let dev_name = device_name.to_string();
    let panic_device_name = dev_name.clone();
    let (result_tx, result_rx) = tokio::sync::oneshot::channel();
    let _open_task = tokio::task::spawn_blocking(move || {
        let result = open_usb_serial_attached(&dev_name, baud_rate).map(PendingAndroidUsbOpen::new);
        let _ = result_tx.send(result);
    });
    let pending = result_rx
        .await
        .map_err(|error| {
            let reason = format!("Android USB open worker ended without an outcome: {error}");
            retain_android_usb_unproven_session(&panic_device_name, reason.clone());
            InterfaceError::SendFailed(reason)
        })?
        .map_err(InterfaceError::SendFailed)?;
    let (owner, writer, reader) = pending
        .into_resources()
        .map_err(InterfaceError::SendFailed)?;

    let online = Arc::new(AtomicBool::new(true));
    let io = spawn_owned_usb_io(
        writer,
        reader,
        owner,
        online.clone(),
        USB_WRITE_QUEUE,
        USB_READ_QUEUE,
        USB_DEFAULT_WRITE_TIMEOUT,
    );
    Ok((io, online))
}

/// Same shape as the serial/BLE RNode interfaces, but over Android USB.
pub async fn spawn_android_usb_rnode_interface(
    config: AndroidUsbConfig,
    id: InterfaceId,
    transport_tx: mpsc::Sender<TransportMessage>,
) -> Result<InterfaceHandle, InterfaceError> {
    Ok(
        spawn_android_usb_rnode_interface_with_driver(config, id, transport_tx)
            .await?
            .interface,
    )
}

/// Spawn Android USB with the same privacy-safe RNode observation surface as
/// the serial, TCP, and BLE drivers.
pub async fn spawn_android_usb_rnode_interface_with_driver(
    config: AndroidUsbConfig,
    id: InterfaceId,
    transport_tx: mpsc::Sender<TransportMessage>,
) -> Result<SpawnedRNodeInterface, InterfaceError> {
    config.validate().map_err(|error| {
        InterfaceError::SendFailed(format!("rnode config {}: {error}", error.field()))
    })?;
    let (mut usb, connected) = open_usb_serial(&config.device_name, config.baud_rate).await?;

    let name = config.name.clone();
    let protocol_target = RNodeProtocolTarget::new(
        config.frequency,
        config.bandwidth,
        config.spreading_factor,
        config.coding_rate,
        config.tx_power,
    );

    // Detect and initialization are distinct, physically acknowledged startup
    // phases. The radio remains disabled until the exact existing init
    // sequence reaches the device.
    let rnode_cfg = rnode_config_from_android_usb_config(&config);
    let init_bytes = rnode::build_init_sequence(&rnode_cfg);
    if let Err(error) = run_usb_rnode_startup(
        &usb.writer,
        rnode::build_detect_sequence(),
        init_bytes,
        USB_STARTUP_ACK_DEADLINE,
    )
    .await
    {
        let shutdown = usb
            .shutdown(None, USB_DETACH_ACK_DEADLINE, USB_WORKER_JOIN_DEADLINE)
            .await;
        let cleanup = shutdown.report.as_result();
        let cleanup = cleanup
            .err()
            .map(|cleanup| format!("; cleanup: {cleanup}"))
            .unwrap_or_default();
        return Err(InterfaceError::SendFailed(format!(
            "Android USB RNode startup failed: {error}{cleanup}"
        )));
    }

    let shared_txb = Arc::new(AtomicU64::new(0));
    let shared_rxb = Arc::new(AtomicU64::new(0));

    let (tx, app_rx) = mpsc::channel::<Bytes>(64);
    let (stop_tx, mut stop_rx) = mpsc::channel::<()>(1);
    let (mut snapshot_publisher, driver) = rnode::new_rnode_driver_observation_with_shutdown(
        RNodeTransportClass::Usb,
        RNodeDriverShutdown::from_stop_sender(stop_tx.clone()),
    );
    snapshot_publisher.connection_established();
    let (shutdown_status_tx, shutdown_status_rx) =
        watch::channel(AndroidUsbShutdownStatus::Running);
    let stop_guard = register_android_usb_rnode_stop(id, stop_tx, shutdown_status_rx);

    let read_name = name.clone();
    let txb = shared_txb.clone();
    let rxb = shared_rxb.clone();
    let online = connected.clone();
    let read_task = tokio::spawn(async move {
        let _stop_guard = stop_guard;
        let (tx_pump_stop_tx, tx_pump_stop_rx) = tokio::sync::oneshot::channel();
        let (tx_pump_exit_tx, mut tx_pump_exit_rx) = tokio::sync::oneshot::channel();
        let pump_writer = usb.writer.clone();
        let pump_txb = txb.clone();
        let mut tx_pump = tokio::spawn(async move {
            let exit = run_usb_tx_pump(app_rx, pump_writer, pump_txb, tx_pump_stop_rx).await;
            let _ = tx_pump_exit_tx.send(exit);
        });
        let mut inbound = UsbInboundState::projected(protocol_target, snapshot_publisher);
        let mut stop_requested = false;
        let mut drain_reader_tail = false;
        let mut terminal_reason = RNodeRuntimeReason::DriverTerminated;

        loop {
            tokio::select! {
                biased;
                stop = stop_rx.recv() => {
                    stop_requested = stop.is_some();
                    if stop_requested {
                        terminal_reason = RNodeRuntimeReason::StopRequested;
                    }
                    break;
                }
                pump = &mut tx_pump_exit_rx => {
                    match pump {
                        Ok(UsbTxPumpExit::WriterRejected(error)) => {
                            terminal_reason = RNodeRuntimeReason::ConnectionLost;
                            tracing::warn!(
                                name = %read_name,
                                error = %error,
                                "Android USB packet could not be queued"
                            );
                            drain_reader_tail = true;
                        }
                        Ok(UsbTxPumpExit::ApplicationClosed) => {
                            terminal_reason = RNodeRuntimeReason::TransportConsumerClosed;
                        }
                        Ok(UsbTxPumpExit::StopRequested) => {
                            stop_requested = true;
                            terminal_reason = RNodeRuntimeReason::StopRequested;
                        }
                        Err(error) => {
                            tracing::warn!(
                                name = %read_name,
                                error = %error,
                                "Android USB TX pump ended without an outcome"
                            );
                            drain_reader_tail = true;
                        }
                    }
                    break;
                }
                event = usb.events.recv() => {
                    match event {
                        Some(UsbIoEvent::Writer(exit)) => {
                            terminal_reason = RNodeRuntimeReason::ConnectionLost;
                            tracing::debug!(
                                name = %read_name,
                                worker = ?exit,
                                "Android USB writer ended"
                            );
                            drain_reader_tail = true;
                            break;
                        }
                        Some(UsbIoEvent::Reader(exit)) => {
                            terminal_reason = RNodeRuntimeReason::ConnectionLost;
                            tracing::debug!(
                                name = %read_name,
                                worker = ?exit,
                                "Android USB reader ended"
                            );
                            break;
                        }
                        Some(UsbIoEvent::Read(bytes)) => {
                            match forward_usb_read_chunk(
                                &mut inbound,
                                &bytes,
                                id,
                                rxb.as_ref(),
                                &transport_tx,
                                &mut stop_rx,
                            ).await {
                                UsbInboundOutcome::Complete => {}
                                UsbInboundOutcome::StopRequested => {
                                    stop_requested = true;
                                    terminal_reason = RNodeRuntimeReason::StopRequested;
                                    break;
                                }
                                UsbInboundOutcome::TransportClosed => {
                                    terminal_reason =
                                        RNodeRuntimeReason::TransportConsumerClosed;
                                    tracing::warn!(
                                        name = %read_name,
                                        "transport channel closed"
                                    );
                                    break;
                                }
                                UsbInboundOutcome::DeadlineElapsed => break,
                            }
                        }
                        None => {
                            terminal_reason = RNodeRuntimeReason::ConnectionLost;
                            break;
                        }
                    }
                }
            }
        }

        inbound.shutting_down(terminal_reason);

        let _ = tx_pump_stop_tx.send(());
        if tokio::time::timeout(USB_WORKER_JOIN_DEADLINE, &mut tx_pump)
            .await
            .is_err()
        {
            tx_pump.abort();
            let _ = tx_pump.await;
            tracing::warn!(name = %read_name, "Android USB TX pump join timed out");
        }

        if drain_reader_tail {
            usb.request_worker_stop();
            match drain_usb_reader_tail(
                &mut usb.events,
                &mut inbound,
                id,
                rxb.as_ref(),
                &transport_tx,
                &mut stop_rx,
                tokio::time::Instant::now() + USB_WORKER_JOIN_DEADLINE,
            )
            .await
            {
                UsbReadDrainOutcome::Drained => {}
                UsbReadDrainOutcome::StopRequested => {
                    stop_requested = true;
                    terminal_reason = RNodeRuntimeReason::StopRequested;
                    inbound.shutting_down(terminal_reason);
                }
                UsbReadDrainOutcome::TransportClosed => {
                    terminal_reason = RNodeRuntimeReason::TransportConsumerClosed;
                    inbound.shutting_down(terminal_reason);
                    tracing::warn!(
                        name = %read_name,
                        "transport channel closed while draining Android USB reader tail"
                    );
                }
                UsbReadDrainOutcome::DeadlineElapsed => tracing::warn!(
                    name = %read_name,
                    "Android USB reader tail did not finish before shutdown deadline"
                ),
            }
        }

        let shutdown = usb
            .shutdown(
                Some(rnode::build_detach_sequence()),
                USB_DETACH_ACK_DEADLINE,
                USB_WORKER_JOIN_DEADLINE,
            )
            .await;
        let report = Arc::new(shutdown.report);
        match &report.detach {
            Some(Ok(())) => tracing::info!(name = %read_name, "Android USB detach sequence sent"),
            Some(Err(error)) => tracing::warn!(
                name = %read_name,
                error = %error,
                "Android USB detach sequence failed"
            ),
            None => {}
        }
        if let Err(error) = report.as_result() {
            tracing::warn!(
                name = %read_name,
                error = %error,
                stop_requested,
                "Android USB owner shutdown completed with errors"
            );
        } else {
            tracing::info!(
                name = %read_name,
                stop_requested,
                "Android USB owner shutdown complete"
            );
        }
        online.store(false, Ordering::SeqCst);
        inbound.stopped(terminal_reason);
        shutdown_status_tx.send_replace(AndroidUsbShutdownStatus::Complete(report));
    });

    let interface = InterfaceHandle {
        id,
        parent_id: None,
        name,
        mode: config.mode,
        direction: InterfaceDirection {
            inbound: true,
            outbound: true,
            forward: true,
            repeat: false,
        },
        bitrate: BAUD_RATE as u64,
        mtu: 500,
        online: connected,
        txb: Some(shared_txb),
        rxb: Some(shared_rxb),
        inspection: None,
        tx,
        read_task,
    };
    Ok(SpawnedRNodeInterface { interface, driver })
}

/// Push an already-KISS-framed control frame through the raw USB writer,
/// bypassing the transport CMD_DATA wrapper. The canonical caller is the
/// BLE→serial handoff, which sends `[FEND, CMD_BT_CTRL, 0x00, FEND]` to turn
/// off the RNode's BT radio before the USB link takes over.
pub async fn send_raw_frame(
    writer: &mpsc::Sender<Vec<u8>>,
    frame: Vec<u8>,
) -> Result<(), InterfaceError> {
    writer
        .send(frame)
        .await
        .map_err(|_| InterfaceError::SendFailed("USB raw writer closed".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;

    fn assert_facade_shape<F, Fut>(_spawn: F)
    where
        F: Fn(AndroidUsbConfig, InterfaceId, mpsc::Sender<TransportMessage>) -> Fut,
        Fut: Future<Output = Result<InterfaceHandle, InterfaceError>>,
    {
    }

    fn assert_driver_shape<F, Fut>(_spawn: F)
    where
        F: Fn(AndroidUsbConfig, InterfaceId, mpsc::Sender<TransportMessage>) -> Fut,
        Fut: Future<Output = Result<SpawnedRNodeInterface, InterfaceError>>,
    {
    }

    #[test]
    fn android_usb_spawn_api_keeps_the_facade_and_adds_the_driver_shape() {
        assert_facade_shape(spawn_android_usb_rnode_interface);
        assert_driver_shape(spawn_android_usb_rnode_interface_with_driver);
        let _usb_transport: RNodeTransportClass = RNodeTransportClass::Usb;
    }

    #[test]
    fn android_usb_config_uses_canonical_rf_and_airtime_validation() {
        let mut config = AndroidUsbConfig::new("validated", "device");
        assert!(config.validate().is_ok());

        config.bandwidth = 0;
        assert!(matches!(
            config.validate(),
            Err(rnode::RNodeConfigValidationError::OutOfRange {
                field: rnode::RNodeConfigField::Bandwidth,
                ..
            })
        ));

        config = AndroidUsbConfig::new("validated", "device");
        config.lt_alock = Some(f32::INFINITY);
        assert!(matches!(
            config.validate(),
            Err(rnode::RNodeConfigValidationError::NonFinite {
                field: rnode::RNodeConfigField::LongTermAirtime,
                ..
            })
        ));
    }

    #[test]
    fn android_usb_exact_shutdown_and_cleanup_resist_same_id_aba() {
        let id: InterfaceId = 0xA11D_0001;
        let (old_tx, mut old_rx) = mpsc::channel::<()>(2);
        let (_old_status_tx, old_status_rx) = watch::channel(AndroidUsbShutdownStatus::Running);
        let (_old_publisher, old_driver) = rnode::new_rnode_driver_observation_with_shutdown(
            RNodeTransportClass::Usb,
            RNodeDriverShutdown::from_stop_sender(old_tx.clone()),
        );
        let old_guard = register_android_usb_rnode_stop(id, old_tx, old_status_rx);

        let (new_tx, mut new_rx) = mpsc::channel::<()>(2);
        let (_new_status_tx, new_status_rx) = watch::channel(AndroidUsbShutdownStatus::Running);
        let (_new_publisher, _new_driver) = rnode::new_rnode_driver_observation_with_shutdown(
            RNodeTransportClass::Usb,
            RNodeDriverShutdown::from_stop_sender(new_tx.clone()),
        );
        let new_guard = register_android_usb_rnode_stop(id, new_tx, new_status_rx);

        drop(old_guard);
        old_driver.request_shutdown();
        assert!(old_rx.try_recv().is_ok());
        assert!(
            matches!(new_rx.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
            "the retired handle must not stop the newer same-ID USB driver"
        );

        stop_android_usb_rnode_interface(id);
        assert!(
            new_rx.try_recv().is_ok(),
            "retired guard cleanup must preserve the newer compatibility entry"
        );
        drop(new_guard);
        assert!(
            !android_usb_rnode_stop_registry()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .contains_key(&id)
        );
    }

    fn fragmented_decode(wire: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let mut deframer = kiss::RawKissDeframer::new();
        let fragment_widths = [1, 2, 1, 3, 2, 4];
        let mut decoded = Vec::new();
        let mut offset = 0;
        let mut fragment = 0;

        while offset < wire.len() {
            let end = (offset + fragment_widths[fragment % fragment_widths.len()]).min(wire.len());
            decoded.extend(deframer.feed(&wire[offset..end]));
            offset = end;
            fragment += 1;
        }

        decoded
    }

    #[test]
    fn android_usb_deframer_preserves_extended_commands_when_fragmented_and_escaped() {
        let expected = vec![
            (
                rnode::CMD_FW_VERSION,
                vec![0x01, kiss::FEND, 0x02, kiss::FESC],
            ),
            (rnode::CMD_ERROR, vec![kiss::FESC, kiss::FEND]),
            (
                rnode::CMD_ROM_READ,
                vec![0x00, kiss::FEND, kiss::FESC, 0xFF],
            ),
            (
                kiss::CMD_DATA,
                vec![0x10, kiss::FESC, 0x20, kiss::FEND, 0x30],
            ),
        ];
        let mut wire = Vec::new();
        for (command, payload) in &expected {
            kiss::frame_with_command_into(*command, payload, &mut wire);
        }

        assert_eq!(fragmented_decode(&wire), expected);
    }

    #[test]
    fn android_usb_only_forwards_and_accounts_real_data_frames() {
        let data_payload = vec![0xAA, kiss::FEND, kiss::FESC, 0x55];
        let expected_controls = [rnode::CMD_FW_VERSION, rnode::CMD_ERROR, rnode::CMD_ROM_READ];
        let mut wire = Vec::new();
        kiss::frame_with_command_into(rnode::CMD_FW_VERSION, &[1, 2], &mut wire);
        kiss::frame_with_command_into(rnode::CMD_ERROR, &[0x01], &mut wire);
        kiss::frame_with_command_into(rnode::CMD_ROM_READ, &[0x10, 0x20], &mut wire);
        kiss::frame_with_command_into(kiss::CMD_DATA, &data_payload, &mut wire);

        let mut last_rssi = None;
        let mut last_snr = None;
        let mut control_commands = Vec::new();
        let mut packet_count = 0;
        let mut packet_bytes = 0;

        for (command, frame) in fragmented_decode(&wire) {
            match rnode::process_rnode_response(command, &frame, 7, &mut last_rssi, &mut last_snr) {
                rnode::RNodeResponse::Packet(_) => {
                    assert_eq!(command, kiss::CMD_DATA);
                    packet_count += 1;
                    packet_bytes += frame.len();
                }
                rnode::RNodeResponse::Ready(_) | rnode::RNodeResponse::None => {
                    if command != kiss::CMD_DATA {
                        control_commands.push(command);
                    }
                }
            }
        }

        assert_eq!(control_commands, expected_controls);
        assert_eq!(packet_count, 1);
        assert_eq!(packet_bytes, data_payload.len());
    }
}
