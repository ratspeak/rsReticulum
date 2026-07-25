//! USB serial RNode over Android USB-C OTG via JNI to `UsbManager`. 115200 8N1.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use bytes::Bytes;
use tokio::sync::mpsc;

use crate::kiss;
use crate::rnode;
use crate::traits::{
    InterfaceDirection, InterfaceError, InterfaceHandle, InterfaceId, InterfaceMode,
};
use rns_transport::messages::TransportMessage;

pub const BAUD_RATE: u32 = 115_200;

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

type AndroidUsbRNodeStopRegistry = Mutex<HashMap<InterfaceId, mpsc::Sender<()>>>;

fn android_usb_rnode_stop_registry() -> &'static AndroidUsbRNodeStopRegistry {
    static REGISTRY: OnceLock<AndroidUsbRNodeStopRegistry> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

struct AndroidUsbRNodeStopRegistryGuard {
    id: InterfaceId,
}

impl Drop for AndroidUsbRNodeStopRegistryGuard {
    fn drop(&mut self) {
        android_usb_rnode_stop_registry()
            .lock()
            .expect("android_usb_rnode_stop_registry mutex poisoned")
            .remove(&self.id);
    }
}

fn register_android_usb_rnode_stop(
    id: InterfaceId,
    stop_tx: mpsc::Sender<()>,
) -> AndroidUsbRNodeStopRegistryGuard {
    android_usb_rnode_stop_registry()
        .lock()
        .expect("android_usb_rnode_stop_registry mutex poisoned")
        .insert(id, stop_tx);
    AndroidUsbRNodeStopRegistryGuard { id }
}

/// Ask an Android USB RNode interface to send upstream's detach sequence before
/// runtime teardown aborts the task. Idempotent; unknown ids are ignored.
pub fn stop_android_usb_rnode_interface(id: InterfaceId) {
    let stop_tx = android_usb_rnode_stop_registry()
        .lock()
        .expect("android_usb_rnode_stop_registry mutex poisoned")
        .get(&id)
        .cloned();
    let Some(stop_tx) = stop_tx else {
        tracing::debug!(id, "Android USB RNode stop requested for unknown interface");
        return;
    };
    match stop_tx.try_send(()) {
        Ok(()) => tracing::info!(id, "Android USB RNode stop signal sent"),
        Err(mpsc::error::TrySendError::Full(_)) => {
            tracing::debug!(id, "Android USB RNode stop signal already pending")
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            tracing::debug!(id, "Android USB RNode stop signal receiver already closed")
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

/// Open device, claim CDC data interface, set line coding.
/// Returns `(tx, rx, connected_flag)` — drop flag to false to stop loops.
async fn open_usb_serial(
    device_name: &str,
    baud_rate: u32,
) -> Result<
    (
        mpsc::Sender<Vec<u8>>,
        mpsc::Receiver<Vec<u8>>,
        Arc<AtomicBool>,
    ),
    InterfaceError,
> {
    let dev_name = device_name.to_string();

    tokio::task::spawn_blocking(move || -> Result<_, String> {
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

            let connection = env
                .call_method(
                    usb_mgr,
                    "openDevice",
                    "(Landroid/hardware/usb/UsbDevice;)Landroid/hardware/usb/UsbDeviceConnection;",
                    &[JValue::Object(device)],
                )
                .map_err(|e| format!("{e}"))?
                .l()
                .map_err(|e| format!("{e}"))?;
            if connection.is_null() {
                return Err("Failed to open USB device (permission denied?)".into());
            }

            // CDC-Data (0x0A) or vendor-specific (0xFF) with bulk IN+OUT.
            let iface_count = env
                .call_method(device, "getInterfaceCount", "()I", &[])
                .map_err(|e| format!("{e}"))?
                .i()
                .map_err(|e| format!("{e}"))?;

            let mut data_iface = JObject::null();
            let mut ep_in = JObject::null();
            let mut ep_out = JObject::null();

            for i in 0..iface_count {
                let iface = env
                    .call_method(
                        device,
                        "getInterface",
                        "(I)Landroid/hardware/usb/UsbInterface;",
                        &[JValue::Int(i)],
                    )
                    .map_err(|e| format!("{e}"))?
                    .l()
                    .map_err(|e| format!("{e}"))?;
                let cls = env
                    .call_method(iface, "getInterfaceClass", "()I", &[])
                    .map_err(|e| format!("{e}"))?
                    .i()
                    .map_err(|e| format!("{e}"))?;

                if cls == 0x0A || cls == 0xFF {
                    let epc = env
                        .call_method(iface, "getEndpointCount", "()I", &[])
                        .map_err(|e| format!("{e}"))?
                        .i()
                        .map_err(|e| format!("{e}"))?;
                    for j in 0..epc {
                        let ep = env
                            .call_method(
                                iface,
                                "getEndpoint",
                                "(I)Landroid/hardware/usb/UsbEndpoint;",
                                &[JValue::Int(j)],
                            )
                            .map_err(|e| format!("{e}"))?
                            .l()
                            .map_err(|e| format!("{e}"))?;
                        let dir = env
                            .call_method(ep, "getDirection", "()I", &[])
                            .map_err(|e| format!("{e}"))?
                            .i()
                            .map_err(|e| format!("{e}"))?;
                        if dir == 0x80 {
                            ep_in = ep;
                        } else {
                            ep_out = ep;
                        }
                    }
                    if !ep_in.is_null() && !ep_out.is_null() {
                        data_iface = iface;
                        break;
                    }
                }
            }
            if data_iface.is_null() {
                return Err("No CDC-ACM interface found".into());
            }

            env.call_method(
                connection,
                "claimInterface",
                "(Landroid/hardware/usb/UsbInterface;Z)Z",
                &[JValue::Object(data_iface), JValue::Bool(1)],
            )
            .map_err(|e| format!("{e}"))?;

            // CDC SET_LINE_CODING (bmRequestType=0x21, bRequest=0x20):
            //   [baud_rate u32 LE][stop_bits u8][parity u8][data_bits u8].
            //
            // The Android signature is `controlTransfer(int, int, int, int,
            // byte[], int, int)` — seven parameters including the trailing
            // timeout. Calling with the six-parameter signature throws
            // NoSuchMethodError into a pending JNI exception, which the next
            // JNI op (new_global_ref) detects as a CheckJNI violation and
            // aborts the process. CP2102 / CH340 / FTDI ignore CDC class
            // requests anyway (they use vendor-specific control transfers),
            // so we send this best-effort and explicitly clear any pending
            // exception before continuing.
            let mut lc = [0u8; 7];
            lc[0..4].copy_from_slice(&baud_rate.to_le_bytes());
            lc[6] = 8;
            let lc_arr = env.byte_array_from_slice(&lc).map_err(|e| format!("{e}"))?;
            let _ = env.call_method(
                connection,
                "controlTransfer",
                "(IIII[BII)I",
                &[
                    JValue::Int(0x21),
                    JValue::Int(0x20),
                    JValue::Int(0),
                    JValue::Int(0),
                    JValue::Object(lc_arr.into()),
                    JValue::Int(7),
                    JValue::Int(1000),
                ],
            );
            // Defensive: ensure any Java exception from the optional CDC call
            // is cleared so the subsequent global-ref allocations don't trip
            // CheckJNI's "pending exception" abort.
            if env.exception_check().unwrap_or(false) {
                let _ = env.exception_clear();
            }

            let conn_ref = env.new_global_ref(connection).map_err(|e| format!("{e}"))?;
            let ep_in_ref = env.new_global_ref(ep_in).map_err(|e| format!("{e}"))?;
            let ep_out_ref = env.new_global_ref(ep_out).map_err(|e| format!("{e}"))?;

            let connected = Arc::new(AtomicBool::new(true));
            let (write_tx, mut write_rx) = mpsc::channel::<Vec<u8>>(64);
            let (read_tx, read_rx) = mpsc::channel::<Vec<u8>>(64);

            let cw = connected.clone();
            let vm = match JAVA_VM.get() {
                Some(v) => v,
                None => return Err("JavaVM not initialized for USB write loop".into()),
            };
            let cr_w = conn_ref.clone();
            let ep_w = ep_out_ref.clone();
            tokio::task::spawn_blocking(move || {
                let rt = tokio::runtime::Handle::current();
                while cw.load(Ordering::Relaxed) {
                    match rt.block_on(write_rx.recv()) {
                        Some(data) => {
                            if let Ok(env2) = vm.attach_current_thread() {
                                let buf = env2
                                    .byte_array_from_slice(&data)
                                    .expect("JNI byte_array_from_slice failed (OOM in JVM heap)");
                                let _ = env2.call_method(
                                    cr_w.as_obj(),
                                    "bulkTransfer",
                                    "(Landroid/hardware/usb/UsbEndpoint;[BII)I",
                                    &[
                                        JValue::Object(ep_w.as_obj()),
                                        JValue::Object(buf.into()),
                                        JValue::Int(data.len() as i32),
                                        JValue::Int(1000),
                                    ],
                                );
                            }
                        }
                        None => break,
                    }
                }
            });

            let cr = connected.clone();
            let vm2 = match JAVA_VM.get() {
                Some(v) => v,
                None => return Err("JavaVM not initialized for USB read loop".into()),
            };
            tokio::task::spawn_blocking(move || {
                loop {
                    if !cr.load(Ordering::Relaxed) {
                        break;
                    }
                    if let Ok(env2) = vm2.attach_current_thread() {
                        let buf = env2
                            .new_byte_array(1024)
                            .expect("JNI new_byte_array failed (OOM in JVM heap)");
                        match env2.call_method(
                            conn_ref.as_obj(),
                            "bulkTransfer",
                            "(Landroid/hardware/usb/UsbEndpoint;[BII)I",
                            &[
                                JValue::Object(ep_in_ref.as_obj()),
                                JValue::Object(buf.into()),
                                JValue::Int(1024),
                                JValue::Int(100),
                            ],
                        ) {
                            Ok(val) => {
                                let n = val.i().unwrap_or(-1);
                                if n > 0 {
                                    if let Ok(bytes) = env2.convert_byte_array(buf) {
                                        if read_tx
                                            .blocking_send(bytes[..n as usize].to_vec())
                                            .is_err()
                                        {
                                            break;
                                        }
                                    }
                                }
                            }
                            Err(_) => {
                                cr.store(false, Ordering::Relaxed);
                                break;
                            }
                        }
                    }
                }
            });

            Ok((write_tx, read_rx, connected))
        })
    })
    .await
    .map_err(|e| InterfaceError::SendFailed(format!("{e}")))?
    .map_err(|e| InterfaceError::SendFailed(e))
}

/// Same shape as the serial/BLE RNode interfaces, but over Android USB.
pub async fn spawn_android_usb_rnode_interface(
    config: AndroidUsbConfig,
    id: InterfaceId,
    transport_tx: mpsc::Sender<TransportMessage>,
) -> Result<InterfaceHandle, InterfaceError> {
    let (raw_write_tx, mut raw_read_rx, connected) =
        open_usb_serial(&config.device_name, config.baud_rate).await?;

    let name = config.name.clone();

    // Radio stays disabled until we push an init sequence, so do it before
    // handing the write channel to the transport-facing task.
    let mut rnode_cfg = rnode::RNodeConfig::new(&config.name, &config.device_name);
    rnode_cfg.baud_rate = config.baud_rate;
    rnode_cfg.frequency = config.frequency;
    rnode_cfg.bandwidth = config.bandwidth;
    rnode_cfg.spreading_factor = config.spreading_factor;
    rnode_cfg.coding_rate = config.coding_rate;
    rnode_cfg.tx_power = config.tx_power;
    rnode_cfg.mode = config.mode;
    rnode_cfg.flow_control = config.flow_control;
    rnode_cfg.st_alock = config.st_alock;
    rnode_cfg.lt_alock = config.lt_alock;
    let init_bytes = rnode::build_init_sequence(&rnode_cfg);
    if raw_write_tx.send(init_bytes).await.is_err() {
        return Err(InterfaceError::SendFailed(
            "Android USB writer closed before RNode init could be sent".into(),
        ));
    }

    let shared_txb = Arc::new(AtomicU64::new(0));
    let shared_rxb = Arc::new(AtomicU64::new(0));

    let (tx, mut app_rx) = mpsc::channel::<Bytes>(64);
    let (stop_tx, mut stop_rx) = mpsc::channel::<()>(1);
    let stop_guard = register_android_usb_rnode_stop(id, stop_tx);

    let txb = shared_txb.clone();
    let wtx = raw_write_tx.clone();
    let write_name = name.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                Some(payload) = app_rx.recv() => {
                    let frame = kiss::frame(&payload);
                    txb.fetch_add(frame.len() as u64, Ordering::Relaxed);
                    if wtx.send(frame).await.is_err() {
                        tracing::warn!(name = %write_name, "USB write channel closed");
                        break;
                    }
                }
                Some(_) = stop_rx.recv() => {
                    if wtx.send(rnode::build_detach_sequence()).await.is_err() {
                        tracing::warn!(name = %write_name, "USB detach sequence could not be queued");
                    } else {
                        tracing::info!(name = %write_name, "USB detach sequence queued");
                    }
                    break;
                }
                else => break,
            }
        }
    });

    // Any RSSI/SNR from a preceding CMD_STAT_* frame attaches to the next
    // inbound data packet; both reset after use.
    let read_name = name.clone();
    let rxb = shared_rxb.clone();
    let online = connected.clone();
    let read_task = tokio::spawn(async move {
        let _stop_guard = stop_guard;
        // RNode extends KISS with full-byte commands such as CMD_FW_VERSION
        // (0x50) and CMD_ERROR (0x90). A classic KISS deframer masks the high
        // nibble as a TNC port, which would turn both into CMD_DATA and forward
        // their metadata as Reticulum packets. Preserve the complete command
        // byte so control frames reach the RNode response handler unchanged.
        let mut deframer = kiss::RawKissDeframer::new();
        let mut last_rssi: Option<f32> = None;
        let mut last_snr: Option<f32> = None;
        while let Some(bytes) = raw_read_rx.recv().await {
            if bytes.is_empty() {
                continue;
            }
            // Count only real LoRa data payloads, not KISS framing or
            // control responses (DETECT_RESP, CMD_STAT_*, CMD_FW_VERSION,
            // etc.). Mirrors ble_rnode.rs so UI RX counters don't tick up
            // while the radio is idle.
            for (cmd, frame) in deframer.feed(&bytes) {
                match rnode::process_rnode_response(cmd, &frame, id, &mut last_rssi, &mut last_snr)
                {
                    rnode::RNodeResponse::Packet(msg) => {
                        rxb.fetch_add(frame.len() as u64, Ordering::Relaxed);
                        if transport_tx.send(msg).await.is_err() {
                            tracing::warn!(name = %read_name, "transport channel closed");
                            online.store(false, Ordering::SeqCst);
                            return;
                        }
                    }
                    rnode::RNodeResponse::Ready(_) | rnode::RNodeResponse::None => {}
                }
            }
        }
        tracing::info!(name = %read_name, "Android USB read task exiting (channel closed)");
        online.store(false, Ordering::SeqCst);
    });

    Ok(InterfaceHandle {
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
    })
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
