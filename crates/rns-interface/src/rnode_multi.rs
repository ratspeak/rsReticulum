//! Multi-radio RNode: up to 11 sub-interfaces on one serial connection.
//! One read task demuxes by per-vport command byte; one write task prepends
//! `CMD_SEL_INT` so the device picks the right radio.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc;

use crate::kiss;
use crate::rnode;
use crate::traits::{
    InterfaceDirection, InterfaceError, InterfaceHandle, InterfaceId, InterfaceMode,
};
use rns_transport::messages::{InboundPacket, TransportMessage};

pub const MAX_SUBINTERFACES: usize = 11;

/// Minimum firmware supporting multi-interface mode.
pub const REQUIRED_FW_VER_MAJ: u8 = 1;
pub const REQUIRED_FW_VER_MIN: u8 = 74;

pub const CMD_SEL_INT: u8 = 0x1F;
pub const CMD_INTERFACES: u8 = 0x71;
pub const CMD_ERROR: u8 = 0x90;

pub const ERROR_INITRADIO: u8 = 0x01;
pub const ERROR_TXFAILED: u8 = 0x02;

/// Per-sub-interface data command bytes. NOT port-nibble; some collide
/// (e.g. `CMD_INT5_DATA == CMD_ERROR`) — demux by vport index, not byte.
pub const CMD_INT_DATA: [u8; 12] = [
    0x00, 0x10, 0x20, 0x70, 0x75, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RadioType {
    SX127X = 0x00,
    SX1276 = 0x01,
    SX1278 = 0x02,
    SX126X = 0x10,
    SX1262 = 0x11,
    SX128X = 0x20,
    SX1280 = 0x21,
}

impl RadioType {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x00 => Some(Self::SX127X),
            0x01 => Some(Self::SX1276),
            0x02 => Some(Self::SX1278),
            0x10 => Some(Self::SX126X),
            0x11 => Some(Self::SX1262),
            0x20 => Some(Self::SX128X),
            0x21 => Some(Self::SX1280),
            _ => None,
        }
    }

    pub fn family_name(&self) -> &'static str {
        match self {
            Self::SX127X | Self::SX1276 | Self::SX1278 => "SX127X",
            Self::SX126X | Self::SX1262 => "SX126X",
            Self::SX128X | Self::SX1280 => "SX128X",
        }
    }

    /// Sub-GHz: 137 MHz..1 GHz; SX128X: 2.2..2.6 GHz.
    pub fn validate_frequency(&self, freq_hz: u32) -> bool {
        match self {
            Self::SX127X | Self::SX1276 | Self::SX1278 | Self::SX126X | Self::SX1262 => {
                (137_000_000..=1_000_000_000).contains(&freq_hz)
            }
            Self::SX128X | Self::SX1280 => (2_200_000_000..=2_600_000_000).contains(&freq_hz),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SubInterfaceConfig {
    pub name: String,
    /// vport index on RNode (0..MAX_SUBINTERFACES).
    pub vport: u8,
    pub frequency: u32,
    pub bandwidth: u32,
    pub spreading_factor: u8,
    pub coding_rate: u8,
    pub tx_power: u8,
    pub mode: InterfaceMode,
    pub flow_control: bool,
    pub outgoing: bool,
    /// Short-term airtime cap, percent of duty cycle.
    pub st_alock: Option<f32>,
    /// Long-term airtime cap, percent of duty cycle.
    pub lt_alock: Option<f32>,
}

impl SubInterfaceConfig {
    pub fn new(name: &str, vport: u8, frequency: u32) -> Self {
        Self {
            name: name.to_string(),
            vport,
            frequency,
            bandwidth: 125_000,
            spreading_factor: 7,
            coding_rate: 5,
            tx_power: 14,
            mode: InterfaceMode::Full,
            flow_control: false,
            outgoing: true,
            st_alock: None,
            lt_alock: None,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.tx_power > 37 {
            return Err(format!(
                "Invalid TX power {} for sub-interface {}",
                self.tx_power, self.name
            ));
        }
        if self.bandwidth < 7800 || self.bandwidth > 1_625_000 {
            return Err(format!(
                "Invalid bandwidth {} for sub-interface {}",
                self.bandwidth, self.name
            ));
        }
        if self.spreading_factor < 5 || self.spreading_factor > 12 {
            return Err(format!(
                "Invalid spreading factor {} for sub-interface {}",
                self.spreading_factor, self.name
            ));
        }
        if self.coding_rate < 5 || self.coding_rate > 8 {
            return Err(format!(
                "Invalid coding rate {} for sub-interface {}",
                self.coding_rate, self.name
            ));
        }
        if let Some(st) = self.st_alock {
            if !(0.0..=100.0).contains(&st) {
                return Err(format!(
                    "Invalid short-term airtime limit {} for sub-interface {}",
                    st, self.name
                ));
            }
        }
        if let Some(lt) = self.lt_alock {
            if !(0.0..=100.0).contains(&lt) {
                return Err(format!(
                    "Invalid long-term airtime limit {} for sub-interface {}",
                    lt, self.name
                ));
            }
        }
        if self.vport as usize > MAX_SUBINTERFACES {
            return Err(format!(
                "Virtual port {} exceeds max {} for sub-interface {}",
                self.vport, MAX_SUBINTERFACES, self.name
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct RNodeMultiConfig {
    pub name: String,
    pub port: String,
    pub baud_rate: u32,
    pub flow_control: bool,
    /// Up to `MAX_SUBINTERFACES` radios on this device.
    pub subinterfaces: Vec<SubInterfaceConfig>,
    /// Station-ID beacon, parent-level: when due, the callsign is sent on
    /// all subinterfaces (Python RNodeMultiInterface.py:849-859).
    pub id_interval: Option<u64>,
    pub id_callsign: Option<Vec<u8>>,
}

impl RNodeMultiConfig {
    pub fn new(name: &str, port: &str) -> Self {
        Self {
            name: name.to_string(),
            port: port.to_string(),
            baud_rate: 115200,
            flow_control: false,
            subinterfaces: Vec::new(),
            id_interval: None,
            id_callsign: None,
        }
    }
}

/// SEL_INT, push params, then RADIO_STATE=ON last.
pub fn build_subinterface_init(index: u8, config: &SubInterfaceConfig) -> Vec<u8> {
    let mut out = Vec::with_capacity(80);

    kiss::frame_with_command_into(CMD_SEL_INT, &[index], &mut out);
    kiss::frame_with_command_into(
        rnode::CMD_FREQUENCY,
        &config.frequency.to_be_bytes(),
        &mut out,
    );
    kiss::frame_with_command_into(
        rnode::CMD_BANDWIDTH,
        &config.bandwidth.to_be_bytes(),
        &mut out,
    );
    kiss::frame_with_command_into(rnode::CMD_SF, &[config.spreading_factor], &mut out);
    kiss::frame_with_command_into(rnode::CMD_CR, &[config.coding_rate], &mut out);
    kiss::frame_with_command_into(rnode::CMD_TXPOWER, &[config.tx_power], &mut out);
    if let Some(st) = config.st_alock {
        let at = (st * 100.0) as u16;
        let c1 = (at >> 8) as u8;
        let c2 = (at & 0xFF) as u8;
        kiss::frame_with_command_into(rnode::CMD_ST_ALOCK, &[c1, c2], &mut out);
    }
    if let Some(lt) = config.lt_alock {
        let at = (lt * 100.0) as u16;
        let c1 = (at >> 8) as u8;
        let c2 = (at & 0xFF) as u8;
        kiss::frame_with_command_into(rnode::CMD_LT_ALOCK, &[c1, c2], &mut out);
    }
    kiss::frame_with_command_into(rnode::CMD_RADIO_STATE, &[rnode::RADIO_STATE_ON], &mut out);

    out
}

pub fn build_detect_sequence() -> Vec<u8> {
    let mut out = Vec::with_capacity(40);
    kiss::frame_with_command_into(rnode::CMD_DETECT, &[rnode::DETECT_REQ], &mut out);
    kiss::frame_with_command_into(rnode::CMD_FW_VERSION, &[0x00], &mut out);
    kiss::frame_with_command_into(rnode::CMD_PLATFORM, &[0x00], &mut out);
    kiss::frame_with_command_into(rnode::CMD_MCU, &[0x00], &mut out);
    kiss::frame_with_command_into(CMD_INTERFACES, &[0x00], &mut out);
    out
}

/// Wire form: `[FEND][CMD_SEL_INT][index][FEND][FEND][CMD_DATA][escaped_data][FEND]`.
pub fn build_subinterface_data_frame(index: u8, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + data.len() + data.len() / 8);
    kiss::frame_with_command_into(CMD_SEL_INT, &[index], &mut out);
    kiss::frame_into(data, &mut out);
    out
}

pub fn command_to_subinterface(cmd_byte: u8) -> Option<usize> {
    for (i, &port_cmd) in CMD_INT_DATA.iter().enumerate() {
        if cmd_byte == port_cmd {
            return Some(i);
        }
    }
    None
}

struct WriteRequest {
    index: u8,
    /// Raw payload, not yet KISS-escaped.
    data: Bytes,
    flow_control: bool,
}

#[derive(Default)]
struct SubInterfaceSignal {
    last_rssi: Option<f32>,
    last_snr: Option<f32>,
}

const RNODE_READ_TIMEOUT_MS: u64 = 100;

/// Spawn one RNodeMulti over a single serial port.
///
/// Returns one `InterfaceHandle` per configured sub-interface. Each handle has
/// its own tx channel and `InterfaceId`; all of them share one serial
/// connection and one online flag, so the whole device goes up or down atomically.
///
/// `ids.len()` must equal `config.subinterfaces.len()`.
pub async fn spawn_rnode_multi_interface(
    config: RNodeMultiConfig,
    ids: &[InterfaceId],
    transport_tx: mpsc::Sender<TransportMessage>,
) -> Result<Vec<InterfaceHandle>, InterfaceError> {
    if config.subinterfaces.is_empty() {
        return Err(InterfaceError::SendFailed(
            "RNodeMulti: no sub-interfaces configured".to_string(),
        ));
    }
    if ids.len() != config.subinterfaces.len() {
        return Err(InterfaceError::SendFailed(format!(
            "RNodeMulti: {} IDs provided but {} sub-interfaces configured",
            ids.len(),
            config.subinterfaces.len()
        )));
    }
    if config.subinterfaces.len() > MAX_SUBINTERFACES {
        return Err(InterfaceError::SendFailed(format!(
            "RNodeMulti: {} sub-interfaces exceeds max {}",
            config.subinterfaces.len(),
            MAX_SUBINTERFACES
        )));
    }

    for sub in &config.subinterfaces {
        sub.validate()
            .map_err(|e| InterfaceError::SendFailed(format!("RNodeMulti config: {}", e)))?;
    }

    let port = serialport::new(&config.port, config.baud_rate)
        .timeout(Duration::from_millis(RNODE_READ_TIMEOUT_MS))
        .open()
        .map_err(|e| InterfaceError::SendFailed(format!("RNodeMulti open: {}", e)))?;

    tracing::info!(
        name = %config.name,
        port = %config.port,
        subinterfaces = config.subinterfaces.len(),
        "RNodeMulti interface opened"
    );

    {
        let mut detect_port = port
            .try_clone()
            .map_err(|e| InterfaceError::SendFailed(format!("RNodeMulti clone: {}", e)))?;
        let detect_seq = build_detect_sequence();
        use std::io::Write;
        detect_port
            .write_all(&detect_seq)
            .map_err(|e| InterfaceError::SendFailed(format!("RNodeMulti detect write: {}", e)))?;
        detect_port
            .flush()
            .map_err(|e| InterfaceError::SendFailed(format!("RNodeMulti detect flush: {}", e)))?;
    }

    {
        let mut init_port = port
            .try_clone()
            .map_err(|e| InterfaceError::SendFailed(format!("RNodeMulti clone: {}", e)))?;
        let mut init_seq = Vec::new();
        for sub in &config.subinterfaces {
            init_seq.extend_from_slice(&build_subinterface_init(sub.vport, sub));
        }
        use std::io::Write;
        init_port
            .write_all(&init_seq)
            .map_err(|e| InterfaceError::SendFailed(format!("RNodeMulti init write: {}", e)))?;
        init_port
            .flush()
            .map_err(|e| InterfaceError::SendFailed(format!("RNodeMulti init flush: {}", e)))?;
    }

    let online = Arc::new(AtomicBool::new(true));

    let num_subs = config.subinterfaces.len();

    // All sub-interface handles funnel into one writer so CMD_SEL_INT framing
    // stays ordered relative to each data frame.
    let (write_tx, mut write_rx) = mpsc::channel::<WriteRequest>(256);

    let mut handles = Vec::with_capacity(num_subs);
    let mut sub_txb: Vec<Arc<AtomicU64>> = Vec::with_capacity(num_subs);
    let mut sub_rxb: Vec<Arc<AtomicU64>> = Vec::with_capacity(num_subs);

    for (i, sub_cfg) in config.subinterfaces.iter().enumerate() {
        let bitrate = rnode::calculate_bitrate(
            sub_cfg.spreading_factor,
            sub_cfg.coding_rate,
            sub_cfg.bandwidth,
        );

        let rxb = Arc::new(AtomicU64::new(0));
        let txb = Arc::new(AtomicU64::new(0));
        sub_rxb.push(rxb.clone());
        sub_txb.push(txb.clone());

        // Adapt the per-handle `Vec<u8>` channel into the shared WriteRequest
        // channel so the handle type stays symmetric with other interfaces.
        let (sub_tx, mut sub_rx) = mpsc::channel::<Bytes>(256);
        let write_tx_clone = write_tx.clone();
        let vport = sub_cfg.vport;
        let sub_flow_control = config.flow_control || sub_cfg.flow_control;
        let txb_fwd = txb.clone();

        tokio::spawn(async move {
            while let Some(data) = sub_rx.recv().await {
                txb_fwd.fetch_add(data.len() as u64, Ordering::Relaxed);
                if write_tx_clone
                    .send(WriteRequest {
                        index: vport,
                        data,
                        flow_control: sub_flow_control,
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });

        let sub_name = format!("{}[{}]", config.name, sub_cfg.name);

        tracing::info!(
            name = %sub_name,
            vport = vport,
            freq = sub_cfg.frequency,
            bw = sub_cfg.bandwidth,
            sf = sub_cfg.spreading_factor,
            cr = sub_cfg.coding_rate,
            bitrate_bps = bitrate,
            "RNodeMulti sub-interface configured"
        );

        // The real read loop is shared by all sub-interfaces; each handle just
        // needs a JoinHandle that exits when the device goes offline.
        let online_sub = online.clone();
        let sub_read_task = tokio::spawn(async move {
            loop {
                if !online_sub.load(Ordering::SeqCst) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        });

        handles.push(InterfaceHandle {
            id: ids[i],
            parent_id: None,
            name: sub_name,
            mode: sub_cfg.mode,
            direction: InterfaceDirection {
                inbound: true,
                outbound: sub_cfg.outgoing,
                forward: false,
                repeat: false,
            },
            bitrate,
            mtu: rns_wire::constants::MTU as u32,
            online: online.clone(),
            rxb: Some(rxb),
            txb: Some(txb),
            tx: sub_tx,
            read_task: sub_read_task,
        });
    }

    // Drop our clone so the writer exits once every sub-interface handle drops.
    drop(write_tx);

    let port_write = port
        .try_clone()
        .map_err(|e| InterfaceError::SendFailed(format!("RNodeMulti clone: {}", e)))?;
    let online_w = online.clone();
    let ready = Arc::new(AtomicBool::new(true));
    let ready_w = ready.clone();

    // Python RNodeMultiInterface.py:281-291 — oversized callsigns disable
    // beaconing; when due, the callsign goes out on all subinterfaces.
    let beacon: Option<(Duration, Bytes)> = config
        .id_interval
        .zip(config.id_callsign.clone())
        .filter(|(_, callsign)| {
            let ok = callsign.len() <= rnode::CALLSIGN_MAX_LEN;
            if !ok {
                tracing::error!(
                    name = %config.name,
                    len = callsign.len(),
                    "id_callsign exceeds {} bytes, beaconing disabled",
                    rnode::CALLSIGN_MAX_LEN
                );
            }
            ok
        })
        .map(|(interval, callsign)| (Duration::from_secs(interval), Bytes::from(callsign)));
    let beacon_vports: Vec<u8> = config.subinterfaces.iter().map(|s| s.vport).collect();

    tokio::spawn(async move {
        let mut port_w = port_write;
        let mut first_tx: Option<tokio::time::Instant> = None;
        loop {
            let req = if let Some((interval, ref callsign)) = beacon {
                match tokio::time::timeout(Duration::from_secs(1), write_rx.recv()).await {
                    Ok(Some(req)) => req,
                    Ok(None) => break,
                    Err(_) => {
                        if !first_tx.is_some_and(|t| t.elapsed() >= interval)
                            || !online_w.load(Ordering::SeqCst)
                        {
                            continue;
                        }
                        tracing::debug!("RNodeMulti transmitting station-ID beacon on all subinterfaces");
                        first_tx = None;
                        let mut frames = Vec::new();
                        for &vport in &beacon_vports {
                            frames.extend_from_slice(&build_subinterface_data_frame(
                                vport, callsign,
                            ));
                        }
                        let online_ref = online_w.clone();
                        let result = tokio::task::spawn_blocking(move || {
                            use std::io::Write;
                            port_w.write_all(&frames)?;
                            port_w.flush()?;
                            Ok::<_, std::io::Error>(port_w)
                        })
                        .await;
                        match result {
                            Ok(Ok(p)) => {
                                port_w = p;
                                continue;
                            }
                            _ => {
                                online_ref.store(false, Ordering::SeqCst);
                                break;
                            }
                        }
                    }
                }
            } else {
                match write_rx.recv().await {
                    Some(req) => req,
                    None => break,
                }
            };
            if !online_w.load(Ordering::SeqCst) {
                break;
            }
            if let Some((_, ref callsign)) = beacon {
                if req.data == *callsign {
                    first_tx = None;
                } else if first_tx.is_none() {
                    first_tx = Some(tokio::time::Instant::now());
                }
            }

            if req.flow_control {
                // Bound CMD_READY wait at ~5 s so a stuck TNC can't block tx.
                let mut wait_count = 0;
                while !ready_w.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    wait_count += 1;
                    if !online_w.load(Ordering::SeqCst) || wait_count > 500 {
                        break;
                    }
                }
            }

            let frame = build_subinterface_data_frame(req.index, &req.data);
            let online_ref = online_w.clone();
            let result = tokio::task::spawn_blocking(move || {
                use std::io::Write;
                port_w.write_all(&frame)?;
                port_w.flush()?;
                Ok::<_, std::io::Error>(port_w)
            })
            .await;
            match result {
                Ok(Ok(p)) => {
                    port_w = p;
                }
                Ok(Err(e)) => {
                    tracing::warn!(error = %e, "RNodeMulti write error");
                    online_ref.store(false, Ordering::SeqCst);
                    break;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "RNodeMulti write task panicked");
                    break;
                }
            }
        }
    });

    let online_r = online.clone();
    let ready_r = ready;
    let parent_name = config.name.clone();

    // `vport_map[vport] -> Some(local_index)` for configured sub-interfaces.
    let mut vport_map: [Option<usize>; 12] = [None; 12];
    let mut sub_ids: Vec<InterfaceId> = Vec::with_capacity(num_subs);
    for (i, sub_cfg) in config.subinterfaces.iter().enumerate() {
        let vp = sub_cfg.vport as usize;
        if vp < 12 {
            vport_map[vp] = Some(i);
        }
        sub_ids.push(ids[i]);
    }

    tokio::spawn(async move {
        let mut port_r = port;
        let mut deframer = kiss::RawKissDeframer::new();
        let mut buf = [0u8; 1024];

        let mut signals: Vec<SubInterfaceSignal> = (0..num_subs)
            .map(|_| SubInterfaceSignal::default())
            .collect();

        // Which sub-interface the device is currently addressing via
        // CMD_SEL_INT; status commands below target this index.
        let mut selected_index: usize = 0;

        let mut interfaces_buf: Vec<u8> = Vec::new();

        loop {
            if !online_r.load(Ordering::SeqCst) {
                break;
            }

            let result = tokio::task::spawn_blocking(move || {
                use std::io::Read;
                match port_r.read(&mut buf) {
                    Ok(n) => Ok((port_r, buf, n)),
                    Err(e) if e.kind() == std::io::ErrorKind::TimedOut => Ok((port_r, buf, 0)),
                    Err(e) => Err((port_r, e)),
                }
            })
            .await;

            match result {
                Ok(Ok((p, b, n))) => {
                    port_r = p;
                    buf = b;
                    if n == 0 {
                        continue;
                    }

                    for (raw_cmd, frame) in deframer.feed(&buf[..n]) {
                        if let Some(vport) = command_to_subinterface(raw_cmd) {
                            if frame.is_empty() {
                                continue;
                            }
                            if let Some(local_idx) = vport_map[vport] {
                                sub_rxb[local_idx].fetch_add(frame.len() as u64, Ordering::Relaxed);

                                let rssi = signals[local_idx].last_rssi.take();
                                let snr = signals[local_idx].last_snr.take();

                                let msg = TransportMessage::Inbound(InboundPacket {
                                    raw: Bytes::from(frame),
                                    interface_id: sub_ids[local_idx],
                                    rssi,
                                    snr,
                                    q: None,
                                });
                                if transport_tx.send(msg).await.is_err() {
                                    tracing::warn!(
                                        parent = %parent_name,
                                        "transport channel closed"
                                    );
                                    online_r.store(false, Ordering::SeqCst);
                                    return;
                                }
                            } else {
                                tracing::debug!(
                                    parent = %parent_name,
                                    vport,
                                    "data for unconfigured sub-interface, dropping"
                                );
                            }
                            continue;
                        }

                        match raw_cmd {
                            CMD_SEL_INT => {
                                // Device echoes selection before emitting any
                                // status/config responses for that sub-interface.
                                if let Some(&idx) = frame.first() {
                                    selected_index = idx as usize;
                                }
                            }

                            rnode::CMD_STAT_RSSI => {
                                if !frame.is_empty() {
                                    let rssi = frame[0] as i8 as f32;
                                    if let Some(local_idx) =
                                        vport_map.get(selected_index).copied().flatten()
                                    {
                                        signals[local_idx].last_rssi = Some(rssi);
                                    }
                                }
                            }
                            rnode::CMD_STAT_SNR => {
                                if !frame.is_empty() {
                                    let snr = frame[0] as i8 as f32 / 4.0;
                                    if let Some(local_idx) =
                                        vport_map.get(selected_index).copied().flatten()
                                    {
                                        signals[local_idx].last_snr = Some(snr);
                                    }
                                }
                            }

                            rnode::CMD_READY => {
                                let is_ready = frame.first().copied().unwrap_or(0) != 0;
                                ready_r.store(is_ready, Ordering::SeqCst);
                            }

                            rnode::CMD_DETECT => {
                                if frame.first().copied() == Some(rnode::DETECT_RESP) {
                                    tracing::info!(
                                        parent = %parent_name,
                                        "RNodeMulti device detected"
                                    );
                                }
                            }

                            rnode::CMD_FW_VERSION => {
                                if frame.len() >= 2 {
                                    let major = frame[0];
                                    let minor = frame[1];
                                    tracing::info!(
                                        parent = %parent_name,
                                        major, minor,
                                        "RNodeMulti firmware version {}.{}",
                                        major, minor,
                                    );
                                    if major < REQUIRED_FW_VER_MAJ
                                        || (major == REQUIRED_FW_VER_MAJ
                                            && minor < REQUIRED_FW_VER_MIN)
                                    {
                                        tracing::warn!(
                                            parent = %parent_name,
                                            "RNodeMulti firmware {}.{} below required {}.{}",
                                            major, minor,
                                            REQUIRED_FW_VER_MAJ, REQUIRED_FW_VER_MIN,
                                        );
                                    }
                                }
                            }

                            rnode::CMD_RADIO_STATE => {
                                if let Some(local_idx) =
                                    vport_map.get(selected_index).copied().flatten()
                                {
                                    if frame.first().copied() == Some(rnode::RADIO_STATE_ON) {
                                        tracing::info!(
                                            parent = %parent_name,
                                            subinterface = local_idx,
                                            vport = selected_index,
                                            "RNodeMulti sub-interface radio online"
                                        );
                                    } else {
                                        tracing::warn!(
                                            parent = %parent_name,
                                            subinterface = local_idx,
                                            vport = selected_index,
                                            "RNodeMulti sub-interface radio offline"
                                        );
                                    }
                                }
                            }

                            rnode::CMD_FREQUENCY => {
                                if frame.len() >= 4 {
                                    let freq = u32::from_be_bytes([
                                        frame[0], frame[1], frame[2], frame[3],
                                    ]);
                                    tracing::debug!(
                                        parent = %parent_name,
                                        vport = selected_index,
                                        freq_mhz = format!("{:.3}", freq as f64 / 1_000_000.0),
                                        "Radio reporting frequency"
                                    );
                                }
                            }

                            rnode::CMD_BANDWIDTH => {
                                if frame.len() >= 4 {
                                    let bw = u32::from_be_bytes([
                                        frame[0], frame[1], frame[2], frame[3],
                                    ]);
                                    tracing::debug!(
                                        parent = %parent_name,
                                        vport = selected_index,
                                        bw_khz = format!("{:.1}", bw as f64 / 1000.0),
                                        "Radio reporting bandwidth"
                                    );
                                }
                            }

                            rnode::CMD_SF => {
                                if !frame.is_empty() {
                                    tracing::debug!(
                                        parent = %parent_name,
                                        vport = selected_index,
                                        sf = frame[0],
                                        "Radio reporting spreading factor"
                                    );
                                }
                            }

                            rnode::CMD_CR => {
                                if !frame.is_empty() {
                                    tracing::debug!(
                                        parent = %parent_name,
                                        vport = selected_index,
                                        cr = frame[0],
                                        "Radio reporting coding rate"
                                    );
                                }
                            }

                            rnode::CMD_TXPOWER => {
                                if !frame.is_empty() {
                                    let txp = frame[0] as i8;
                                    tracing::debug!(
                                        parent = %parent_name,
                                        vport = selected_index,
                                        txpower_dbm = txp,
                                        "Radio reporting TX power"
                                    );
                                }
                            }

                            rnode::CMD_ST_ALOCK => {
                                if frame.len() >= 2 {
                                    let at = ((frame[0] as u16) << 8) | frame[1] as u16;
                                    let pct = at as f32 / 100.0;
                                    tracing::debug!(
                                        parent = %parent_name,
                                        vport = selected_index,
                                        "RNodeMulti short-term airtime limit: {:.2}%", pct,
                                    );
                                }
                            }

                            rnode::CMD_LT_ALOCK => {
                                if frame.len() >= 2 {
                                    let at = ((frame[0] as u16) << 8) | frame[1] as u16;
                                    let pct = at as f32 / 100.0;
                                    tracing::debug!(
                                        parent = %parent_name,
                                        vport = selected_index,
                                        "RNodeMulti long-term airtime limit: {:.2}%", pct,
                                    );
                                }
                            }

                            rnode::CMD_PLATFORM => {
                                if !frame.is_empty() {
                                    tracing::debug!(
                                        parent = %parent_name,
                                        platform = format!("0x{:02X}", frame[0]),
                                        "RNodeMulti platform"
                                    );
                                }
                            }

                            rnode::CMD_MCU => {
                                if !frame.is_empty() {
                                    tracing::debug!(
                                        parent = %parent_name,
                                        mcu = format!("0x{:02X}", frame[0]),
                                        "RNodeMulti MCU"
                                    );
                                }
                            }

                            CMD_INTERFACES => {
                                // Reply is a stream of 2-byte `[vport, radio_type]`
                                // pairs, one per radio module; accumulate then pop.
                                interfaces_buf.extend_from_slice(&frame);
                                if interfaces_buf.len() >= 2 {
                                    let vp = interfaces_buf[0];
                                    let rt = interfaces_buf[1];
                                    let rtype = RadioType::from_u8(rt)
                                        .map(|r| r.family_name().to_string())
                                        .unwrap_or_else(|| format!("unknown(0x{:02X})", rt));
                                    tracing::info!(
                                        parent = %parent_name,
                                        vport = vp,
                                        radio_type = %rtype,
                                        "RNodeMulti radio module reported"
                                    );
                                    interfaces_buf.clear();
                                }
                            }

                            CMD_ERROR => {
                                if !frame.is_empty() {
                                    match frame[0] {
                                        ERROR_INITRADIO => {
                                            tracing::error!(
                                                parent = %parent_name,
                                                "RNodeMulti hardware initialisation error"
                                            );
                                        }
                                        ERROR_TXFAILED => {
                                            tracing::error!(
                                                parent = %parent_name,
                                                "RNodeMulti hardware TX error"
                                            );
                                        }
                                        code => {
                                            tracing::error!(
                                                parent = %parent_name,
                                                code = format!("0x{:02X}", code),
                                                "RNodeMulti hardware error"
                                            );
                                        }
                                    }
                                }
                            }

                            rnode::CMD_RESET => {
                                if frame.first().copied() == Some(0xF8) {
                                    tracing::error!(
                                        parent = %parent_name,
                                        "RNodeMulti device reset detected"
                                    );
                                    online_r.store(false, Ordering::SeqCst);
                                    return;
                                }
                            }

                            _ => {
                                tracing::debug!(
                                    parent = %parent_name,
                                    cmd = format!("0x{:02X}", raw_cmd),
                                    "RNodeMulti: ignoring KISS command"
                                );
                            }
                        }
                    }
                }
                Ok(Err((_p, e))) => {
                    tracing::warn!(
                        parent = %parent_name,
                        error = %e,
                        "RNodeMulti read error"
                    );
                    online_r.store(false, Ordering::SeqCst);
                    return;
                }
                Err(e) => {
                    tracing::warn!(
                        parent = %parent_name,
                        error = %e,
                        "RNodeMulti read task panicked"
                    );
                    online_r.store(false, Ordering::SeqCst);
                    return;
                }
            }
        }
    });

    Ok(handles)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rnode_multi_config() {
        let mut cfg = RNodeMultiConfig::new("multi0", "/dev/ttyACM0");
        assert_eq!(cfg.baud_rate, 115200);
        assert!(!cfg.flow_control);
        assert!(cfg.subinterfaces.is_empty());

        cfg.subinterfaces
            .push(SubInterfaceConfig::new("radio0", 0, 868_000_000));
        cfg.subinterfaces
            .push(SubInterfaceConfig::new("radio1", 1, 915_000_000));
        assert_eq!(cfg.subinterfaces.len(), 2);
        assert!(cfg.subinterfaces.iter().all(|sub| sub.outgoing));
        assert!(cfg.subinterfaces.iter().all(|sub| !sub.flow_control));
    }

    #[test]
    fn test_subinterface_init_sequence() {
        let sub_cfg = SubInterfaceConfig::new("radio0", 0, 868_000_000);
        let seq = build_subinterface_init(0, &sub_cfg);
        assert!(!seq.is_empty());

        let mut deframer = kiss::KissDeframer::new();
        let frames = deframer.feed(&seq);
        // sel_int + freq + bw + sf + cr + txpower + radio_state
        assert_eq!(frames.len(), 7);
    }

    #[test]
    fn test_subinterface_init_with_airtime() {
        let mut sub_cfg = SubInterfaceConfig::new("radio0", 0, 868_000_000);
        sub_cfg.st_alock = Some(15.0);
        sub_cfg.lt_alock = Some(25.0);

        let seq = build_subinterface_init(0, &sub_cfg);
        let mut deframer = kiss::KissDeframer::new();
        let frames = deframer.feed(&seq);
        // 7 base + 2 airtime limits
        assert_eq!(frames.len(), 9);
    }

    #[test]
    fn test_command_to_subinterface() {
        assert_eq!(command_to_subinterface(0x00), Some(0));
        assert_eq!(command_to_subinterface(0x10), Some(1));
        assert_eq!(command_to_subinterface(0x20), Some(2));
        assert_eq!(command_to_subinterface(0x70), Some(3));
        assert_eq!(command_to_subinterface(0x75), Some(4));
        assert_eq!(command_to_subinterface(0x90), Some(5));
        assert_eq!(command_to_subinterface(0xA0), Some(6));
        assert_eq!(command_to_subinterface(0xB0), Some(7));
        assert_eq!(command_to_subinterface(0xC0), Some(8));
        assert_eq!(command_to_subinterface(0xD0), Some(9));
        assert_eq!(command_to_subinterface(0xE0), Some(10));
        assert_eq!(command_to_subinterface(0xF0), Some(11));
        assert_eq!(command_to_subinterface(0x55), None);
        assert_eq!(command_to_subinterface(0xFF), None);
        assert_eq!(command_to_subinterface(0x01), None);
    }

    #[test]
    fn test_radio_type() {
        assert_eq!(RadioType::from_u8(0x00), Some(RadioType::SX127X));
        assert_eq!(RadioType::from_u8(0x11), Some(RadioType::SX1262));
        assert_eq!(RadioType::from_u8(0x21), Some(RadioType::SX1280));
        assert_eq!(RadioType::from_u8(0xFF), None);

        assert_eq!(RadioType::SX127X.family_name(), "SX127X");
        assert_eq!(RadioType::SX1262.family_name(), "SX126X");
        assert_eq!(RadioType::SX1280.family_name(), "SX128X");
    }

    #[test]
    fn test_radio_type_frequency_validation() {
        let sx127x = RadioType::SX127X;
        assert!(sx127x.validate_frequency(868_000_000));
        assert!(sx127x.validate_frequency(915_000_000));
        assert!(sx127x.validate_frequency(137_000_000));
        assert!(sx127x.validate_frequency(1_000_000_000));
        assert!(!sx127x.validate_frequency(136_999_999));
        assert!(!sx127x.validate_frequency(1_000_000_001));

        let sx1280 = RadioType::SX1280;
        assert!(sx1280.validate_frequency(2_400_000_000));
        assert!(!sx1280.validate_frequency(868_000_000));
    }

    #[test]
    fn test_max_subinterfaces() {
        assert_eq!(MAX_SUBINTERFACES, 11);
        assert_eq!(CMD_INT_DATA.len(), 12);
    }

    #[test]
    fn test_detect_sequence() {
        let seq = build_detect_sequence();
        assert!(!seq.is_empty());
        let mut deframer = kiss::KissDeframer::new();
        let frames = deframer.feed(&seq);
        // DETECT + FW_VERSION + PLATFORM + MCU + INTERFACES
        assert_eq!(frames.len(), 5);
    }

    #[test]
    fn test_build_subinterface_data_frame() {
        let data = b"hello radio";
        let frame = build_subinterface_data_frame(2, data);
        assert!(!frame.is_empty());

        let mut deframer = kiss::RawKissDeframer::new();
        let frames = deframer.feed(&frame);
        // CMD_SEL_INT then CMD_DATA
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].0, CMD_SEL_INT);
        assert_eq!(frames[0].1, &[2u8]);
        assert_eq!(frames[1].0, kiss::CMD_DATA);
        assert_eq!(frames[1].1, data);
    }

    #[test]
    fn test_raw_kiss_deframer_preserves_command() {
        // CMD_INT5_DATA = 0x90 collides with CMD_ERROR after masking; the raw
        // deframer must keep the high nibble intact.
        let payload = b"test data";
        let mut raw_frame = Vec::new();
        raw_frame.push(kiss::FEND);
        raw_frame.push(0x90);
        raw_frame.extend_from_slice(&kiss::escape(payload));
        raw_frame.push(kiss::FEND);

        let mut deframer = kiss::RawKissDeframer::new();
        let frames = deframer.feed(&raw_frame);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].0, 0x90);
        assert_eq!(frames[0].1, payload);

        assert_eq!(command_to_subinterface(0x90), Some(5));
    }

    #[test]
    fn test_raw_kiss_deframer_streaming() {
        let payload = b"streamed";
        let mut raw_frame = Vec::new();
        raw_frame.push(kiss::FEND);
        raw_frame.push(0xA0);
        raw_frame.extend_from_slice(&kiss::escape(payload));
        raw_frame.push(kiss::FEND);

        let mid = raw_frame.len() / 2;
        let mut deframer = kiss::RawKissDeframer::new();

        let f1 = deframer.feed(&raw_frame[..mid]);
        assert!(f1.is_empty());

        let f2 = deframer.feed(&raw_frame[mid..]);
        assert_eq!(f2.len(), 1);
        assert_eq!(f2[0].0, 0xA0);
        assert_eq!(f2[0].1, payload);
    }

    #[test]
    fn test_raw_kiss_deframer_multiple_frames() {
        let mut stream = vec![
            kiss::FEND,
            CMD_SEL_INT,
            3,
            kiss::FEND,
            kiss::FEND,
            rnode::CMD_STAT_RSSI,
            0x80,
            kiss::FEND,
            kiss::FEND,
            0x70,
        ];
        stream.extend_from_slice(b"packet");
        stream.push(kiss::FEND);

        let mut deframer = kiss::RawKissDeframer::new();
        let frames = deframer.feed(&stream);
        assert_eq!(frames.len(), 3);

        assert_eq!(frames[0].0, CMD_SEL_INT);
        assert_eq!(frames[0].1, &[3u8]);

        assert_eq!(frames[1].0, rnode::CMD_STAT_RSSI);
        assert_eq!(frames[1].1, &[0x80u8]);

        assert_eq!(frames[2].0, 0x70);
        assert_eq!(frames[2].1, b"packet");
    }

    #[test]
    fn test_raw_kiss_deframer_escape_handling() {
        let raw_frame = vec![
            kiss::FEND,
            0xB0,
            kiss::FESC,
            kiss::TFEND,
            kiss::FESC,
            kiss::TFESC,
            0x42,
            kiss::FEND,
        ];

        let mut deframer = kiss::RawKissDeframer::new();
        let frames = deframer.feed(&raw_frame);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].0, 0xB0);
        assert_eq!(frames[0].1, &[kiss::FEND, kiss::FESC, 0x42]);
    }

    #[test]
    fn test_subinterface_config_validate() {
        let cfg = SubInterfaceConfig::new("radio0", 0, 868_000_000);
        assert!(cfg.validate().is_ok());

        let mut bad = SubInterfaceConfig::new("radio0", 0, 868_000_000);
        bad.spreading_factor = 13;
        assert!(bad.validate().is_err());

        let mut bad = SubInterfaceConfig::new("radio0", 0, 868_000_000);
        bad.coding_rate = 9;
        assert!(bad.validate().is_err());

        let mut bad = SubInterfaceConfig::new("radio0", 0, 868_000_000);
        bad.bandwidth = 1000;
        assert!(bad.validate().is_err());

        let mut bad = SubInterfaceConfig::new("radio0", 0, 868_000_000);
        bad.bandwidth = 2_000_000;
        assert!(bad.validate().is_err());

        let mut bad = SubInterfaceConfig::new("radio0", 0, 868_000_000);
        bad.st_alock = Some(101.0);
        assert!(bad.validate().is_err());

        let bad = SubInterfaceConfig::new("radio0", 12, 868_000_000);
        assert!(bad.validate().is_err());
    }

    #[test]
    fn test_subinterface_config_validate_edge_cases() {
        let mut cfg = SubInterfaceConfig::new("radio0", 0, 868_000_000);
        cfg.spreading_factor = 5;
        cfg.coding_rate = 5;
        cfg.bandwidth = 7800;
        assert!(cfg.validate().is_ok());

        cfg.spreading_factor = 12;
        cfg.coding_rate = 8;
        cfg.bandwidth = 1_625_000;
        cfg.st_alock = Some(100.0);
        cfg.lt_alock = Some(100.0);
        assert!(cfg.validate().is_ok());

        cfg.st_alock = Some(0.0);
        cfg.lt_alock = Some(0.0);
        assert!(cfg.validate().is_ok());

        cfg.st_alock = Some(-1.0);
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_multi_detect_sequence_includes_interfaces_query() {
        let seq = build_detect_sequence();
        let mut deframer = kiss::RawKissDeframer::new();
        let frames = deframer.feed(&seq);

        assert_eq!(frames.len(), 5);
        assert_eq!(frames[0].0, rnode::CMD_DETECT);
        assert_eq!(frames[1].0, rnode::CMD_FW_VERSION);
        assert_eq!(frames[2].0, rnode::CMD_PLATFORM);
        assert_eq!(frames[3].0, rnode::CMD_MCU);
        assert_eq!(frames[4].0, CMD_INTERFACES);
    }

    #[test]
    fn test_data_frame_roundtrip() {
        let payload = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let frame = build_subinterface_data_frame(1, &payload);

        let mut deframer = kiss::RawKissDeframer::new();
        let frames = deframer.feed(&frame);
        assert_eq!(frames.len(), 2);

        assert_eq!(frames[0].0, CMD_SEL_INT);
        assert_eq!(frames[0].1, &[1u8]);

        assert_eq!(frames[1].0, kiss::CMD_DATA);
        assert_eq!(frames[1].1, payload);
    }

    #[test]
    fn test_data_frame_with_escape_chars() {
        let payload = vec![kiss::FEND, kiss::FESC, 0x42, kiss::FEND];
        let frame = build_subinterface_data_frame(0, &payload);

        let mut deframer = kiss::RawKissDeframer::new();
        let frames = deframer.feed(&frame);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[1].0, kiss::CMD_DATA);
        assert_eq!(frames[1].1, payload);
    }

    #[test]
    fn test_all_subinterface_data_commands_unique() {
        for (i, lhs) in CMD_INT_DATA.iter().enumerate() {
            for (j, rhs) in CMD_INT_DATA.iter().enumerate().skip(i + 1) {
                assert_ne!(
                    lhs, rhs,
                    "CMD_INT_DATA[{}] == CMD_INT_DATA[{}] == 0x{:02X}",
                    i, j, *lhs
                );
            }
        }
    }

    #[test]
    fn test_data_commands_dont_collide_with_control_commands() {
        let control_cmds = [
            CMD_SEL_INT,
            rnode::CMD_STAT_RSSI,
            rnode::CMD_STAT_SNR,
            rnode::CMD_READY,
            rnode::CMD_DETECT,
            rnode::CMD_FW_VERSION,
            rnode::CMD_RADIO_STATE,
            rnode::CMD_FREQUENCY,
            rnode::CMD_BANDWIDTH,
            rnode::CMD_SF,
            rnode::CMD_CR,
            rnode::CMD_TXPOWER,
            rnode::CMD_ST_ALOCK,
            rnode::CMD_LT_ALOCK,
            rnode::CMD_PLATFORM,
            rnode::CMD_MCU,
            CMD_INTERFACES,
            rnode::CMD_RESET,
        ];

        for &data_cmd in &CMD_INT_DATA {
            for &ctrl_cmd in &control_cmds {
                // CMD_INT0_DATA == CMD_DATA (0x00) and CMD_INT5_DATA ==
                // CMD_ERROR (0x90) are known, intentional overlaps; the read
                // loop disambiguates by checking data commands first.
                if data_cmd == 0x00 || data_cmd == 0x90 {
                    continue;
                }
                assert_ne!(
                    data_cmd, ctrl_cmd,
                    "CMD_INT_DATA 0x{:02X} collides with control cmd 0x{:02X}",
                    data_cmd, ctrl_cmd
                );
            }
        }
    }
}
