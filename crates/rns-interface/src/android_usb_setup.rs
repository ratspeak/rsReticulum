//! Production descriptor selection and serial control requests for Android USB.

#[derive(Clone, Debug)]
pub(crate) struct UsbEndpointDescriptor {
    pub direction: i32,
    pub transfer_type: i32,
}

#[derive(Clone, Debug)]
pub(crate) struct UsbInterfaceDescriptor {
    pub number: u16,
    pub alternate_setting: i32,
    pub class: i32,
    pub subclass: i32,
    pub endpoints: Vec<UsbEndpointDescriptor>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UsbSerialKind {
    Cp210x,
    CdcAcm,
    Ftdi,
    Ch34x,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(feature = "serial"), allow(dead_code))]
pub(crate) enum UsbParity {
    None,
    Even,
    Odd,
}

/// Serial line settings the Android Serial and KISS interfaces pass to
/// usbserial4a: speed, data bits, parity `N`/`E`/`O` and stop bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct UsbSerialLine {
    pub baud_rate: u32,
    pub data_bits: u8,
    pub parity: UsbParity,
    pub stop_bits: u8,
}

impl UsbSerialLine {
    pub(crate) const fn eight_n_one(baud_rate: u32) -> Self {
        Self {
            baud_rate,
            data_bits: 8,
            parity: UsbParity::None,
            stop_bits: 1,
        }
    }
}

/// usbserial4a 0.4.0 `vidpid4a.FTDI_VID_PID_GROUP`: FTDI chips under other vendors.
const FTDI_VID_PID_GROUP: &[(i32, i32)] = &[
    (0x03eb, 0x2109),
    (0x0456, 0xf000),
    (0x0456, 0xf001),
    (0x04d8, 0x000a),
    (0x0584, 0xb020),
    (0x0647, 0x0100),
    (0x06ce, 0x8311),
    (0x06d3, 0x0284),
    (0x0856, 0xac01),
    (0x0856, 0xac02),
    (0x0856, 0xac03),
    (0x0856, 0xac11),
    (0x0856, 0xac12),
    (0x0856, 0xac16),
    (0x0856, 0xac17),
    (0x0856, 0xac18),
    (0x0856, 0xac19),
    (0x0856, 0xac25),
    (0x0856, 0xac26),
    (0x0856, 0xac27),
    (0x0856, 0xac33),
    (0x0856, 0xac34),
    (0x0856, 0xac49),
    (0x0856, 0xac50),
    (0x0856, 0xba02),
    (0x093c, 0x0601),
    (0x093c, 0x0701),
    (0x0acd, 0x0300),
    (0x0b39, 0x0103),
    (0x0b39, 0x0421),
    (0x0c26, 0x0004),
    (0x0c26, 0x0018),
    (0x0c26, 0x0009),
    (0x0c26, 0x000a),
    (0x0c26, 0x000b),
    (0x0c26, 0x000c),
    (0x0c26, 0x000d),
    (0x0c26, 0x0010),
    (0x0c26, 0x0011),
    (0x0c26, 0x0012),
    (0x0c26, 0x0013),
    (0x0c33, 0x0010),
    (0x0c52, 0x2101),
    (0x0c52, 0x2102),
    (0x0c52, 0x2103),
    (0x0c52, 0x2104),
    (0x0c52, 0x9020),
    (0x0c52, 0x2211),
    (0x0c52, 0x2221),
    (0x0c52, 0x2212),
    (0x0c52, 0x2222),
    (0x0c52, 0x2213),
    (0x0c52, 0x2223),
    (0x0c52, 0x2411),
    (0x0c52, 0x2421),
    (0x0c52, 0x2431),
    (0x0c52, 0x2441),
    (0x0c52, 0x2412),
    (0x0c52, 0x2422),
    (0x0c52, 0x2432),
    (0x0c52, 0x2442),
    (0x0c52, 0x2413),
    (0x0c52, 0x2423),
    (0x0c52, 0x2433),
    (0x0c52, 0x2443),
    (0x0c52, 0x2811),
    (0x0c52, 0x2821),
    (0x0c52, 0x2831),
    (0x0c52, 0x2841),
    (0x0c52, 0x2851),
    (0x0c52, 0x2861),
    (0x0c52, 0x2871),
    (0x0c52, 0x2881),
    (0x0c52, 0x2812),
    (0x0c52, 0x2822),
    (0x0c52, 0x2832),
    (0x0c52, 0x2842),
    (0x0c52, 0x2852),
    (0x0c52, 0x2862),
    (0x0c52, 0x2872),
    (0x0c52, 0x2882),
    (0x0c52, 0x2813),
    (0x0c52, 0x2823),
    (0x0c52, 0x2833),
    (0x0c52, 0x2843),
    (0x0c52, 0x2853),
    (0x0c52, 0x2863),
    (0x0c52, 0x2873),
    (0x0c52, 0x2883),
    (0x0c52, 0xa02a),
    (0x0c52, 0xa02b),
    (0x0c52, 0xa02c),
    (0x0c52, 0xa02d),
    (0x0c6c, 0x04b2),
    (0x0c7d, 0x0005),
    (0x0d3a, 0x0300),
    (0x0d46, 0x2020),
    (0x0d46, 0x2021),
    (0x0dcd, 0x0001),
    (0x0f94, 0x0001),
    (0x0f94, 0x0005),
    (0x0fd8, 0x0001),
    (0x103e, 0x03e8),
    (0x104d, 0x3000),
    (0x104d, 0x3002),
    (0x104d, 0x3006),
    (0x1209, 0x1002),
    (0x1209, 0x1006),
    (0x128d, 0x0001),
    (0x1342, 0x0202),
    (0x1457, 0x5118),
    (0x15ba, 0x0003),
    (0x15ba, 0x002b),
    (0x1781, 0x0c30),
    (0x2100, 0x9001),
    (0x2100, 0x9e50),
    (0x2100, 0x9e51),
    (0x2100, 0x9e52),
    (0x2100, 0x9e53),
    (0x2100, 0x9e54),
    (0x2100, 0x9e55),
    (0x2100, 0x9e56),
    (0x2100, 0x9e57),
    (0x2100, 0x9e58),
    (0x2100, 0x9e59),
    (0x2100, 0x9e5a),
    (0x2100, 0x9e5b),
    (0x2100, 0x9e5c),
    (0x2100, 0x9e5d),
    (0x2100, 0x9e5e),
    (0x2100, 0x9e5f),
    (0x2100, 0x9e60),
    (0x2100, 0x9e61),
    (0x2100, 0x9e62),
    (0x2100, 0x9e63),
    (0x2100, 0x9e64),
    (0x2100, 0x9e65),
    (0x2100, 0x9e66),
    (0x2100, 0x9e67),
    (0x2100, 0x9e68),
    (0x2100, 0x9e69),
    (0x2100, 0x9e6a),
    (0x1a72, 0x1000),
    (0x1a72, 0x1001),
    (0x1a72, 0x1002),
    (0x1a72, 0x1005),
    (0x1a72, 0x1007),
    (0x1a72, 0x1008),
    (0x1a72, 0x1009),
    (0x1a72, 0x100d),
    (0x1a72, 0x100e),
    (0x1a72, 0x100f),
    (0x1a72, 0x1011),
    (0x1a72, 0x1012),
    (0x1a72, 0x1013),
    (0x1a72, 0x1014),
    (0x1a72, 0x1015),
    (0x1a72, 0x1016),
    (0x165c, 0x0002),
    (0x1a79, 0x6001),
    (0x1b3d, 0x0100),
    (0x1b3d, 0x0101),
    (0x1b3d, 0x0102),
    (0x1b3d, 0x0103),
    (0x1b3d, 0x0104),
    (0x1b3d, 0x0105),
    (0x1b3d, 0x0106),
    (0x1b3d, 0x0107),
    (0x1b3d, 0x0108),
    (0x1b3d, 0x0109),
    (0x1b3d, 0x010a),
    (0x1b3d, 0x010b),
    (0x1b3d, 0x010c),
    (0x1b3d, 0x010d),
    (0x1b3d, 0x010e),
    (0x1b3d, 0x010f),
    (0x1b3d, 0x0110),
    (0x1b3d, 0x0111),
    (0x1b3d, 0x0112),
    (0x1b3d, 0x0113),
    (0x1b3d, 0x0114),
    (0x1b3d, 0x0115),
    (0x1b3d, 0x0116),
    (0x1b3d, 0x0117),
    (0x1b3d, 0x0118),
    (0x1b3d, 0x0119),
    (0x1b3d, 0x011a),
    (0x1b3d, 0x011b),
    (0x1b3d, 0x011c),
    (0x1b3d, 0x011d),
    (0x1b3d, 0x011e),
    (0x1b3d, 0x011f),
    (0x1b3d, 0x0120),
    (0x1b3d, 0x0121),
    (0x1b3d, 0x0122),
    (0x1b3d, 0x0123),
    (0x1b3d, 0x0124),
    (0x1b3d, 0x0125),
    (0x1b3d, 0x0126),
    (0x1b3d, 0x0127),
    (0x1b3d, 0x0128),
    (0x1b3d, 0x0129),
    (0x1b3d, 0x012a),
    (0x1b3d, 0x012b),
    (0x1b3d, 0x012c),
    (0x1b3d, 0x012e),
    (0x1b3d, 0x012f),
    (0x1b3d, 0x0130),
    (0x1b91, 0x0064),
    (0x1bc9, 0x6001),
    (0x1c0c, 0x0102),
    (0x1cf1, 0x0001),
    (0x1cf1, 0x0041),
    (0x0483, 0x3746),
    (0x0483, 0x3747),
    (0x5050, 0x0100),
    (0x5050, 0x0101),
    (0x5050, 0x0102),
    (0x5050, 0x0103),
    (0x5050, 0x0104),
    (0x5050, 0x0105),
    (0x5050, 0x0106),
    (0x5050, 0x0107),
    (0x5050, 0x0300),
    (0x5050, 0x0301),
    (0x5050, 0x0400),
    (0x5050, 0x0500),
    (0x5050, 0x0700),
    (0x5050, 0x0800),
    (0x5050, 0x0900),
    (0x5050, 0x0a00),
    (0x5050, 0x0b00),
    (0x5050, 0x0c00),
    (0x5050, 0x0d00),
    (0x5050, 0x0e00),
    (0x5050, 0x0f00),
    (0x5050, 0x1000),
    (0x5050, 0x8000),
    (0x5050, 0x8001),
    (0x5050, 0x8002),
    (0x5050, 0x8003),
    (0x5050, 0x8004),
    (0x5050, 0x8005),
    (0x9e88, 0x9e8f),
    (0xdeee, 0x0300),
    (0xdeee, 0x02ff),
    (0xdeee, 0x0302),
    (0xdeee, 0x0303),
    (0x05d1, 0x1001),
    (0x05d1, 0x1002),
    (0x05d1, 0x1003),
    (0x05d1, 0x1004),
    (0x05d1, 0x1011),
    (0x05d1, 0x1013),
    (0x05d1, 0x2001),
    (0x05d1, 0x2002),
    (0x05d1, 0x2003),
    (0x05d1, 0x2011),
    (0x05d1, 0x2012),
    (0x05d1, 0x2021),
    (0x05d1, 0x2022),
    (0x05d1, 0x2023),
    (0x05d1, 0x2024),
    (0x05d1, 0x3011),
    (0x05d1, 0x3012),
    (0x05d1, 0x5001),
    (0x05d1, 0x6001),
    (0x05d1, 0x7001),
    (0x05d1, 0x8001),
    (0x05d1, 0x8002),
    (0x05d1, 0x8003),
    (0x05d1, 0x8004),
    (0x05d1, 0x9001),
    (0x05d1, 0x9002),
    (0x05d1, 0x9003),
    (0x05d1, 0x9004),
    (0x05d1, 0x9005),
    (0x05d1, 0x9006),
    (0x05d1, 0x9007),
    (0x05d1, 0x9008),
];

/// usbserial4a `serial4a.get_serial_port` driver choice, with RNS's override
/// of the Qinheng `1a86:55d4` (CH9102) to the CDC driver
/// (`RNS/Interfaces/Android/KISSInterface.py` `open_port`).
fn usbserial4a_kind(vendor_id: i32, product_id: i32) -> Option<UsbSerialKind> {
    if vendor_id == 0x1a86 && product_id == 0x55d4 {
        None
    } else if vendor_id == 0x0403 || FTDI_VID_PID_GROUP.contains(&(vendor_id, product_id)) {
        Some(UsbSerialKind::Ftdi)
    } else if vendor_id == 0x1a86 || (vendor_id, product_id) == (0x4348, 0x5523) {
        Some(UsbSerialKind::Ch34x)
    } else {
        None
    }
}

/// Python Android `open_port` per-chip `USB_READ_TIMEOUT_MILLIS`.
pub(crate) const fn usb_read_timeout_ms(vendor_id: i32, product_id: i32) -> i32 {
    if vendor_id == 0x10c4 || (vendor_id == 0x1a86 && product_id == 0x55d4) {
        12
    } else {
        100
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UsbSerialPort {
    pub kind: UsbSerialKind,
    /// Positions in UsbDevice's interface array, not bInterfaceNumber.
    pub data_interface: usize,
    pub control_interface: usize,
    /// bInterfaceNumber used as wIndex in control transfers.
    pub control_number: u16,
    /// Positions in the data interface's endpoint array.
    pub input_endpoint: usize,
    pub output_endpoint: usize,
}

fn bulk_pair(interface: &UsbInterfaceDescriptor) -> Option<(usize, usize)> {
    let mut input = None;
    let mut output = None;
    for (index, endpoint) in interface.endpoints.iter().enumerate() {
        if endpoint.transfer_type != 2 {
            continue;
        }
        match endpoint.direction {
            0x80 if input.is_none() => input = Some(index),
            0x00 if output.is_none() => output = Some(index),
            _ => return None,
        }
    }
    Some((input?, output?))
}

pub(crate) fn select_serial_port(
    vendor_id: i32,
    product_id: i32,
    interfaces: &[UsbInterfaceDescriptor],
) -> Result<UsbSerialPort, String> {
    if let Some(kind) = usbserial4a_kind(vendor_id, product_id) {
        // usbserial4a uses interface 0 for FTDI and the last interface for
        // CH34x, with its bulk IN and OUT endpoints.
        let data_interface = match kind {
            UsbSerialKind::Ftdi => 0,
            _ => interfaces
                .len()
                .checked_sub(1)
                .ok_or("USB device has no interfaces")?,
        };
        let interface = &interfaces[data_interface];
        let (input_endpoint, output_endpoint) = bulk_pair(interface)
            .ok_or_else(|| "No USB serial interface with bulk IN and OUT endpoints".to_string())?;
        return Ok(UsbSerialPort {
            kind,
            data_interface,
            control_interface: data_interface,
            control_number: interface.number,
            input_endpoint,
            output_endpoint,
        });
    }
    // Heltec V3 uses the standard CP2102/CP2102N VID/PID. Do not apply
    // Silicon Labs requests to every vendor-specific interface or VID.
    let cp210x = vendor_id == 0x10c4 && product_id == 0xea60;
    let mut candidates = interfaces
        .iter()
        .enumerate()
        .filter_map(|(index, interface)| {
            if interface.alternate_setting != 0
                || interface.class != if cp210x { 0xff } else { 0x0a }
            {
                return None;
            }
            bulk_pair(interface).map(|pair| (index, pair))
        });
    let (data_interface, (input_endpoint, output_endpoint)) =
        candidates.next().ok_or_else(|| {
            "No supported USB serial interface with bulk IN and OUT endpoints".to_string()
        })?;
    if candidates.next().is_some() {
        return Err("Multiple USB serial data interfaces are unsupported".into());
    }
    let control_interface = if cp210x {
        data_interface
    } else {
        // A single CDC-ACM function is unambiguous even when unrelated JTAG
        // or other interfaces precede it. Multi-port CDC needs a union/IAD
        // association parser; never guess a control interface for it.
        let mut controls = interfaces.iter().enumerate().filter(|(_, interface)| {
            interface.alternate_setting == 0
                && interface.class == 0x02
                && interface.subclass == 0x02
        });
        let (index, _) = controls
            .next()
            .ok_or_else(|| "No CDC-ACM control interface found".to_string())?;
        if controls.next().is_some() {
            return Err("Multiple CDC-ACM control interfaces are unsupported".into());
        }
        index
    };
    Ok(UsbSerialPort {
        kind: if cp210x {
            UsbSerialKind::Cp210x
        } else {
            UsbSerialKind::CdcAcm
        },
        data_interface,
        control_interface,
        control_number: interfaces[control_interface].number,
        input_endpoint,
        output_endpoint,
    })
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct UsbControlRequest<'a> {
    pub request_type: u8,
    pub request: u8,
    pub value: u16,
    pub index: u16,
    pub payload: &'a [u8],
}

/// Configure the UART. Device-to-host requests (request type bit 7) carry a
/// zeroed payload of the expected length; every request must transfer exactly
/// its payload length.
pub(crate) fn configure_serial_port(
    port: &UsbSerialPort,
    line: &UsbSerialLine,
    mut transfer: impl FnMut(&UsbControlRequest<'_>) -> Result<i32, String>,
) -> Result<(), String> {
    let baud_rate = line.baud_rate;
    if baud_rate == 0 {
        return Err("USB serial baud rate must be nonzero".into());
    }
    match port.kind {
        UsbSerialKind::Ftdi => return configure_ftdi(port, line, transfer),
        UsbSerialKind::Ch34x => return configure_ch34x(line, transfer),
        _ => {}
    }
    let request_type = match port.kind {
        UsbSerialKind::Cp210x => 0x41,
        _ => 0x21,
    };
    let mut send = |request, value, payload: &[u8]| {
        let setup = UsbControlRequest {
            request_type,
            request,
            value,
            index: port.control_number,
            payload,
        };
        let transferred = transfer(&setup)
            .map_err(|error| format!("USB serial setup request 0x{request:02x}: {error}"))?;
        if transferred != payload.len() as i32 {
            return Err(format!(
                "USB serial setup request 0x{request:02x} transferred {transferred} bytes; expected {}",
                payload.len()
            ));
        }
        Ok(())
    };
    match port.kind {
        UsbSerialKind::Cp210x => {
            // Silicon Labs AN571 sections 5.1, 5.5, 5.7, 5.9, 5.11 and
            // tables 9-11: https://www.silabs.com/documents/public/application-notes/AN571.pdf
            send(0x00, 0x0001, &[])?; // IFC_ENABLE must precede other requests.
            send(0x1e, 0, &baud_rate.to_le_bytes())?;
            send(0x03, 0x0800, &[])?; // 8 data bits, no parity, 1 stop bit.
            // Static DTR/RTS active, no CTS/DSR/DCD or XON/XOFF handshake,
            // no NULL stripping or inserted characters. Thresholds unused.
            let mut flow = [0u8; 16];
            flow[0..4].copy_from_slice(&1u32.to_le_bytes());
            flow[4..8].copy_from_slice(&0x40u32.to_le_bytes());
            send(0x13, 0, &flow)?;
            // Set both lines together, with both write masks. No reset pulse
            // or one-line transition to ESP download mode is requested.
            // https://docs.espressif.com/projects/esptool/en/latest/esp32s3/advanced-topics/boot-mode-selection.html
            send(0x07, 0x0303, &[])?;
        }
        UsbSerialKind::CdcAcm => {
            // SET_LINE_CODING: rate, stop-bit code, parity code, data bits.
            let mut line_coding = [0u8; 7];
            line_coding[..4].copy_from_slice(&baud_rate.to_le_bytes());
            line_coding[4] = if line.stop_bits == 2 { 2 } else { 0 };
            line_coding[5] = match line.parity {
                UsbParity::None => 0,
                UsbParity::Odd => 1,
                UsbParity::Even => 2,
            };
            line_coding[6] = line.data_bits;
            // usbserial4a `CdcAcmSerial.open`: DTR and RTS, then the coding.
            send(0x22, 3, &[])?; // SET_CONTROL_LINE_STATE
            send(0x20, 0, &line_coding)?;
        }
        UsbSerialKind::Ftdi | UsbSerialKind::Ch34x => unreachable!("handled above"),
    }
    Ok(())
}

fn control(
    transfer: &mut impl FnMut(&UsbControlRequest<'_>) -> Result<i32, String>,
    request_type: u8,
    request: u8,
    value: u16,
    index: u16,
    payload: &[u8],
) -> Result<(), String> {
    let setup = UsbControlRequest {
        request_type,
        request,
        value,
        index,
        payload,
    };
    let transferred = transfer(&setup)
        .map_err(|error| format!("USB serial setup request 0x{request:02x}: {error}"))?;
    if transferred != payload.len() as i32 {
        return Err(format!(
            "USB serial setup request 0x{request:02x} transferred {transferred} bytes; expected {}",
            payload.len()
        ));
    }
    Ok(())
}

/// usbserial4a `FtdiSerial._reconfigure_port`: SET_BAUDRATE, SET_DATA, then
/// flow control off. wIndex carries the port (`interface id + 1`).
fn configure_ftdi(
    port: &UsbSerialPort,
    line: &UsbSerialLine,
    mut transfer: impl FnMut(&UsbControlRequest<'_>) -> Result<i32, String>,
) -> Result<(), String> {
    const OUT: u8 = 0x40;
    let port_index = port.control_number + 1;
    let (value, index) = ftdi_baud_divisor(line.baud_rate, port_index)?;
    control(&mut transfer, OUT, 0x03, value, index, &[])?;
    let parity: u16 = match line.parity {
        UsbParity::None => 0,
        UsbParity::Odd => 1,
        UsbParity::Even => 2,
    };
    let stop: u16 = if line.stop_bits == 2 { 2 } else { 0 };
    let data = u16::from(line.data_bits & 0x0f) | (parity << 8) | (stop << 11);
    control(&mut transfer, OUT, 0x04, data, port_index, &[])?;
    control(&mut transfer, OUT, 0x02, 0, port_index, &[])
}

/// usbserial4a `FtdiSerial._convert_baudrate` (3 % tolerance in
/// `_set_baudrate`). usbserial4a tests `_is_legacy`, `_has_mpsse` and
/// `_is_H_series` without calling them, so all three are always true; the
/// wire values follow that.
fn ftdi_baud_divisor(baud_rate: u32, port_index: u16) -> Result<(u16, u16), String> {
    const REF_BASE: u64 = 3_000_000;
    const REF_HIGH: u64 = 12_000_000;
    let baud = u64::from(baud_rate);
    if baud < (2 * REF_BASE) / (2 * 16_384 + 1) {
        return Err(format!("Invalid FTDI baud rate {baud_rate} (too low)"));
    }
    let (refclock, hispeed) = if baud > REF_BASE {
        if baud > REF_HIGH {
            return Err(format!("Invalid FTDI baud rate {baud_rate} (too high)"));
        }
        (REF_HIGH, true)
    } else {
        (REF_BASE, false)
    };
    const AM_ADJUST_UP: [u64; 8] = [0, 0, 0, 1, 0, 3, 2, 1];
    const AM_ADJUST_DN: [u64; 8] = [0, 0, 0, 1, 0, 1, 2, 3];
    const FRAC_CODE: [u64; 8] = [0, 3, 2, 4, 1, 5, 6, 7];
    let mut divisor = (refclock * 8) / baud;
    divisor -= AM_ADJUST_DN[(divisor & 7) as usize];
    let (mut best_divisor, mut best_baud, mut best_diff) = (0, 0, 0);
    for i in 0..2 {
        let mut try_divisor = divisor + i;
        if !hispeed {
            if try_divisor <= 8 {
                try_divisor = 8;
            } else if try_divisor < 12 {
                try_divisor = 12;
            } else if divisor < 16 {
                try_divisor = 16;
            } else {
                try_divisor += AM_ADJUST_UP[(try_divisor & 7) as usize];
                try_divisor = try_divisor.min(0x1fff8);
            }
        }
        let estimate = (refclock * 8 + try_divisor / 2) / try_divisor;
        let diff = estimate.abs_diff(baud);
        if i == 0 || diff < best_diff {
            (best_divisor, best_baud, best_diff) = (try_divisor, estimate, diff);
            if diff == 0 {
                break;
            }
        }
    }
    let delta = 100.0 * best_baud.abs_diff(baud) as f64 / baud as f64;
    if delta > 3.0 {
        return Err(format!(
            "FTDI baud rate tolerance exceeded: {delta:.2}% (wanted {baud_rate}, achievable {best_baud})"
        ));
    }
    let mut encoded = (best_divisor >> 3) | (FRAC_CODE[(best_divisor & 7) as usize] << 14);
    if encoded == 1 {
        encoded = 0;
    } else if encoded == 0x4001 {
        encoded = 1;
    }
    let value = (encoded & 0xffff) as u16;
    let mut index = (((encoded >> 8) & 0xff00) as u16) | port_index;
    if hispeed {
        index |= 1 << 9;
    }
    Ok((value, index))
}

/// usbserial4a `Ch34xSerial._init_device` and `_reconfigure_port`.
fn configure_ch34x(
    line: &UsbSerialLine,
    mut transfer: impl FnMut(&UsbControlRequest<'_>) -> Result<i32, String>,
) -> Result<(), String> {
    const OUT: u8 = 0x40;
    const IN: u8 = 0xc0;
    let write = |transfer: &mut _, value, index| control(transfer, OUT, 0x9a, value, index, &[]);
    let check = |transfer: &mut _| control(transfer, IN, 0x95, 0x0706, 0, &[0, 0]);
    control(&mut transfer, OUT, 0xa1, 0xc29c, 0xb2b9, &[])?;
    control(&mut transfer, OUT, 0xa4, 0xdf, 0, &[])?;
    control(&mut transfer, OUT, 0xa4, 0x9f, 0, &[])?;
    check(&mut transfer)?;
    write(&mut transfer, 0x2727, 0)?;
    write(&mut transfer, 0x1312, 0xb282)?;
    write(&mut transfer, 0x0f2c, 0x0008)?;
    write(&mut transfer, 0x2518, 0x00c3)?;
    check(&mut transfer)?;
    write(&mut transfer, 0x2727, 0)?;

    let (index1312, index0f2c) = match line.baud_rate {
        0..=300 => (0xd980, 0xeb),
        301..=600 => (0x6481, 0x76),
        601..=1_200 => (0xb281, 0x3b),
        1_201..=2_400 => (0xd981, 0x1e),
        2_401..=4_800 => (0x6482, 0x0f),
        4_801..=9_600 => (0xb282, 0x08),
        9_601..=19_200 => (0xd982, 0x07),
        19_201..=38_400 => (0x6483, 0x07),
        38_401..=57_600 => (0x9883, 0x07),
        57_601..=115_200 => (0xcc83, 0x07),
        115_201..=230_400 => (0xe683, 0x07),
        230_401..=460_800 => (0xf383, 0x07),
        460_801..=921_600 => (0xf387, 0x07),
        _ => return Err(format!("CH34x baud rate {} out of range", line.baud_rate)),
    };
    write(&mut transfer, 0x1312, index1312)?;
    write(&mut transfer, 0x0f2c, index0f2c)?;
    check(&mut transfer)?;
    write(&mut transfer, 0x2727, 0)?;

    let mut lcr: u16 = 0x80 | 0x40;
    lcr |= match line.data_bits {
        5 => 0x00,
        6 => 0x01,
        7 => 0x02,
        8 => 0x03,
        bits => return Err(format!("CH34x cannot use {bits} data bits")),
    };
    lcr |= match line.parity {
        UsbParity::None => 0,
        UsbParity::Odd => 0x08,
        UsbParity::Even => 0x18,
    };
    if line.stop_bits == 2 {
        lcr |= 0x04;
    }
    write(&mut transfer, 0x2518, lcr)?;
    check(&mut transfer)?;
    write(&mut transfer, 0x2727, 0)?;

    check(&mut transfer)?;
    write(&mut transfer, 0x2727, 0)
}

/// usbserial4a `FtdiSerial._filterStatusBytes`: every bulk IN packet starts
/// with two modem-status bytes.
pub(crate) fn strip_ftdi_status(raw: &[u8], max_packet_size: usize) -> Vec<u8> {
    let mut payload = Vec::with_capacity(raw.len());
    for packet in raw.chunks(max_packet_size.max(3)) {
        if packet.len() > 2 {
            payload.extend_from_slice(&packet[2..]);
        }
    }
    payload
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every control request usbserial4a 0.4.0 issues when upstream's Android
    /// interfaces open an FTDI, CH34x or force-CDC CH9102 adapter.
    #[test]
    fn usb_serial_setup_matches_usbserial4a() {
        let golden: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/android_usb_serial/cases.json"
        ))
        .unwrap();
        assert_eq!(golden["usbserial4a_version"], "0.4.0");
        for case in golden["cases"].as_array().unwrap() {
            let vid = case["vid"].as_i64().unwrap() as i32;
            let pid = case["pid"].as_i64().unwrap() as i32;
            let descriptors: Vec<_> = match case["device"].as_str().unwrap() {
                "ch340" => vec![interface(0, 0xff, 0, &[(0x80, 3), (0x80, 2), (0, 2)])],
                "ch9102_forced_cdc" => vec![
                    interface(0, 2, 2, &[(0x80, 3)]),
                    interface(1, 0x0a, 0, &[(0x80, 2), (0, 2)]),
                ],
                _ => vec![interface(0, 0xff, 0, &[(0x80, 2), (0, 2)])],
            };
            let port = select_serial_port(vid, pid, &descriptors).expect("selectable");
            let line = UsbSerialLine {
                baud_rate: case["baud"].as_u64().unwrap() as u32,
                data_bits: case["databits"].as_u64().unwrap() as u8,
                parity: match case["parity"].as_str().unwrap() {
                    "E" => UsbParity::Even,
                    "O" => UsbParity::Odd,
                    _ => UsbParity::None,
                },
                stop_bits: case["stopbits"].as_u64().unwrap() as u8,
            };
            let mut requests = Vec::new();
            configure_serial_port(&port, &line, |request| {
                let input = request.request_type & 0x80 != 0;
                requests.push(serde_json::json!([
                    request.request_type,
                    request.request,
                    request.value,
                    request.index,
                    if input {
                        String::new()
                    } else {
                        hex::encode(request.payload)
                    },
                    request.payload.len(),
                ]));
                Ok(request.payload.len() as i32)
            })
            .unwrap();
            assert_eq!(&requests, case["requests"].as_array().unwrap(), "{case}");
        }
    }

    #[test]
    fn ftdi_status_bytes_are_stripped_per_packet() {
        let raw: Vec<u8> = [vec![0x01, 0x60], vec![7; 62], vec![0x01, 0x60], vec![9, 9]].concat();
        assert_eq!(
            strip_ftdi_status(&raw, 64),
            [vec![7; 62], vec![9, 9]].concat()
        );
        assert!(strip_ftdi_status(&[0x01, 0x60], 64).is_empty());
        assert_eq!(usb_read_timeout_ms(0x10c4, 0xea60), 12);
        assert_eq!(usb_read_timeout_ms(0x1a86, 0x55d4), 12);
        assert_eq!(usb_read_timeout_ms(0x0403, 0x6001), 100);
    }

    fn interface(
        number: u16,
        class: i32,
        subclass: i32,
        endpoints: &[(i32, i32)],
    ) -> UsbInterfaceDescriptor {
        UsbInterfaceDescriptor {
            number,
            alternate_setting: 0,
            class,
            subclass,
            endpoints: endpoints
                .iter()
                .map(|&(direction, transfer_type)| UsbEndpointDescriptor {
                    direction,
                    transfer_type,
                })
                .collect(),
        }
    }

    fn cp210x() -> UsbSerialPort {
        select_serial_port(
            0x10c4,
            0xea60,
            &[interface(4, 0xff, 0, &[(0x80, 2), (0, 2)])],
        )
        .unwrap()
    }

    #[test]
    fn cp210x_setup_is_scoped_and_uses_vendor_requests_without_reset() {
        let descriptors = [interface(4, 0xff, 0, &[(0x80, 2), (0, 2)])];
        for (vid, pid) in [(0x10c4, 0xea61), (0x303a, 0x1001)] {
            assert!(select_serial_port(vid, pid, &descriptors).is_err());
        }
        let mut requests = Vec::new();
        configure_serial_port(&cp210x(), &UsbSerialLine::eight_n_one(115_200), |request| {
            requests.push((
                request.request_type,
                request.request,
                request.value,
                request.index,
                request.payload.to_vec(),
            ));
            Ok(request.payload.len() as i32)
        })
        .unwrap();
        assert_eq!(
            requests,
            vec![
                (0x41, 0x00, 1, 4, vec![]),
                (0x41, 0x1e, 0, 4, vec![0x00, 0xc2, 0x01, 0x00]),
                (0x41, 0x03, 0x0800, 4, vec![]),
                (
                    0x41,
                    0x13,
                    0,
                    4,
                    vec![1, 0, 0, 0, 0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
                ),
                (0x41, 0x07, 0x0303, 4, vec![]),
            ]
        );
    }

    #[test]
    fn cdc_uses_actual_control_number_and_only_bulk_endpoints() {
        let port = select_serial_port(
            0x303a,
            0x1001,
            &[
                interface(0, 0xff, 0, &[(0x80, 2), (0, 2)]), // JTAG, not CDC.
                interface(6, 0x02, 0x02, &[(0x80, 3)]),
                interface(7, 0x0a, 0, &[(0x80, 3), (0x80, 2), (0, 2), (0, 3)]),
            ],
        )
        .unwrap();
        assert_eq!(port.data_interface, 2);
        assert_eq!(port.control_interface, 1);
        assert_eq!((port.input_endpoint, port.output_endpoint), (1, 2));
        let mut requests = Vec::new();
        configure_serial_port(&port, &UsbSerialLine::eight_n_one(9_600), |request| {
            requests.push((
                request.request_type,
                request.request,
                request.value,
                request.index,
                request.payload.to_vec(),
            ));
            Ok(request.payload.len() as i32)
        })
        .unwrap();
        assert_eq!(
            requests,
            vec![
                (0x21, 0x22, 3, 6, vec![]),
                (0x21, 0x20, 0, 6, vec![0x80, 0x25, 0, 0, 0, 0, 8]),
            ]
        );
    }

    #[test]
    fn selection_rejects_incomplete_ambiguous_and_nonbulk_interfaces() {
        let control = interface(0, 2, 2, &[(0x80, 3)]);
        let data = interface(1, 0x0a, 0, &[(0x80, 2), (0, 2)]);
        for descriptors in [
            vec![data.clone()],
            vec![control.clone(), interface(1, 0x0a, 0, &[(0x80, 3), (0, 3)])],
            vec![
                control.clone(),
                interface(1, 0x0a, 0, &[(0x80, 2)]),
                interface(2, 0x0a, 0, &[(0, 2)]),
            ],
            vec![control.clone(), data.clone(), interface(2, 2, 2, &[])],
            vec![
                control.clone(),
                data.clone(),
                interface(2, 0x0a, 0, &[(0x80, 2), (0, 2)]),
            ],
            vec![
                control.clone(),
                interface(1, 0x0a, 0, &[(0x80, 2), (0, 2), (0, 2)]),
            ],
        ] {
            assert!(select_serial_port(0x303a, 0x1001, &descriptors).is_err());
        }
        let mut alternate = data.clone();
        alternate.alternate_setting = 1;
        assert!(select_serial_port(0x303a, 0x1001, &[control, alternate]).is_err());
    }

    #[test]
    fn setup_stops_on_every_failed_short_or_impossible_control_completion() {
        let cdc = select_serial_port(
            0x303a,
            0x1001,
            &[
                interface(0, 2, 2, &[]),
                interface(1, 0x0a, 0, &[(0x80, 2), (0, 2)]),
            ],
        )
        .unwrap();
        for (port, count) in [(cp210x(), 5), (cdc, 2)] {
            for fail_at in 0..count {
                for failure in 0..4 {
                    let mut called = 0;
                    let result = configure_serial_port(
                        &port,
                        &UsbSerialLine::eight_n_one(115_200),
                        |request| {
                            let index = called;
                            called += 1;
                            let length = request.payload.len() as i32;
                            if index != fail_at {
                                return Ok(length);
                            }
                            match failure {
                                0 => Err("JNI exception".into()),
                                1 => Ok(-1),
                                2 => Ok(length - 1),
                                _ => Ok(length + 1),
                            }
                        },
                    );
                    assert!(result.is_err());
                    assert_eq!(called, fail_at + 1);
                }
            }
        }
        assert!(
            configure_serial_port(&cp210x(), &UsbSerialLine::eight_n_one(0), |_| panic!(
                "invalid baud must not touch USB"
            ))
            .is_err()
        );
    }
}
