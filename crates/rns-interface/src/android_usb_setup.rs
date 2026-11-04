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

pub(crate) fn configure_serial_port(
    port: &UsbSerialPort,
    baud_rate: u32,
    mut transfer: impl FnMut(&UsbControlRequest<'_>) -> Result<i32, String>,
) -> Result<(), String> {
    if baud_rate == 0 {
        return Err("USB serial baud rate must be nonzero".into());
    }
    let request_type = match port.kind {
        UsbSerialKind::Cp210x => 0x41,
        UsbSerialKind::CdcAcm => 0x21,
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
            let mut line_coding = [0u8; 7];
            line_coding[..4].copy_from_slice(&baud_rate.to_le_bytes());
            line_coding[6] = 8;
            send(0x20, 0, &line_coding)?; // SET_LINE_CODING, 8N1.
            send(0x22, 3, &[])?; // SET_CONTROL_LINE_STATE, DTR and RTS.
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        for (vid, pid) in [
            (0x10c4, 0xea61),
            (0x0403, 0x6001),
            (0x1a86, 0x7523),
            (0x303a, 0x1001),
        ] {
            assert!(select_serial_port(vid, pid, &descriptors).is_err());
        }
        let mut requests = Vec::new();
        configure_serial_port(&cp210x(), 115_200, |request| {
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
        configure_serial_port(&port, 9_600, |request| {
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
                (0x21, 0x20, 0, 6, vec![0x80, 0x25, 0, 0, 0, 0, 8]),
                (0x21, 0x22, 3, 6, vec![]),
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
                    let result = configure_serial_port(&port, 115_200, |request| {
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
                    });
                    assert!(result.is_err());
                    assert_eq!(called, fail_at + 1);
                }
            }
        }
        assert!(
            configure_serial_port(&cp210x(), 0, |_| panic!("invalid baud must not touch USB"))
                .is_err()
        );
    }
}
