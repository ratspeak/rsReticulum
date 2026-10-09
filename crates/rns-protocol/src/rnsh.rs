//! rnsh channel message codecs.
//!
//! Python reference: `RNS/Utilities/rnsh/protocol.py`.

use std::io::Cursor;

use rmpv::Value;

use crate::channel_message::{ChannelMessageError, MessageBase};
use crate::compression;

pub const MSG_MAGIC: u8 = 0xAC;
pub const PROTOCOL_VERSION: u64 = 1;

pub const MSG_TYPE_NOOP: u16 = make_msg_type(0);
pub const MSG_TYPE_WINDOW_SIZE: u16 = make_msg_type(2);
pub const MSG_TYPE_EXECUTE_COMMAND: u16 = make_msg_type(3);
pub const MSG_TYPE_STREAM_DATA: u16 = make_msg_type(4);
pub const MSG_TYPE_VERSION_INFO: u16 = make_msg_type(5);
pub const MSG_TYPE_ERROR: u16 = make_msg_type(6);
pub const MSG_TYPE_COMMAND_EXITED: u16 = make_msg_type(7);

pub const MESSAGE_TYPES: [u16; 7] = [
    MSG_TYPE_NOOP,
    MSG_TYPE_VERSION_INFO,
    MSG_TYPE_WINDOW_SIZE,
    MSG_TYPE_EXECUTE_COMMAND,
    MSG_TYPE_STREAM_DATA,
    MSG_TYPE_COMMAND_EXITED,
    MSG_TYPE_ERROR,
];

pub const STREAM_ID_STDIN: u16 = 0;
pub const STREAM_ID_STDOUT: u16 = 1;
pub const STREAM_ID_STDERR: u16 = 2;

pub const STREAM_ID_MAX: u16 = 0x3FFF;
pub const STREAM_DATA_OVERHEAD: usize = 8;

pub const fn make_msg_type(val: u8) -> u16 {
    ((MSG_MAGIC as u16) << 8) | (val as u16)
}

#[derive(Debug, thiserror::Error)]
pub enum RnshCodecError {
    #[error("msgpack decode failed: {0}")]
    Decode(String),
    #[error("msgpack encode failed: {0}")]
    Encode(String),
    #[error("unexpected msgpack shape for {0}")]
    InvalidShape(&'static str),
    #[error("invalid utf-8 string")]
    InvalidUtf8,
    #[error("unknown rnsh message type: 0x{0:04X}")]
    UnknownMessageType(u16),
    #[error("stream data unpack failed")]
    StreamData,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NoopMessage;

impl MessageBase for NoopMessage {
    fn msg_type(&self) -> u16 {
        MSG_TYPE_NOOP
    }

    fn pack(&self) -> Vec<u8> {
        Vec::new()
    }

    fn unpack(&mut self, _raw: &[u8]) -> Result<(), ChannelMessageError> {
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WindowSizeMessage {
    pub rows: Option<u32>,
    pub cols: Option<u32>,
    pub hpix: Option<u32>,
    pub vpix: Option<u32>,
}

impl WindowSizeMessage {
    pub fn new(rows: Option<u32>, cols: Option<u32>, hpix: Option<u32>, vpix: Option<u32>) -> Self {
        Self {
            rows,
            cols,
            hpix,
            vpix,
        }
    }

    pub fn unpack_payload(raw: &[u8]) -> Result<Self, RnshCodecError> {
        let values = decode_array(raw, 4, "WindowSizeMessage")?;
        Ok(Self {
            rows: value_to_u32_opt(&values[0], "rows")?,
            cols: value_to_u32_opt(&values[1], "cols")?,
            hpix: value_to_u32_opt(&values[2], "hpix")?,
            vpix: value_to_u32_opt(&values[3], "vpix")?,
        })
    }
}

impl MessageBase for WindowSizeMessage {
    fn msg_type(&self) -> u16 {
        MSG_TYPE_WINDOW_SIZE
    }

    fn pack(&self) -> Vec<u8> {
        encode_value(&Value::Array(vec![
            u32_opt_to_value(self.rows),
            u32_opt_to_value(self.cols),
            u32_opt_to_value(self.hpix),
            u32_opt_to_value(self.vpix),
        ]))
        .expect("rnsh window size msgpack encode")
    }

    fn unpack(&mut self, raw: &[u8]) -> Result<(), ChannelMessageError> {
        *self = Self::unpack_payload(raw).map_err(|_| ChannelMessageError::UnpackFailed)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct ExecuteCommandMessage {
    pub cmdline: Option<Vec<String>>,
    pub pipe_stdin: bool,
    pub pipe_stdout: bool,
    pub pipe_stderr: bool,
    pub tcflags: Option<Value>,
    pub term: Option<String>,
    pub rows: Option<u32>,
    pub cols: Option<u32>,
    pub hpix: Option<u32>,
    pub vpix: Option<u32>,
}

impl ExecuteCommandMessage {
    // Mirrors the rnsh ExecuteCommand channel payload; each parameter maps to
    // a serialized field in the message.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cmdline: Option<Vec<String>>,
        pipe_stdin: bool,
        pipe_stdout: bool,
        pipe_stderr: bool,
        tcflags: Option<Value>,
        term: Option<String>,
        rows: Option<u32>,
        cols: Option<u32>,
        hpix: Option<u32>,
        vpix: Option<u32>,
    ) -> Self {
        Self {
            cmdline,
            pipe_stdin,
            pipe_stdout,
            pipe_stderr,
            tcflags,
            term,
            rows,
            cols,
            hpix,
            vpix,
        }
    }

    pub fn unpack_payload(raw: &[u8]) -> Result<Self, RnshCodecError> {
        let values = decode_array(raw, 10, "ExecuteCommandMessage")?;
        Ok(Self {
            cmdline: value_to_string_vec_opt(&values[0], "cmdline")?,
            pipe_stdin: value_to_bool(&values[1], "pipe_stdin")?,
            pipe_stdout: value_to_bool(&values[2], "pipe_stdout")?,
            pipe_stderr: value_to_bool(&values[3], "pipe_stderr")?,
            tcflags: none_if_nil(values[4].clone()),
            term: value_to_string_opt(&values[5], "term")?,
            rows: value_to_u32_opt(&values[6], "rows")?,
            cols: value_to_u32_opt(&values[7], "cols")?,
            hpix: value_to_u32_opt(&values[8], "hpix")?,
            vpix: value_to_u32_opt(&values[9], "vpix")?,
        })
    }
}

impl MessageBase for ExecuteCommandMessage {
    fn msg_type(&self) -> u16 {
        MSG_TYPE_EXECUTE_COMMAND
    }

    fn pack(&self) -> Vec<u8> {
        encode_value(&Value::Array(vec![
            string_vec_opt_to_value(self.cmdline.as_ref()),
            Value::Boolean(self.pipe_stdin),
            Value::Boolean(self.pipe_stdout),
            Value::Boolean(self.pipe_stderr),
            self.tcflags.clone().unwrap_or(Value::Nil),
            string_opt_to_value(self.term.as_deref()),
            u32_opt_to_value(self.rows),
            u32_opt_to_value(self.cols),
            u32_opt_to_value(self.hpix),
            u32_opt_to_value(self.vpix),
        ]))
        .expect("rnsh execute command msgpack encode")
    }

    fn unpack(&mut self, raw: &[u8]) -> Result<(), ChannelMessageError> {
        *self = Self::unpack_payload(raw).map_err(|_| ChannelMessageError::UnpackFailed)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RnshStreamDataMessage {
    pub stream_id: u16,
    pub eof: bool,
    pub compressed: bool,
    pub data: Vec<u8>,
}

impl RnshStreamDataMessage {
    pub fn new(stream_id: u16, data: Vec<u8>, eof: bool) -> Self {
        Self {
            stream_id: stream_id & STREAM_ID_MAX,
            eof,
            compressed: false,
            data,
        }
    }

    fn header_value(&self) -> u16 {
        let mut val = self.stream_id & STREAM_ID_MAX;
        if self.eof {
            val |= 0x8000;
        }
        if self.compressed {
            val |= 0x4000;
        }
        val
    }

    fn parse_header(val: u16) -> (u16, bool, bool) {
        let eof = (val & 0x8000) != 0;
        let compressed = (val & 0x4000) != 0;
        let stream_id = val & STREAM_ID_MAX;
        (stream_id, eof, compressed)
    }

    pub fn unpack_payload(raw: &[u8]) -> Result<Self, RnshCodecError> {
        if raw.len() < 2 {
            return Err(RnshCodecError::StreamData);
        }

        let header_val = u16::from_be_bytes([raw[0], raw[1]]);
        let (stream_id, eof, compressed) = Self::parse_header(header_val);
        let payload = &raw[2..];
        let data = if compressed && !payload.is_empty() {
            compression::bz2_decompress(payload, crate::buffer::MAX_CHUNK_LEN)
                .map_err(|_| RnshCodecError::StreamData)?
        } else {
            payload.to_vec()
        };

        Ok(Self {
            stream_id,
            eof,
            compressed,
            data,
        })
    }
}

impl Default for RnshStreamDataMessage {
    fn default() -> Self {
        Self::new(0, Vec::new(), false)
    }
}

impl MessageBase for RnshStreamDataMessage {
    fn msg_type(&self) -> u16 {
        MSG_TYPE_STREAM_DATA
    }

    fn pack(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(2 + self.data.len());
        result.extend_from_slice(&self.header_value().to_be_bytes());
        result.extend_from_slice(&self.data);
        result
    }

    fn unpack(&mut self, raw: &[u8]) -> Result<(), ChannelMessageError> {
        *self = Self::unpack_payload(raw).map_err(|_| ChannelMessageError::UnpackFailed)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionInfoMessage {
    pub sw_version: String,
    pub protocol_version: u64,
}

impl VersionInfoMessage {
    pub fn new(sw_version: impl Into<String>) -> Self {
        Self {
            sw_version: sw_version.into(),
            protocol_version: PROTOCOL_VERSION,
        }
    }

    pub fn unpack_payload(raw: &[u8]) -> Result<Self, RnshCodecError> {
        let values = decode_array(raw, 2, "VersionInfoMessage")?;
        Ok(Self {
            sw_version: value_to_string(&values[0], "sw_version")?,
            protocol_version: value_to_u64(&values[1], "protocol_version")?,
        })
    }
}

impl Default for VersionInfoMessage {
    fn default() -> Self {
        Self::new(env!("CARGO_PKG_VERSION"))
    }
}

impl MessageBase for VersionInfoMessage {
    fn msg_type(&self) -> u16 {
        MSG_TYPE_VERSION_INFO
    }

    fn pack(&self) -> Vec<u8> {
        encode_value(&Value::Array(vec![
            string_to_value(&self.sw_version),
            Value::from(self.protocol_version),
        ]))
        .expect("rnsh version info msgpack encode")
    }

    fn unpack(&mut self, raw: &[u8]) -> Result<(), ChannelMessageError> {
        *self = Self::unpack_payload(raw).map_err(|_| ChannelMessageError::UnpackFailed)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct ErrorMessage {
    pub msg: Option<String>,
    pub fatal: bool,
    pub data: Option<Value>,
}

impl ErrorMessage {
    pub fn new(msg: Option<String>, fatal: bool, data: Option<Value>) -> Self {
        Self { msg, fatal, data }
    }

    pub fn unpack_payload(raw: &[u8]) -> Result<Self, RnshCodecError> {
        let values = decode_array(raw, 3, "ErrorMessage")?;
        Ok(Self {
            msg: value_to_string_opt(&values[0], "msg")?,
            fatal: value_to_bool(&values[1], "fatal")?,
            data: none_if_nil(values[2].clone()),
        })
    }
}

impl MessageBase for ErrorMessage {
    fn msg_type(&self) -> u16 {
        MSG_TYPE_ERROR
    }

    fn pack(&self) -> Vec<u8> {
        encode_value(&Value::Array(vec![
            string_opt_to_value(self.msg.as_deref()),
            Value::Boolean(self.fatal),
            self.data.clone().unwrap_or(Value::Nil),
        ]))
        .expect("rnsh error msgpack encode")
    }

    fn unpack(&mut self, raw: &[u8]) -> Result<(), ChannelMessageError> {
        *self = Self::unpack_payload(raw).map_err(|_| ChannelMessageError::UnpackFailed)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CommandExitedMessage {
    pub return_code: i64,
}

impl CommandExitedMessage {
    pub fn new(return_code: i64) -> Self {
        Self { return_code }
    }

    pub fn unpack_payload(raw: &[u8]) -> Result<Self, RnshCodecError> {
        let value = decode_value(raw)?;
        let return_code = value_to_i64(&value, "return_code")?;
        Ok(Self { return_code })
    }
}

impl MessageBase for CommandExitedMessage {
    fn msg_type(&self) -> u16 {
        MSG_TYPE_COMMAND_EXITED
    }

    fn pack(&self) -> Vec<u8> {
        encode_value(&Value::from(self.return_code)).expect("rnsh command exited msgpack encode")
    }

    fn unpack(&mut self, raw: &[u8]) -> Result<(), ChannelMessageError> {
        *self = Self::unpack_payload(raw).map_err(|_| ChannelMessageError::UnpackFailed)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum RnshMessage {
    Noop(NoopMessage),
    WindowSize(WindowSizeMessage),
    ExecuteCommand(ExecuteCommandMessage),
    StreamData(RnshStreamDataMessage),
    VersionInfo(VersionInfoMessage),
    Error(ErrorMessage),
    CommandExited(CommandExitedMessage),
}

impl RnshMessage {
    pub fn decode(msg_type: u16, payload: &[u8]) -> Result<Self, RnshCodecError> {
        match msg_type {
            MSG_TYPE_NOOP => Ok(Self::Noop(NoopMessage)),
            MSG_TYPE_WINDOW_SIZE => Ok(Self::WindowSize(WindowSizeMessage::unpack_payload(
                payload,
            )?)),
            MSG_TYPE_EXECUTE_COMMAND => Ok(Self::ExecuteCommand(
                ExecuteCommandMessage::unpack_payload(payload)?,
            )),
            MSG_TYPE_STREAM_DATA => Ok(Self::StreamData(RnshStreamDataMessage::unpack_payload(
                payload,
            )?)),
            MSG_TYPE_VERSION_INFO => Ok(Self::VersionInfo(VersionInfoMessage::unpack_payload(
                payload,
            )?)),
            MSG_TYPE_ERROR => Ok(Self::Error(ErrorMessage::unpack_payload(payload)?)),
            MSG_TYPE_COMMAND_EXITED => Ok(Self::CommandExited(
                CommandExitedMessage::unpack_payload(payload)?,
            )),
            other => Err(RnshCodecError::UnknownMessageType(other)),
        }
    }

    pub fn msg_type(&self) -> u16 {
        match self {
            Self::Noop(msg) => msg.msg_type(),
            Self::WindowSize(msg) => msg.msg_type(),
            Self::ExecuteCommand(msg) => msg.msg_type(),
            Self::StreamData(msg) => msg.msg_type(),
            Self::VersionInfo(msg) => msg.msg_type(),
            Self::Error(msg) => msg.msg_type(),
            Self::CommandExited(msg) => msg.msg_type(),
        }
    }

    pub fn pack(&self) -> Vec<u8> {
        match self {
            Self::Noop(msg) => msg.pack(),
            Self::WindowSize(msg) => msg.pack(),
            Self::ExecuteCommand(msg) => msg.pack(),
            Self::StreamData(msg) => msg.pack(),
            Self::VersionInfo(msg) => msg.pack(),
            Self::Error(msg) => msg.pack(),
            Self::CommandExited(msg) => msg.pack(),
        }
    }
}

fn encode_value(value: &Value) -> Result<Vec<u8>, RnshCodecError> {
    let mut buf = Vec::new();
    rmpv::encode::write_value(&mut buf, value)
        .map_err(|e| RnshCodecError::Encode(e.to_string()))?;
    Ok(buf)
}

fn decode_value(raw: &[u8]) -> Result<Value, RnshCodecError> {
    let mut cursor = Cursor::new(raw);
    let value =
        rmpv::decode::read_value(&mut cursor).map_err(|e| RnshCodecError::Decode(e.to_string()))?;
    if cursor.position() as usize != raw.len() {
        return Err(RnshCodecError::InvalidShape("trailing msgpack bytes"));
    }
    Ok(value)
}

fn decode_array(
    raw: &[u8],
    expected_len: usize,
    name: &'static str,
) -> Result<Vec<Value>, RnshCodecError> {
    let value = decode_value(raw)?;
    match value {
        Value::Array(items) if items.len() == expected_len => Ok(items),
        _ => Err(RnshCodecError::InvalidShape(name)),
    }
}

fn none_if_nil(value: Value) -> Option<Value> {
    if matches!(value, Value::Nil) {
        None
    } else {
        Some(value)
    }
}

fn u32_opt_to_value(value: Option<u32>) -> Value {
    value.map(Value::from).unwrap_or(Value::Nil)
}

fn string_to_value(value: &str) -> Value {
    Value::String(rmpv::Utf8String::from(value))
}

fn string_opt_to_value(value: Option<&str>) -> Value {
    value.map(string_to_value).unwrap_or(Value::Nil)
}

fn string_vec_opt_to_value(value: Option<&Vec<String>>) -> Value {
    value
        .map(|items| Value::Array(items.iter().map(|s| string_to_value(s)).collect()))
        .unwrap_or(Value::Nil)
}

fn value_to_bool(value: &Value, field: &'static str) -> Result<bool, RnshCodecError> {
    value.as_bool().ok_or(RnshCodecError::InvalidShape(field))
}

fn value_to_u32_opt(value: &Value, field: &'static str) -> Result<Option<u32>, RnshCodecError> {
    if matches!(value, Value::Nil) {
        return Ok(None);
    }
    let number = value_to_u64(value, field)?;
    if number > u32::MAX as u64 {
        return Err(RnshCodecError::InvalidShape(field));
    }
    Ok(Some(number as u32))
}

fn value_to_u64(value: &Value, field: &'static str) -> Result<u64, RnshCodecError> {
    if let Some(number) = value.as_u64() {
        return Ok(number);
    }
    if let Some(number) = value.as_i64()
        && number >= 0
    {
        return Ok(number as u64);
    }
    Err(RnshCodecError::InvalidShape(field))
}

fn value_to_i64(value: &Value, field: &'static str) -> Result<i64, RnshCodecError> {
    if let Some(number) = value.as_i64() {
        return Ok(number);
    }
    if let Some(number) = value.as_u64()
        && number <= i64::MAX as u64
    {
        return Ok(number as i64);
    }
    Err(RnshCodecError::InvalidShape(field))
}

fn value_to_string(value: &Value, field: &'static str) -> Result<String, RnshCodecError> {
    value_to_string_opt(value, field)?.ok_or(RnshCodecError::InvalidShape(field))
}

fn value_to_string_opt(
    value: &Value,
    field: &'static str,
) -> Result<Option<String>, RnshCodecError> {
    match value {
        Value::Nil => Ok(None),
        Value::String(s) => Ok(Some(
            s.as_str().ok_or(RnshCodecError::InvalidUtf8)?.to_string(),
        )),
        Value::Binary(b) => String::from_utf8(b.clone())
            .map(Some)
            .map_err(|_| RnshCodecError::InvalidUtf8),
        _ => Err(RnshCodecError::InvalidShape(field)),
    }
}

fn value_to_string_vec_opt(
    value: &Value,
    field: &'static str,
) -> Result<Option<Vec<String>>, RnshCodecError> {
    match value {
        Value::Nil => Ok(None),
        Value::Array(items) => items
            .iter()
            .map(|item| value_to_string(item, field))
            .collect::<Result<Vec<_>, _>>()
            .map(Some),
        _ => Err(RnshCodecError::InvalidShape(field)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::Envelope;

    #[test]
    fn msg_type_constants_match_python_magic() {
        assert_eq!(MSG_TYPE_NOOP, 0xAC00);
        assert_eq!(MSG_TYPE_WINDOW_SIZE, 0xAC02);
        assert_eq!(MSG_TYPE_EXECUTE_COMMAND, 0xAC03);
        assert_eq!(MSG_TYPE_STREAM_DATA, 0xAC04);
        assert_eq!(MSG_TYPE_VERSION_INFO, 0xAC05);
        assert_eq!(MSG_TYPE_ERROR, 0xAC06);
        assert_eq!(MSG_TYPE_COMMAND_EXITED, 0xAC07);
        assert_eq!(PROTOCOL_VERSION, 1);
    }

    #[test]
    fn noop_envelope_vector_is_python_compatible() {
        let msg = NoopMessage;
        let env = Envelope::pack(&msg, 0x1234);
        assert_eq!(env.raw, [0xAC, 0x00, 0x12, 0x34, 0x00, 0x00]);
    }

    #[test]
    fn window_size_msgpack_vector_roundtrips() {
        let msg = WindowSizeMessage::new(Some(24), Some(80), None, None);
        let expected = [0x94, 0x18, 0x50, 0xC0, 0xC0];
        assert_eq!(msg.pack(), expected);
        assert_eq!(WindowSizeMessage::unpack_payload(&expected).unwrap(), msg);
    }

    #[test]
    fn window_size_all_fields_vector_roundtrips() {
        let msg = WindowSizeMessage::new(Some(40), Some(120), Some(1920), Some(1080));
        let expected = [0x94, 0x28, 0x78, 0xCD, 0x07, 0x80, 0xCD, 0x04, 0x38];
        assert_eq!(msg.pack(), expected);
        assert_eq!(WindowSizeMessage::unpack_payload(&expected).unwrap(), msg);
    }

    #[test]
    fn execute_command_msgpack_vector_roundtrips() {
        let msg = ExecuteCommandMessage::new(
            Some(vec!["sh".into(), "-lc".into(), "echo hi".into()]),
            true,
            true,
            true,
            None,
            Some("xterm".into()),
            Some(24),
            Some(80),
            None,
            None,
        );
        let expected = [
            0x9A, 0x93, 0xA2, b's', b'h', 0xA3, b'-', b'l', b'c', 0xA7, b'e', b'c', b'h', b'o',
            b' ', b'h', b'i', 0xC3, 0xC3, 0xC3, 0xC0, 0xA5, b'x', b't', b'e', b'r', b'm', 0x18,
            0x50, 0xC0, 0xC0,
        ];
        assert_eq!(msg.pack(), expected);
        assert_eq!(
            ExecuteCommandMessage::unpack_payload(&expected).unwrap(),
            msg
        );
    }

    #[test]
    fn stream_data_vector_roundtrips() {
        let msg = RnshStreamDataMessage::new(STREAM_ID_STDOUT, b"hi".to_vec(), false);
        let expected = [0x00, 0x01, b'h', b'i'];
        assert_eq!(msg.pack(), expected);
        assert_eq!(
            RnshStreamDataMessage::unpack_payload(&expected).unwrap(),
            msg
        );

        let eof = RnshStreamDataMessage::new(STREAM_ID_STDIN, Vec::new(), true);
        assert_eq!(eof.pack(), [0x80, 0x00]);
    }

    #[test]
    fn compressed_stream_data_payload_is_decompressed_on_unpack() {
        let data = b"rnsh stream compression".repeat(200);
        let compressed = compression::bz2_compress(&data).unwrap();
        let mut raw = vec![0xC0, 0x01];
        raw.extend_from_slice(&compressed);

        let unpacked = RnshStreamDataMessage::unpack_payload(&raw).unwrap();
        assert_eq!(unpacked.stream_id, STREAM_ID_STDOUT);
        assert!(unpacked.eof);
        assert!(unpacked.compressed);
        assert_eq!(unpacked.data, data);
    }

    #[test]
    fn version_info_msgpack_and_envelope_vectors_roundtrip() {
        let msg = VersionInfoMessage::new("0.9.0");
        let payload = [0x92, 0xA5, b'0', b'.', b'9', b'.', b'0', 0x01];
        assert_eq!(msg.pack(), payload);
        assert_eq!(VersionInfoMessage::unpack_payload(&payload).unwrap(), msg);

        let env = Envelope::pack(&msg, 7);
        let expected = [
            0xAC, 0x05, 0x00, 0x07, 0x00, 0x08, 0x92, 0xA5, b'0', b'.', b'9', b'.', b'0', 0x01,
        ];
        assert_eq!(env.raw, expected);
    }

    #[test]
    fn error_and_exit_vectors_roundtrip() {
        let error = ErrorMessage::new(Some("boom".into()), true, None);
        let error_payload = [0x93, 0xA4, b'b', b'o', b'o', b'm', 0xC3, 0xC0];
        assert_eq!(error.pack(), error_payload);
        assert_eq!(ErrorMessage::unpack_payload(&error_payload).unwrap(), error);

        let exited = CommandExitedMessage::new(0);
        assert_eq!(exited.pack(), [0x00]);
        assert_eq!(
            CommandExitedMessage::unpack_payload(&[0x00]).unwrap(),
            exited
        );
    }

    #[test]
    fn decode_dispatches_by_msg_type() {
        let payload = VersionInfoMessage::new("0.9.0").pack();
        let decoded = RnshMessage::decode(MSG_TYPE_VERSION_INFO, &payload).unwrap();
        assert!(matches!(decoded, RnshMessage::VersionInfo(_)));
        assert!(RnshMessage::decode(0xAC08, &[]).is_err());
    }
}
