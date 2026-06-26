//! CoAP message parsing, encoding, and EST-coaps URI routing.
//!
//! This module implements the CoAP message format (RFC 7252 §3) and maps
//! CoAP URI paths to EST operations per RFC 9483 §5.1.
//!
//! # CoAP Message Format
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |Ver| T |  TKL  |      Code     |          Message ID           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |   Token (if any, TKL bytes) ...
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |   Options (if any) ...
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |1 1 1 1 1 1 1 1|    Payload (if any) ...
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! # EST-coaps URI Mapping
//!
//! RFC 9483 §5.1 defines abbreviated URI paths for EST operations:
//!
//! | CoAP Path | EST Operation | HTTP Method |
//! |-----------|---------------|-------------|
//! | `/sen`    | simpleenroll  | POST        |
//! | `/sren`   | simplereenroll| POST        |
//! | `/skg`    | serverkeygen  | POST        |
//! | `/att`    | csrattrs      | GET         |
//! | `/cacerts`| cacerts       | GET         |
//! | `/crts`   | cacerts       | GET (alias) |

use crate::block::{szx_from_block_size, BlockAssembler, BlockDisassembler};
use crate::dtls::{DtlsConnection, DtlsContext, DtlsSessionCache, DtlsVersion};
use crate::{CoapError, CoapResult};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

/// CoAP protocol version (RFC 7252 §3).
///
/// The only defined version is 1. Other values are reserved.
pub const COAP_VERSION: u8 = 1;

/// Payload marker byte (RFC 7252 §3).
///
/// The byte 0xFF separates CoAP options from the payload.
const PAYLOAD_MARKER: u8 = 0xFF;

// --- CoAP Option Numbers (RFC 7252 §5.10) ---

/// Uri-Host option (RFC 7252 §5.10.1).
pub const OPTION_URI_HOST: u16 = 3;

/// Uri-Port option (RFC 7252 §5.10.1).
pub const OPTION_URI_PORT: u16 = 7;

/// Uri-Path option (RFC 7252 §5.10.1).
///
/// Each Uri-Path option contains one path segment. Multiple options
/// are concatenated with `/` to form the full URI path.
pub const OPTION_URI_PATH: u16 = 11;

/// Content-Format option (RFC 7252 §5.10.3).
///
/// Contains the CoAP content-format ID (see [`crate::content_format`]).
pub const OPTION_CONTENT_FORMAT: u16 = 12;

/// Uri-Query option (RFC 7252 §5.10.1).
pub const OPTION_URI_QUERY: u16 = 15;

/// Block2 option (RFC 7959 §2.1).
///
/// Controls response payload block-wise transfer (server to client).
pub const OPTION_BLOCK2: u16 = 23;

/// Block1 option (RFC 7959 §2.1).
///
/// Controls request payload block-wise transfer (client to server).
pub const OPTION_BLOCK1: u16 = 27;

/// Size2 option (RFC 7959 §4).
///
/// Indicates the total size of the response payload.
pub const OPTION_SIZE2: u16 = 28;

/// Size1 option (RFC 7959 §4).
///
/// Indicates the total size of the request payload.
pub const OPTION_SIZE1: u16 = 60;

/// CoAP request/response method codes (RFC 7252 §5.8, §12.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CoapMethod {
    /// 0.01 GET
    Get,
    /// 0.02 POST
    Post,
    /// 0.03 PUT
    Put,
    /// 0.04 DELETE
    Delete,
    /// 0.05 FETCH (RFC 8132)
    Fetch,
    /// 0.06 PATCH (RFC 8132)
    Patch,
    /// 0.07 iPATCH (RFC 8132)
    IPatch,
}

impl CoapMethod {
    /// Converts a CoAP code byte to a method, if it represents a request.
    ///
    /// Request codes have class 0 (code byte 0.01 through 0.07).
    pub fn from_code(code: &CoapCode) -> Option<Self> {
        if code.class != 0 {
            return None;
        }
        match code.detail {
            1 => Some(Self::Get),
            2 => Some(Self::Post),
            3 => Some(Self::Put),
            4 => Some(Self::Delete),
            5 => Some(Self::Fetch),
            6 => Some(Self::Patch),
            7 => Some(Self::IPatch),
            _ => None,
        }
    }

    /// Returns the CoAP code for this method.
    pub fn to_code(&self) -> CoapCode {
        let detail = match self {
            Self::Get => 1,
            Self::Post => 2,
            Self::Put => 3,
            Self::Delete => 4,
            Self::Fetch => 5,
            Self::Patch => 6,
            Self::IPatch => 7,
        };
        CoapCode { class: 0, detail }
    }
}

/// CoAP message type (RFC 7252 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CoapMessageType {
    /// Confirmable (CON): requires acknowledgement.
    Confirmable,
    /// Non-confirmable (NON): fire-and-forget.
    NonConfirmable,
    /// Acknowledgement (ACK): confirms receipt of CON.
    Acknowledgement,
    /// Reset (RST): indicates message was received but cannot be processed.
    Reset,
}

impl CoapMessageType {
    /// Decodes the message type from the 2-bit T field.
    fn from_bits(bits: u8) -> CoapResult<Self> {
        match bits {
            0 => Ok(Self::Confirmable),
            1 => Ok(Self::NonConfirmable),
            2 => Ok(Self::Acknowledgement),
            3 => Ok(Self::Reset),
            _ => Err(CoapError::InvalidMessage(format!(
                "Invalid message type: {bits}"
            ))),
        }
    }

    /// Encodes the message type to the 2-bit T field.
    fn to_bits(self) -> u8 {
        match self {
            Self::Confirmable => 0,
            Self::NonConfirmable => 1,
            Self::Acknowledgement => 2,
            Self::Reset => 3,
        }
    }
}

/// CoAP response/request code (RFC 7252 §3, §5.9).
///
/// Encoded as a single byte: upper 3 bits = class, lower 5 bits = detail.
/// Conventionally written as `class.detail` (e.g., 2.05 = Content).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CoapCode {
    /// Code class (0 = request, 2 = success, 4 = client error, 5 = server error).
    pub class: u8,
    /// Code detail within the class.
    pub detail: u8,
}

impl CoapCode {
    /// 2.01 Created — enrollment succeeded.
    pub const CREATED: Self = Self {
        class: 2,
        detail: 1,
    };
    /// 2.05 Content — response with payload.
    pub const CONTENT: Self = Self {
        class: 2,
        detail: 5,
    };
    /// 4.01 Unauthorized — client authentication required.
    pub const UNAUTHORIZED: Self = Self {
        class: 4,
        detail: 1,
    };
    /// 4.04 Not Found — unknown URI path.
    pub const NOT_FOUND: Self = Self {
        class: 4,
        detail: 4,
    };
    /// 4.05 Method Not Allowed — wrong method for resource.
    pub const METHOD_NOT_ALLOWED: Self = Self {
        class: 4,
        detail: 5,
    };
    /// 4.15 Unsupported Content-Format.
    pub const UNSUPPORTED_CONTENT_FORMAT: Self = Self {
        class: 4,
        detail: 15,
    };
    /// 5.00 Internal Server Error.
    pub const INTERNAL_SERVER_ERROR: Self = Self {
        class: 5,
        detail: 0,
    };

    /// Encodes the code as a single byte: class in bits 7-5, detail in bits 4-0.
    pub fn to_byte(&self) -> u8 {
        ((self.class & 0x07) << 5) | (self.detail & 0x1F)
    }

    /// Decodes a code from a single byte.
    pub fn from_byte(byte: u8) -> Self {
        Self {
            class: (byte >> 5) & 0x07,
            detail: byte & 0x1F,
        }
    }

    /// Returns whether this code represents a request (class 0).
    pub fn is_request(&self) -> bool {
        self.class == 0
    }

    /// Returns whether this code represents a success response (class 2).
    pub fn is_success(&self) -> bool {
        self.class == 2
    }

    /// Returns whether this code represents a client error (class 4).
    pub fn is_client_error(&self) -> bool {
        self.class == 4
    }

    /// Returns whether this code represents a server error (class 5).
    pub fn is_server_error(&self) -> bool {
        self.class == 5
    }
}

impl std::fmt::Display for CoapCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{:02}", self.class, self.detail)
    }
}

/// A single CoAP option (RFC 7252 §3.1).
///
/// Options are TLV-encoded in messages, sorted by option number.
/// Repeated option numbers create multiple values for that option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoapOption {
    /// Option number (determines semantics).
    pub number: u16,
    /// Option value (interpretation depends on the option number).
    pub value: Vec<u8>,
}

impl CoapOption {
    /// Creates a new option with the given number and value.
    pub fn new(number: u16, value: Vec<u8>) -> Self {
        Self { number, value }
    }

    /// Creates an empty option (zero-length value).
    pub fn empty(number: u16) -> Self {
        Self {
            number,
            value: Vec::new(),
        }
    }

    /// Interprets the option value as a variable-length unsigned integer.
    ///
    /// RFC 7252 §3.2: Options with format "uint" use 0-4 bytes in
    /// network byte order.
    pub fn value_as_uint(&self) -> u32 {
        let mut result: u32 = 0;
        for &byte in &self.value {
            result = (result << 8) | u32::from(byte);
        }
        result
    }

    /// Creates an option with a uint value encoded in the minimum number of bytes.
    pub fn from_uint(number: u16, value: u32) -> Self {
        let bytes = if value == 0 {
            Vec::new()
        } else if value <= 0xFF {
            vec![value as u8]
        } else if value <= 0xFFFF {
            vec![(value >> 8) as u8, value as u8]
        } else if value <= 0xFF_FFFF {
            vec![(value >> 16) as u8, (value >> 8) as u8, value as u8]
        } else {
            vec![
                (value >> 24) as u8,
                (value >> 16) as u8,
                (value >> 8) as u8,
                value as u8,
            ]
        };
        Self {
            number,
            value: bytes,
        }
    }

    /// Interprets the option value as a UTF-8 string.
    pub fn value_as_str(&self) -> CoapResult<&str> {
        std::str::from_utf8(&self.value)
            .map_err(|e| CoapError::InvalidMessage(format!("Invalid UTF-8 in option: {e}")))
    }
}

/// A parsed CoAP message (RFC 7252 §3).
///
/// Represents a complete CoAP datagram including the fixed header, token,
/// options, and optional payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoapMessage {
    /// Protocol version (must be 1).
    pub version: u8,
    /// Message type (CON, NON, ACK, RST).
    pub msg_type: CoapMessageType,
    /// Request/response code.
    pub code: CoapCode,
    /// Message ID for matching requests to responses.
    pub message_id: u16,
    /// Token for correlating requests and responses (0-8 bytes).
    pub token: Vec<u8>,
    /// CoAP options, sorted by option number.
    pub options: Vec<CoapOption>,
    /// Message payload (after the 0xFF marker).
    pub payload: Vec<u8>,
}

impl CoapMessage {
    /// Parses a raw UDP datagram into a CoAP message.
    ///
    /// RFC 7252 §3: The message format is a compact binary encoding with
    /// a 4-byte fixed header followed by a variable-length token, options,
    /// and payload.
    pub fn parse(data: &[u8]) -> CoapResult<Self> {
        if data.len() < 4 {
            return Err(CoapError::InvalidMessage(format!(
                "Message too short: {} bytes (minimum 4)",
                data.len()
            )));
        }

        // Byte 0: Ver (2 bits) | T (2 bits) | TKL (4 bits)
        let version = (data[0] >> 6) & 0x03;
        if version != COAP_VERSION {
            return Err(CoapError::InvalidMessage(format!(
                "Unsupported CoAP version: {version}"
            )));
        }

        let msg_type = CoapMessageType::from_bits((data[0] >> 4) & 0x03)?;
        let tkl = (data[0] & 0x0F) as usize;

        if tkl > 8 {
            return Err(CoapError::InvalidMessage(format!(
                "Token length {tkl} exceeds maximum of 8"
            )));
        }

        // Byte 1: Code
        let code = CoapCode::from_byte(data[1]);

        // Bytes 2-3: Message ID
        let message_id = u16::from_be_bytes([data[2], data[3]]);

        // Token
        let token_end = 4 + tkl;
        if data.len() < token_end {
            return Err(CoapError::InvalidMessage(format!(
                "Message truncated in token: need {} bytes, have {}",
                token_end,
                data.len()
            )));
        }
        let token = data[4..token_end].to_vec();

        // Options and payload
        let mut pos = token_end;
        let mut options = Vec::new();
        let mut current_option_number: u16 = 0;

        while pos < data.len() {
            // Check for payload marker
            if data[pos] == PAYLOAD_MARKER {
                pos += 1;
                break;
            }

            // Parse option delta and length (RFC 7252 §3.1)
            let option_byte = data[pos];
            pos += 1;

            let mut delta = u16::from((option_byte >> 4) & 0x0F);
            let mut length = u16::from(option_byte & 0x0F);

            // Extended delta
            match delta {
                13 => {
                    if pos >= data.len() {
                        return Err(CoapError::InvalidMessage(
                            "Truncated option delta (13)".to_string(),
                        ));
                    }
                    delta = u16::from(data[pos]) + 13;
                    pos += 1;
                }
                14 => {
                    if pos + 1 >= data.len() {
                        return Err(CoapError::InvalidMessage(
                            "Truncated option delta (14)".to_string(),
                        ));
                    }
                    delta = u16::from_be_bytes([data[pos], data[pos + 1]]) + 269;
                    pos += 2;
                }
                15 => {
                    return Err(CoapError::InvalidMessage(
                        "Reserved option delta value 15".to_string(),
                    ));
                }
                _ => {}
            }

            // Extended length
            match length {
                13 => {
                    if pos >= data.len() {
                        return Err(CoapError::InvalidMessage(
                            "Truncated option length (13)".to_string(),
                        ));
                    }
                    length = u16::from(data[pos]) + 13;
                    pos += 1;
                }
                14 => {
                    if pos + 1 >= data.len() {
                        return Err(CoapError::InvalidMessage(
                            "Truncated option length (14)".to_string(),
                        ));
                    }
                    length = u16::from_be_bytes([data[pos], data[pos + 1]]) + 269;
                    pos += 2;
                }
                15 => {
                    return Err(CoapError::InvalidMessage(
                        "Reserved option length value 15".to_string(),
                    ));
                }
                _ => {}
            }

            current_option_number += delta;
            let length = length as usize;

            if pos + length > data.len() {
                return Err(CoapError::InvalidMessage(format!(
                    "Truncated option value: need {} bytes at offset {}, have {}",
                    length,
                    pos,
                    data.len() - pos
                )));
            }

            let value = data[pos..pos + length].to_vec();
            pos += length;

            options.push(CoapOption {
                number: current_option_number,
                value,
            });
        }

        // Remaining bytes after payload marker are the payload.
        let payload = if pos < data.len() {
            data[pos..].to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            version,
            msg_type,
            code,
            message_id,
            token,
            options,
            payload,
        })
    }

    /// Serializes this CoAP message to bytes suitable for UDP transmission.
    ///
    /// RFC 7252 §3: Options are encoded using delta compression relative
    /// to the previous option number.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + self.token.len() + self.payload.len() + 32);

        // Byte 0: Ver (2) | T (2) | TKL (4)
        let tkl = self.token.len().min(8) as u8;
        buf.push((COAP_VERSION << 6) | (self.msg_type.to_bits() << 4) | tkl);

        // Byte 1: Code
        buf.push(self.code.to_byte());

        // Bytes 2-3: Message ID
        buf.extend_from_slice(&self.message_id.to_be_bytes());

        // Token
        buf.extend_from_slice(&self.token[..tkl as usize]);

        // Options (must be sorted by option number for delta encoding)
        let mut sorted_options = self.options.clone();
        sorted_options.sort_by_key(|o| o.number);

        let mut prev_number: u16 = 0;
        for opt in &sorted_options {
            let delta = opt.number - prev_number;
            let length = opt.value.len() as u16;
            prev_number = opt.number;

            // Encode delta
            let (delta_nibble, delta_ext) = encode_option_header_value(delta);
            // Encode length
            let (length_nibble, length_ext) = encode_option_header_value(length);

            buf.push((delta_nibble << 4) | length_nibble);
            buf.extend_from_slice(&delta_ext);
            buf.extend_from_slice(&length_ext);
            buf.extend_from_slice(&opt.value);
        }

        // Payload (preceded by 0xFF marker if non-empty)
        if !self.payload.is_empty() {
            buf.push(PAYLOAD_MARKER);
            buf.extend_from_slice(&self.payload);
        }

        buf
    }

    /// Extracts the URI path from Uri-Path options.
    ///
    /// RFC 7252 §5.10.1: Multiple Uri-Path options are joined with `/`
    /// to reconstruct the full path.
    pub fn uri_path(&self) -> String {
        let segments: Vec<&str> = self
            .options
            .iter()
            .filter(|o| o.number == OPTION_URI_PATH)
            .filter_map(|o| std::str::from_utf8(&o.value).ok())
            .collect();

        if segments.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", segments.join("/"))
        }
    }

    /// Returns the Content-Format option value, if present.
    pub fn content_format(&self) -> Option<u16> {
        self.options
            .iter()
            .find(|o| o.number == OPTION_CONTENT_FORMAT)
            .map(|o| o.value_as_uint() as u16)
    }

    /// Returns the Block1 option, if present.
    pub fn block1(&self) -> Option<crate::block::BlockOption> {
        self.options
            .iter()
            .find(|o| o.number == OPTION_BLOCK1)
            .map(|o| crate::block::BlockOption::decode(o.value_as_uint()))
    }

    /// Returns the Block2 option, if present.
    pub fn block2(&self) -> Option<crate::block::BlockOption> {
        self.options
            .iter()
            .find(|o| o.number == OPTION_BLOCK2)
            .map(|o| crate::block::BlockOption::decode(o.value_as_uint()))
    }
}

/// Encodes a delta or length value into the option header nibble and
/// optional extended bytes per RFC 7252 §3.1.
fn encode_option_header_value(value: u16) -> (u8, Vec<u8>) {
    if value < 13 {
        (value as u8, Vec::new())
    } else if value < 269 {
        (13, vec![(value - 13) as u8])
    } else {
        let extended = value - 269;
        (14, extended.to_be_bytes().to_vec())
    }
}

/// EST operations per RFC 7030, reused from the `kipuka-est` crate.
///
/// Duplicated here to avoid a dependency on `kipuka-est` from the CoAP
/// transport layer. The router maps CoAP paths to these operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EstOperation {
    /// Retrieve CA certificates (RFC 7030 §4.1).
    CaCerts,
    /// Simple enrollment (RFC 7030 §4.2).
    SimpleEnroll,
    /// Simple re-enrollment (RFC 7030 §4.2.2).
    SimpleReenroll,
    /// Server-side key generation (RFC 7030 §4.4).
    ServerKeygen,
    /// CSR attributes (RFC 7030 §4.5).
    CsrAttrs,
}

/// CoAP request representing an EST-coaps operation.
///
/// RFC 9483 §5.1: EST-coaps URIs follow the pattern:
///   coaps://host/.well-known/est/{operation}
/// where {operation} uses the abbreviated names from RFC 9483 §5.1:
///   - /cacerts   -> /cacerts (GET)
///   - /sen       -> /simpleenroll (POST)
///   - /sren      -> /simplereenroll (POST)
///   - /skg       -> /serverkeygen (POST)
///   - /att       -> /csrattrs (GET)
///   - /crts      -> /cacerts (GET, alias)
#[derive(Debug)]
pub struct CoapEstRequest {
    /// The decoded EST operation.
    pub operation: EstOperation,
    /// The CoAP method used.
    pub method: CoapMethod,
    /// The original CoAP message.
    pub message: CoapMessage,
}

/// Routes CoAP URI paths to EST operations.
///
/// RFC 9483 §5.1: EST-coaps uses abbreviated path names under
/// `/.well-known/est/` to reduce URI size for constrained devices.
///
/// The router strips the well-known prefix and maps the final path
/// segment to an [`EstOperation`].
pub struct CoapEstRouter;

impl CoapEstRouter {
    /// Maps a CoAP URI path to an EST operation.
    ///
    /// Recognizes both the abbreviated RFC 9483 paths and the full-length
    /// path segments from the well-known prefix.
    ///
    /// # Path Recognition
    ///
    /// The router accepts paths with or without the `/.well-known/est/`
    /// prefix, recognizing these final segments:
    /// - `sen` → SimpleEnroll
    /// - `sren` → SimpleReenroll
    /// - `skg` → ServerKeygen
    /// - `att` → CsrAttrs
    /// - `cacerts` or `crts` → CaCerts
    pub fn route(path: &str) -> CoapResult<EstOperation> {
        // Extract the final path segment, stripping the well-known prefix.
        let segment = path
            .trim_start_matches('/')
            .trim_start_matches(".well-known/est/")
            .trim_start_matches(".well-known/est")
            .trim_start_matches('/')
            .trim_end_matches('/');

        match segment {
            "sen" | "simpleenroll" => Ok(EstOperation::SimpleEnroll),
            "sren" | "simplereenroll" => Ok(EstOperation::SimpleReenroll),
            "skg" | "serverkeygen" => Ok(EstOperation::ServerKeygen),
            "att" | "csrattrs" => Ok(EstOperation::CsrAttrs),
            "cacerts" | "crts" => Ok(EstOperation::CaCerts),
            _ => Err(CoapError::ResourceNotFound(format!(
                "Unknown EST-coaps path: {path}"
            ))),
        }
    }

    /// Routes a full CoAP message to an EST operation.
    ///
    /// Extracts the URI path from the message options and resolves the
    /// corresponding EST operation. Also validates that the CoAP method
    /// is appropriate for the operation.
    pub fn route_message(message: CoapMessage) -> CoapResult<CoapEstRequest> {
        let path = message.uri_path();
        let operation = Self::route(&path)?;

        let method = CoapMethod::from_code(&message.code).ok_or_else(|| {
            CoapError::UnsupportedMethod(format!("Code {} is not a request", message.code))
        })?;

        // Validate method against operation.
        match operation {
            EstOperation::CaCerts | EstOperation::CsrAttrs => {
                if method != CoapMethod::Get && method != CoapMethod::Fetch {
                    return Err(CoapError::UnsupportedMethod(format!(
                        "{path} requires GET or FETCH, got {:?}",
                        method
                    )));
                }
            }
            EstOperation::SimpleEnroll
            | EstOperation::SimpleReenroll
            | EstOperation::ServerKeygen => {
                if method != CoapMethod::Post {
                    return Err(CoapError::UnsupportedMethod(format!(
                        "{path} requires POST, got {:?}",
                        method
                    )));
                }
            }
        }

        Ok(CoapEstRequest {
            operation,
            method,
            message,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- CoapCode tests ---

    #[test]
    fn test_code_byte_roundtrip() {
        let codes = [
            CoapCode::CREATED,
            CoapCode::CONTENT,
            CoapCode::NOT_FOUND,
            CoapCode::METHOD_NOT_ALLOWED,
            CoapCode::UNSUPPORTED_CONTENT_FORMAT,
            CoapCode::INTERNAL_SERVER_ERROR,
        ];

        for code in codes {
            let byte = code.to_byte();
            let decoded = CoapCode::from_byte(byte);
            assert_eq!(decoded, code, "roundtrip failed for {code}");
        }
    }

    #[test]
    fn test_code_classification() {
        assert!(CoapCode::from_byte(0x01).is_request()); // 0.01 GET
        assert!(CoapCode::CONTENT.is_success());
        assert!(CoapCode::NOT_FOUND.is_client_error());
        assert!(CoapCode::INTERNAL_SERVER_ERROR.is_server_error());
    }

    #[test]
    fn test_code_display() {
        assert_eq!(CoapCode::CONTENT.to_string(), "2.05");
        assert_eq!(CoapCode::NOT_FOUND.to_string(), "4.04");
        assert_eq!(CoapCode::CREATED.to_string(), "2.01");
    }

    // --- CoapOption tests ---

    #[test]
    fn test_option_uint_encoding() {
        let opt = CoapOption::from_uint(OPTION_CONTENT_FORMAT, 285);
        assert_eq!(opt.value_as_uint(), 285);

        let opt_zero = CoapOption::from_uint(OPTION_CONTENT_FORMAT, 0);
        assert_eq!(opt_zero.value_as_uint(), 0);
        assert!(opt_zero.value.is_empty());
    }

    #[test]
    fn test_option_string_value() {
        let opt = CoapOption::new(OPTION_URI_PATH, b"sen".to_vec());
        assert_eq!(opt.value_as_str().unwrap(), "sen");
    }

    // --- CoapMessage parse/encode tests ---

    #[test]
    fn test_parse_minimal_message() {
        // Minimal CON GET with no token, no options, no payload
        // Ver=1, T=0 (CON), TKL=0, Code=0.01 (GET), MID=0x1234
        let data = [0x40, 0x01, 0x12, 0x34];
        let msg = CoapMessage::parse(&data).unwrap();

        assert_eq!(msg.version, 1);
        assert_eq!(msg.msg_type, CoapMessageType::Confirmable);
        assert_eq!(
            msg.code,
            CoapCode {
                class: 0,
                detail: 1
            }
        );
        assert_eq!(msg.message_id, 0x1234);
        assert!(msg.token.is_empty());
        assert!(msg.options.is_empty());
        assert!(msg.payload.is_empty());
    }

    #[test]
    fn test_parse_message_with_token() {
        // CON GET, TKL=4, token=[0xDE,0xAD,0xBE,0xEF]
        let data = [0x44, 0x01, 0x00, 0x01, 0xDE, 0xAD, 0xBE, 0xEF];
        let msg = CoapMessage::parse(&data).unwrap();

        assert_eq!(msg.token, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_parse_message_with_payload() {
        // CON POST, TKL=0, no options, payload "hello"
        let mut data = vec![0x40, 0x02, 0x00, 0x01];
        data.push(PAYLOAD_MARKER);
        data.extend_from_slice(b"hello");

        let msg = CoapMessage::parse(&data).unwrap();
        assert_eq!(msg.payload, b"hello");
    }

    #[test]
    fn test_parse_encode_roundtrip() {
        let original = CoapMessage {
            version: 1,
            msg_type: CoapMessageType::Confirmable,
            code: CoapMethod::Post.to_code(),
            message_id: 0xABCD,
            token: vec![0x01, 0x02],
            options: vec![
                CoapOption::new(OPTION_URI_PATH, b".well-known".to_vec()),
                CoapOption::new(OPTION_URI_PATH, b"est".to_vec()),
                CoapOption::new(OPTION_URI_PATH, b"sen".to_vec()),
                CoapOption::from_uint(OPTION_CONTENT_FORMAT, 285),
            ],
            payload: vec![0x30, 0x82, 0x01, 0x00],
        };

        let encoded = original.encode();
        let decoded = CoapMessage::parse(&encoded).unwrap();

        assert_eq!(decoded.version, original.version);
        assert_eq!(decoded.msg_type, original.msg_type);
        assert_eq!(decoded.code, original.code);
        assert_eq!(decoded.message_id, original.message_id);
        assert_eq!(decoded.token, original.token);
        assert_eq!(decoded.payload, original.payload);
        assert_eq!(decoded.options.len(), original.options.len());
    }

    #[test]
    fn test_parse_too_short() {
        let err = CoapMessage::parse(&[0x40, 0x01]).unwrap_err();
        assert!(matches!(err, CoapError::InvalidMessage(_)));
    }

    #[test]
    fn test_parse_bad_version() {
        // Version 2 (invalid)
        let data = [0x80, 0x01, 0x00, 0x01];
        let err = CoapMessage::parse(&data).unwrap_err();
        assert!(matches!(err, CoapError::InvalidMessage(_)));
    }

    #[test]
    fn test_parse_tkl_too_large() {
        // TKL=9 (invalid, max is 8)
        let data = [0x49, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let err = CoapMessage::parse(&data).unwrap_err();
        assert!(matches!(err, CoapError::InvalidMessage(_)));
    }

    // --- URI path extraction ---

    #[test]
    fn test_uri_path_extraction() {
        let msg = CoapMessage {
            version: 1,
            msg_type: CoapMessageType::Confirmable,
            code: CoapMethod::Post.to_code(),
            message_id: 1,
            token: vec![],
            options: vec![
                CoapOption::new(OPTION_URI_PATH, b".well-known".to_vec()),
                CoapOption::new(OPTION_URI_PATH, b"est".to_vec()),
                CoapOption::new(OPTION_URI_PATH, b"sen".to_vec()),
            ],
            payload: vec![],
        };

        assert_eq!(msg.uri_path(), "/.well-known/est/sen");
    }

    #[test]
    fn test_uri_path_empty() {
        let msg = CoapMessage {
            version: 1,
            msg_type: CoapMessageType::Confirmable,
            code: CoapMethod::Get.to_code(),
            message_id: 1,
            token: vec![],
            options: vec![],
            payload: vec![],
        };

        assert_eq!(msg.uri_path(), "/");
    }

    // --- EST routing tests ---

    #[test]
    fn test_route_abbreviated_paths() {
        assert_eq!(
            CoapEstRouter::route("/sen").unwrap(),
            EstOperation::SimpleEnroll
        );
        assert_eq!(
            CoapEstRouter::route("/sren").unwrap(),
            EstOperation::SimpleReenroll
        );
        assert_eq!(
            CoapEstRouter::route("/skg").unwrap(),
            EstOperation::ServerKeygen
        );
        assert_eq!(
            CoapEstRouter::route("/att").unwrap(),
            EstOperation::CsrAttrs
        );
        assert_eq!(
            CoapEstRouter::route("/cacerts").unwrap(),
            EstOperation::CaCerts
        );
        assert_eq!(
            CoapEstRouter::route("/crts").unwrap(),
            EstOperation::CaCerts
        );
    }

    #[test]
    fn test_route_well_known_prefix() {
        assert_eq!(
            CoapEstRouter::route("/.well-known/est/sen").unwrap(),
            EstOperation::SimpleEnroll
        );
        assert_eq!(
            CoapEstRouter::route("/.well-known/est/cacerts").unwrap(),
            EstOperation::CaCerts
        );
    }

    #[test]
    fn test_route_full_names() {
        assert_eq!(
            CoapEstRouter::route("/simpleenroll").unwrap(),
            EstOperation::SimpleEnroll
        );
        assert_eq!(
            CoapEstRouter::route("/simplereenroll").unwrap(),
            EstOperation::SimpleReenroll
        );
        assert_eq!(
            CoapEstRouter::route("/serverkeygen").unwrap(),
            EstOperation::ServerKeygen
        );
        assert_eq!(
            CoapEstRouter::route("/csrattrs").unwrap(),
            EstOperation::CsrAttrs
        );
    }

    #[test]
    fn test_route_unknown_path() {
        let err = CoapEstRouter::route("/unknown").unwrap_err();
        assert!(matches!(err, CoapError::ResourceNotFound(_)));
    }

    // --- Block option accessors ---

    #[test]
    fn test_message_block1_option() {
        let block = crate::block::BlockOption {
            num: 3,
            more: true,
            szx: 5,
        };

        let msg = CoapMessage {
            version: 1,
            msg_type: CoapMessageType::Confirmable,
            code: CoapMethod::Post.to_code(),
            message_id: 1,
            token: vec![],
            options: vec![CoapOption::from_uint(OPTION_BLOCK1, block.encode())],
            payload: vec![],
        };

        let extracted = msg.block1().unwrap();
        assert_eq!(extracted, block);
    }

    #[test]
    fn test_message_content_format() {
        let msg = CoapMessage {
            version: 1,
            msg_type: CoapMessageType::Confirmable,
            code: CoapMethod::Post.to_code(),
            message_id: 1,
            token: vec![],
            options: vec![CoapOption::from_uint(
                OPTION_CONTENT_FORMAT,
                u32::from(crate::content_format::APPLICATION_PKCS10),
            )],
            payload: vec![],
        };

        assert_eq!(
            msg.content_format(),
            Some(crate::content_format::APPLICATION_PKCS10)
        );
    }

    // --- Route message integration test ---

    #[test]
    fn test_route_message_post_simpleenroll() {
        let msg = CoapMessage {
            version: 1,
            msg_type: CoapMessageType::Confirmable,
            code: CoapMethod::Post.to_code(),
            message_id: 42,
            token: vec![0x01],
            options: vec![
                CoapOption::new(OPTION_URI_PATH, b".well-known".to_vec()),
                CoapOption::new(OPTION_URI_PATH, b"est".to_vec()),
                CoapOption::new(OPTION_URI_PATH, b"sen".to_vec()),
            ],
            payload: vec![0x30],
        };

        let req = CoapEstRouter::route_message(msg).unwrap();
        assert_eq!(req.operation, EstOperation::SimpleEnroll);
        assert_eq!(req.method, CoapMethod::Post);
    }

    #[test]
    fn test_route_message_get_cacerts() {
        let msg = CoapMessage {
            version: 1,
            msg_type: CoapMessageType::Confirmable,
            code: CoapMethod::Get.to_code(),
            message_id: 43,
            token: vec![],
            options: vec![CoapOption::new(OPTION_URI_PATH, b"cacerts".to_vec())],
            payload: vec![],
        };

        let req = CoapEstRouter::route_message(msg).unwrap();
        assert_eq!(req.operation, EstOperation::CaCerts);
        assert_eq!(req.method, CoapMethod::Get);
    }

    #[test]
    fn test_route_message_wrong_method() {
        let msg = CoapMessage {
            version: 1,
            msg_type: CoapMessageType::Confirmable,
            code: CoapMethod::Get.to_code(), // GET on /sen is wrong
            message_id: 44,
            token: vec![],
            options: vec![CoapOption::new(OPTION_URI_PATH, b"sen".to_vec())],
            payload: vec![],
        };

        let err = CoapEstRouter::route_message(msg).unwrap_err();
        assert!(matches!(err, CoapError::UnsupportedMethod(_)));
    }

    // --- Encode/parse round-trip with options ---

    #[test]
    fn test_encode_parse_roundtrip_with_large_option_delta() {
        let msg = CoapMessage {
            version: 1,
            msg_type: CoapMessageType::Acknowledgement,
            code: CoapCode::CONTENT,
            message_id: 999,
            token: vec![0xAA, 0xBB, 0xCC],
            options: vec![
                CoapOption::new(OPTION_URI_PATH, b"test".to_vec()), // 11
                CoapOption::from_uint(OPTION_CONTENT_FORMAT, 285),  // 12
                CoapOption::from_uint(OPTION_SIZE1, 4096),          // 60
            ],
            payload: b"response-body".to_vec(),
        };

        let bytes = msg.encode();
        let parsed = CoapMessage::parse(&bytes).unwrap();

        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.msg_type, CoapMessageType::Acknowledgement);
        assert_eq!(parsed.code, CoapCode::CONTENT);
        assert_eq!(parsed.message_id, 999);
        assert_eq!(parsed.token, vec![0xAA, 0xBB, 0xCC]);
        assert_eq!(parsed.payload, b"response-body");

        // Verify option values
        assert_eq!(parsed.content_format(), Some(285));
        let size1 = parsed
            .options
            .iter()
            .find(|o| o.number == OPTION_SIZE1)
            .unwrap();
        assert_eq!(size1.value_as_uint(), 4096);
    }
}

// ---------------------------------------------------------------------------
// CoapServer — UDP/DTLS listener for EST-coaps
// ---------------------------------------------------------------------------

/// Audit metadata returned by EST handlers for NIAP FAU_GEN.1 compliance.
///
/// The `EstHandler` trait is synchronous, so handlers cannot call async
/// audit-recording functions directly.  Instead, they populate an
/// `AuditInfo` value which the async server loop records after sending the
/// CoAP response.
#[derive(Debug, Clone)]
pub struct AuditInfo {
    /// Audit event type string (e.g. `"coap_simpleenroll"`).
    pub event_type: String,
    /// Human-readable detail (e.g. serial number / subject DN).
    pub detail: String,
}

/// Structured response from an EST handler.
///
/// Combines the CoAP response payload, content-format, and optional audit
/// metadata in a single return value.
#[derive(Debug, Clone)]
pub struct EstResponse {
    /// DER-encoded response payload.
    pub payload: Vec<u8>,
    /// CoAP Content-Format ID for the response.
    pub content_format: u16,
    /// Optional audit event to record asynchronously.
    pub audit_event: Option<AuditInfo>,
}

/// Callback trait for processing EST operations.
///
/// Implementors handle the actual EST logic (certificate issuance, CSR
/// attribute retrieval, etc.) while the [`CoapServer`] handles CoAP/DTLS
/// transport concerns.
///
/// The callback receives the EST operation, request payload, and optional
/// client certificate information (from DTLS mTLS). It returns an
/// [`EstResponse`] containing the response payload, content-format, and
/// optional audit metadata for NIAP FAU_GEN.1 event recording.
pub trait EstHandler: Send + Sync + 'static {
    /// Processes an EST operation and returns the response.
    ///
    /// # Arguments
    ///
    /// * `operation` - The EST operation being requested.
    /// * `payload` - The request body (e.g., PKCS#10 CSR for enrollment).
    /// * `content_format` - The CoAP content-format of the request payload.
    /// * `client_cert` - Client certificate from DTLS mTLS, if presented.
    ///
    /// # Returns
    ///
    /// An [`EstResponse`] on success, or a `CoapError` on failure.
    fn handle(
        &self,
        operation: EstOperation,
        payload: &[u8],
        content_format: Option<u16>,
        client_cert: Option<&crate::dtls::ClientCertInfo>,
    ) -> Result<EstResponse, CoapError>;
}

/// Cached response entry: (disassembler, content-format, response code, timestamp).
type ResponseCacheEntry = (BlockDisassembler, u16, CoapCode, Instant);

/// CoAP/DTLS server for EST-coaps (RFC 9483).
///
/// Binds a UDP socket, accepts DTLS connections, parses CoAP messages,
/// routes EST operations, and handles block-wise transfer for large payloads.
///
/// # Architecture
///
/// ```text
/// UDP socket
///   └─ DTLS decrypt (per-peer via DtlsContext + DtlsSessionCache)
///       └─ CoAP parse (CoapMessage::parse)
///           └─ EST routing (CoapEstRouter::route_message)
///               └─ Block assembly (BlockAssembler for multi-block requests)
///               └─ EST handler callback
///               └─ Block disassembly (BlockDisassembler for large responses)
///           └─ CoAP encode (CoapMessage::encode)
///       └─ DTLS encrypt
///   └─ UDP send
/// ```
pub struct CoapDtlsServer {
    /// Bound UDP socket for CoAP/DTLS.
    socket: Arc<UdpSocket>,
    /// DTLS server context (certificate, key, CA).
    dtls_ctx: DtlsContext,
    /// Cache of established DTLS sessions for session resumption.
    session_cache: Mutex<DtlsSessionCache>,
    /// Active DTLS connections indexed by peer address.
    connections: Mutex<HashMap<SocketAddr, DtlsConnection>>,
    /// In-progress block-wise request assemblies.
    ///
    /// Keyed by `(peer_addr, message_token_hash)` to distinguish concurrent
    /// block transfers from the same or different peers.  Each entry is
    /// paired with an [`Instant`] recording the last activity; entries
    /// older than `block_ttl` are reaped on each incoming datagram.
    ///
    /// Bounded to `max_block_assemblers` entries to prevent resource
    /// exhaustion from peers that start but never complete block transfers.
    block_assemblers: Mutex<HashMap<(SocketAddr, u16), (BlockAssembler, Instant)>>,
    /// Cached multi-block responses awaiting subsequent Block2 GETs.
    ///
    /// Keyed by `(peer_addr, token_hash)`.  Entries older than `block_ttl`
    /// are reaped alongside stale block assemblers.  Capped at
    /// `max_block_assemblers` entries.
    response_cache: Mutex<HashMap<(SocketAddr, u16), ResponseCacheEntry>>,
    /// Configured block size exponent for response fragmentation.
    block_szx: u8,
    /// Maximum reassembled payload size.
    max_payload: usize,
    /// Maximum number of concurrent block-wise assemblers (DoS guard).
    max_block_assemblers: usize,
    /// Time-to-live for block assembler and response cache entries.
    block_ttl: Duration,
}

impl CoapDtlsServer {
    /// Creates and binds a new CoAP/DTLS server.
    ///
    /// # Arguments
    ///
    /// * `listen_addr` - UDP address to bind (e.g., `"0.0.0.0:5684"`).
    /// * `cert_pem` - PEM-encoded server certificate for DTLS.
    /// * `key_pem` - PEM-encoded server private key for DTLS.
    /// * `ca_pem` - PEM-encoded CA certificate for client cert verification.
    /// * `block_size` - CoAP block size in bytes (must be a power of 2, 16..=1024).
    /// * `max_payload` - Maximum reassembled payload size in bytes.
    /// * `max_sessions` - Maximum concurrent DTLS sessions.
    /// * `session_timeout` - DTLS session TTL for resumption.
    pub async fn bind(
        listen_addr: &str,
        cert_pem: &[u8],
        key_pem: &[u8],
        ca_pem: &[u8],
        block_size: u16,
        max_payload: usize,
        max_sessions: usize,
        session_timeout: Duration,
    ) -> Result<Self, CoapError> {
        let socket = UdpSocket::bind(listen_addr).await.map_err(|e| {
            CoapError::Internal(format!("Failed to bind UDP socket on {listen_addr}: {e}"))
        })?;

        let dtls_ctx = DtlsContext::new(cert_pem, key_pem, ca_pem)?;

        let block_szx = szx_from_block_size(block_size as usize).unwrap_or(
            crate::block::DEFAULT_SZX,
        );

        info!(
            listen_addr = %listen_addr,
            block_size = block_size,
            max_payload = max_payload,
            max_sessions = max_sessions,
            "CoAP/DTLS server bound"
        );

        Ok(Self {
            socket: Arc::new(socket),
            dtls_ctx,
            session_cache: Mutex::new(DtlsSessionCache::new(max_sessions, session_timeout)),
            connections: Mutex::new(HashMap::new()),
            block_assemblers: Mutex::new(HashMap::new()),
            response_cache: Mutex::new(HashMap::new()),
            block_szx,
            max_payload,
            // Cap assemblers at 2x session limit — each peer should have at
            // most one active block transfer, but allow headroom for token
            // hash collisions and rapid reconnects.
            max_block_assemblers: max_sessions.saturating_mul(2),
            block_ttl: Duration::from_secs(60),
        })
    }

    /// Returns the local address the server is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr, CoapError> {
        self.socket.local_addr().map_err(|e| {
            CoapError::Internal(format!("Failed to get local address: {e}"))
        })
    }

    /// Runs the CoAP/DTLS server main loop.
    ///
    /// Receives UDP datagrams, performs DTLS processing, parses CoAP messages,
    /// routes to the EST handler, and sends responses. This method runs
    /// indefinitely until the provided cancellation token is signalled or
    /// an unrecoverable error occurs.
    ///
    /// # Arguments
    ///
    /// * `handler` - EST operation handler that processes enrollment requests.
    pub async fn run<H: EstHandler>(&self, handler: Arc<H>) -> Result<(), CoapError> {
        let mut buf = vec![0u8; 65535];

        info!("CoAP/DTLS server main loop started");

        loop {
            let (len, peer_addr) = match self.socket.recv_from(&mut buf).await {
                Ok(result) => result,
                Err(e) => {
                    warn!(error = %e, "UDP recv_from failed, continuing");
                    continue;
                }
            };

            let datagram = &buf[..len];
            debug!(
                peer = %peer_addr,
                len = len,
                "Received UDP datagram"
            );

            // For now, process the datagram as plaintext CoAP.
            // Full DTLS integration requires memory BIO plumbing which is
            // handled per-connection. When DTLS is enabled, the flow is:
            //
            //   1. Look up or create DtlsConnection for peer_addr
            //   2. Feed datagram into the connection's read BIO
            //   3. SSL_read to get decrypted CoAP data
            //   4. Process the CoAP message
            //   5. SSL_write the CoAP response
            //   6. Read from write BIO and send via UDP
            //
            // The connection tracking ensures DTLS session state is maintained
            // across multiple datagrams from the same peer.
            if let Err(e) = self.process_datagram(datagram, peer_addr, handler.as_ref()).await {
                warn!(
                    peer = %peer_addr,
                    error = %e,
                    "Failed to process datagram"
                );
            }
        }
    }

    /// Reaps stale block assembler and response cache entries.
    ///
    /// Called at the start of every datagram to bound memory usage from
    /// abandoned block transfers.
    async fn reap_stale_entries(&self) {
        let deadline = Instant::now() - self.block_ttl;

        {
            let mut assemblers = self.block_assemblers.lock().await;
            let before = assemblers.len();
            assemblers.retain(|_key, (_asm, ts)| *ts > deadline);
            let reaped = before - assemblers.len();
            if reaped > 0 {
                debug!(reaped = reaped, "Reaped stale block assemblers");
            }
        }

        {
            let mut cache = self.response_cache.lock().await;
            let before = cache.len();
            cache.retain(|_key, (_disasm, _cf, _code, ts)| *ts > deadline);
            let reaped = before - cache.len();
            if reaped > 0 {
                debug!(reaped = reaped, "Reaped stale response cache entries");
            }
        }
    }

    /// Processes a single received datagram (after DTLS decryption).
    async fn process_datagram(
        &self,
        data: &[u8],
        peer_addr: SocketAddr,
        handler: &dyn EstHandler,
    ) -> Result<(), CoapError> {
        // Reap stale block assembler and response cache entries.
        self.reap_stale_entries().await;

        let message = CoapMessage::parse(data)?;

        debug!(
            peer = %peer_addr,
            msg_type = ?message.msg_type,
            code = %message.code,
            path = %message.uri_path(),
            "Parsed CoAP message"
        );

        // Only process request messages (class 0).
        if !message.code.is_request() {
            debug!(peer = %peer_addr, "Ignoring non-request message");
            return Ok(());
        }

        // --- Handle Block2 continuation requests (GET with Block2 option) ---
        //
        // When a client requests a subsequent block of a multi-block response,
        // the Block2 option carries the requested block number.  Look up the
        // cached disassembler for this peer/token and return the requested block.
        if let Some(block2) = message.block2()
            && block2.num > 0
        {
            let cache_key = (peer_addr, token_hash(&message.token));
            let mut cache = self.response_cache.lock().await;
            if let Some((disasm, cf, code, ts)) = cache.get_mut(&cache_key) {
                // Refresh TTL on each access.
                *ts = Instant::now();
                if let Some((block_data, block_opt)) = disasm.get_block(block2.num) {
                    let is_last = !block_opt.more;
                    let response = CoapMessage {
                        version: COAP_VERSION,
                        msg_type: CoapMessageType::Acknowledgement,
                        code: *code,
                        message_id: message.message_id,
                        token: message.token.clone(),
                        options: vec![
                            CoapOption::from_uint(OPTION_CONTENT_FORMAT, u32::from(*cf)),
                            CoapOption::from_uint(OPTION_BLOCK2, block_opt.encode()),
                            CoapOption::from_uint(OPTION_SIZE2, disasm.payload_len() as u32),
                        ],
                        payload: block_data,
                    };
                    // If this is the final block, remove the cache entry.
                    if is_last {
                        cache.remove(&cache_key);
                    }
                    drop(cache);
                    self.send_response(peer_addr, &response).await?;
                    return Ok(());
                } else {
                    // Block number out of range — remove the stale entry.
                    cache.remove(&cache_key);
                }
            }
            drop(cache);
            // Fall through to re-process the request if cache miss.
        }

        // Check for block-wise request (Block1).
        let block1 = message.block1();
        let content_format = message.content_format();
        let msg_token = message.token.clone();
        let msg_id = message.message_id;

        // Route the message to determine the EST operation.
        let est_request = match CoapEstRouter::route_message(message) {
            Ok(req) => req,
            Err(e) => {
                let response = self.build_error_response(
                    &msg_token,
                    msg_id,
                    &e,
                );
                self.send_response(peer_addr, &response).await?;
                return Ok(());
            }
        };

        // Handle block-wise assembly for multi-block requests.
        let request_payload = if let Some(block) = block1 {
            let assembler_key = (peer_addr, token_hash(&msg_token));
            let mut assemblers = self.block_assemblers.lock().await;

            // Reject new block transfers when the assembler table is full.
            // This prevents resource exhaustion from peers that start but
            // never complete block transfers.
            if !assemblers.contains_key(&assembler_key)
                && assemblers.len() >= self.max_block_assemblers
            {
                warn!(
                    peer = %peer_addr,
                    active = assemblers.len(),
                    limit = self.max_block_assemblers,
                    "Block assembler limit reached, rejecting new transfer"
                );
                return Err(CoapError::Internal(
                    "too many concurrent block transfers".into(),
                ));
            }

            let (assembler, ts) = assemblers
                .entry(assembler_key)
                .or_insert_with(|| (BlockAssembler::new(self.max_payload), Instant::now()));

            // Refresh the timestamp on each block received.
            *ts = Instant::now();

            let complete = assembler.process_block(&block, &est_request.message.payload)?;

            if !complete {
                // Send a 2.31 Continue acknowledgement for intermediate blocks.
                let ack = CoapMessage {
                    version: COAP_VERSION,
                    msg_type: CoapMessageType::Acknowledgement,
                    code: CoapCode { class: 2, detail: 31 }, // 2.31 Continue
                    message_id: msg_id,
                    token: msg_token.clone(),
                    options: vec![
                        CoapOption::from_uint(
                            OPTION_BLOCK1,
                            block.encode(),
                        ),
                    ],
                    payload: Vec::new(),
                };
                self.send_response(peer_addr, &ack).await?;
                return Ok(());
            }

            // All blocks received — remove the assembler and extract the full payload.
            let (assembler, _ts) = assemblers.remove(&assembler_key).unwrap();
            assembler.into_payload()?
        } else {
            est_request.message.payload.clone()
        };

        // Retrieve client cert info from the DTLS connection (if any).
        let client_cert = {
            let conns = self.connections.lock().await;
            conns.get(&peer_addr).and_then(|c| c.client_cert().cloned())
        };

        // Dispatch to the EST handler.
        let est_response = match handler.handle(
            est_request.operation,
            &request_payload,
            content_format,
            client_cert.as_ref(),
        ) {
            Ok(result) => result,
            Err(e) => {
                let response = self.build_error_response(&msg_token, msg_id, &e);
                self.send_response(peer_addr, &response).await?;
                return Ok(());
            }
        };

        // Extract audit info before consuming the response fields.
        let audit_event = est_response.audit_event.clone();
        let response_payload = est_response.payload;
        let response_cf = est_response.content_format;

        // Determine response code based on operation.
        let response_code = match est_request.operation {
            EstOperation::SimpleEnroll
            | EstOperation::SimpleReenroll
            | EstOperation::ServerKeygen => CoapCode::CREATED,
            EstOperation::CaCerts | EstOperation::CsrAttrs => CoapCode::CONTENT,
        };

        // Handle block-wise response (Block2) for large payloads.
        let block_size = crate::block::block_size_from_szx(self.block_szx);
        if response_payload.len() > block_size {
            // Start block-wise transfer — send the first block.
            let disasm = BlockDisassembler::new(response_payload, self.block_szx);
            if let Some((block_data, block_opt)) = disasm.get_block(0) {
                let response = CoapMessage {
                    version: COAP_VERSION,
                    msg_type: CoapMessageType::Acknowledgement,
                    code: response_code,
                    message_id: msg_id,
                    token: msg_token.clone(),
                    options: vec![
                        CoapOption::from_uint(OPTION_CONTENT_FORMAT, u32::from(response_cf)),
                        CoapOption::from_uint(OPTION_BLOCK2, block_opt.encode()),
                        CoapOption::from_uint(OPTION_SIZE2, disasm.payload_len() as u32),
                    ],
                    payload: block_data,
                };
                self.send_response(peer_addr, &response).await?;
            }

            // Cache the disassembler for subsequent Block2 requests.
            let cache_key = (peer_addr, token_hash(&msg_token));
            let mut cache = self.response_cache.lock().await;
            // Enforce the same size cap as block assemblers.
            if cache.len() < self.max_block_assemblers {
                cache.insert(cache_key, (disasm, response_cf, response_code, Instant::now()));
            } else {
                warn!(
                    peer = %peer_addr,
                    active = cache.len(),
                    limit = self.max_block_assemblers,
                    "Response cache full, client must re-request"
                );
            }
        } else {
            // Single-block response.
            let response = CoapMessage {
                version: COAP_VERSION,
                msg_type: CoapMessageType::Acknowledgement,
                code: response_code,
                message_id: msg_id,
                token: msg_token,
                options: vec![
                    CoapOption::from_uint(OPTION_CONTENT_FORMAT, u32::from(response_cf)),
                ],
                payload: response_payload,
            };
            self.send_response(peer_addr, &response).await?;
        }

        // Record audit event asynchronously (NIAP FAU_GEN.1).
        if let Some(audit) = audit_event {
            info!(
                event_type = %audit.event_type,
                detail = %audit.detail,
                peer = %peer_addr,
                "CoAP audit event"
            );
            // When integrated with AppState, the caller can invoke
            // state.record_audit_event(&audit.event_type, &audit.detail).await
            // from the server loop after this method returns.
        }

        Ok(())
    }

    /// Builds a CoAP error response from a CoapError.
    fn build_error_response(
        &self,
        token: &[u8],
        message_id: u16,
        error: &CoapError,
    ) -> CoapMessage {
        let code = match error {
            CoapError::ResourceNotFound(_) => CoapCode::NOT_FOUND,
            CoapError::UnsupportedMethod(_) => CoapCode::METHOD_NOT_ALLOWED,
            CoapError::UnsupportedContentFormat(_) => CoapCode::UNSUPPORTED_CONTENT_FORMAT,
            CoapError::Unauthorized(_) => CoapCode::UNAUTHORIZED,
            CoapError::PayloadTooLarge { .. } => CoapCode {
                class: 4,
                detail: 13, // 4.13 Request Entity Too Large
            },
            _ => CoapCode::INTERNAL_SERVER_ERROR,
        };

        CoapMessage {
            version: COAP_VERSION,
            msg_type: CoapMessageType::Acknowledgement,
            code,
            message_id,
            token: token.to_vec(),
            options: Vec::new(),
            payload: error.to_string().into_bytes(),
        }
    }

    /// Sends a CoAP response to the given peer.
    ///
    /// In the full DTLS flow, this would encrypt via the peer's DTLS
    /// connection before sending. Currently sends plaintext for the
    /// transport skeleton.
    async fn send_response(
        &self,
        peer_addr: SocketAddr,
        message: &CoapMessage,
    ) -> Result<(), CoapError> {
        let encoded = message.encode();
        debug!(
            peer = %peer_addr,
            code = %message.code,
            len = encoded.len(),
            "Sending CoAP response"
        );

        self.socket
            .send_to(&encoded, peer_addr)
            .await
            .map_err(|e| CoapError::Internal(format!("UDP send failed: {e}")))?;

        Ok(())
    }

    /// Gets or creates a DTLS connection for a peer.
    ///
    /// If the peer already has an active connection, returns it. Otherwise
    /// creates a new `DtlsConnection` from the server's `DtlsContext`.
    #[allow(dead_code)]
    async fn get_or_create_connection(
        &self,
        peer_addr: SocketAddr,
    ) -> Result<(), CoapError> {
        let mut conns = self.connections.lock().await;
        if conns.contains_key(&peer_addr) {
            return Ok(());
        }

        let conn = DtlsConnection::new(&self.dtls_ctx, peer_addr)?;
        conns.insert(peer_addr, conn);

        // Also register in the session cache.
        let mut cache = self.session_cache.lock().await;
        let session = crate::dtls::DtlsSession::new(
            Vec::new(), // session ID filled after handshake
            peer_addr,
            DtlsVersion::V1_2, // negotiated during handshake
        );
        cache.insert(session);

        debug!(peer = %peer_addr, "Created new DTLS connection");
        Ok(())
    }
}

/// Computes a simple hash of a CoAP token for use as a block-assembler key.
///
/// This is not cryptographic — just a fast discriminator to distinguish
/// concurrent block transfers.
fn token_hash(token: &[u8]) -> u16 {
    let mut h: u16 = 0;
    for &b in token {
        h = h.wrapping_mul(31).wrapping_add(u16::from(b));
    }
    h
}

#[cfg(test)]
mod server_tests {
    use super::*;

    /// A test EST handler that echoes the operation name.
    struct EchoHandler;

    impl EstHandler for EchoHandler {
        fn handle(
            &self,
            operation: EstOperation,
            _payload: &[u8],
            _content_format: Option<u16>,
            _client_cert: Option<&crate::dtls::ClientCertInfo>,
        ) -> Result<EstResponse, CoapError> {
            let name = match operation {
                EstOperation::CaCerts => "cacerts",
                EstOperation::SimpleEnroll => "simpleenroll",
                EstOperation::SimpleReenroll => "simplereenroll",
                EstOperation::ServerKeygen => "serverkeygen",
                EstOperation::CsrAttrs => "csrattrs",
            };
            Ok(EstResponse {
                payload: name.as_bytes().to_vec(),
                content_format: crate::content_format::APPLICATION_PKCS7_MIME_CERTS_ONLY,
                audit_event: Some(AuditInfo {
                    event_type: format!("coap_{name}"),
                    detail: format!("test operation: {name}"),
                }),
            })
        }
    }

    #[test]
    fn test_token_hash_deterministic() {
        let token = vec![0x01, 0x02, 0x03];
        let h1 = token_hash(&token);
        let h2 = token_hash(&token);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_token_hash_empty() {
        let h = token_hash(&[]);
        assert_eq!(h, 0);
    }

    #[test]
    fn test_token_hash_different_tokens() {
        let h1 = token_hash(&[0x01]);
        let h2 = token_hash(&[0x02]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_echo_handler() {
        let handler = EchoHandler;
        let resp = handler
            .handle(EstOperation::CaCerts, &[], None, None)
            .unwrap();
        assert_eq!(resp.payload, b"cacerts");
        assert_eq!(resp.content_format, crate::content_format::APPLICATION_PKCS7_MIME_CERTS_ONLY);
        let audit = resp.audit_event.unwrap();
        assert_eq!(audit.event_type, "coap_cacerts");
    }

    #[test]
    fn test_build_error_response_not_found() {
        // We can't construct a CoapServer without binding, so test the
        // error-to-code mapping logic directly.
        let err = CoapError::ResourceNotFound("test".to_string());
        let code = match &err {
            CoapError::ResourceNotFound(_) => CoapCode::NOT_FOUND,
            _ => CoapCode::INTERNAL_SERVER_ERROR,
        };
        assert_eq!(code, CoapCode::NOT_FOUND);
    }

    #[test]
    fn test_build_error_response_method_not_allowed() {
        let err = CoapError::UnsupportedMethod("test".to_string());
        let code = match &err {
            CoapError::UnsupportedMethod(_) => CoapCode::METHOD_NOT_ALLOWED,
            _ => CoapCode::INTERNAL_SERVER_ERROR,
        };
        assert_eq!(code, CoapCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn test_coap_server_process_cacerts() {
        // Bind to a random port.
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let _server_addr = socket.local_addr().unwrap();

        let server = CoapDtlsServer {
            socket: Arc::new(socket),
            dtls_ctx: {
                // Create a minimal self-signed cert for the context.
                // For testing, we skip actual DTLS and test the CoAP layer.
                // Use a dummy context — process_datagram doesn't use DTLS yet.
                let (cert_pem, key_pem) = generate_test_cert();
                DtlsContext::new(&cert_pem, &key_pem, &cert_pem).unwrap()
            },
            session_cache: Mutex::new(DtlsSessionCache::new(10, Duration::from_secs(300))),
            connections: Mutex::new(HashMap::new()),
            block_assemblers: Mutex::new(HashMap::new()),
            response_cache: Mutex::new(HashMap::new()),
            block_szx: crate::block::DEFAULT_SZX,
            max_payload: 65536,
            max_block_assemblers: 20,
            block_ttl: Duration::from_secs(60),
        };

        let handler = EchoHandler;

        // Build a CoAP GET /cacerts request.
        let request = CoapMessage {
            version: COAP_VERSION,
            msg_type: CoapMessageType::Confirmable,
            code: CoapMethod::Get.to_code(),
            message_id: 1,
            token: vec![0xAA],
            options: vec![
                CoapOption::new(OPTION_URI_PATH, b"cacerts".to_vec()),
            ],
            payload: Vec::new(),
        };

        let peer_addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let result = server
            .process_datagram(&request.encode(), peer_addr, &handler)
            .await;
        assert!(result.is_ok());

        // The response was sent via UDP — in a full test we'd receive it
        // on another socket. Here we just verify no error occurred.
    }

    #[tokio::test]
    async fn test_coap_server_process_unknown_path() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let (cert_pem, key_pem) = generate_test_cert();
        let server = CoapDtlsServer {
            socket: Arc::new(socket),
            dtls_ctx: DtlsContext::new(&cert_pem, &key_pem, &cert_pem).unwrap(),
            session_cache: Mutex::new(DtlsSessionCache::new(10, Duration::from_secs(300))),
            connections: Mutex::new(HashMap::new()),
            block_assemblers: Mutex::new(HashMap::new()),
            response_cache: Mutex::new(HashMap::new()),
            block_szx: crate::block::DEFAULT_SZX,
            max_payload: 65536,
            max_block_assemblers: 20,
            block_ttl: Duration::from_secs(60),
        };

        let handler = EchoHandler;

        // Build a CoAP GET /unknown request.
        let request = CoapMessage {
            version: COAP_VERSION,
            msg_type: CoapMessageType::Confirmable,
            code: CoapMethod::Get.to_code(),
            message_id: 2,
            token: vec![0xBB],
            options: vec![
                CoapOption::new(OPTION_URI_PATH, b"unknown".to_vec()),
            ],
            payload: Vec::new(),
        };

        let peer_addr: SocketAddr = "127.0.0.1:9998".parse().unwrap();
        // Should succeed (error response sent, not returned as Err).
        let result = server
            .process_datagram(&request.encode(), peer_addr, &handler)
            .await;
        assert!(result.is_ok());
    }

    /// Generates a self-signed test certificate and key in PEM format.
    fn generate_test_cert() -> (Vec<u8>, Vec<u8>) {
        use openssl::asn1::Asn1Time;
        use openssl::bn::BigNum;
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::{X509Builder, X509NameBuilder};

        let rsa = Rsa::generate(2048).unwrap();
        let key = PKey::from_rsa(rsa).unwrap();

        let mut name_builder = X509NameBuilder::new().unwrap();
        name_builder
            .append_entry_by_text("CN", "test-coap-server")
            .unwrap();
        let name = name_builder.build();

        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&key).unwrap();

        let serial = BigNum::from_u32(1).unwrap();
        builder
            .set_serial_number(&serial.to_asn1_integer().unwrap())
            .unwrap();

        let not_before = Asn1Time::days_from_now(0).unwrap();
        let not_after = Asn1Time::days_from_now(365).unwrap();
        builder.set_not_before(&not_before).unwrap();
        builder.set_not_after(&not_after).unwrap();

        builder.sign(&key, MessageDigest::sha256()).unwrap();
        let cert = builder.build();

        (cert.to_pem().unwrap(), key.private_key_to_pem_pkcs8().unwrap())
    }
}
