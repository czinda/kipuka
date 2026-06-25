//! CoAP block-wise transfer per RFC 7959.
//!
//! EST payloads frequently exceed the CoAP datagram size limit, especially
//! with post-quantum certificates (ML-DSA-87 certificates can exceed 7KB).
//! Block-wise transfer splits large payloads into numbered blocks that are
//! individually acknowledged.
//!
//! # Block Options
//!
//! - **Block1** (option 27): Controls request payload transfer (client to server).
//!   The client sends the request body in numbered chunks; the server acknowledges
//!   each chunk before the next is sent.
//!
//! - **Block2** (option 23): Controls response payload transfer (server to client).
//!   The server splits its response into numbered chunks; the client requests
//!   successive chunks.
//!
//! # SZX Encoding
//!
//! Block sizes are encoded as `szx` where actual size = 2^(szx + 4):
//! - szx=0 → 16 bytes
//! - szx=1 → 32 bytes
//! - szx=2 → 64 bytes
//! - szx=3 → 128 bytes
//! - szx=4 → 256 bytes
//! - szx=5 → 512 bytes (default)
//! - szx=6 → 1024 bytes (maximum)

use crate::{CoapError, CoapResult};

/// Default block size exponent (szx=5 → 512 bytes).
///
/// RFC 7959 §2.2: 512 bytes is a safe default that fits within most
/// link-layer MTUs without IP fragmentation.
pub const DEFAULT_SZX: u8 = 5;

/// Maximum block size exponent (szx=6 → 1024 bytes).
pub const MAX_SZX: u8 = 6;

/// A decoded Block1 or Block2 option value.
///
/// RFC 7959 §2.2: The option value encodes three fields in a variable-length
/// unsigned integer:
/// - Bits 0-2: SZX (block size exponent)
/// - Bit 3: M (more blocks follow)
/// - Bits 4+: NUM (block number)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockOption {
    /// Block number (0-based).
    pub num: u32,
    /// Whether more blocks follow this one.
    pub more: bool,
    /// Block size exponent: actual size = 2^(szx + 4).
    pub szx: u8,
}

impl BlockOption {
    /// Decodes a Block option from its wire representation.
    ///
    /// RFC 7959 §2.2: The option value is a variable-length unsigned integer
    /// with the three least significant bits encoding SZX, bit 3 encoding M,
    /// and the remaining upper bits encoding NUM.
    pub fn decode(value: u32) -> Self {
        let szx = (value & 0x07) as u8;
        let more = (value & 0x08) != 0;
        let num = value >> 4;
        Self { num, more, szx }
    }

    /// Encodes this Block option to its wire representation.
    ///
    /// RFC 7959 §2.2: Packs NUM, M, and SZX into a single unsigned integer.
    pub fn encode(&self) -> u32 {
        let mut value = self.num << 4;
        if self.more {
            value |= 0x08;
        }
        value |= (self.szx as u32) & 0x07;
        value
    }

    /// Returns the block size in bytes for this option's SZX value.
    pub fn block_size(&self) -> usize {
        block_size_from_szx(self.szx)
    }

    /// Returns the byte offset of this block within the full payload.
    pub fn offset(&self) -> usize {
        self.num as usize * self.block_size()
    }
}

/// Converts an SZX exponent to the actual block size in bytes.
///
/// RFC 7959 §2.2: size = 2^(szx + 4). Values of szx above 6 are clamped
/// to 6 (1024 bytes) since larger sizes are reserved.
pub fn block_size_from_szx(szx: u8) -> usize {
    let clamped = szx.min(MAX_SZX);
    1 << (clamped as usize + 4)
}

/// Converts a block size in bytes to the corresponding SZX exponent.
///
/// Returns `None` if the size is not a valid power of 2 in the range
/// 16..=1024 (szx 0..=6).
pub fn szx_from_block_size(size: usize) -> Option<u8> {
    match size {
        16 => Some(0),
        32 => Some(1),
        64 => Some(2),
        128 => Some(3),
        256 => Some(4),
        512 => Some(5),
        1024 => Some(6),
        _ => None,
    }
}

/// Reassembles Block1 fragments into a complete request payload.
///
/// RFC 7959 §2.5: The server collects Block1 fragments from the client,
/// validating sequential block numbers and consistent SZX values.
/// Once the final block (M=0) arrives, the full payload is returned.
#[derive(Debug)]
pub struct BlockAssembler {
    /// Accumulated payload bytes.
    buffer: Vec<u8>,
    /// Next expected block number.
    next_num: u32,
    /// Negotiated block size exponent.
    szx: u8,
    /// Maximum allowed reassembled payload size.
    max_payload: usize,
    /// Whether the final block has been received.
    complete: bool,
}

impl BlockAssembler {
    /// Creates a new assembler with default block size and the given payload limit.
    ///
    /// # Arguments
    ///
    /// * `max_payload` - Maximum total payload size after reassembly. Prevents
    ///   resource exhaustion from unbounded block sequences.
    pub fn new(max_payload: usize) -> Self {
        Self {
            buffer: Vec::new(),
            next_num: 0,
            szx: DEFAULT_SZX,
            max_payload,
            complete: false,
        }
    }

    /// Processes an incoming Block1 fragment.
    ///
    /// Validates that blocks arrive in order and that the reassembled payload
    /// does not exceed the configured maximum size.
    ///
    /// Returns `true` when the final block has been received and the full
    /// payload is available via [`payload()`](Self::payload).
    pub fn process_block(&mut self, block: &BlockOption, data: &[u8]) -> CoapResult<bool> {
        if self.complete {
            return Err(CoapError::BlockTransferError(
                "Transfer already complete".to_string(),
            ));
        }

        if block.num != self.next_num {
            return Err(CoapError::BlockTransferError(format!(
                "Expected block {}, received block {}",
                self.next_num, block.num
            )));
        }

        // On first block, adopt the client's SZX preference.
        if block.num == 0 {
            self.szx = block.szx;
        }

        let new_size = self.buffer.len() + data.len();
        if new_size > self.max_payload {
            return Err(CoapError::PayloadTooLarge {
                size: new_size,
                max: self.max_payload,
            });
        }

        self.buffer.extend_from_slice(data);
        self.next_num = block.num + 1;

        if !block.more {
            self.complete = true;
        }

        Ok(self.complete)
    }

    /// Returns the reassembled payload, or `None` if transfer is incomplete.
    pub fn payload(&self) -> Option<&[u8]> {
        if self.complete {
            Some(&self.buffer)
        } else {
            None
        }
    }

    /// Consumes the assembler and returns the reassembled payload.
    ///
    /// Returns `Err` if the transfer is not yet complete.
    pub fn into_payload(self) -> CoapResult<Vec<u8>> {
        if self.complete {
            Ok(self.buffer)
        } else {
            Err(CoapError::BlockTransferError(format!(
                "Transfer incomplete: received {} blocks, waiting for more",
                self.next_num
            )))
        }
    }

    /// Returns the negotiated block size exponent.
    pub fn szx(&self) -> u8 {
        self.szx
    }

    /// Returns whether the final block has been received.
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// Resets the assembler for reuse.
    pub fn reset(&mut self) {
        self.buffer.clear();
        self.next_num = 0;
        self.szx = DEFAULT_SZX;
        self.complete = false;
    }
}

/// Splits a response payload into Block2 chunks for incremental delivery.
///
/// RFC 7959 §2.4: The server sends the first block proactively, then the
/// client requests subsequent blocks by including a Block2 option with the
/// desired block number.
#[derive(Debug)]
pub struct BlockDisassembler {
    /// Full response payload.
    payload: Vec<u8>,
    /// Block size exponent.
    szx: u8,
}

impl BlockDisassembler {
    /// Creates a new disassembler for the given payload and block size.
    ///
    /// # Arguments
    ///
    /// * `payload` - Complete response payload to split into blocks.
    /// * `szx` - Block size exponent. Clamped to [`MAX_SZX`].
    pub fn new(payload: Vec<u8>, szx: u8) -> Self {
        Self {
            payload,
            szx: szx.min(MAX_SZX),
        }
    }

    /// Returns the block data and corresponding Block2 option for the given
    /// block number.
    ///
    /// Returns `None` if `block_num` is beyond the last block.
    pub fn get_block(&self, block_num: u32) -> Option<(Vec<u8>, BlockOption)> {
        let block_size = block_size_from_szx(self.szx);
        let offset = block_num as usize * block_size;

        if offset >= self.payload.len() {
            return None;
        }

        let end = (offset + block_size).min(self.payload.len());
        let data = self.payload[offset..end].to_vec();
        let more = end < self.payload.len();

        let option = BlockOption {
            num: block_num,
            more,
            szx: self.szx,
        };

        Some((data, option))
    }

    /// Returns the total number of blocks required for this payload.
    pub fn total_blocks(&self) -> u32 {
        let block_size = block_size_from_szx(self.szx);
        if self.payload.is_empty() {
            return 1; // Empty payload still requires one (empty) block
        }
        self.payload.len().div_ceil(block_size) as u32
    }

    /// Returns the full payload length in bytes.
    pub fn payload_len(&self) -> usize {
        self.payload.len()
    }

    /// Returns the block size exponent.
    pub fn szx(&self) -> u8 {
        self.szx
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_size_from_szx() {
        assert_eq!(block_size_from_szx(0), 16);
        assert_eq!(block_size_from_szx(1), 32);
        assert_eq!(block_size_from_szx(2), 64);
        assert_eq!(block_size_from_szx(3), 128);
        assert_eq!(block_size_from_szx(4), 256);
        assert_eq!(block_size_from_szx(5), 512);
        assert_eq!(block_size_from_szx(6), 1024);
    }

    #[test]
    fn test_block_size_from_szx_clamps() {
        // Values above 6 should clamp to 1024.
        assert_eq!(block_size_from_szx(7), 1024);
        assert_eq!(block_size_from_szx(255), 1024);
    }

    #[test]
    fn test_szx_from_block_size() {
        assert_eq!(szx_from_block_size(16), Some(0));
        assert_eq!(szx_from_block_size(32), Some(1));
        assert_eq!(szx_from_block_size(64), Some(2));
        assert_eq!(szx_from_block_size(128), Some(3));
        assert_eq!(szx_from_block_size(256), Some(4));
        assert_eq!(szx_from_block_size(512), Some(5));
        assert_eq!(szx_from_block_size(1024), Some(6));
    }

    #[test]
    fn test_szx_from_block_size_invalid() {
        assert_eq!(szx_from_block_size(0), None);
        assert_eq!(szx_from_block_size(8), None);
        assert_eq!(szx_from_block_size(100), None);
        assert_eq!(szx_from_block_size(2048), None);
    }

    #[test]
    fn test_block_option_decode_encode_roundtrip() {
        // Block 0, more=true, szx=5 (512 bytes)
        let opt = BlockOption {
            num: 0,
            more: true,
            szx: 5,
        };
        let encoded = opt.encode();
        let decoded = BlockOption::decode(encoded);
        assert_eq!(decoded, opt);

        // Block 7, more=false, szx=3 (128 bytes)
        let opt = BlockOption {
            num: 7,
            more: false,
            szx: 3,
        };
        let encoded = opt.encode();
        let decoded = BlockOption::decode(encoded);
        assert_eq!(decoded, opt);

        // Large block number
        let opt = BlockOption {
            num: 1000,
            more: true,
            szx: 6,
        };
        let encoded = opt.encode();
        let decoded = BlockOption::decode(encoded);
        assert_eq!(decoded, opt);
    }

    #[test]
    fn test_block_option_offset() {
        let opt = BlockOption {
            num: 3,
            more: true,
            szx: 5,
        };
        // Block 3 at 512 bytes/block = offset 1536
        assert_eq!(opt.offset(), 1536);
    }

    #[test]
    fn test_block_option_block_size() {
        let opt = BlockOption {
            num: 0,
            more: false,
            szx: 4,
        };
        assert_eq!(opt.block_size(), 256);
    }

    #[test]
    fn test_assembler_single_block() {
        let mut assembler = BlockAssembler::new(4096);
        let block = BlockOption {
            num: 0,
            more: false,
            szx: 5,
        };
        let data = b"hello coap";

        let complete = assembler.process_block(&block, data).unwrap();
        assert!(complete);
        assert!(assembler.is_complete());
        assert_eq!(assembler.payload(), Some(data.as_slice()));
    }

    #[test]
    fn test_assembler_multi_block() {
        let mut assembler = BlockAssembler::new(4096);

        let block0 = BlockOption {
            num: 0,
            more: true,
            szx: 5,
        };
        let block1 = BlockOption {
            num: 1,
            more: true,
            szx: 5,
        };
        let block2 = BlockOption {
            num: 2,
            more: false,
            szx: 5,
        };

        assert!(!assembler.process_block(&block0, b"aaa").unwrap());
        assert!(!assembler.process_block(&block1, b"bbb").unwrap());
        assert!(assembler.process_block(&block2, b"ccc").unwrap());

        assert_eq!(assembler.payload(), Some(b"aaabbbccc".as_slice()));
    }

    #[test]
    fn test_assembler_out_of_order() {
        let mut assembler = BlockAssembler::new(4096);

        let block0 = BlockOption {
            num: 0,
            more: true,
            szx: 5,
        };
        let block2 = BlockOption {
            num: 2,
            more: false,
            szx: 5,
        };

        assembler.process_block(&block0, b"aaa").unwrap();
        // Skip block 1 — should fail
        let err = assembler.process_block(&block2, b"ccc").unwrap_err();
        assert!(matches!(err, CoapError::BlockTransferError(_)));
    }

    #[test]
    fn test_assembler_payload_too_large() {
        let mut assembler = BlockAssembler::new(5);

        let block = BlockOption {
            num: 0,
            more: false,
            szx: 5,
        };

        let err = assembler.process_block(&block, b"too large").unwrap_err();
        assert!(matches!(err, CoapError::PayloadTooLarge { .. }));
    }

    #[test]
    fn test_assembler_into_payload_incomplete() {
        let assembler = BlockAssembler::new(4096);
        let err = assembler.into_payload().unwrap_err();
        assert!(matches!(err, CoapError::BlockTransferError(_)));
    }

    #[test]
    fn test_assembler_reset() {
        let mut assembler = BlockAssembler::new(4096);
        let block = BlockOption {
            num: 0,
            more: false,
            szx: 5,
        };
        assembler.process_block(&block, b"data").unwrap();
        assert!(assembler.is_complete());

        assembler.reset();
        assert!(!assembler.is_complete());
        assert_eq!(assembler.payload(), None);
    }

    #[test]
    fn test_disassembler_single_block() {
        let payload = b"small".to_vec();
        let disasm = BlockDisassembler::new(payload.clone(), DEFAULT_SZX);

        assert_eq!(disasm.total_blocks(), 1);

        let (data, opt) = disasm.get_block(0).unwrap();
        assert_eq!(data, payload);
        assert!(!opt.more);
        assert_eq!(opt.num, 0);

        assert!(disasm.get_block(1).is_none());
    }

    #[test]
    fn test_disassembler_multi_block() {
        // 100 bytes with szx=2 (64-byte blocks) = 2 blocks
        let payload = vec![0xAB; 100];
        let disasm = BlockDisassembler::new(payload, 2);

        assert_eq!(disasm.total_blocks(), 2);

        let (data0, opt0) = disasm.get_block(0).unwrap();
        assert_eq!(data0.len(), 64);
        assert!(opt0.more);
        assert_eq!(opt0.num, 0);

        let (data1, opt1) = disasm.get_block(1).unwrap();
        assert_eq!(data1.len(), 36);
        assert!(!opt1.more);
        assert_eq!(opt1.num, 1);

        assert!(disasm.get_block(2).is_none());
    }

    #[test]
    fn test_disassembler_exact_boundary() {
        // Exactly 128 bytes with szx=3 (128-byte blocks) = 1 block
        let payload = vec![0xCD; 128];
        let disasm = BlockDisassembler::new(payload, 3);

        assert_eq!(disasm.total_blocks(), 1);

        let (data, opt) = disasm.get_block(0).unwrap();
        assert_eq!(data.len(), 128);
        assert!(!opt.more);
    }

    #[test]
    fn test_disassembler_empty_payload() {
        let disasm = BlockDisassembler::new(Vec::new(), DEFAULT_SZX);
        assert_eq!(disasm.total_blocks(), 1);
    }

    #[test]
    fn test_assembler_disassembler_roundtrip() {
        let original = vec![0x42; 2000]; // ~4 blocks at 512 bytes
        let disasm = BlockDisassembler::new(original.clone(), DEFAULT_SZX);
        let mut assembler = BlockAssembler::new(4096);

        for i in 0..disasm.total_blocks() {
            let (data, opt) = disasm.get_block(i).unwrap();
            assembler.process_block(&opt, &data).unwrap();
        }

        assert!(assembler.is_complete());
        let reassembled = assembler.into_payload().unwrap();
        assert_eq!(reassembled, original);
    }
}
