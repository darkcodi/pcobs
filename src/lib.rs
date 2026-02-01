//! Binary encoding for structured data communication.
//!
//! This module provides a complete protocol implementation featuring:
//! - **COBS framing** via `corncobs` - eliminates delimiter issues in binary data
//! - **CRC-16 error detection** via `crc` - catches transmission errors
//! - **postcard serialization** - compact no_std serde format
//!
//! # Protocol Stack
//!
//! ```text
//! ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
//! │ Application │ -> │  postcard   │ -> │  + CRC-16   │ -> │    COBS     │ -> Transport
//! │   Structs   │    │   Serialize │    │  (appended) │    │   Framing   │
//! └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
//!
//! Transport -> ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
//!              │    COBS     │ -> │  CRC-16     │ -> │  postcard   │ -> │ Application │
//!              │  Unframing  │    │  Verify     │    │  Deserialize│    │   Structs   │
//!              └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
//! ```
//!
//! # Packet Format
//!
//! ```text
//! ┌───────────────────────────────────────────────┬────────┐
//! │ COBS Encoded: {postcard_payload, crc16_le}    │ 0x00   │
//! │                                               │ (COBS  │
//! │                                               │ marker)│
//! └───────────────────────────────────────────────┴────────┘
//! ```
//!
//! The protocol is optimized for minimal overhead:
//! - User data is serialized once with postcard
//! - CRC-16 is appended directly (no double serialization)
//! - The combined payload is COBS-encoded to eliminate zero bytes
//!
//! # Example Usage
//!
//! ```rust,ignore
//! use framed_postcard::{serialize, deserialize};
//!
//! // Create a message
//! let msg = SensorData {
//!     sensor_id: 0,
//!     value: 2345,
//!     timestamp: 12345,
//! };
//!
//! // Encode for transmission
//! let mut buf = [0u8; 512];
//! let len = serialize(&msg, &mut buf)?;
//! transport.write(&buf[..len]).await?;
//! transport.write(&[0x00]).await?; // COBS delimiter
//!
//! // Decode received data (after accumulating until 0x00)
//! let decoded: SensorData = deserialize(&mut buf)?;
//! ```
//!
//! # Buffer Size Requirements
//!
//! The buffer is split 50/50 between input and COBS output. The maximum payload
//! size is approximately **45% of buffer size** (accounts for payload + CRC + COBS overhead).
//!
//! For example, a 512-byte buffer can handle payloads up to ~230 bytes.
//!
//! # Transport Agnostic
//!
//! This protocol is transport-agnostic and can be used over any byte stream:
//! - UART/Serial
//! - TCP sockets
//! - USB bulk endpoints
//! - Radio protocols
//! - File I/O for testing

#![no_std]
#![allow(dead_code)]

use core::fmt;
use serde::{Deserialize, Serialize};

/// CRC-16 algorithm used for packet verification.
///
/// CRC-16-IBM_SDLC (Poly 0x1021) is commonly used in embedded systems.
const CRC_ALGORITHM: crc::Crc<u16> = crc::Crc::<u16>::new(&crc::CRC_16_IBM_SDLC);

/// Error during encoding (serialization).
#[derive(Debug)]
pub enum EncodeError {
    /// Postcard serialization failed - data type not supported
    PostcardSerializationFailed,

    /// Buffer too small for the data
    BufferOverflow {
        needed: usize,
        capacity: usize,
    },
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PostcardSerializationFailed => write!(f, "Postcard serialization failed"),
            Self::BufferOverflow { needed, capacity } => {
                write!(f, "Buffer overflow: needed {needed}, had {capacity}")
            }
        }
    }
}

impl core::error::Error for EncodeError {}

/// Error during decoding (deserialization).
#[derive(Debug)]
pub enum DecodeError {
    /// COBS decoding failed - invalid framing (packet corruption)
    CobsDecodeFailed,

    /// Postcard deserialization failed - invalid data format
    PostcardDeserializationFailed,

    /// CRC mismatch - packet may be corrupted
    CrcMismatch {
        expected: u16,
        computed: u16,
    },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CobsDecodeFailed => write!(f, "COBS decoding failed"),
            Self::PostcardDeserializationFailed => write!(f, "Postcard deserialization failed"),
            Self::CrcMismatch { expected, computed } => {
                write!(f, "CRC mismatch: expected {expected}, got {computed}")
            }
        }
    }
}

impl core::error::Error for DecodeError {}

/// CRC-protected wrapper for byte slices.
///
/// This struct is used internally for testing. The actual protocol
/// manually appends the CRC to avoid double serialization overhead.
///
/// # Fields
/// * `payload` - Byte slice to protect
/// * `crc` - CRC-16 checksum of the payload
#[derive(Serialize, Deserialize, Debug)]
struct CrcProtected<'a> {
    /// Payload bytes
    payload: &'a [u8],

    /// CRC-16 of the payload (little-endian)
    crc: u16,
}

impl<'a> CrcProtected<'a> {
    /// Create a new CrcProtected wrapper with given payload and CRC.
    fn new(payload: &'a [u8], crc: u16) -> Self {
        Self { payload, crc }
    }

    /// Create a new CrcProtected wrapper, computing the CRC automatically.
    fn from_payload(payload: &'a [u8]) -> Self {
        let crc = CRC_ALGORITHM.checksum(payload);
        Self { payload, crc }
    }

    /// Verify the CRC is valid for the contained payload.
    fn is_valid(&self) -> bool {
        self.crc == CRC_ALGORITHM.checksum(self.payload)
    }
}

/// Encodes a complete packet with CRC inside COBS framing.
///
/// # Process
/// 1. Serialize user data with postcard → payload_bytes
/// 2. Append CRC-16 checksum to payload_bytes (no double serialization!)
/// 3. COBS-encode → transmission_bytes
///
/// # Buffer Size Requirements
///
/// Buffer is split 50/50 between input and COBS output. The maximum payload size
/// is approximately **45% of buffer size** (accounts for payload + CRC + COBS overhead).
///
/// For example, a 512-byte buffer can handle payloads up to ~230 bytes.
///
/// # Arguments
/// * `payload` - Data to encode (must implement Serialize)
/// * `buf` - Output buffer (see size requirements above)
///
/// # Returns
/// Number of bytes written to `buf`
pub fn serialize<T>(payload: &T, buf: &mut [u8]) -> Result<usize, EncodeError>
where
    T: serde::Serialize,
{
    // Buffer layout: COBS output at start, wrapper input at end.
    // COBS can expand by ~1.33x worst-case, so we split roughly evenly.
    let split_idx = buf.len() / 2;

    // Step 1: Serialize user data to end of buffer (input area)
    let payload_len = postcard::to_slice(payload, &mut buf[split_idx..])
        .map_err(|_| EncodeError::PostcardSerializationFailed)?
        .len();

    // Step 2: Append CRC (manually construct wrapper - no double serialization!)
    let wrapper_len = payload_len + 2; // payload + u16 CRC
    if split_idx + wrapper_len > buf.len() {
        return Err(EncodeError::BufferOverflow {
            needed: wrapper_len,
            capacity: buf.len() - split_idx,
        });
    }
    let payload_start = split_idx;
    let crc_start = payload_start + payload_len;
    let crc = CRC_ALGORITHM.checksum(&buf[payload_start..crc_start]);
    buf[crc_start] = crc as u8;
    buf[crc_start + 1] = (crc >> 8) as u8;

    // Step 3: COBS encode from input (at end) to output (at start)
    let max_cobs_len = corncobs::max_encoded_len(wrapper_len);
    if max_cobs_len > split_idx {
        return Err(EncodeError::BufferOverflow {
            needed: max_cobs_len,
            capacity: split_idx,
        });
    }
    // Use split_at_mut to get non-overlapping mutable slices
    let (buf_out, buf_in) = buf.split_at_mut(split_idx);
    let cobs_len = corncobs::encode_buf(&buf_in[..wrapper_len], buf_out);

    // corncobs::encode_buf may include a trailing zero (COBS delimiter)
    // The delimiter is added by the transport layer, not part of the packet
    let actual_len = if cobs_len > 0 && buf_out[cobs_len - 1] == 0 {
        cobs_len - 1
    } else {
        cobs_len
    };

    Ok(actual_len)
}

/// Decodes a complete packet with CRC inside COBS framing.
///
/// # Process
/// 1. COBS-decode received bytes → payload_bytes + crc16
/// 2. Verify CRC
/// 3. Deserialize payload to user data
///
/// # Arguments
/// * `buf` - Buffer containing COBS-encoded packet
///
/// # Returns
/// Decoded user data of type T
pub fn deserialize<T>(
    buf: &mut [u8],
) -> Result<T, DecodeError>
where
    T: serde::de::DeserializeOwned,
{
    // Step 1: COBS decode (in-place)
    let wrapper_len = corncobs::decode_in_place(buf)
        .map_err(|_| DecodeError::CobsDecodeFailed)?;

    // Step 2: Extract payload and CRC (format: [payload_bytes][crc16])
    if wrapper_len < 2 {
        return Err(DecodeError::PostcardDeserializationFailed);
    }
    let payload_len = wrapper_len - 2;
    let payload = &buf[..payload_len];
    let crc_received = u16::from_le_bytes([buf[payload_len], buf[payload_len + 1]]);

    // Step 3: Verify CRC (compute once, reuse for error if needed)
    let crc_computed = CRC_ALGORITHM.checksum(payload);
    if crc_received != crc_computed {
        return Err(DecodeError::CrcMismatch {
            expected: crc_received,
            computed: crc_computed,
        });
    }

    // Step 4: Deserialize user data from payload
    postcard::from_bytes(payload)
        .map_err(|_| DecodeError::PostcardDeserializationFailed)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use std::string::ToString;

    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct TestMessage {
        id: u32,
        value: i32,
        data: [u8; 16],
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct EmptyStruct {}

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct NestedStruct {
        inner: InnerData,
        flag: bool,
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct InnerData {
        a: u8,
        b: u16,
        c: u32,
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    enum TestEnum {
        VariantA,
        VariantB(u32),
        VariantC { x: i32, y: i32 },
    }

    #[test]
    fn test_roundtrip_simple_message() {
        let original = TestMessage {
            id: 42,
            value: -12345,
            data: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        };

        let mut buf = [0u8; 512];
        let len = serialize(&original, &mut buf).expect("serialize failed");

        let result: TestMessage = deserialize(&mut buf[..len]).expect("deserialize failed");

        assert_eq!(result, original);
    }

    #[test]
    fn test_roundtrip_empty_struct() {
        let original = EmptyStruct {};
        let mut buf = [0u8; 64];
        let len = serialize(&original, &mut buf).expect("serialize failed");

        let result: EmptyStruct = deserialize(&mut buf[..len]).expect("deserialize failed");

        assert_eq!(result, original);
    }

    #[test]
    fn test_roundtrip_nested_struct() {
        let original = NestedStruct {
            inner: InnerData { a: 1, b: 256, c: 65536 },
            flag: true,
        };

        let mut buf = [0u8; 128];
        let len = serialize(&original, &mut buf).expect("serialize failed");

        let result: NestedStruct = deserialize(&mut buf[..len]).expect("deserialize failed");

        assert_eq!(result, original);
    }

    #[test]
    fn test_roundtrip_enum() {
        let variants = [
            TestEnum::VariantA,
            TestEnum::VariantB(42),
            TestEnum::VariantC { x: -10, y: 20 },
        ];

        for original in variants {
            let mut buf = [0u8; 128];
            let len = serialize(&original, &mut buf).expect("serialize failed");

            let result: TestEnum = deserialize(&mut buf[..len]).expect("deserialize failed");

            assert_eq!(result, original);
        }
    }

    #[test]
    fn test_roundtrip_various_primitives() {
        // Test u8
        let original_u8: u8 = 255;
        let mut buf = [0u8; 64];
        let len = serialize(&original_u8, &mut buf).unwrap();
        let result_u8: u8 = deserialize(&mut buf[..len]).unwrap();
        assert_eq!(result_u8, original_u8);

        // Test i8
        let original_i8: i8 = -128;
        let len = serialize(&original_i8, &mut buf).unwrap();
        let result_i8: i8 = deserialize(&mut buf[..len]).unwrap();
        assert_eq!(result_i8, original_i8);

        // Test u64
        let original_u64: u64 = 0x123456789ABCDEF0;
        let len = serialize(&original_u64, &mut buf).unwrap();
        let result_u64: u64 = deserialize(&mut buf[..len]).unwrap();
        assert_eq!(result_u64, original_u64);

        // Test bool
        let original_bool: bool = true;
        let len = serialize(&original_bool, &mut buf).unwrap();
        let result_bool: bool = deserialize(&mut buf[..len]).unwrap();
        assert_eq!(result_bool, original_bool);

        // Test Option
        let original_some: Option<u32> = Some(42);
        let len = serialize(&original_some, &mut buf).unwrap();
        let result_some: Option<u32> = deserialize(&mut buf[..len]).unwrap();
        assert_eq!(result_some, original_some);

        let original_none: Option<u32> = None;
        let len = serialize(&original_none, &mut buf).unwrap();
        let result_none: Option<u32> = deserialize(&mut buf[..len]).unwrap();
        assert_eq!(result_none, original_none);
    }

    #[test]
    fn test_roundtrip_byte_array() {
        let original: [u8; 8] = [0, 1, 2, 3, 4, 5, 6, 7];
        let mut buf = [0u8; 128];
        let len = serialize(&original, &mut buf).expect("serialize failed");

        let result: [u8; 8] = deserialize(&mut buf[..len]).expect("deserialize failed");

        assert_eq!(result, original);
    }

    #[test]
    fn test_roundtrip_large_array() {
        let original: [u32; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let mut buf = [0u8; 512];
        let len = serialize(&original, &mut buf).expect("serialize failed");

        let result: [u32; 16] = deserialize(&mut buf[..len]).expect("deserialize failed");

        assert_eq!(result, original);
    }

    #[test]
    fn test_crc_mismatch_detection() {
        let original = TestMessage {
            id: 42,
            value: -12345,
            data: [0xFF; 16],
        };

        let mut buf = [0u8; 512];
        let len = serialize(&original, &mut buf).expect("serialize failed");

        // Corrupt a byte in the middle of the encoded data
        // The corruption will be detected when the CRC is verified
        buf[len / 2] = buf[len / 2].wrapping_add(1);

        let result: Result<TestMessage, DecodeError> = deserialize(&mut buf[..len]);

        match result {
            Err(DecodeError::CrcMismatch { expected, computed }) => {
                // CRC mismatch is expected
                assert_ne!(expected, computed);
            }
            _ => panic!("Expected CrcMismatch error, got {:?}", result),
        }
    }

    #[test]
    fn test_cobs_decode_failure() {
        // Create invalid COBS data - starts with 0x00 which is invalid for COBS
        let invalid_cobs = [0x00, 0x01, 0x02, 0x03];

        let result: Result<TestMessage, DecodeError> = deserialize(&mut invalid_cobs.clone());

        match result {
            Err(DecodeError::CobsDecodeFailed) => {
                // Expected error - COBS decode failed
            }
            Err(DecodeError::PostcardDeserializationFailed) => {
                // Also acceptable - COBS might decode but produces invalid postcard data
            }
            _ => panic!("Expected CobsDecodeFailed or PostcardDeserializationFailed error, got {:?}", result),
        }
    }

    #[test]
    fn test_buffer_overflow() {
        // Use nested struct to create a large payload
        let large_data = NestedStruct {
            inner: InnerData { a: 255, b: 0xFFFF, c: 0xFFFFFFFF },
            flag: true,
        };

        // Buffer that's too small (only 4 bytes)
        let mut buf = [0u8; 4];

        let result: Result<usize, EncodeError> = serialize(&large_data, &mut buf);

        // With such a small buffer, postcard serialization will fail
        // This is expected behavior
        match result {
            Err(EncodeError::PostcardSerializationFailed) => {
                // Expected - buffer too small for postcard
            }
            Err(EncodeError::BufferOverflow { .. }) => {
                // Also acceptable
            }
            _ => panic!("Expected PostcardSerializationFailed or BufferOverflow error, got {:?}", result),
        }
    }

    #[test]
    fn test_empty_buffer_serialization() {
        let data = 42u32;
        let mut buf = [0u8; 0];

        let result: Result<usize, EncodeError> = serialize(&data, &mut buf);

        match result {
            Err(EncodeError::PostcardSerializationFailed) => {
                // Expected - buffer too small for postcard
            }
            Err(EncodeError::BufferOverflow { .. }) => {
                // Also acceptable
            }
            _ => panic!("Expected error for empty buffer, got {:?}", result),
        }
    }

    #[test]
    fn test_zero_values() {
        let original = TestMessage {
            id: 0,
            value: 0,
            data: [0u8; 16],
        };

        let mut buf = [0u8; 512];
        let len = serialize(&original, &mut buf).expect("serialize failed");

        let result: TestMessage = deserialize(&mut buf[..len]).expect("deserialize failed");

        assert_eq!(result, original);
    }

    #[test]
    fn test_multiple_messages_same_buffer() {
        let msg1 = TestMessage {
            id: 1,
            value: 100,
            data: [10; 16],
        };
        let msg2 = TestMessage {
            id: 2,
            value: 200,
            data: [20; 16],
        };

        let mut buf = [0u8; 512];

        // Encode and decode first message
        let len1 = serialize(&msg1, &mut buf).expect("serialize failed");
        let decoded1: TestMessage = deserialize(&mut buf[..len1]).expect("deserialize failed");
        assert_eq!(decoded1, msg1);

        // Reuse buffer for second message
        let len2 = serialize(&msg2, &mut buf).expect("serialize failed");
        let decoded2: TestMessage = deserialize(&mut buf[..len2]).expect("deserialize failed");
        assert_eq!(decoded2, msg2);
    }

    #[test]
    fn test_corrupted_crc_field() {
        let original: u32 = 12345;
        let mut buf = [0u8; 64];
        let len = serialize(&original, &mut buf).expect("serialize failed");

        // Since COBS encoding makes finding the exact CRC field tricky,
        // we'll just corrupt something and expect a CRC mismatch
        buf[1] = buf[1].wrapping_add(1);

        let result: Result<u32, DecodeError> = deserialize(&mut buf[..len]);

        match result {
            Err(DecodeError::CrcMismatch { .. }) => {
                // Expected
            }
            Err(DecodeError::CobsDecodeFailed) => {
                // Also acceptable - corruption could make COBS invalid
            }
            _ => panic!("Expected CrcMismatch or CobsDecodeFailed error, got {:?}", result),
        }
    }

    #[test]
    fn test_large_message() {
        // Use size 32 which is supported by default by serde
        let original: [u64; 32] = {
            let mut arr = [0u64; 32];
            let mut i = 0;
            while i < 32 {
                arr[i] = i as u64;
                i += 1;
            }
            arr
        };
        let mut buf = [0u8; 1024];
        let len = serialize(&original, &mut buf).expect("serialize failed");

        let result: [u64; 32] = deserialize(&mut buf[..len]).expect("deserialize failed");

        assert_eq!(result, original);
    }

    #[test]
    fn test_postcard_deserialization_failure() {
        // Manually craft a COBS-encoded packet that decodes to invalid postcard data
        // We'll create valid COBS but invalid postcard wrapper

        // First, encode a valid message
        let original: u32 = 42;
        let mut buf = [0u8; 64];
        let len = serialize(&original, &mut buf).expect("serialize failed");

        // Truncate the buffer to cause postcard deserialization to fail
        // The COBS decode might succeed or fail depending on where we cut
        // Let's cut it very short to ensure something fails
        let truncated_len = len / 2;

        let result: Result<u32, DecodeError> = deserialize(&mut buf[..truncated_len]);

        // Either COBS decode or postcard deserialize should fail
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_error_display() {
        let err = EncodeError::PostcardSerializationFailed;
        assert_eq!(err.to_string(), "Postcard serialization failed");

        let err = EncodeError::BufferOverflow { needed: 100, capacity: 50 };
        assert_eq!(err.to_string(), "Buffer overflow: needed 100, had 50");
    }

    #[test]
    fn test_decode_error_display() {
        let err = DecodeError::CobsDecodeFailed;
        assert_eq!(err.to_string(), "COBS decoding failed");

        let err = DecodeError::PostcardDeserializationFailed;
        assert_eq!(err.to_string(), "Postcard deserialization failed");

        let err = DecodeError::CrcMismatch { expected: 1234, computed: 5678 };
        assert_eq!(err.to_string(), "CRC mismatch: expected 1234, got 5678");
    }

    #[test]
    fn test_crc_protected_new() {
        let payload = b"test payload";
        let crc = CRC_ALGORITHM.checksum(payload);
        let protected = CrcProtected::new(payload, crc);

        assert_eq!(protected.payload, payload);
        assert_eq!(protected.crc, crc);
        assert!(protected.is_valid());
    }

    #[test]
    fn test_crc_protected_from_payload() {
        let payload = b"test payload";
        let protected = CrcProtected::from_payload(payload);

        assert_eq!(protected.payload, payload);
        assert!(protected.is_valid());
    }

    #[test]
    fn test_crc_protected_invalid() {
        let payload = b"test payload";
        let mut protected = CrcProtected::from_payload(payload);

        // Corrupt the CRC
        protected.crc = protected.crc.wrapping_add(1);

        assert!(!protected.is_valid());
    }

    #[test]
    fn test_cobs_encoded_output_no_zero_bytes() {
        // COBS encoding should produce no zero bytes (except for the delimiter)
        let original = TestMessage {
            id: 42,
            value: -12345,
            data: [5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60, 65, 70, 75, 80],
        };

        let mut buf = [0u8; 512];
        let len = serialize(&original, &mut buf).expect("serialize failed");

        // The encoded data should contain no zero bytes
        for (i, &byte) in buf[..len].iter().enumerate() {
            assert_ne!(byte, 0, "COBS encoding should not produce zero bytes at index {}", i);
        }
    }

    #[test]
    fn test_single_byte_values() {
        for val in [0u8, 1, 128, 255] {
            let mut buf = [0u8; 64];
            let len = serialize(&val, &mut buf).expect("serialize failed");
            let result: u8 = deserialize(&mut buf[..len]).expect("deserialize failed");
            assert_eq!(result, val);
        }
    }

    #[test]
    fn test_tuple_roundtrip() {
        let original = (42u32, -100i32, true);
        let mut buf = [0u8; 128];
        let len = serialize(&original, &mut buf).expect("serialize failed");

        let result: (u32, i32, bool) = deserialize(&mut buf[..len]).expect("deserialize failed");

        assert_eq!(result, original);
    }

    #[test]
    fn test_unit_type_roundtrip() {
        let original = ();
        let mut buf = [0u8; 64];
        let len = serialize(&original, &mut buf).expect("serialize failed");

        let result: () = deserialize(&mut buf[..len]).expect("deserialize failed");

        assert_eq!(result, original);
    }

    #[test]
    fn test_result_type_roundtrip() {
        // Result with owned error type (u32 instead of &str to avoid lifetime issues)
        let original_ok: Result<u32, u32> = Ok(42);
        let mut buf = [0u8; 64];
        let len = serialize(&original_ok, &mut buf).expect("serialize failed");
        let result_ok: Result<u32, u32> = deserialize(&mut buf[..len]).expect("deserialize failed");
        assert_eq!(result_ok, original_ok);

        let original_err: Result<u32, u32> = Err(999);
        let len = serialize(&original_err, &mut buf).expect("serialize failed");
        let result_err: Result<u32, u32> = deserialize(&mut buf[..len]).expect("deserialize failed");
        assert_eq!(result_err, original_err);
    }
}
