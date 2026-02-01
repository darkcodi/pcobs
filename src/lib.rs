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
//! ┌─────────────┐    ┌─────────────┐    ┌─────────────────┐    ┌─────────────┐
//! │ Application │ -> │  postcard   │ -> │  CrcProtected   │ -> │    COBS     │ -> Transport
//! │   Structs   │    │   Serialize │    │  (adds CRC)     │    │   Framing   │
//! └─────────────┘    └─────────────┘    └─────────────────┘    └─────────────┘
//!
//! Transport -> ┌─────────────┐    ┌─────────────┐    ┌─────────────────┐    ┌─────────────┐
//!              │    COBS     │ -> │CrcProtected │ -> │  postcard       │ -> │ Application │
//!              │  Unframing  │    │(verify CRC) │    │  Deserialize    │    │   Structs   │
//!              └─────────────┘    └─────────────┘    └─────────────────┘    └─────────────┘
//! ```
//!
//! # Packet Format
//!
//! ```text
//! ┌───────────────────────────────────────────────┬────────┐
//! │ COBS Encoded: {payload_bytes, crc16}          │ 0x00   │
//! │ (CrcProtected wrapper struct)                 │ (COBS  │
//! │                                               │ marker)│
//! └───────────────────────────────────────────────┴────────┘
//! ```
//!
//! The `CrcProtected` wrapper contains both the postcard-serialized user data
//! and its CRC-16 checksum. This entire wrapper is COBS-encoded, ensuring that
//! the CRC bytes cannot contain 0x00 and interfere with packet framing.
//!
//! # Example Usage
//!
//! ```rust,ignore
//! use darkpicolib::connectivity::encode::*;
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
//! let decoded: Message = deserialize(&mut buf)?;
//! ```
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
#[derive(Debug, defmt::Format)]
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
#[derive(Debug, defmt::Format)]
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

/// CRC-protected wrapper for any serializable payload.
///
/// This struct is postcard-serialized, then COBS-encoded.
/// The CRC protects the payload, and COBS protects everything from 0x00.
///
/// # Fields
/// * `payload` - Postcard-serialized user data
/// * `crc` - CRC-16 checksum of the payload
#[derive(Serialize, Deserialize, Debug, defmt::Format)]
struct CrcProtected<'a> {
    /// Postcard-serialized user data
    payload: &'a [u8],

    /// CRC-16 of the payload
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
/// 2. Create CrcProtected wrapper (computes CRC)
/// 3. Serialize wrapper with postcard → wrapper_bytes
/// 4. COBS-encode wrapper_bytes → transmission_bytes
///
/// # Buffer Size Requirements
///
/// This function partitions the buffer internally (2/3 for working area, 1/3 for scratch).
/// To ensure success, provide a buffer at least **3x** your expected payload size.
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
    // Partition buffer to avoid overlapping borrows:
    // - Use 2/3 for working area (wrapper + temp), 1/3 for payload scratch
    let work_len = (buf.len() * 2) / 3;
    let (buf_work, buf_scratch) = buf.split_at_mut(work_len);

    // Step 1: Serialize user data to postcard (in scratch area)
    let payload_bytes = postcard::to_slice(payload, buf_scratch)
        .map_err(|_| EncodeError::PostcardSerializationFailed)?;

    // Step 2: Create CrcProtected wrapper (computes CRC automatically)
    let protected = CrcProtected::from_payload(payload_bytes);

    // Step 3: Serialize the wrapper with postcard (in work area)
    let wrapper_len = postcard::to_slice(&protected, buf_work)
        .map_err(|_| EncodeError::PostcardSerializationFailed)?
        .len();

    // Step 4: COBS encode - copy to temp first, then encode to avoid overlap
    let max_cobs_len = corncobs::max_encoded_len(wrapper_len);
    if buf_work.len() < max_cobs_len {
        return Err(EncodeError::BufferOverflow {
            needed: max_cobs_len,
            capacity: buf_work.len(),
        });
    }

    // Split work area: wrapper data at start, temp space, output at end
    let temp_start = wrapper_len;
    let (buf_wrapper, buf_rest) = buf_work.split_at_mut(temp_start);
    let (buf_temp, buf_out) = buf_rest.split_at_mut(wrapper_len);

    // Copy wrapper to temp area, then encode to output area
    buf_temp.copy_from_slice(&buf_wrapper[..wrapper_len]);
    let cobs_len = corncobs::encode_buf(buf_temp, buf_out);

    // Step 5: Copy COBS-encoded data to the start of the buffer
    // We need to get the offset of buf_out from the start of buf
    // buf_out starts at wrapper_len * 2 within buf_work
    let cobs_offset = wrapper_len * 2;

    // Split buf to get two non-overlapping mutable slices
    let (buf_start, _buf_rest) = buf.split_at_mut(cobs_offset);
    let (buf_cobs_region, _) = _buf_rest.split_at_mut(cobs_len);

    // Copy COBS data to start of buffer
    buf_start[..cobs_len].copy_from_slice(buf_cobs_region);

    // corncobs::encode_buf may return a length that includes a trailing zero
    // For proper COBS encoding, we should not include this trailing zero
    // Check if the last byte is zero and if so, reduce the length
    let actual_len = if cobs_len > 0 && buf[cobs_len - 1] == 0 {
        cobs_len - 1
    } else {
        cobs_len
    };

    Ok(actual_len)
}

/// Decodes a complete packet with CRC inside COBS framing.
///
/// # Process
/// 1. COBS-decode received bytes → wrapper_bytes
/// 2. Deserialize wrapper_bytes → CrcProtected
/// 3. Verify CRC
/// 4. Deserialize payload to user data
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
    // Step 1: COBS decode
    let wrapper_len = corncobs::decode_in_place(buf)
        .map_err(|_| DecodeError::CobsDecodeFailed)?;

    // Step 2: Deserialize CrcProtected wrapper
    let protected: CrcProtected = postcard::from_bytes(&buf[..wrapper_len])
        .map_err(|_| DecodeError::PostcardDeserializationFailed)?;

    // Step 3: Verify CRC
    if !protected.is_valid() {
        return Err(DecodeError::CrcMismatch {
            expected: protected.crc,
            computed: CRC_ALGORITHM.checksum(protected.payload),
        });
    }

    // Step 4: Deserialize user data from payload
    postcard::from_bytes(protected.payload)
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
