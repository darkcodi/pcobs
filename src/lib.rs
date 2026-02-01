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

    Ok(cobs_len)
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
