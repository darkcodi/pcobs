<div align="center">

# 📦 pcobs

**postcard + crc + cobs = structured data over anything**

[![Crates.io](https://img.shields.io/crates/v/pcobs)](https://crates.io/crates/pcobs)
[![Documentation](https://docs.rs/pcobs/badge.svg)](https://docs.rs/pcobs)
[![Rust](https://img.shields.io/badge/rust-1.82%2B-orange.svg)](https://www.rust-lang.org)
[![no_std](https://img.shields.io/badge/no__std-support-brightgreen.svg)](https://github.com/rust-embedded/wg)
[![zero-alloc](https://img.shields.io/badge/alloc--free-brightgreen.svg)](https://github.com/rust-embedded/wg)

**`no_std` • zero-allocation • embedded-ready**

</div>

---

## 💡 Why?

You've got structs. You need to send them over UART/TCP/USB/whatever.

**pcobs** gives you:
- 📝 **postcard** — compact serde serialization, `no_std` friendly
- 🔐 **CRC-16** — catch corrupted packets
- 🧱 **COBS framing** — zero-byte delimiters, no escaping hell
- 💾 **Zero allocations** — stack-only, no `Vec`/`Box`/`HashMap`
- ⚡ **`no_std`** — works on bare-metal, no OS required

Two functions. That's it.

```rust
let encoded = serialize(&my_struct, &mut buf)?;
let decoded = deserialize::<MyStruct>(&mut buf)?;
```

---

## 🚀 Quick Start

```toml
[dependencies]
pcobs = "0.1"
serde = { version = "1", features = ["derive"] }
```

```rust
use pcobs::{serialize, deserialize};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct SensorData {
    id: u8,
    value: f32,
    flags: u16,
}

// Sender
let data = SensorData { id: 1, value: 23.5, flags: 0xABCD };
let mut buf = [0u8; 256];
let len = serialize(&data, &mut buf)?;
stream.write_all(&buf[..len])?;
stream.write_all(&[0x00])?; // COBS delimiter

// Receiver
let mut buf = [0u8; 256];
let n = read_until_delimiter(stream, &mut buf)?;
let decoded: SensorData = deserialize(&mut buf[..n])?;
```

---

## 📐 Packet Format

```
┌────────────────────────────────────────┬──────┐
│ COBS(payload + CRC16)                  │ 0x00 │
│                                        │      │
│ • payload = postcard(your data)        │ delim│
│ • CRC-16 = checksum                    │      │
│ • COBS = no zeros in encoded data      │      │
└────────────────────────────────────────┴──────┘
```

---

## 📏 Buffer Math

Encoding is done **in-place** - no buffer splitting needed. COBS adds minimal overhead (at most 1 byte per 254 bytes), plus 2 bytes for CRC.

| Buffer | Max Payload |
|--------|-------------|
| 64 B   | ~60 B       |
| 256 B  | ~252 B      |
| 512 B  | ~508 B      |
| 1024 B | ~1018 B     |

---

## 🛠️ Transport Agnostic

Works over anything that moves bytes:

- 📡 UART / Serial
- 🌐 TCP sockets
- 🔌 USB bulk endpoints
- 📻 Radio (LoRa, BLE, etc.)
- 🧪 Pipes / files for testing

---

## ⚡ Features

- **`no_std`** — works on bare-metal, no OS required
- **Zero allocations** — stack-only, no heap, embedded-friendly
- `serde` — derive your structs
- Single-pass encoding
- In-place decoding
