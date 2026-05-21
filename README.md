<p align="center">
  <img src="assets/logo-bindkey.png" alt="BindKey Logo" width="450"/>
</p>

<h1 align="center">BindKey</h1>

<p align="center"><i>Security at your fingertip</i></p>

---

## Project overview

**BindKey** is a hardware cybersecurity solution that resolves the trade-off between offline data security and the need for enterprise collaboration. The device sits between the host PC and a standard storage medium (USB stick, SSD, SD reader) and acts as a **legitimate Man-in-the-Middle**: every byte that flows through it is sealed and encrypted on-the-fly in **AES-256-GCM** by a secure microcontroller, and is decrypted only for users who have been **biometrically** authenticated and whose BindKey holds the access rights to the target volume. Any modification performed outside the BindKey environment makes the content unreadable. The whole system works **off-cloud**, **with no host driver**, on Windows / Linux / macOS.

### The three pillars of the project

1. **The BindKey hardware proxy** — the physical box that handles local biometric authentication, key derivation through an ATECC608A secure element, and on-the-fly encryption of the data. Made of two ESP32-S3 microcontrollers:
   - a **master** (USB MSC emulation + biometrics + AES-GCM crypto + secure element) — repo [`bindkey-tinyesp`](https://github.com/bindkey-project/bindkey-tinyesp) **← this repo**
   - a **slave** (drives the real physical media in USB Host mode) — repo [`bindkey-esp`](https://github.com/bindkey-project/bindkey-esp)
2. **A backend server (API)** — repo [`bindkey-server`](https://github.com/bindkey-project/bindkey-server) — manages users' public identities and orchestrates access delegation between BindKeys in *Zero-Knowledge* mode: only wrapped keys (ECDH-wrapped) ever travel over the network, never the plaintext volume key.
3. **The desktop software** — repo [`bindkey-software`](https://github.com/bindkey-project/bindkey-software) — Rust application that drives the BindKey through UART and provides the GUI: volume creation / deletion, sharing with a colleague, formatting, reset, and any administration operation that requires the physical presence of the key.

### Main features

- **Transparent on-the-fly encryption** — no host driver, behaves as a standard USB MSC drive
- **Local biometric authentication** by fingerprint, hardware-gated and replay-protected
- **Provable integrity** — any change made outside the BindKey makes the data unreadable (AES-GCM tag)
- **Collaborative sharing** between BindKeys of the same organization via ECDH P-256 (Zero-Knowledge)
- **Delegated enrollment** — an administrator can grant *Enroller* privilege to a team leader
- **Lifecycle management** — remote revocation, recovery-code-based restoration, wipe & reassignment
- **Tamper-evident centralized audit log** (GDPR compliance and forensic traceability)
- **Air-gapped maintenance** — secure transport of payloads to isolated systems (OT, industrial)

This repository contains the **master** firmware (ESP32-S3 #1) — one of the two MCUs that make up the BindKey hardware proxy.

---

# bindkey-tinyesp

BindKey - Master Project - ESP32#1 Code Repository

> Rust firmware for the BindKey **master** — ESP32-S3 #1 of the BindKey project.

`bindkey-tinyesp` is one of the two firmwares that make up the transparent
encrypted USB proxy **BindKey**. This MCU is the one that talks directly to
the host PC: it emulates a standard USB Mass Storage drive, intercepts every
read / write, biometrically authenticates the user, derives the volume keys
from an ATECC608A Secure Element, encrypts the sectors on the fly in
AES-256-GCM, and then forwards the operations to the second MCU
(`bindkey-esp`, see dedicated repo) that drives the real physical media.

Encryption is **transparent to the host OS**: no driver, no changes required
on Windows/Linux/macOS/iOS/Android…

---

## Place in the BindKey architecture

```
        Host PC
            │  USB (native OS driver, MSC class)
            ▼
  ┌─────────────────────────────┐
  │   bindkey-tinyesp  (master) │   ← THIS REPO
  │   ESP32-S3 #1               │
  │   • USB MSC emulation       │
  │   • Fingerprint sensor      │
  │   • ATECC608A (SE)          │
  │   • AES-256-GCM             │
  │   • UART control channel    │
  └─────────────┬───────────────┘
                │  SPI3 inter-MCU (10–60 MHz)
                ▼
  ┌─────────────────────────────┐
  │   bindkey-esp  (slave)      │
  │   ESP32-S3 #2               │
  │   • SPI slave               │
  │   • USB Host (real drive)   │
  └─────────────────────────────┘
```

---

## Features

- **USB MSC Full Speed** emulation via TinyUSB (VID `0x303A`, PID `0x4001`)
- Biometric authentication:
  - **R503** (Grow, UART2, 57600 bps) — sensor enabled by default
  - **BM-Lite FPC** (SPI2) — alternative selectable via the `USE_R503` constant
- **ATECC608A** Secure Element (I2C 100 kHz):
  - ECDSA P-256 signature (slot 0)
  - ECDH P-256 for key sharing (slot 1)
  - HMAC-SHA256 for volume key derivation (slot 9)
  - Slots 10–14 for shared keys received from other BindKeys
- **AES-256-GCM** disk encryption (hardware-accelerated through mbedTLS):
  - Unique IV per `(LBA, counter)`, 16-byte tag stored in MetaSector
  - Layout: 24 data sectors + 1 meta sector per group
- **SPI3 master** link to the slave with a custom CRC32-protected protocol and resync logic
- **UART1** control channel for the desktop software (commands `ping`,
  `uid`, `enroll`, `challenge=`, `create_volume`, `share`, `recv_share`)
- Volume table (BkTable) stored at LBA 0 of the physical media, supporting
  up to 6 volumes and 5 shared BindKeys per volume

---

## Hardware required

| Item              | Reference                                                       |
|-------------------|-----------------------------------------------------------------|
| MCU               | ESP32-S3 (any dev-board, e.g. ESP32-S3-DevKitC-1)               |
| Fingerprint sensor| Grow R503 (default) or Fingerprint Cards BM-Lite                |
| Secure Element    | Microchip ATECC608A Trust & GO (I2C)                            |
| USB connector     | native ESP32-S3 USB-OTG port (D+/D-)                            |
| Inter-MCU link    | 5 SPI3 wires + READY line to the `bindkey-esp` board            |
| Programmer        | USB-UART built into the dev-board, or ESP-Prog, or CP2102 on PCB|

---

## Software prerequisites

This firmware uses the **Rust for Xtensa** toolchain maintained by Espressif,
distinct from the regular stable toolchain. Three essential tools:

### 1. Rust + `rustup`

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### 2. `espup` (Xtensa toolchain installer)

```bash
cargo install espup --locked
espup install
. $HOME/export-esp.sh        # to source in every shell
```

`espup install` automatically installs the patched `rustc` compiler for
Xtensa, GCC for Xtensa, LLVM, and configures the ESP-IDF environment
variables required by `esp-idf-sys`.

### 3. Flash and scaffolding tools

```bash
cargo install ldproxy           # linker proxy used by esp-idf-sys
cargo install espflash --locked # flash + serial monitor
cargo install cargo-generate    # to create new ESP-IDF projects
```

### 4. (Optional) Bootstrapping a new ESP-IDF + Rust project from scratch

If you want to regenerate a skeleton equivalent to this repo:

```bash
cargo generate esp-rs/esp-idf-template cargo
```

Answers to give to the template:
- **MCU**: `esp32s3`
- **ESP-IDF version**: `v5.3.3` (see `.cargo/config.toml` in this repo)
- **STD support**: `true` (used here)

The template produces the `Cargo.toml` + `.cargo/config.toml` +
`sdkconfig.defaults` + `rust-toolchain.toml` layout that you find in this repo.

### System dependencies (Linux/macOS)

```bash
# Debian/Ubuntu
sudo apt install -y git wget flex bison gperf python3 python3-pip python3-venv \
                    cmake ninja-build ccache libffi-dev libssl-dev dfu-util \
                    libusb-1.0-0 pkg-config
```

---

## Pinned versions (extract from `Cargo.toml`)

| Item             | Version                                         |
|------------------|-------------------------------------------------|
| Rust edition     | 2021                                            |
| `rust-version`   | ≥ 1.77                                          |
| Rust toolchain   | `channel = "esp"` (see `rust-toolchain.toml`)   |
| Target           | `xtensa-esp32s3-espidf`                         |
| ESP-IDF          | `v5.3.3`                                        |
| `esp-idf-svc`    | `0.51`                                          |
| `esp-idf-sys`    | `0.36` (feature `native`)                       |
| `embuild`        | `0.33`                                          |
| TinyUSB          | `espressif/tinyusb 0.17.0~2` (managed component)|

---

## Build, flash, monitor

```bash
# Clone the repo
git clone https://github.com/bindkey-project/bindkey-tinyesp.git
cd bindkey-tinyesp

# Make sure the ESP toolchain is active
. $HOME/export-esp.sh

# Debug build
cargo build

# Release build (recommended for SPI / USB performance)
cargo build --release

# Build + flash + serial monitor (main command)
cargo run
# equivalent to: cargo build && espflash flash --monitor target/...

# Lint
cargo clippy -- -D warnings
```

> ⚠️ Always use `cargo build` / `cargo run`. **Never** invoke `idf.py build`
> directly — `esp-idf-sys` already orchestrates the full ESP-IDF call.
> `idf.py menuconfig` is still useful, but only to interactively edit
> `sdkconfig.defaults`.

---

## `sdkconfig.defaults` configuration

The most structural entries:

```ini
CONFIG_ESP_MAIN_TASK_STACK_SIZE=16384
CONFIG_FREERTOS_HZ=1000

CONFIG_TINYUSB_ENABLED=y
CONFIG_TINYUSB_MSC_ENABLED=y
CONFIG_TINYUSB_TASK_STACK_SIZE=24576
CONFIG_TINYUSB_MSC_BUFSIZE=8192

# ATECC608A via cryptoauthlib (legacy I2C driver for ESP-IDF ≥ 5.2)
CONFIG_ATCA_I2C_USE_LEGACY_DRIVER=y
CONFIG_ATECC608A_TCUSTOM=y
CONFIG_ATCA_I2C_SDA_PIN=4
CONFIG_ATCA_I2C_SCL_PIN=5
CONFIG_ATCA_I2C_ADDRESS=0xC0
CONFIG_ATCA_I2C_BAUD_RATE=100000
```

---

## Source tree

```
src/
├── main.rs                  ← boot, init sequence
├── crypto/                  ← AES-256-GCM, ATECC608, BkTable, MetaSector
│   ├── mod.rs
│   ├── aes.rs               ← AES-256-GCM wrapper (esp_aes_gcm_*)
│   ├── secure_element.rs    ← AteccSession, derive_volume_key_hmac, ECDH wrap/unwrap
│   ├── disk_crypto.rs       ← encrypt_sector / decrypt_sector, make_iv / make_aad
│   ├── disk_layout.rs       ← G=24, GROUP_PHYS=25, map_lba()
│   ├── disk_meta.rs         ← MetaSector, MetaEntry (counter + tag), magic "BKMD"
│   ├── encrypted_disk.rs    ← EncryptedDisk, read10/write10, meta cache, GLOBAL_DISK
│   ├── volume_table.rs      ← BkTable (LBA 0), VolumeEntry, SharedAccess, dirty flag
│   └── esp-cryptoauthlib/   ← C component for ATECC608 (FFI via bindgen)
├── fingerprint/             ← fingerprint sensor drivers
│   ├── mod.rs
│   ├── fingerprint.rs       ← BM-Lite (SPI2) — bmlite bindings
│   ├── fingerprint_r503.rs  ← R503 (UART2) — custom packet protocol
│   └── BMLite/              ← C component for BM-Lite (FFI via bindgen)
├── spi_link/                ← master-side SPI3 protocol
│   ├── mod.rs
│   ├── pins.rs              ← MOSI=13 MISO=12 SCLK=11 CS=10 READY=9
│   ├── protocol.rs          ← 16B header, Cmd enum, MAX_PAYLOAD=8192, CRC32, magic "BK"
│   ├── spi_master.rs        ← SpiMaster, DmaBuf, spi_xfer, wait_ready, resync
│   └── api_spi.rs           ← public API read/write/flush/get_status/get_capacity + stats
├── usb_emulation/           ← TinyUSB MSC device
│   ├── mod.rs
│   ├── fake_usb.rs          ← SCSI / MSC callbacks (#[no_mangle]), init_fake_usb_msc
│   └── esp-usb/             ← C component for esp_tinyusb (FFI via bindgen)
├── software_link/           ← UART control channel (UART1, 115200 bps)
│   ├── mod.rs
│   ├── task.rs              ← uart_task (FreeRTOS core 1, prio 10, stack 32KB)
│   └── test_com.rs          ← parser for ping/uid/enroll/challenge/share/recv_share
└── led/                     ← status indicator (GPIO 8)
    ├── mod.rs
    └── led.rs               ← LedGuard (RAII: LED ON at new, OFF at drop)
```

---

## Related repo

[`bindkey-esp`](https://github.com/bindkey-project/bindkey-esp) — firmware for
the second MCU, SPI slave + USB Host. Any change to the SPI protocol (header,
payload size, READY handshake sequence, CRC32) **must be coordinated** between
the two repos.

---

## Build profiles

```toml
[profile.release]
opt-level = "s"   # size-optimized (production binary to flash)

[profile.dev]
opt-level = "z"   # max size optimization
debug = true      # debug symbols included, binary stays compact
```

---

## License and authors

BindKey academic project — INIZIATO William, LOPEZ Pierre-Louis, MATTEI Jean-Baptiste, ZAIETER Jassime, ADDOUH Marwa
