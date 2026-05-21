<p align="center">
  <img src="assets/logo-bindkey.png" alt="Logo BindKey" width="600"/>
</p>

<h1 align="center">BindKey</h1>

<p align="center"><i>Security at your fingertip</i></p>

---

## Présentation globale du projet BindKey

**BindKey** est une solution de cybersécurité matérielle qui résout le compromis entre la sécurité des données hors-ligne et le besoin de collaboration en entreprise. Le boîtier se place entre le PC et un support de stockage standard (clé USB, SSD, lecteur SD) et agit comme un **Man-in-the-Middle légitime** : toutes les données qui le traversent sont scellées et chiffrées à la volée en **AES-256-GCM** par un microcontrôleur sécurisé, et ne sont déchiffrées que pour les utilisateurs authentifiés **biométriquement** dont la BindKey détient les droits sur le volume. Toute modification effectuée en dehors de l'environnement BindKey rend le contenu illisible. Le tout fonctionne **hors cloud**, **sans driver hôte**, sur Windows / Linux / macOS.

### Les trois piliers du projet

1. **Le proxy matériel BindKey** — le boîtier physique qui assure l'authentification biométrique locale, la dérivation des clés via un secure element ATECC608A, et le chiffrement à la volée des données. Composé de deux microcontrôleurs ESP32-S3 :
   - un **master** (émulation USB MSC + biométrie + crypto AES-GCM + élément sécurisé) — dépôt [`bindkey-tinyesp`](https://github.com/bindkey-project/bindkey-tinyesp) **← ce dépôt**
   - un **slave** (pilotage du vrai média physique en USB Host) — dépôt [`bindkey-esp`](https://github.com/bindkey-project/bindkey-esp)
2. **Un serveur backend (API)** — dépôt [`bindkey-server`](https://github.com/bindkey-project/bindkey-server) — gère les identités publiques des utilisateurs et orchestre la délégation d'accès entre BindKeys en mode *Zero-Knowledge* : seules des clés enveloppées (wrapped via ECDH) circulent sur le réseau, jamais la clé volume en clair.
3. **Le logiciel de bureau** — dépôt [`bindkey-software`](https://github.com/bindkey-project/bindkey-software) — application Rust qui pilote la BindKey via UART et offre l'interface graphique : création / suppression de volumes, partage avec un collègue, formatage, réinitialisation, et toute opération d'administration nécessitant la présence physique de la clé.

### Fonctionnalités principales

- **Chiffrement transparent** à la volée — aucun driver côté hôte, comportement de clé USB MSC standard
- **Authentification biométrique** locale par empreinte digitale, hardware-gated et anti-rejeu
- **Intégrité prouvable** — toute modification hors BindKey rend les données illisibles (tag AES-GCM)
- **Partage collaboratif** entre BindKeys d'une même organisation via ECDH P-256 (Zero-Knowledge)
- **Délégation d'enrôlement** — un administrateur peut accorder un privilège *Enroller* à un responsable d'équipe
- **Gestion du cycle de vie** — révocation à distance, restauration via code de recovery, wipe & réassignation
- **Audit log** centralisé tamper-evident (conformité GDPR et traçabilité forensic)
- **Maintenance air-gapped** — transport sécurisé de payloads vers des systèmes isolés (OT, industriels)

Ce dépôt contient le firmware **master** (ESP32-S3 N°1) — l'une des deux MCU qui composent le proxy matériel BindKey.

---

# bindkey-tinyesp

BindKey - Master Project - ESP32#1 Code Repository

> Firmware Rust de BindKey **master** — ESP32-S3 N°1 du projet BindKey.

`bindkey-tinyesp` est l'un des deux firmwares qui composent le proxy USB chiffré transparent
**BindKey**. Cette MCU est celle qui parle directement au PC hôte : elle émule
une clé USB Mass Storage standard, intercepte chaque lecture / écriture,
authentifie biométriquement l'utilisateur, dérive les clés des volumes depuis un
Secure Element ATECC608A, chiffre les secteurs à la volée en AES-256-GCM, puis
relaie les opérations vers la seconde MCU (`bindkey-esp`, voir repo dédié) qui
pilote le vrai média physique.

Le chiffrement est **transparent pour l'OS hôte** : aucun driver, aucune
modification côté Windows/Linux/macOS/iOS/Android...

---

## Place dans l'architecture BindKey

```
        Client PC
            │  USB (driver OS natif, classe MSC)
            ▼
  ┌─────────────────────────────┐
  │   bindkey-tinyesp  (master) │   ← CE REPO
  │   ESP32-S3 #1               │
  │   • Émulation USB MSC       │
  │   • Capteur empreinte       │
  │   • ATECC608A (SE)          │
  │   • AES-256-GCM             │
  │   • UART de contrôle        │
  └─────────────┬───────────────┘
                │  SPI3 inter-MCU (10–60 MHz)
                ▼
  ┌─────────────────────────────┐
  │   bindkey-esp  (slave)      │
  │   ESP32-S3 #2               │
  │   • SPI slave               │
  │   • USB Host (vraie clé USB)│
  └─────────────────────────────┘
```

---

## Fonctionnalités

- Émulation **USB MSC Full Speed** via TinyUSB (VID `0x303A`, PID `0x4001`)
- Authentification biométrique :
  - **R503** (Grow, UART2, 57600 bps) — capteur actif par défaut
  - **BM-Lite FPC** (SPI2) — alternative configurable via la constante `USE_R503`
- Secure Element **ATECC608A** (I2C 100 kHz) :
  - Signature ECDSA P-256 (slot 0)
  - ECDH P-256 pour le partage de clés (slot 1)
  - HMAC-SHA256 pour la dérivation des clés volume (slot 9)
  - Slots 10–14 pour les clés partagées reçues d'autres BindKeys
- Chiffrement disque **AES-256-GCM** (accélération hardware mbedTLS) :
  - IV unique par `(LBA, counter)`, tag 16 octets stocké en MetaSector
  - Layout 24 secteurs data + 1 meta par groupe
- Lien **SPI3 master** vers le slave avec protocole maison à CRC32 et resync
- Canal de contrôle **UART1** pour le logiciel desktop (commandes `ping`,
  `uid`, `enroll`, `challenge=`, `create_volume`, `share`, `recv_share`)
- Table des volumes (BkTable) stockée au LBA 0 du média physique, supportant
  jusqu'à 6 volumes et 5 BindKeys partagées par volume

---

## Matériel requis

| Élément           | Référence                                                          |
|-------------------|--------------------------------------------------------------------|
| MCU               | ESP32-S3 (n'importe quelle dev-board, ex. ESP32-S3-DevKitC-1)      |
| Capteur empreinte | Grow R503 (par défaut) ou Fingerprint Cards BM-Lite                |
| Secure Element    | Microchip ATECC608A Trust & GO (I2C)                               |
| Adaptateur USB    | port USB-OTG natif de l'ESP32-S3 (D+/D-)                           |
| Lien inter-MCU    | 5 fils SPI3 + ligne READY vers la carte `bindkey-esp`              |
| Programmateur     | USB-UART intégré à la dev-board, ou ESP-Prog, ou CP2102 sur le PCB |

---

## Prérequis logiciels

Ce firmware utilise la toolchain **Rust pour Xtensa** maintenue par
Espressif, distincte de la toolchain stable habituelle. Trois outils
indispensables :

### 1. Rust + `rustup`

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### 2. `espup` (installateur de la toolchain Xtensa)

```bash
cargo install espup --locked
espup install
. $HOME/export-esp.sh        # à sourcer dans chaque shell
```

`espup install` installe automatiquement le compilateur `rustc` patché pour
Xtensa, GCC pour Xtensa, LLVM, et configure les variables d'environnement
ESP-IDF nécessaires à `esp-idf-sys`.

### 3. Outils de flash et de scaffolding

```bash
cargo install ldproxy           # linker proxy utilisé par esp-idf-sys
cargo install espflash --locked # flash + monitor série
cargo install cargo-generate    # pour créer de nouveaux projets ESP-IDF
```

### 4. (Optionnel) Création d'un projet ESP-IDF + Rust « from scratch »

Si vous voulez régénérer un squelette équivalent à ce repo :

```bash
cargo generate esp-rs/esp-idf-template cargo
```

Réponses à donner au template :
- **MCU** : `esp32s3`
- **ESP-IDF version** : `v5.3.3` (cf. `.cargo/config.toml` de ce repo)
- **STD support** : `true` (utilisé ici)

Le template produit la structure `Cargo.toml` + `.cargo/config.toml` +
`sdkconfig.defaults` + `rust-toolchain.toml` que tu retrouves dans ce repo.

### Dépendances système (Linux/macOS)

```bash
# Debian/Ubuntu
sudo apt install -y git wget flex bison gperf python3 python3-pip python3-venv \
                    cmake ninja-build ccache libffi-dev libssl-dev dfu-util \
                    libusb-1.0-0 pkg-config
```

---

## Versions verrouillées (extrait `Cargo.toml`)

| Élément          | Version                                         |
|------------------|-------------------------------------------------|
| Edition Rust     | 2021                                            |
| `rust-version`   | ≥ 1.77                                          |
| Toolchain Rust   | `channel = "esp"` (cf. `rust-toolchain.toml`)   |
| Target           | `xtensa-esp32s3-espidf`                         |
| ESP-IDF          | `v5.3.3`                                        |
| `esp-idf-svc`    | `0.51`                                          |
| `esp-idf-sys`    | `0.36` (feature `native`)                       |
| `embuild`        | `0.33`                                          |
| TinyUSB          | `espressif/tinyusb 0.17.0~2` (composant managé) |

---

## Build, flash, monitor

```bash
# Cloner le repo
git clone https://github.com/bindkey-project/bindkey-tinyesp.git
cd bindkey-tinyesp

# S'assurer que la toolchain ESP est active
. $HOME/export-esp.sh

# Build debug
cargo build

# Build release (recommandé pour la perf SPI / USB)
cargo build --release

# Build + flash + monitor série (commande principale)
cargo run
# équivalent à : cargo build && espflash flash --monitor target/...

# Lint
cargo clippy -- -D warnings
```

> ⚠️ Toujours utiliser `cargo build` / `cargo run`. **Ne jamais** invoquer
> `idf.py build` directement — `esp-idf-sys` orchestre déjà tout l'appel
> ESP-IDF nécessaire. `idf.py menuconfig` reste utilisable uniquement pour
> éditer interactivement `sdkconfig.defaults`.

---

## Configuration `sdkconfig.defaults`

Les éléments les plus structurants :

```ini
CONFIG_ESP_MAIN_TASK_STACK_SIZE=16384
CONFIG_FREERTOS_HZ=1000

CONFIG_TINYUSB_ENABLED=y
CONFIG_TINYUSB_MSC_ENABLED=y
CONFIG_TINYUSB_TASK_STACK_SIZE=24576
CONFIG_TINYUSB_MSC_BUFSIZE=8192

# ATECC608A via cryptoauthlib (driver I2C legacy pour ESP-IDF ≥ 5.2)
CONFIG_ATCA_I2C_USE_LEGACY_DRIVER=y
CONFIG_ATECC608A_TCUSTOM=y
CONFIG_ATCA_I2C_SDA_PIN=4
CONFIG_ATCA_I2C_SCL_PIN=5
CONFIG_ATCA_I2C_ADDRESS=0xC0
CONFIG_ATCA_I2C_BAUD_RATE=100000
```

---

## Structure du code

```
src/
├── main.rs                  ← boot, séquence d'init
├── crypto/                  ← AES-256-GCM, ATECC608, BkTable, MetaSector
│   ├── mod.rs
│   ├── aes.rs               ← wrapper AES-256-GCM (esp_aes_gcm_*)
│   ├── secure_element.rs    ← AteccSession, derive_volume_key_hmac, ECDH wrap/unwrap
│   ├── disk_crypto.rs       ← encrypt_sector / decrypt_sector, make_iv / make_aad
│   ├── disk_layout.rs       ← G=24, GROUP_PHYS=25, map_lba()
│   ├── disk_meta.rs         ← MetaSector, MetaEntry (counter + tag), magic "BKMD"
│   ├── encrypted_disk.rs    ← EncryptedDisk, read10/write10, cache meta, GLOBAL_DISK
│   ├── volume_table.rs      ← BkTable (LBA 0), VolumeEntry, SharedAccess, dirty flag
│   └── esp-cryptoauthlib/   ← composant C ATECC608 (FFI bindgen)
├── fingerprint/             ← drivers capteur empreinte
│   ├── mod.rs
│   ├── fingerprint.rs       ← BM-Lite (SPI2) — bindings bmlite
│   ├── fingerprint_r503.rs  ← R503 (UART2) — protocole packet maison
│   └── BMLite/              ← composant C BM-Lite (FFI bindgen)
├── spi_link/                ← protocole SPI3 master vers slave
│   ├── mod.rs
│   ├── pins.rs              ← MOSI=13 MISO=12 SCLK=11 CS=10 READY=9
│   ├── protocol.rs          ← header 16B, Cmd enum, MAX_PAYLOAD=8192, CRC32, magic "BK"
│   ├── spi_master.rs        ← SpiMaster, DmaBuf, spi_xfer, wait_ready, resync
│   └── api_spi.rs           ← API publique read/write/flush/get_status/get_capacity + stats
├── usb_emulation/           ← TinyUSB MSC device
│   ├── mod.rs
│   ├── fake_usb.rs          ← callbacks SCSI / MSC (#[no_mangle]), init_fake_usb_msc
│   └── esp-usb/             ← composant C esp_tinyusb (FFI bindgen)
├── software_link/           ← UART de contrôle (UART1, 115200 bps)
│   ├── mod.rs
│   ├── task.rs              ← uart_task (FreeRTOS core 1, prio 10, stack 32KB)
│   └── test_com.rs          ← parser ping/uid/enroll/challenge/share/recv_share
└── led/                     ← indicateur d'état (GPIO 8)
    ├── mod.rs
    └── led.rs               ← LedGuard (RAII : LED ON au new, OFF au drop)
```

---

## Repo lié

[`bindkey-esp`](https://github.com/bindkey-project/bindkey-esp) — firmware de la seconde MCU, SPI slave +
USB Host. Toute modification du protocole SPI (header, taille de payload,
séquence du handshake READY, CRC32) **doit être coordonnée** entre les deux
repos.

---

## Profils de build

```toml
[profile.release]
opt-level = "s"   # optimisé taille (binaire à flasher en prod)

[profile.dev]
opt-level = "z"   # taille max
debug = true      # symboles présents, binaire compact
```

---

## Licence et auteurs

Projet académique BindKey — INIZIATO William, LOPEZ Pierre-Louis, MATTEI Jean-Baptiste, ZAIETER Jassime, ADDOUH Marwa
