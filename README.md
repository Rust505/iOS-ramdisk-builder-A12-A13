# iOS Ramdisk Builder for A12/A13 (iPhone 11 / XS / XR / SE2)

**Repository:** `Rust505/iOS-ramdisk-builder-A12-A13`
**Supported devices:** iPhone 11, 11 Pro, 11 Pro Max, SE 2, XS, XS Max, XR, iPad mini 5, iPad Air 3
**Supported iOS:** 14.0 – 27.0.1 (SSH ramdisk build)

---

## 📋 Overview

`build4.sh` builds an **SSH ramdisk** for devices with A12/A13 chips (CPID `0x8020` / `0x8030`). The resulting bootchain is loaded via `boot.sh` in DFU mode and provides root SSH access (port 2222, password `alpine`).

### What the script does

1. Downloads the IPSW for the specified iOS version from Apple servers (via `api.ipsw.me`)
2. Extracts `BuildManifest.plist`, `iBSS`, `iBEC`, `DeviceTree`, `KernelCache`, `RestoreRamDisk`, `RestoreTrustCache`, and firmware (ANE, GFX, SIO…) from the IPSW
3. Decrypts `iBSS` (iOS ≤ 17.3.1) or `iBEC` (iOS ≥ 17.4) with the appropriate key
4. Patches:
   - **iBSS** → via `iBootPatch` (SSHRD-style) for iOS 15.0–17.3.1
   - **iBEC** → via `iboot_patchfinder.py` / `iBoot64Patcher` for iOS 17.4+
5. Patches the kernel (`Kernel64Patcher` for ≤17, `apply_kernel_patches.py` for 18+)
6. Expands the ramdisk, injects `ssh.tar.gz`, adds trustcache
7. Packages `.img4` files with IM4M signature into `bootchain/`

---

## 🗂️ Repository structure

```
iOS-ramdisk-builder-A12-A13/
├── bin/                       # binary patchers (iBootPatch, iBoot64Patcher, img4, img4tool…)
├── keys/                      # SSHRD keys: keys/iPhone12,1.txt etc.
├── patch/                     # python patch scripts (iboot_patchfinder.py etc.)
├── resources/                 # resources: IM4M, ssh.tar.gz, sshtarlist.txt
├── scripts/                   # devices.sh, ramdisk_expand.sh
├── tools/                     # irecovery, pzb, img4, gtar, trustcache, jq (darwin/linux)
├── boot.sh                    # loads the built bootchain onto the device
├── build4.sh                  # ⭐ main build script
├── collect_ibec_keys.py       # utility to collect iBEC keys
├── env.sh                     # environment variables
├── ibec_keys_iPhone12_1.json  # keys for iPhone 11
├── ibec_keys_iPhone12_3.json  # keys for iPhone 11 Pro
├── ibec_keys_iPhone12_5.json  # keys for iPhone 11 Pro Max
├── ramdisk_expand.sh          # APFS ramdisk expansion
├── requirements.txt           # python dependencies
├── setup.sh                   # dependency installer
└── status.sh                  # environment check
```

---

## ⚙️ 1. Installation

### Requirements

- **macOS** (Intel or Apple Silicon) – required for `hdiutil`, `diskutil`
- **Python 3.9+**
- **pip** and packages from `requirements.txt`
- Utilities: `curl`, `xxd`, `ipsw`, `jq` (usually preinstalled except `ipsw`)
- **Pwned DFU** mode on the device (requires `Pi Pico` or `usbliter8`)
- `sudo` for ramdisk operations

### Install dependencies

```bash
git clone https://github.com/Rust505/iOS-ramdisk-builder-A12-A13.git
cd iOS-ramdisk-builder-A12-A13
chmod +x *.sh
./setup.sh                     # installs pip packages and checks binaries
./status.sh                    # shows if everything is in place
```

If `setup.sh` doesn't install `ipsw` – install it manually:

```bash
brew install blacktop/tap/ipsw    # macOS
```

### Environment check

```bash
./status.sh
```

Expected output:
- ✅ `bin/img4`, `bin/iBootPatch`, `bin/Kernel64Patcher`
- ✅ `tools/darwin/{irecovery,pzb,img4,gtar,trustcache,jq}`
- ✅ `resources/IM4M_0x8030` (A13) or `IM4M_0x8020` (A12)
- ✅ `resources/ssh.tar.gz`, `resources/sshtarlist.txt`
- ✅ `keys/<device>.txt` or `ibec_keys_<device>.json`

---

## 🚀 2. Building the bootchain

### Syntax

```bash
./build4.sh [options]
```

### Main options

| Option | Description |
|---|---|
| `--product <PRODUCT>` | Device identifier: `iPhone12,1`, `iPhone12,3`, `iPhone12,5`, `iPhone12,8` |
| `--version <VERSION>` | iOS version, e.g. `17.3.1`, `18.4` |
| `--build <BUILD>` | Build number (if you don't know the version): e.g. `21D61` |
| `--url <IPSW_URL>` | Direct IPSW URL |
| `--kernel stock\|patched` | Whether to patch kernel (default `patched`) |
| `--kpf-set ios18\|ios27\|auto` | Kernel patch set (default `auto`) |
| `--with-fw` / `--no-fw` | Include/exclude firmware components (default `with-fw`) |
| `--im4m <PATH>` | Path to custom IM4M blob |
| `--list` | List all available firmwares for the device |
| `--dry-run` | Only show plan, don't build |

### Examples

**iPhone 11, iOS 17.3.1 (iBSS path):**
```bash
./build4.sh --product iPhone12,1 --version 17.3.1
```

**iPhone 11 Pro, iOS 18.4 (iBEC path):**
```bash
./build4.sh --product iPhone12,3 --version 18.4
```

**List firmwares:**
```bash
./build4.sh --product iPhone12,1 --list
```

**Dry run:**
```bash
./build4.sh --product iPhone12,1 --version 17.3.1 --dry-run
```

### Output after build

```
bootchain/n104-17.3.1-21D61-ramdisk/
├── chain.info              # summary: product, model, cpid, version, build, kernel
├── iBSS.patched.bin        # iBSS patched by iBootPatch (if 15.0–17.3.1)
├── iBEC.img4               # iBEC for 17.4+
├── devicetree.img4
├── kernelcache.img4
├── ramdisk.img4            # SSH ramdisk
├── trustcache.img4
├── ANE.img4, GFX.img4, SIO.img4, AOP.img4, …
└── sep-firmware.img4       # if RestoreSEP present in IPSW
```

---

## 📲 3. Booting the device

### Step 1. Enter **pwned DFU**

iPhone 11 / SE 2 / XS / XR require a hardware exploit:
- **usbliter8** (for A12/A13) – via Pi Pico
- Or connect to **Pi Pico** and run `usbliter8`

Check state:
```bash
./tools/darwin/irecovery -q
# Should show: MODE: DFU, PWND: usbliter8
```

### Step 2. Load the bootchain

```bash
./boot.sh
```

The script will:
1. Send `iBSS.patched.bin` via `liter8ctl` (or `iBEC.img4` via `irecovery -f`)
2. Wait for Recovery
3. Send `ramdisk.img4` + `trustcache.img4` + firmware + devicetree + kernel
4. Execute `bootx`
5. After ~15 seconds the device boots into ramdisk

### Step 3. Connect via SSH

```bash
iproxy 2222 22 &
ssh root@localhost -p 2222
# password: alpine
```

---

## 🔑 4. Decryption keys

### Where they are stored

1. **`keys/<PRODUCT>.txt`** – SSHRD keys:
   ```
   ibss-17.3.1: 5c2cf067e1e3c6b6...364b2
   ibec-21D61: aa2e8d3a3c744fe4...6f7f
   ```

2. **`ibec_keys_<PRODUCT>.json`** (in root) – JSON from `collect_ibec_keys.py`:
   ```json
   {
     "17.3.1": {
       "21D61": {
         "iBSS": { "iv": "aa2e...", "key": "8076..." },
         "iBEC": { "iv": "9a72...", "key": "ec0a..." }
       }
     }
   }
   ```

3. **Built-in fallback** inside `build4.sh` – if no key is found in files or JSON.

### How to build/update JSON

```bash
python3 collect_ibec_keys.py --product iPhone12,1 --output ibec_keys_iPhone12_1.json
```

Or manually add the required build to an existing JSON.

### Key lookup order

| Mode | 1st source | 2nd | 3rd |
|---|---|---|---|
| iBSS (≤17.3.1) | `keys/<PROD>.txt` → `ibss-<VER>` | `ibec_keys_<PROD>.json` | inline fallback |
| iBEC (≥17.4)   | `ibec_keys_<PROD>.json` → `release`/`iBEC` | `keys/<PROD>.txt` → `ibec-<BUILD>` | inline fallback |

---

## 🧩 5. Dependencies

### Binaries (`bin/`)

| File | Required | Purpose |
|---|---|---|
| `img4` | ✅ | Decrypt iBSS/iBEC with 96-hex key |
| `iBootPatch` | ✅ for ≤17.3.1 | Patch iBSS (SSHRD-style) |
| `iBoot64Patcher` | ⚠️ fallback | Patch iBEC for 17.4+ |
| `Kernel64Patcher` | ✅ for ≤17 | Patch kernel |
| `kerneldiff` | ⚠️ optional | Kernel diff patch |
| `img4tool` | ⚠️ optional | IV:KEY decryption |
| `dtpatch.py` | ⚠️ optional | DeviceTree patch |

### Scripts (`patch/`)

| File | When needed |
|---|---|
| `iboot_patchfinder.py` | iBEC for iOS 17.4+ |
| `finalize_iboot.py` | Finalize boot-args |
| `apply_kernel_patches.py` | Kernel iOS 18+ |
| `sptm_patchfinder.py` / `txm_patchfinder.py` | iOS 18+ |

### Resources (`resources/`)

| File | Required |
|---|---|
| `IM4M_0x8030` (A13) / `IM4M_0x8020` (A12) | ✅ |
| `ssh.tar.gz` | ✅ |
| `sshtarlist.txt` | ✅ |
| `restored_external` | ⚠️ optional |

### System utilities

`curl`, `xxd`, `python3`, `jq`, `ipsw`, `hdiutil`, `diskutil` (macOS)

---

## 🐛 6. Troubleshooting

### "iBSS not patched — build impossible"

1. Check that `bin/iBootPatch` is not an HTML stub:
   ```bash
   xxd -l 4 bin/iBootPatch
   # should be: cffaedfe / cefaedfe / feedface / feedfacf
   ```
2. If it's garbage – restore from surrealra1n release:
   ```bash
   curl -L -o bin/iBootPatch \
     https://github.com/pwnerblu/surrealra1n/raw/refs/heads/main/bin/iBootPatch
   chmod +x bin/iBootPatch
   ```

### "iBSS decrypted, but magic=9f97aa83" (garbage)

The key in `keys/<PRODUCT>.txt` for `ibss-<VERSION>` is **wrong** (not for that file). Check:
```bash
grep -i "ibss-17.3.1" keys/iPhone12,1.txt
```

A correct key will produce `magic=0df74f6e` or `6e4ff70d`.

### "missing IM4M: ..."

Place the IM4M in `resources/`:
```bash
cp /path/to/IM4M_0x8030 resources/
```
IM4M is obtained from a signed SHSH2 (via `tsschecker`) or from a ready dump.

### "BuildManifest mismatch"

The iOS version does not match the build in the manifest. Use `--build <BUILD>` explicitly or omit `--version` when using `--url`.

### Device doesn't boot after `bootx`

- Verify `MODE: DFU` + `PWND: usbliter8` before running `boot.sh`
- Ensure `iBSS.patched.bin` is built for your board (`n104`, `d421`, `d431`, `d79`)
- Rebuild with `--kernel stock` – kernel patch may conflict

---

## 📖 7. Useful links

- **The Apple Wiki** (keys): https://theapplewiki.com/wiki/Firmware_Keys
- **SSHRD_Script**: https://github.com/verygenericname/SSHRD_Script
- **surrealra1n**: https://github.com/pwnerblu/surrealra1n
- **usbliter8** (A12/A13 pwn)


---

## ⚖️ 8. License & disclaimer

MIT License (see `LICENSE`). The author is not responsible for bricked devices. You perform all actions at your own risk. SSH ramdisk is a tool for research and recovery, not for bypassing iCloud or other protections.

---

## 💬 9. Quick reference

```bash
# 1. Install
git clone https://github.com/Rust505/iOS-ramdisk-builder-A12-A13.git
cd iOS-ramdisk-builder-A12-A13
./setup.sh

# 2. Check
./status.sh

# 3. Build (example)
./build4.sh --product iPhone12,1 --version 17.3.1

# 4. Pwned DFU → boot
./boot.sh

# 5. SSH
iproxy 2222 22 &
ssh root@localhost -p 2222    # alpine
```

Done. If something doesn't work – check the log next to the build (`bootchain/<name>/chain.info`) and the `magic=` line for iBSS/iBEC: `0df74f6e` / `6e4ff70d` – valid, `9f97aa83` – garbage, wrong key.
