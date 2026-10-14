#!/usr/bin/env bash
# build_hybrid.sh — Hybrid A12/A13 SSH ramdisk builder
#
#   iBEC         ← из iOS 17.4 (гарантированно патчится)
#   остальное    ← из target-версии (14.0 – 17.3)
#
# Использование:
#   ./build_hybrid.sh --product iPhone12,1 --version 15.1
#   ./build_hybrid.sh --product iPhone12,1 --version 14.3 --ibec-from 17.4
#
# По умолчанию IBEC-FROM = 17.4 (21E219 / 21E236 / 21E237).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
source "$ROOT/env.sh"
source "$ROOT/scripts/devices.sh"
source "$ROOT/scripts/ramdisk_expand.sh"

nr_banner "build (hybrid)"

IRECOVERY="$NR_TOOLS/irecovery"
PZB="$NR_TOOLS/pzb"
IMG4="$NR_TOOLS/img4"
GTAR="$NR_TOOLS/gtar"
TC="$NR_TOOLS/trustcache"
JQ="$NR_TOOLS/jq"

IB_IMG4="$ROOT/bin/img4"
KERNEL_PATCHER="$ROOT/bin/Kernel64Patcher"
KERNEL_DIFF="$ROOT/bin/kerneldiff"
DT_PATCH="$ROOT/bin/dtpatch.py"

IMG4TOOL="${IMG4TOOL:-}"
if [[ -z "$IMG4TOOL" ]]; then
    if   command -v img4tool >/dev/null 2>&1; then IMG4TOOL="$(command -v img4tool)"
    elif [[ -x "$NR_TOOLS/img4tool" ]];        then IMG4TOOL="$NR_TOOLS/img4tool"
    elif [[ -x "$ROOT/bin/img4tool" ]];        then IMG4TOOL="$ROOT/bin/img4tool"
    fi
fi

KEYS_DIR="$ROOT/keys"
mkdir -p "$KEYS_DIR"

# ════════════════════════════════════════════════════════════════
# Ключи (RELEASE + RESEARCH) — те, что уже есть в build3.sh
# ════════════════════════════════════════════════════════════════
declare -A DECRYPT_KEYS_FALLBACK

# iPhone12,1 — основные версии
DECRYPT_KEYS_FALLBACK["iPhone12,1_18B92_iBEC"]="461d557d6a3295bc290047de084cf85a:695fd08c1ee82b4406b85e86d4f0b3732e35f6860c13d8ddbc8f765a7977ed83"
DECRYPT_KEYS_FALLBACK["iPhone12,1_18B92_iBEC_research"]="061e6baf075b058a8490dac0487e73f1:80abe2cf1342f813e2cb36a8a2045ce0a0e3beb8d3a8ec47fa9d417c40579794"
DECRYPT_KEYS_FALLBACK["iPhone12,1_19B74_iBEC"]="0eb14e53497ca827857597658af7b048:6cb5c604e7ed7283ca59ff69c6c9d90c1b51f6814ab43b4a6955ca4be68ae7e9"
DECRYPT_KEYS_FALLBACK["iPhone12,1_19B74_iBEC_research"]="a49266039080f2c666dac3c8a6a23371:bb05d267f9ac9e73887250f45cbbc007f37da7956599950fc86285013f09c8be"
DECRYPT_KEYS_FALLBACK["iPhone12,1_21D50_iBEC"]="5439ed20c257e8ed712954d78be01435:f94f3553b337062746d65237e43a183d8a1f9939a9399c0516764140bfe7e94e"
DECRYPT_KEYS_FALLBACK["iPhone12,1_21E219_iBEC"]="5455ee1bd7f07abdfc8fb0b46130d8f3:4868bdcd119e22548ea3ea5c8276c540f272abd3c32d66085866c1fe19f84278"
DECRYPT_KEYS_FALLBACK["iPhone12,1_21E236_iBEC"]="e3f46fc057a62f430c0d750e0c26cff0:7c117fab12659c78f3a7bcc9469470877599f402bc33fdc862c5352f4376c62b"
DECRYPT_KEYS_FALLBACK["iPhone12,1_21G93_iBEC"]="45b96cb41c4aec55888a049de7efdafe:302df247254b5f6302d47bfc7c8da9de906cfbdcc6ae52a3f05c84126117693c"
DECRYPT_KEYS_FALLBACK["iPhone12,1_21H16_iBEC"]="6fa0b358acab2a888edf2de3069f946a:c2aed1bcc2b360d1b00529c8969c8a9af905be565a483aa1fc24b39aff5d018a"

# ════════════════════════════════════════════════════════════════
# ARGS
# ════════════════════════════════════════════════════════════════
USER_PRODUCT=""
TARGET_VERSION=""
IBEC_FROM_VERSION="17.4"     # default
WITH_FW=1
USE_IBSS=0
KERNEL_MODE="patched"
DRY_RUN=0

usage() {
    cat <<'EOF'
usage: ./build_hybrid.sh --product PRODUCT --version TARGET_VERSION
                         [--ibec-from VERSION] [--kernel stock|patched]
                         [--with-fw|--no-fw] [--use-ibss] [--dry-run]

Примеры:
  ./build_hybrid.sh --product iPhone12,1 --version 15.1
  ./build_hybrid.sh --product iPhone12,1 --version 14.3 --ibec-from 17.4
EOF
}

while (($#)); do
    case "$1" in
        --product)   (($# >= 2)) || { usage >&2; exit 64; }; USER_PRODUCT="$2"; shift 2 ;;
        --version)   (($# >= 2)) || { usage >&2; exit 64; }; TARGET_VERSION="$2"; shift 2 ;;
        --ibec-from) (($# >= 2)) || { usage >&2; exit 64; }; IBEC_FROM_VERSION="$2"; shift 2 ;;
        --kernel)    (($# >= 2)) || { usage >&2; exit 64; }
                     KERNEL_MODE="$2"
                     case "$KERNEL_MODE" in stock|patched) ;; *) echo "bad --kernel" >&2; exit 64 ;; esac
                     shift 2 ;;
        --with-fw) WITH_FW=1; shift ;;
        --no-fw)   WITH_FW=0; shift ;;
        --use-ibss) USE_IBSS=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown: $1" >&2; usage >&2; exit 64 ;;
    esac
done

[[ -n "$USER_PRODUCT"    ]] || { usage >&2; exit 64; }
[[ -n "$TARGET_VERSION"  ]] || { usage >&2; exit 64; }

get_model_for_product() {
    local p="$1"
    case "$p" in
        iPhone12,1) echo "n104" ;;
        iPhone12,3) echo "d421" ;;
        iPhone12,5) echo "d431" ;;
        iPhone12,8) echo "d79" ;;
        iPhone11,2) echo "d321" ;;
        iPhone11,8) echo "n841" ;;
        *) echo "" ;;
    esac
}

get_cpid_for_product() {
    case "$1" in
        iPhone11,*) echo "0x8020" ;;
        iPhone12,*) echo "0x8030" ;;
        *) echo "" ;;
    esac
}

PRODUCT="$USER_PRODUCT"
MODEL="$(get_model_for_product "$PRODUCT")"
CPID="$(get_cpid_for_product  "$PRODUCT")"
[[ -n "$MODEL" && -n "$CPID" ]] || { echo "unknown product $PRODUCT" >&2; exit 1; }
CHIP="$(nr_chip_for_cpid "$CPID" 2>/dev/null || echo "A13")"

echo "=== device ==="
echo "  product:      $PRODUCT"
echo "  board:        $MODEL"
echo "  cpid:         $CPID ($CHIP)"
echo "  target iOS:   $TARGET_VERSION"
echo "  iBEC from:    iOS $IBEC_FROM_VERSION"

# ════════════════════════════════════════════════════════════════
# version_ge: v1 >= v2
# ════════════════════════════════════════════════════════════════
version_ge() {
    awk -v v1="$1" -v v2="$2" 'BEGIN {
        na = split(v1, a, "."); nb = split(v2, b, ".");
        n = (na > nb) ? na : nb;
        for (i = 1; i <= n; i++) {
            ai = (i <= na) ? a[i]+0 : 0;
            bi = (i <= nb) ? b[i]+0 : 0;
            if (ai > bi) exit 0;
            if (ai < bi) exit 1;
        }
        exit 0;
    }'
}

# ════════════════════════════════════════════════════════════════
# API: resolve IPSW URL for (product, version)
# ════════════════════════════════════════════════════════════════
resolve_ipsw() {
    local product="$1" version="$2"
    local api="https://api.ipsw.me/v4/device/$product?type=ipsw"
    local json; json="$(curl --fail -sL "$api")"
    "$JQ" -r --arg v "$version" '
        [.firmwares[] | select(.version == $v)]
        | sort_by(.releasedate // "") | reverse | .[0] // empty
        | "\(.version)|\(.buildid)|\(.url)"
    ' <<<"$json"
}

TARGET_INFO="$(resolve_ipsw "$PRODUCT" "$TARGET_VERSION")"
[[ -n "$TARGET_INFO" ]] || { echo "no IPSW for $PRODUCT $TARGET_VERSION" >&2; exit 1; }
TARGET_VERSION="${TARGET_INFO%%|*}"
rest="${TARGET_INFO#*|}"; TARGET_BUILD="${rest%%|*}"; TARGET_URL="${rest#*|}"

IBEC_INFO="$(resolve_ipsw "$PRODUCT" "$IBEC_FROM_VERSION")"
[[ -n "$IBEC_INFO" ]] || { echo "no IPSW for $PRODUCT $IBEC_FROM_VERSION" >&2; exit 1; }
IBEC_VERSION="${IBEC_INFO%%|*}"
rest="${IBEC_INFO#*|}"; IBEC_BUILD="${rest%%|*}"; IBEC_URL="${rest#*|}"

echo
echo "=== firmware ==="
echo "  target:     iOS $TARGET_VERSION ($TARGET_BUILD)"
echo "  iBEC from:  iOS $IBEC_VERSION ($IBEC_BUILD)"

if ((DRY_RUN)); then exit 0; fi

# ════════════════════════════════════════════════════════════════
# Cache dirs
# ════════════════════════════════════════════════════════════════
CACHE_T="$NR_CACHE/$PRODUCT-$TARGET_BUILD"
CACHE_I="$NR_CACHE/$PRODUCT-$IBEC_BUILD"
mkdir -p "$CACHE_T" "$CACHE_I"

# ════════════════════════════════════════════════════════════════
# Manifest fetch + parse
# ════════════════════════════════════════════════════════════════
fetch_manifest() {
    local cache="$1" url="$2"
    local mf="$cache/BuildManifest.plist"
    [[ -s "$mf" ]] || ( cd "$cache" && "$PZB" -g BuildManifest.plist "$url" )
    [[ -s "$mf" ]] || { echo "manifest fail" >&2; exit 1; }
    printf '%s' "$mf"
}

parse_manifest() {
    local mf="$1" board="$2"
    python3 - "$mf" "$board" <<'PY'
import plistlib, sys
from pathlib import Path
m = plistlib.loads(Path(sys.argv[1]).read_bytes())
board = sys.argv[2].lower().replace('ap','')
ident = None
for it in m["BuildIdentities"]:
    dc = it.get("Info", {}).get("DeviceClass", "").lower().replace('ap','')
    if dc == board:
        ident = it; break
if ident is None:
    raise SystemExit(f"no identity for {board}")
required = ["iBEC","DeviceTree","KernelCache",
            "RestoreRamDisk","RestoreTrustCache"]
optional = {
    "iBSS":["iBSS"], "RestoreSEP":["RestoreSEP"],
    "SPTM":["SPTM","Ap,SPTM","SecurePageTableMonitor","RestoreSPTM"],
    "TXM":["TXM","Ap,TXM","TrustedExecutionMonitor","Ap,TrustedExecutionMonitor"],
    "AOP":["AOP"],"ANE":["ANE"],"AVE":["AVE"],"ISP":["ISP"],
    "GFX":["GFX"],"SIO":["SIO"],"PMP":["PMP","Ap,PMP"],
}
imgs = ident["Manifest"]
for k in required:
    p = imgs.get(k,{}).get("Info",{}).get("Path")
    if p is None: raise SystemExit(f"missing required {k}")
    print(f"{k}={p}")
for k, cs in optional.items():
    for c in cs:
        p = imgs.get(c,{}).get("Info",{}).get("Path")
        if p:
            print(f"{k}={p}"); break
print(f"Build={ident['Info'].get('BuildNumber','')}")
PY
}

TARGET_MF="$(fetch_manifest "$CACHE_T" "$TARGET_URL")"
IBEC_MF="$(fetch_manifest   "$CACHE_I" "$IBEC_URL")"

TARGET_INFO_STR="$(parse_manifest "$TARGET_MF" "$MODEL")"
IBEC_INFO_STR="$(parse_manifest   "$IBEC_MF"   "$MODEL")"

mfield() { awk -F= -v k="$1" '$1==k{print substr($0,length(k)+2);exit}' <<<"$2"; }

TARGET_BUILD="$(mfield Build "$TARGET_INFO_STR")"
IBEC_BUILD="$(mfield Build   "$IBEC_INFO_STR")"
echo "  confirmed target build: $TARGET_BUILD"
echo "  confirmed iBEC build:   $IBEC_BUILD"

# ════════════════════════════════════════════════════════════════
# Fetch members
# ════════════════════════════════════════════════════════════════
fetch_member() {
    local cache="$1" url="$2" member="$3"
    local dst="$cache/$(basename "$member")"
    if [[ ! -s "$dst" ]]; then
        ( cd "$cache" && "$PZB" -g "$member" "$url" )
    fi
    [[ -s "$dst" ]] || { echo "pzb fail: $member" >&2; exit 1; }
    printf '%s' "$dst"
}

# ════════════════════════════════════════════════════════════════
# WORK dirs
# ════════════════════════════════════════════════════════════════
WORK="$NR_WORK/hybrid-$PRODUCT-$TARGET_BUILD-from-$IBEC_BUILD"
OUT="$NR_WORK/out-$PRODUCT-$TARGET_BUILD"
BOOTCHAIN_NAME="$MODEL-$TARGET_VERSION-$TARGET_BUILD-hybrid-ramdisk"
BOOTCHAIN="$NR_BOOTCHAIN_ROOT/$BOOTCHAIN_NAME"
rm -rf "$WORK" "$OUT" "$BOOTCHAIN"
mkdir -p "$WORK" "$OUT" "$BOOTCHAIN"

echo
echo "=== fetching iBEC from $IBEC_BUILD ==="
IBEC_PATH="$(mfield iBEC "$IBEC_INFO_STR")"
[[ -n "$IBEC_PATH" ]] || { echo "no iBEC in manifest" >&2; exit 1; }
cp "$(fetch_member "$CACHE_I" "$IBEC_URL" "$IBEC_PATH")" "$WORK/iBEC.im4p"

if ((USE_IBSS)); then
    IBSS_PATH="$(mfield iBSS "$IBEC_INFO_STR")"
    if [[ -n "$IBSS_PATH" ]]; then
        cp "$(fetch_member "$CACHE_I" "$IBEC_URL" "$IBSS_PATH")" "$WORK/iBSS.im4p"
    fi
fi

echo
echo "=== fetching target files from $TARGET_BUILD ==="
for k in DeviceTree KernelCache RestoreRamDisk RestoreTrustCache; do
    P="$(mfield "$k" "$TARGET_INFO_STR")"
    [[ -n "$P" ]] || { echo "missing $k" >&2; exit 1; }
    cp "$(fetch_member "$CACHE_T" "$TARGET_URL" "$P")" "$WORK/$k.im4p"
done

# SEP-firmware — из target
SEP_PATH="$(mfield RestoreSEP "$TARGET_INFO_STR")"
if [[ -n "$SEP_PATH" ]]; then
    cp "$(fetch_member "$CACHE_T" "$TARGET_URL" "$SEP_PATH")" "$WORK/RestoreSEP.im4p"
fi

# FW components — из target
if ((WITH_FW)); then
    for k in AOP ANE AVE ISP GFX SIO PMP; do
        P="$(mfield "$k" "$TARGET_INFO_STR")"
        [[ -n "$P" ]] || continue
        cp "$(fetch_member "$CACHE_T" "$TARGET_URL" "$P")" "$WORK/$k.im4p"
    done
fi

# ════════════════════════════════════════════════════════════════
# IM4M
# ════════════════════════════════════════════════════════════════
IM4M="$NR_RESOURCES/IM4M_$CPID"
[[ -f "$IM4M" ]] || { echo "missing IM4M: $IM4M" >&2; exit 1; }

[[ -f "$NR_RESOURCES/ssh.tar.gz"     ]] || { echo "missing ssh.tar.gz" >&2; exit 1; }
[[ -f "$NR_RESOURCES/sshtarlist.txt" ]] || { echo "missing sshtarlist.txt" >&2; exit 1; }

# ════════════════════════════════════════════════════════════════
# Extract iBEC.raw (17.4 — зашифрован, нужно decrypt)
# ════════════════════════════════════════════════════════════════
echo
echo "=== decrypt iBEC ($IBEC_VERSION) ==="
ipsw img4 im4p extract -o "$WORK/iBEC.raw" "$WORK/iBEC.im4p" 2>/dev/null || true

need_decrypt() {
    local f="$1"
    [[ -s "$f" ]] || return 0
    local mg; mg="$(xxd -p -l4 "$f" 2>/dev/null || echo "")"
    case "$mg" in
        cffaedfe|cefaedfe|feedface|feedfacf) return 1 ;;
        00000090) return 1 ;;
        62767832|6276782d|6276786e) return 1 ;;
        0df74f6e|6e4ff70d) return 1 ;;
    esac
    return 0
}

try_decrypt() {
    local in="$1" out="$2" product="$3" build="$4" comp="$5"
    local key_kind="$6"   # release | research

    local iv key
    if [[ "$key_kind" == "research" ]]; then
        local rk="${DECRYPT_KEYS_FALLBACK[${product}_${build}_${comp}_research]:-}"
        [[ -n "$rk" ]] || return 1
        iv="${rk%%:*}"; key="${rk##*:}"
    else
        local rk="${DECRYPT_KEYS_FALLBACK[${product}_${build}_${comp}]:-}"
        [[ -n "$rk" ]] || return 1
        iv="${rk%%:*}"; key="${rk##*:}"
    fi

    echo "  [i] $comp ($key_kind) IV=$iv"
    "$IMG4TOOL" -e --iv "$iv" --key "$key" -o "$out" "$in" >/dev/null 2>&1 || return 1

    local mg; mg="$(xxd -p -l4 "$out" 2>/dev/null || echo "")"
    case "$mg" in
        cffaedfe|cefaedfe|feedface|feedfacf|00000090|62767832|6276782d|6276786e|0df74f6e|6e4ff70d)
            return 0 ;;
    esac
    return 1
}

if need_decrypt "$WORK/iBEC.raw"; then
    # Release
    if ! try_decrypt "$WORK/iBEC.im4p" "$WORK/iBEC.raw" "$PRODUCT" "$IBEC_BUILD" "iBEC" "release"; then
        echo "  [!] release ключ не сработал, пробую research"
        if ! try_decrypt "$WORK/iBEC.im4p" "$WORK/iBEC.raw" "$PRODUCT" "$IBEC_BUILD" "iBEC" "research"; then
            echo "[!] decrypt iBEC failed" >&2; exit 1
        fi
    fi
    strip_to_macho() {  # inline helper
        local f="$1" mg
        mg="$(xxd -p -l4 "$f" 2>/dev/null || echo "")"
        case "$mg" in cffaedfe|cefaedfe|feedface|feedfacf) return 0 ;; esac
        local off
        off="$(python3 - "$f" <<'PY'
import sys
with open(sys.argv[1],'rb') as fp: d=fp.read(4*1024*1024)
for m in (b'\xcf\xfa\xed\xfe',b'\xce\xfa\xed\xfe',b'\xfe\xed\xfa\xcf',b'\xfe\xed\xfa\xce'):
    i=d.find(m)
    if i>=0: print(i); sys.exit(0)
sys.exit(1)
PY
)" || off=""
        [[ -z "$off" || "$off" == "0" ]] && return 0
        dd if="$f" of="$f.macho" bs=1 skip="$off" 2>/dev/null
        mv "$f.macho" "$f"
    }
    strip_to_macho "$WORK/iBEC.raw" || true

    mg="$(xxd -p -l4 "$WORK/iBEC.raw" 2>/dev/null || echo "")"
    echo "  [✓] iBEC.raw magic=$mg"
fi

# ════════════════════════════════════════════════════════════════
# PATCH iBEC 17.4 (наш patchfinder работает на 17.4)
# ════════════════════════════════════════════════════════════════
echo
echo "=== patch iBEC ($IBEC_VERSION) with iboot_patchfinder ==="
IBEC_MAJOR="${IBEC_VERSION%%.*}"

python3 "$NR_PATCH/iboot_patchfinder.py" \
    "$WORK/iBEC.raw" \
    "$OUT/iBEC.patched.raw" \
    --mode ibec \
    --ios "$IBEC_MAJOR" \
    --cpid "$CPID"

[[ -s "$OUT/iBEC.patched.raw" ]] || { echo "patchfinder failed" >&2; exit 1; }

# Finalize iboot (обёртка в IMG4) — используем raw payload напрямую
cp "$OUT/iBEC.patched.raw" "$OUT/iBoot.patched.bin"
cp "$OUT/iBoot.patched.bin" "$BOOTCHAIN/iBoot.patched.bin"

# ════════════════════════════════════════════════════════════════
# DeviceTree — из target. Legacy-patch (14-17): удалить content-protect
# ════════════════════════════════════════════════════════════════
echo
echo "=== DeviceTree ($TARGET_VERSION) ==="
"$IMG4" -i "$WORK/DeviceTree.im4p" -o "$WORK/DeviceTree.raw" 2>/dev/null || \
    ipsw img4 im4p extract -o "$WORK/DeviceTree.raw" "$WORK/DeviceTree.im4p" 2>/dev/null || true
[[ -s "$WORK/DeviceTree.raw" ]] || { echo "DT extract failed" >&2; exit 1; }

if [[ -f "$DT_PATCH" ]]; then
    python3 "$DT_PATCH" "$WORK/DeviceTree.raw" -o "$WORK/DeviceTree.patched.raw"
else
    cp "$WORK/DeviceTree.raw" "$WORK/DeviceTree.patched.raw"
    perl -pi -e 's/content-protect/content-protecV/g' "$WORK/DeviceTree.patched.raw"
fi

"$IMG4" -i "$WORK/DeviceTree.patched.raw" -o "$BOOTCHAIN/devicetree.img4" \
    -A -T rdtr -M "$IM4M"

# ════════════════════════════════════════════════════════════════
# iBEC.img4 (для полноты)
# ════════════════════════════════════════════════════════════════
"$IMG4" -i "$OUT/iBoot.patched.bin" -o "$BOOTCHAIN/iBEC.img4" \
    -A -T ibec -M "$IM4M"

# ════════════════════════════════════════════════════════════════
# RamDisk: expand + inject SSH
# ════════════════════════════════════════════════════════════════
echo
echo "=== ramdisk ($TARGET_VERSION) ==="
"$IMG4" -i "$WORK/RestoreRamDisk.im4p" -o "$WORK/ramdisk.dmg"

trap 'hdiutil detach -force /tmp/NewRamdiskRD >/dev/null 2>&1 || true' EXIT
nr_expand_inject_ramdisk "$WORK/ramdisk.dmg" "$NR_RESOURCES/ssh.tar.gz" \
    /tmp/NewRamdiskRD "$GTAR"

if [[ -f "$NR_RESOURCES/restored_external" ]]; then
    hdiutil attach -mountpoint /tmp/NewRamdiskRD -owners off \
        -imagekey diskimage-class=CRawDiskImage "$WORK/ramdisk.dmg" >/dev/null
    if [[ -d /tmp/NewRamdiskRD/usr/local/bin ]]; then
        cp "$NR_RESOURCES/restored_external" \
            /tmp/NewRamdiskRD/usr/local/bin/restored_external
        chmod 755 /tmp/NewRamdiskRD/usr/local/bin/restored_external
    fi
    hdiutil detach -force /tmp/NewRamdiskRD >/dev/null 2>&1 || true
fi
trap - EXIT

# ════════════════════════════════════════════════════════════════
# TrustCache — из target
# ════════════════════════════════════════════════════════════════
echo
echo "=== trustcache ($TARGET_VERSION) ==="
"$IMG4" -i "$WORK/RestoreTrustCache.im4p" -o "$NR_WORK/trustcache.bin"

if [[ -f "$NR_RESOURCES/restored_external" ]]; then
    if ! grep -qxF "/usr/local/bin/restored_external" "$NR_RESOURCES/sshtarlist.txt"; then
        printf '/usr/local/bin/restored_external\n' >> "$NR_RESOURCES/sshtarlist.txt"
    fi
fi

(
    cd "$ROOT"
    mkdir -p work
    cp "$NR_WORK/trustcache.bin" work/trustcache.bin
    "$TC" append work/trustcache.bin $(<"resources/sshtarlist.txt")
)
cp "$NR_WORK/trustcache.bin" "$WORK/trustcache.bin"

"$IMG4" -i "$WORK/trustcache.bin" -o "$BOOTCHAIN/trustcache.img4" \
    -A -T rtsc -M "$IM4M"
"$IMG4" -i "$WORK/ramdisk.dmg" -o "$BOOTCHAIN/ramdisk.img4" \
    -A -T rdsk -M "$IM4M"

# ════════════════════════════════════════════════════════════════
# KernelCache — из target, патч Kernel64Patcher
# ════════════════════════════════════════════════════════════════
echo
echo "=== kernel ($TARGET_VERSION) ==="
if [[ ! -f "$WORK/kernelcache.raw" ]]; then
    if [[ -n "$IMG4TOOL" ]]; then
        "$IMG4TOOL" -e "$WORK/KernelCache.im4p" -o "$WORK/kernelcache.raw" 2>/dev/null || true
    fi
    [[ -s "$WORK/kernelcache.raw" ]] || \
        ipsw img4 im4p extract -o "$WORK/kernelcache.raw" "$WORK/KernelCache.im4p" 2>/dev/null || true
    [[ -s "$WORK/kernelcache.raw" ]] || { echo "kernel extract failed" >&2; exit 1; }
fi

KERNEL_SIZE=$(stat -f%z "$WORK/kernelcache.raw" 2>/dev/null || stat -c%s "$WORK/kernelcache.raw")
[[ "$KERNEL_SIZE" -ge 10000000 ]] || { echo "kernel too small" >&2; exit 1; }

[[ -x "$KERNEL_PATCHER" ]] || {
    curl -L -o "$KERNEL_PATCHER" \
        https://github.com/pwnerblu/surrealra1n/raw/refs/heads/main/bin/Kernel64Patcher
    chmod +x "$KERNEL_PATCHER"
}
[[ -x "$KERNEL_DIFF" ]] || {
    curl -L -o "$KERNEL_DIFF" \
        https://github.com/pwnerblu/surrealra1n/raw/refs/heads/main/bin/kerneldiff
    chmod +x "$KERNEL_DIFF"
}

"$KERNEL_PATCHER" "$WORK/kernelcache.raw" "$OUT/kernelcache.patched.raw" -a -d -e -o
[[ -f "$OUT/kernelcache.patched.raw" ]] || { echo "Kernel64Patcher failed" >&2; exit 1; }

KERNEL_DIFF_OK=1
"$KERNEL_DIFF" "$WORK/kernelcache.raw" "$OUT/kernelcache.patched.raw" \
    "$OUT/kernelcache.diff" || KERNEL_DIFF_OK=0

if ((KERNEL_DIFF_OK)) && [[ -s "$OUT/kernelcache.diff" ]]; then
    "$IMG4" -i "$WORK/KernelCache.im4p" -o "$BOOTCHAIN/kernelcache.img4" \
        -T rkrn -P "$OUT/kernelcache.diff" -M "$IM4M" -J
else
    "$IMG4" -i "$OUT/kernelcache.patched.raw" -o "$BOOTCHAIN/kernelcache.img4" \
        -A -T rkrn -M "$IM4M"
fi
echo "kernel patched (Kernel64Patcher)"

# ════════════════════════════════════════════════════════════════
# Firmware components — из target
# ════════════════════════════════════════════════════════════════
if ((WITH_FW)); then
    for c in PMP AOP ANE AVE ISP GFX SIO; do
        [[ -f "$WORK/$c.im4p" ]] || continue
        "$IMG4" -i "$WORK/$c.im4p" -o "$BOOTCHAIN/$c.img4" -M "$IM4M"
    done
    printf '1\n' > "$BOOTCHAIN/with-fw.enabled"
fi

# SEP — из target
[[ -f "$WORK/RestoreSEP.im4p" ]] && \
    "$IMG4" -i "$WORK/RestoreSEP.im4p" -o "$BOOTCHAIN/sep-firmware.img4" -M "$IM4M"

# ════════════════════════════════════════════════════════════════
# Chain info
# ════════════════════════════════════════════════════════════════
{
    echo "product=$PRODUCT"
    echo "model=$MODEL"
    echo "cpid=$CPID"
    echo "chip=$CHIP"
    echo "version=$TARGET_VERSION"
    echo "build=$TARGET_BUILD"
    echo "ibec_from_version=$IBEC_VERSION"
    echo "ibec_from_build=$IBEC_BUILD"
    echo "hybrid=1"
    echo "ibss=$USE_IBSS"
    echo "kernel=$KERNEL_MODE"
    echo "with_fw=$WITH_FW"
    echo "boot_args=serial=3 -v debug=0x2014e rd=md0"
} > "$BOOTCHAIN/chain.info"

# ════════════════════════════════════════════════════════════════
# Preflight
# ════════════════════════════════════════════════════════════════
if [[ -f "$NR_PATCH/preflight.py" ]]; then
    PREFLIGHT=(
        python3 "$NR_PATCH/preflight.py"
        --bootchain "$BOOTCHAIN"
        --stock-iboot "$WORK/iBEC.raw"
        --expected-board "$MODEL"
        --expected-build "$TARGET_BUILD"
        --kernel-mode "$KERNEL_MODE"
        --stock-kernel "$WORK/KernelCache.im4p"
        --allow-patched-kernel
    )
    "${PREFLIGHT[@]}" || echo "[!] preflight failed — check logs"
fi

printf '%s\n' "$BOOTCHAIN_NAME" > "$NR_LAST_BOOTCHAIN_FILE"

echo
echo "Built: $BOOTCHAIN"
echo "Boot:  ./boot.sh"
nr_footer