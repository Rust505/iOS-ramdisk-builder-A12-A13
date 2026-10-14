#!/usr/bin/env bash
# Boot the SSH ramdisk for A12/A13 after usbliter8 pwned DFU.
#
# Порядок (как в рабочей Windows-версии BootService.cs):
#   1) iBEC (DFU → Recovery)
#   2) logo
#   3) firmware : ANE AOP AVE GFX ISP PMP SIO WCH
#   4) trustcache : firmware
#   5) ramdisk : ramdisk
#   6) devicetree : devicetree
#   7) SEP → rsepfirmware (fallback: sepfirmware)
#   8) kernelcache
#   9) setenv boot-args
#  10) bootx

set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
source "$ROOT/env.sh"
source "$ROOT/scripts/devices.sh"

IRECOVERY="$NR_TOOLS/irecovery"
USBLITER8_BOOT="$NR_TOOLS/usbliter8_boot"
USBLITER8CTL="${USBLITER8CTL:-}"
if [[ -z "$USBLITER8CTL" ]]; then
    for cand in \
        "$ROOT/../usbliter8ra1n/tools/usbliter8ctl" \
        "$ROOT/../usbliter8-xr-ramdisk/tools/usbliter8ctl" \
        "$NR_TOOLS/usbliter8ctl"; do
        [[ -f "$cand" ]] && USBLITER8CTL="$cand" && break
    done
fi
LOGO_HOLD_SECS="${LOGO_HOLD_SECS:-3}"
RECOVERY_WAIT_SECS="${RECOVERY_WAIT_SECS:-120}"
IRECV_CMD_TIMEOUT_SECS="${IRECV_CMD_TIMEOUT_SECS:-30}"
IRECV_UPLOAD_TIMEOUT_SECS="${IRECV_UPLOAD_TIMEOUT_SECS:-300}"

# ═══════════════════════════════════════════════════════════════════
#  BOOT-ARGS — ИСПРАВЛЕНО v2
#  Убран -progress (форсирует display stack → IOSurface panic на
#  patched kernel). Добавлены -v и debug=0x2014e для диагностики.
#  Для возврата progress bar — ./boot.sh --progress
# ═══════════════════════════════════════════════════════════════════
BOOTARGS="${BOOTARGS:-rd=md0 -v debug=0x2014e}"

WITH_FW=-1
SEP=1
USE_LOGO=1
USE_PROGRESS=0
SKIP_FW="${SKIP_FW:-}"   # напр. SKIP_FW="ANE GFX" или --skip-fw ANE,GFX

while (($#)); do
    case "$1" in
        --no-fw) WITH_FW=0; shift ;;
        --with-fw) WITH_FW=1; shift ;;
        --no-logo) USE_LOGO=0; shift ;;
        --logo) USE_LOGO=1; shift ;;
        --progress) USE_PROGRESS=1; shift ;;
        --sep) SEP=1; shift ;;
        --no-sep) SEP=0; shift ;;
        --boot-args) (($#>=2)) || { echo "--boot-args needs value" >&2; exit 64; }
                     BOOTARGS="$2"; shift 2 ;;
        --skip-fw) (($#>=2)) || { echo "--skip-fw needs value" >&2; exit 64; }
                   SKIP_FW="$2"; shift 2 ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 64 ;;
    esac
done

# --progress возвращает progress bar
if ((USE_PROGRESS)); then
    BOOTARGS="$BOOTARGS -progress"
fi

[[ -n "${BOOTCHAIN_NAME:-}" && -d "${BOOTCHAIN:-}" ]] || {
    echo "missing bootchain. Run ./build.sh first, or set BOOTCHAIN_NAME=..." >&2
    exit 1
}

if [[ -z "${LOGO_IMG4:-}" ]]; then
    if [[ -s "$BOOTCHAIN/logo.img4" ]]; then
        LOGO_IMG4="$BOOTCHAIN/logo.img4"
    else
        LOGO_IMG4="$NR_RESOURCES/logo.img4"
    fi
fi

[[ -x "$IRECOVERY" && -x "$USBLITER8_BOOT" ]] || {
    echo "missing tools under $NR_TOOLS" >&2
    exit 1
}

if ((WITH_FW < 0)); then
    if [[ -f "$BOOTCHAIN/with-fw.enabled" ]]; then
        WITH_FW=1
    else
        WITH_FW=0
    fi
fi

with_timeout() {
    local secs="$1"; shift
    perl -e '
        use strict; use warnings;
        my $t = shift @ARGV;
        $SIG{ALRM} = sub { print STDERR "error: timed out after ${t}s: @ARGV\n"; exit 124; };
        alarm $t;
        exec @ARGV or die "exec failed: $!\n";
    ' "$secs" "$@"
}

irecv_field() {
    local key="$1"
    local out
    out="$(with_timeout 5 "$IRECOVERY" -q 2>/dev/null || true)"
    awk -F': ' -v key="$key" '$1 == key { print $2; exit }' <<<"$out"
}

irecv_mode() { irecv_field MODE; }

irecv() {
    local secs="$IRECV_CMD_TIMEOUT_SECS"
    if [[ "${1:-}" == "-f" ]]; then
        secs="$IRECV_UPLOAD_TIMEOUT_SECS"
    fi
    with_timeout "$secs" "$IRECOVERY" "$@"
}

wait_recovery() {
    local i mode last="" prompt_at=25
    echo "Waiting for USB Recovery after iBoot (up to ${RECOVERY_WAIT_SECS}s)..."
    for i in $(seq 1 20); do
        mode="$(irecv_mode)"
        if [[ -z "$mode" || "$mode" != "DFU" ]]; then break; fi
        ((i == 1 || i % 5 == 0)) && echo "  still DFU… (${i}s)"
        sleep 1
    done
    for i in $(seq 1 "$RECOVERY_WAIT_SECS"); do
        mode="$(irecv_mode)"
        [[ "$mode" != "$last" ]] && { echo "  USB MODE: ${mode:-none}"; last="$mode"; }
        if [[ "$mode" == "Recovery" ]]; then
            if with_timeout 8 "$IRECOVERY" -c "getenv build-version" >/dev/null 2>&1 \
                || with_timeout 8 "$IRECOVERY" -q >/dev/null 2>&1; then
                echo "  iBoot Recovery ready (USB)"; return 0
            fi
        fi
        if ((i == prompt_at)); then
            echo "  *** USB Recovery not up yet — replug cable ***"
            prompt_at=$((prompt_at + 30))
        fi
        sleep 1
    done
    echo "error: timed out waiting for Recovery" >&2
    return 1
}

boot_via_usbliter8ctl() {
    local image="$1" tmp logpid
    tmp="$(mktemp -t usbliter8ctl-boot.XXXXXX)"
    echo "  usbliter8ctl boot $(basename "$image")"
    python3 "$USBLITER8CTL" boot "$image" >"$tmp" 2>&1 &
    logpid=$!
    for _ in $(seq 1 25); do
        if ! kill -0 "$logpid" 2>/dev/null; then
            wait "$logpid" || true; cat "$tmp"; rm -f "$tmp"; return 0
        fi
        if irecv_mode | grep -q 'Recovery'; then
            kill "$logpid" 2>/dev/null || true
            wait "$logpid" 2>/dev/null || true
            cat "$tmp"; rm -f "$tmp"
            echo "  device entered Recovery during ctl boot"; return 0
        fi
        sleep 1
    done
    cat "$tmp"; rm -f "$tmp"
    kill "$logpid" 2>/dev/null || true; wait "$logpid" 2>/dev/null || true
    echo "warning: usbliter8ctl boot did not exit; continuing" >&2
}

show_ich_logo_signed() {
    local mode board cpid w h logo
    mode="$(irecv_mode)"
    [[ "$mode" == "Recovery" ]] || { echo "warning: not Recovery — skip logo" >&2; return 1; }
    logo="$LOGO_IMG4"
    if [[ -s "$BOOTCHAIN/logo.img4" ]]; then
        logo="$BOOTCHAIN/logo.img4"
    else
        board="$(irecv_field MODEL)"; cpid="$(irecv_field CPID)"
        board="${board:-unknown}"; cpid="${cpid:-0x8020}"
        read -r w h <<<"$(nr_panel_for_board "$board")"
        if ! NR_CPID="$cpid" "$ROOT/scripts/make_logo.sh" "$board" --out "$BOOTCHAIN/logo.img4"; then
            echo "error: could not build logo" >&2; return 1
        fi
        logo="$BOOTCHAIN/logo.img4"
    fi
    echo "Setting ICH logo ($(wc -c <"$logo") bytes)..."
    if ! irecv -f "$logo"; then return 1; fi
    if irecv -c "setpicture 1" || irecv -c "setpicture" || irecv -c "setpicture 0"; then
        sleep "$LOGO_HOLD_SECS"; return 0
    fi
    return 1
}

# Проверка целостности bootchain (быстрая)
verify_bootchain_file() {
    local f="$1"
    [[ -s "$BOOTCHAIN/$f" ]] || { echo "[!] missing/empty $f" >&2; return 1; }
    return 0
}

nr_banner "boot $NR_VERSION"
echo "Booting: $BOOTCHAIN_NAME"
echo "  new_ramdisk $NR_VERSION by $NR_AUTHOR"
echo "  boot-args: $BOOTARGS"
echo "  USB firmwares: $([[ $WITH_FW -eq 1 ]] && echo enabled || echo disabled)"
[[ -n "$SKIP_FW" ]] && echo "  skip firmware: $SKIP_FW"
[[ -f "$BOOTCHAIN/chain.info" ]] && sed 's/^/  /' "$BOOTCHAIN/chain.info"

DEVICE_INFO="$(with_timeout 8 "$IRECOVERY" -q 2>/dev/null || true)"
PWND="$(awk -F': ' '$1 == "PWND" { print $2; exit }' <<<"$DEVICE_INFO")"
MODE="$(awk -F': ' '$1 == "MODE" { print $2; exit }' <<<"$DEVICE_INFO")"
[[ "$MODE" == "DFU" && "$PWND" == "usbliter8" ]] || {
    echo "need pwned DFU (PWND: usbliter8); MODE=${MODE:-?} PWND=${PWND:-?}" >&2
    exit 1
}

sleep 2

# ── 1) iBEC ────────────────────────────────────────────────────────
if [[ -f "$BOOTCHAIN/iBSS.patched.bin" && -f "$BOOTCHAIN/use-ibss" ]]; then
    echo "Loading iBSS → iBEC..."
    if [[ -n "${USBLITER8CTL:-}" && -f "$USBLITER8CTL" ]]; then
        python3 "$USBLITER8CTL" boot "$BOOTCHAIN/iBSS.patched.bin" || true
    else
        "$USBLITER8_BOOT" "$BOOTCHAIN/iBSS.patched.bin"
    fi
    sleep 4
    echo "Loading iBEC..."
    if [[ -f "$BOOTCHAIN/iBEC.patched.img4" ]]; then
        irecv -f "$BOOTCHAIN/iBEC.patched.img4"
    else
        irecv -f "$BOOTCHAIN/iBoot.patched.bin"
    fi
    irecv -c go || true
    sleep 3
    wait_recovery
else
    echo "Loading iBEC (direct)..."
    if [[ -n "${USBLITER8CTL:-}" && -f "$USBLITER8CTL" ]]; then
        boot_via_usbliter8ctl "$BOOTCHAIN/iBoot.patched.bin"
    else
        "$USBLITER8_BOOT" "$BOOTCHAIN/iBoot.patched.bin"
    fi
    sleep 5
    wait_recovery
fi

# ── 2) logo ────────────────────────────────────────────────────────
echo "Display: bgcolor black, then ICH logo"
irecv -c "bgcolor 0 0 0" || true
sleep 1
if ((USE_LOGO)); then
    show_ich_logo_signed || { echo "warning: logo failed" >&2; irecv -c "bgcolor 0 0 0" || true; }
fi

# ── 3) firmware (порядок как у Apple: ISP→GFX→ANE→AOP→SIO→PMP→AVE→WCH) ──
if ((WITH_FW)); then
    for fw in ISP GFX ANE AOP SIO PMP AVE WCH; do
        # --skip-fw
        if [[ -n "$SKIP_FW" ]] && \
           [[ " ${SKIP_FW//,/ } " == *" $fw "* ]]; then
            echo "  skip $fw (SKIP_FW)"
            continue
        fi
        if [[ -f "$BOOTCHAIN/$fw.img4" && -s "$BOOTCHAIN/$fw.img4" ]]; then
            echo "Loading $fw..."
            if irecv -f "$BOOTCHAIN/$fw.img4"; then
                irecv -c firmware || true
                sleep 2   # ↑ было 1
            else
                echo "  [!] $fw load failed — skip" >&2
            fi
        fi
    done
fi

# ── 4) trustcache ──────────────────────────────────────────────────
verify_bootchain_file "trustcache.img4" || exit 1
echo "Loading trustcache..."
irecv -f "$BOOTCHAIN/trustcache.img4"
irecv -c firmware
sleep 2

# ── 5) ramdisk ─────────────────────────────────────────────────────
verify_bootchain_file "ramdisk.img4" || exit 1
echo "Loading ramdisk ($(wc -c <"$BOOTCHAIN/ramdisk.img4") bytes)..."
irecv -f "$BOOTCHAIN/ramdisk.img4"
sleep 3
irecv -c ramdisk

# ── 6) DeviceTree ──────────────────────────────────────────────────
verify_bootchain_file "devicetree.img4" || exit 1
echo "Loading DeviceTree..."
irecv -f "$BOOTCHAIN/devicetree.img4"
irecv -c devicetree
sleep 2

# ── 7) SEP ─────────────────────────────────────────────────────────
if ((SEP)); then
    if [[ -s "$BOOTCHAIN/sep-firmware.img4" ]]; then
        echo "Loading SEP firmware ($(wc -c <"$BOOTCHAIN/sep-firmware.img4") bytes)..."
        irecv -f "$BOOTCHAIN/sep-firmware.img4"
        # rsepfirmware — правильная команда для iOS 15+, sepfirmware — legacy
        if irecv -c rsepfirmware 2>/dev/null; then :
        elif irecv -c sepfirmware 2>/dev/null; then :
        else echo "  [!] SEP install command failed" >&2; fi
        sleep 4
    else
        echo "  skip SEP (no sep-firmware.img4)"
    fi
fi

# ── 8) kernelcache ─────────────────────────────────────────────────
verify_bootchain_file "kernelcache.img4" || exit 1
echo "Loading kernel ($(wc -c <"$BOOTCHAIN/kernelcache.img4") bytes)..."
irecv -f "$BOOTCHAIN/kernelcache.img4"
sleep 2

# ── 9) boot-args ───────────────────────────────────────────────────
echo "Setting boot-args: $BOOTARGS"
if irecv -c "setenv boot-args $BOOTARGS"; then :
elif irecv -c "setenvnp boot-args $BOOTARGS"; then :
else echo "  [!] setenv failed — kernel will use default args" >&2; fi
sleep 1

# ── 10) bootx ──────────────────────────────────────────────────────
echo
echo "bootx..."
irecv -c bootx

echo
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  bootx sent — ждём SSH (может занять 30-60s)                ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Если паника — попробуйте варианты ниже:                    ║"
echo "║    1) ./boot.sh --no-fw        (без firmware)               ║"
echo "║    2) ./boot.sh --skip-fw GFX  (только GFX выкл)            ║"
echo "║    3) BOOTARGS='rd=md0 -v' ./boot.sh                        ║"
echo "║    4) BOOTARGS='rd=md0 -progress' ./boot.sh   (старый)      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo
echo "SSH:"
echo "  iproxy 2222 22"
echo "  ssh root@localhost -p 2222  (pass: alpine)"
echo "  then: X1PRO_MOUNT_USER=1 /usr/local/bin/remote_mount_dynamic.sh"
nr_footer