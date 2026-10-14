#!/usr/bin/env bash
# build5.sh — A12/A13 SSH ramdisk builder
# Версия 4.0.0:
#   + iOS 15.0–17.3.1: iBSS через iBootPatch (SSHRD-style)
#   + iOS 17.4+     : iBEC через iboot_patchfinder.py / iBoot64Patcher
#   + kairos убран полностью
#   + iBSS скачивается из Firmware/dfu/iBSS.<board>.RELEASE.im4p
#   + Валидность iBSS/iBEC payload проверяется по magic
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
source "$ROOT/env.sh"
source "$ROOT/scripts/devices.sh"
source "$ROOT/scripts/ramdisk_expand.sh"

nr_banner "build"

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
# Inline fallback ключей (iBSS для 15.0–17.3.1, iBEC для 17.4+)
# ════════════════════════════════════════════════════════════════
declare -A DECRYPT_KEYS_FALLBACK

# ── iBSS (SSHRD-стиль, для 15.0–17.3.1) ────────────────────────
DECRYPT_KEYS_FALLBACK["iPhone12,1_18B92_iBSS"]="aa2e8d3a3c744fe44ad3eba1e07549a0:80761afed648b7fe8fe81972c3d509e347d8e5484b17d09c4050a36960526f7f"
DECRYPT_KEYS_FALLBACK["iPhone12,1_18B92_iBSS_research"]="c60b2a77058f5745a7d886ccdeefcaed:001c43533c8484f0e98f734dbc12d008c6f419a561a3640f732587961e4e92bb"
DECRYPT_KEYS_FALLBACK["iPhone12,1_21G93_iBSS"]="d39e3113aad4f82bf837bbb1cd8b78b5:90b033ccb5601e4a351bd6e51973a88633ef19a35081fbc13faba7270dff5570"
DECRYPT_KEYS_FALLBACK["iPhone12,1_21H16_iBSS"]="653c93fa8dbc53274390bafe9a0963d0:3f6469a1c3f064ab5b8358fb4268a8f15a434270d38a2bdbd75bb57420728100"
DECRYPT_KEYS_FALLBACK["iPhone12,5_18B92_iBSS"]="38a1879144794ef03e1a831792cde206:c0ed2878ab09320f9900725974b460bd2102264d984ec3d572128f0e5524cbaf"
DECRYPT_KEYS_FALLBACK["iPhone12,8_21F79_iBSS"]="429cf33d6f035f50d5352c44a8189500:1bf72bc0ceb14b70cc99d5fc90ce9d0b56f43614e68d9f462b63af0ea36861b5"

# ── iBEC (для 17.4+) ──────────────────────────────────────────
DECRYPT_KEYS_FALLBACK["iPhone12,1_18B92_iBEC"]="461d557d6a3295bc290047de084cf85a:695fd08c1ee82b4406b85e86d4f0b3732e35f6860c13d8ddbc8f765a7977ed83"
DECRYPT_KEYS_FALLBACK["iPhone12,1_18B92_iBEC_research"]="061e6baf075b058a8490dac0487e73f1:80abe2cf1342f813e2cb36a8a2045ce0a0e3beb8d3a8ec47fa9d417c40579794"
DECRYPT_KEYS_FALLBACK["iPhone12,1_20B82_iBEC"]="b9e3dce1c6b2fc8eba45a789316a73d4:7aad25c22ba37f0d40d8e81508ad1a81b95803217d1651ab9c2e1b33485d7805"
DECRYPT_KEYS_FALLBACK["iPhone12,1_21D50_iBEC"]="5439ed20c257e8ed712954d78be01435:f94f3553b337062746d65237e43a183d8a1f9939a9399c0516764140bfe7e94e"
DECRYPT_KEYS_FALLBACK["iPhone12,1_21G93_iBEC"]="45b96cb41c4aec55888a049de7efdafe:302df247254b5f6302d47bfc7c8da9de906cfbdcc6ae52a3f05c84126117693c"
DECRYPT_KEYS_FALLBACK["iPhone12,1_21H16_iBEC"]="6fa0b358acab2a888edf2de3069f946a:c2aed1bcc2b360d1b00529c8969c8a9af905be565a483aa1fc24b39aff5d018a"
DECRYPT_KEYS_FALLBACK["iPhone12,1_19B74_iBEC"]="0eb14e53497ca827857597658af7b048:6cb5c604e7ed7283ca59ff69c6c9d90c1b51f6814ab43b4a6955ca4be68ae7e9"
DECRYPT_KEYS_FALLBACK["iPhone12,1_19B74_iBEC_research"]="a49266039080f2c666dac3c8a6a23371:bb05d267f9ac9e73887250f45cbbc007f37da7956599950fc86285013f09c8be"
DECRYPT_KEYS_FALLBACK["iPhone12,5_18B92_iBEC"]="9a721c69d8e4d6aec9dbb1b9e51ba5d5:ec0a8a00460733cfb1cd534f681d1265f98f6f5fe2657c919ac34d09a8a4698d"
DECRYPT_KEYS_FALLBACK["iPhone12,8_21F79_iBEC"]="927c3a8732ce05c6b2ed15d28cf47a8a:2c83d33e8c49323964100391f22f35ad200e50c6bc79daabc51c383888b37ecd"

# ════════════════════════════════════════════════════════════════
# JSON-ключи
# ════════════════════════════════════════════════════════════════
_product_norm() { printf '%s' "${1//,/_}"; }

_find_keys_json() {
    local product="$1"
    local norm; norm="$(_product_norm "$product")"
    local candidates=(
        "$ROOT/keys/ibec_keys_${norm}.json"
        "$ROOT/ibec_keys_${norm}.json"
        "$ROOT/keys_${norm}.json"
        "$KEYS_DIR/ibec_keys_${norm}.json"
        "$HOME/Downloads/ICH_A12_plus_Ramdisk-1.23/ibec_keys_${norm}.json"
    )
    local p
    for p in "${candidates[@]}"; do
        [[ -f "$p" ]] && { printf '%s\n' "$p"; return 0; }
    done
    return 1
}

_json_lookup() {
    local json_path="$1" build="$2" comp="$3"
    python3 - "$json_path" "$build" "$comp" <<'PY'
import json, sys
path, build, comp = sys.argv[1:4]
try:
    d = json.load(open(path, encoding="utf-8"))
except Exception:
    sys.exit(1)

ALIASES = {
    "iBSS":          ("iBSS", "iBSS_release", "iBSS_RELEASE", "iBSS_release_fused"),
    "iBSS_research": ("iBSS_research", "iBSS_RESEARCH", "iBSS_Research"),
    "iBEC":          ("iBEC", "release", "iBEC_release", "iBEC_RELEASE"),
    "iBEC_research": ("iBEC_research", "research", "iBEC_RESEARCH"),
    "release":       ("release", "iBEC", "iBEC_release"),
    "research":      ("research", "iBEC_research"),
}

def _emit(v):
    if isinstance(v, dict) and v.get("iv") and v.get("key"):
        print(f"{v['iv']}:{v['key']}")
        return True
    return False

def _get(data):
    if not isinstance(data, dict): return False
    for k in ALIASES.get(comp, (comp,)):
        if _emit(data.get(k)): return True
    return False

for ios, builds in d.items():
    if isinstance(builds, dict) and build in builds:
        if _get(builds[build]): sys.exit(0)

for ios, builds in d.items():
    if not isinstance(builds, dict): continue
    for b, data in builds.items():
        if b.lower() == build.lower():
            if _get(data): sys.exit(0)

sys.exit(1)
PY
}

fetch_keys_from_json() {
    local product="$1" build="$2" kind="$3"
    local json_path
    json_path="$(_find_keys_json "$product")" || return 1
    local result
    result="$(_json_lookup "$json_path" "$build" "$kind")" || return 1
    [[ -n "$result" && "$result" == *:* ]] || return 1
    printf '%s\n' "$result"
    return 0
}

lookup_iboot_key_from_json() {
    local product="$1" build="$2" component="$3"
    local norm="${product//,/_}"
    local json="" candidate
    for candidate in "$ROOT/ibec_keys_${norm}.json" \
                     "$ROOT/keys/ibec_keys_${norm}.json" \
                     "$ROOT/keys/${norm}.json"; do
        if [[ -f "$candidate" ]]; then json="$candidate"; break; fi
    done
    [[ -z "$json" ]] && return 1
    python3 - "$json" "$build" "$component" <<'PY' 2>/dev/null
import json, sys
path, build, comp = sys.argv[1:4]
try: d = json.load(open(path, encoding="utf-8"))
except Exception: sys.exit(1)
def _emit(v):
    if isinstance(v, dict) and v.get("iv") and v.get("key"):
        print(f"{v['iv']}:{v['key']}"); return True
    return False
def _get(data):
    if not isinstance(data, dict): return False
    for k in (comp, comp+"_release", comp.upper()):
        if _emit(data.get(k)): return True
    return False
for ios, builds in d.items():
    if isinstance(builds, dict) and build in builds:
        if _get(builds[build]): sys.exit(0)
for ios, builds in d.items():
    if not isinstance(builds, dict): continue
    for b, data in builds.items():
        if b.lower() == build.lower():
            if _get(data): sys.exit(0)
sys.exit(1)
PY
}

lookup_ibss_keyfile() {
    local product="$1" component="$2" version="$3" build="$4"
    local keyfile="$ROOT/keys/${product}.txt"
    [[ -f "$keyfile" ]] || return 1
    local comp_lc; comp_lc="$(echo "$component" | tr 'A-Z' 'a-z')"
    local v val
    for v in "$version" "$build"; do
        [[ -z "$v" || "$v" == "unknown" || "$v" == "custom" ]] && continue
        val=$(grep -iE "^${comp_lc}-${v//./\\.}:[[:space:]]*" "$keyfile" 2>/dev/null \
              | head -1 | sed -E "s/^${comp_lc}-[^:]+:[[:space:]]*//" | tr -d '[:space:]' || true)
        [[ -n "$val" ]] && { printf '%s\n' "$val"; return 0; }
    done
    return 1
}

# ════════════════════════════════════════════════════════════════
_im4p_magic_ok() {
    case "$1" in
        cffaedfe|cefaedfe|feedface|feedfacf)   return 0 ;;
        00000090)                               return 0 ;;
        62767832|6276782d|6276786e)             return 0 ;;
        0df74f6e|6e4ff70d)                      return 0 ;;
    esac
    return 1
}

_nr_size() { stat -f%z "$1" 2>/dev/null || stat -c%s "$1" 2>/dev/null || echo 0; }

_nr_ok_payload() {
    [[ -s "$1" ]] || return 1
    (( $(_nr_size "$1") > 100000 )) || return 1
    local mg; mg="$(xxd -p -l4 "$1" 2>/dev/null || echo "")"
    _im4p_magic_ok "$mg"
}

# ════════════════════════════════════════════════════════════════
# iBSS: decrypt + patch (iOS 15.0–17.3.1)
# ════════════════════════════════════════════════════════════════
decrypt_ibss() {
    local im4p_in="$1" raw_out="$2" product="$3" build="$4"

    local keyfile_key=""
    local keyfile="$ROOT/keys/${product}.txt"
    if [[ -f "$keyfile" ]]; then
        local v
        for v in "${VERSION:-}" "$build"; do
            [[ -z "$v" || "$v" == "unknown" || "$v" == "custom" ]] && continue
            keyfile_key=$(grep -iE "^ibss-${v//./\\.}:[[:space:]]*" "$keyfile" 2>/dev/null \
                          | head -1 | cut -d':' -f2- | tr -d '[:space:]' || true)
            [[ -n "$keyfile_key" ]] && break
        done
    fi

    local json_key=""
    json_key="$(lookup_iboot_key_from_json "$product" "$build" "iBSS" 2>/dev/null)" || true
    [[ -z "$json_key" ]] && json_key="$(fetch_keys_from_json "$product" "$build" "iBSS" 2>/dev/null)" || true

    # A) keyfile
    if [[ -n "$keyfile_key" ]]; then
        rm -f "$raw_out"
        echo "  [i] iBSS decrypt (keyfile: img4 -k <96hex>)"
        if "$IB_IMG4" -i "$im4p_in" -o "$raw_out" -k "$keyfile_key" >/dev/null 2>&1 \
           && _nr_ok_payload "$raw_out"; then
            local mg; mg="$(xxd -p -l4 "$raw_out" 2>/dev/null || echo "")"
            echo "  [✓] iBSS расшифрован ($(_nr_size "$raw_out") байт, magic=$mg, keyfile)"
            return 0
        fi
        rm -f "$raw_out"
    fi

    # B) без ключа
    rm -f "$raw_out"
    echo "  [i] iBSS decrypt (img4 без ключа)"
    if "$IB_IMG4" -i "$im4p_in" -o "$raw_out" >/dev/null 2>&1 \
       && _nr_ok_payload "$raw_out"; then
        local mg; mg="$(xxd -p -l4 "$raw_out" 2>/dev/null || echo "")"
        echo "  [✓] iBSS извлечён без ключа ($(_nr_size "$raw_out") байт, magic=$mg)"
        return 0
    fi
    rm -f "$raw_out"

    # C) JSON (fused / key-only / img4tool)
    if [[ -n "$json_key" ]]; then
        local iv="${json_key%%:*}" key="${json_key##*:}"
        local fused="${iv}${key}"
        for mode in fused keyonly; do
            rm -f "$raw_out"
            if [[ "$mode" == "fused" ]]; then
                echo "  [i] iBSS decrypt (JSON → img4 -k FUSED)"
                "$IB_IMG4" -i "$im4p_in" -o "$raw_out" -k "$fused" >/dev/null 2>&1 || true
            else
                echo "  [i] iBSS decrypt (JSON → img4 -k KEY-only)"
                "$IB_IMG4" -i "$im4p_in" -o "$raw_out" -k "$key" >/dev/null 2>&1 || true
            fi
            if _nr_ok_payload "$raw_out"; then
                local mg; mg="$(xxd -p -l4 "$raw_out" 2>/dev/null || echo "")"
                echo "  [✓] iBSS расшифрован ($(_nr_size "$raw_out") байт, magic=$mg, $mode)"
                return 0
            fi
            rm -f "$raw_out"
        done
        if [[ -n "$IMG4TOOL" ]]; then
            rm -f "$raw_out"
            echo "  [i] iBSS decrypt (img4tool -e --iv --key)"
            "$IMG4TOOL" -e --iv "$iv" --key "$key" -o "$raw_out" "$im4p_in" >/dev/null 2>&1 || true
            if _nr_ok_payload "$raw_out"; then
                local mg; mg="$(xxd -p -l4 "$raw_out" 2>/dev/null || echo "")"
                echo "  [✓] iBSS расшифрован ($(_nr_size "$raw_out") байт, magic=$mg, img4tool)"
                return 0
            fi
            rm -f "$raw_out"
        fi
    fi

    # D) inline fallback
    local fb="${DECRYPT_KEYS_FALLBACK[${product}_${build}_iBSS]:-}"
    if [[ -n "$fb" ]]; then
        rm -f "$raw_out"
        echo "  [i] iBSS decrypt (inline fallback)"
        "$IB_IMG4" -i "$im4p_in" -o "$raw_out" -k "$fb" >/dev/null 2>&1 || true
        if _nr_ok_payload "$raw_out"; then
            local mg; mg="$(xxd -p -l4 "$raw_out" 2>/dev/null || echo "")"
            echo "  [✓] iBSS расшифрован ($(_nr_size "$raw_out") байт, magic=$mg, fallback)"
            return 0
        fi
        rm -f "$raw_out"
    fi

    rm -f "$raw_out"
    echo "  [!] iBSS: ни один способ не дал валидный payload" >&2
    return 1
}

patch_ibss() {
    local raw_in="$1" out_bin="$2"

    [[ -s "$raw_in" ]] || { echo "  [!] iBSS.raw пуст" >&2; return 1; }

    local size; size=$(_nr_size "$raw_in")
    local magic; magic=$(xxd -p -l4 "$raw_in" 2>/dev/null || echo "")
    echo "  [i] iBSS.raw: $size байт, magic=$magic"

    if ! _nr_ok_payload "$raw_in"; then
        echo "  [!] iBSS.raw невалидный (magic=$magic)" >&2
        return 1
    fi

    if [[ ! -x "$ROOT/bin/iBootPatch" ]]; then
        echo "  [!] $ROOT/bin/iBootPatch отсутствует" >&2
        return 1
    fi

    local log; log=$(mktemp)
    rm -f "$out_bin"
    echo "  [i] iBootPatch: $raw_in → $out_bin"
    "$ROOT/bin/iBootPatch" -v -b "-v rd=md0 wdt=-1" "$raw_in" "$out_bin" >"$log" 2>&1 || true
    sed 's/^/    /' "$log" >&2

    if [[ -s "$out_bin" ]]; then
        rm -f "$log"
        echo "  [✓] iBSS пропатчен (iBootPatch)"
        return 0
    fi

    rm -f "$log" "$out_bin"
    echo "  [!] iBootPatch не справился с этим iBSS" >&2
    return 1
}

# ════════════════════════════════════════════════════════════════
# iBEC: decrypt + patch (iOS 17.4+)
# ════════════════════════════════════════════════════════════════
fetch_applewiki_keys() {
    local product="$1" build="$2" component="$3"
    local cache_file="$KEYS_DIR/${product}.txt"

    if [[ "$component" == "iBEC" ]]; then
        local jv
        if jv="$(fetch_keys_from_json "$product" "$build" release)"; then
            echo "  [i] JSON(release): iBEC-$build" >&2
            printf '%s\n' "$jv"; return 0
        fi
    fi

    if [[ -f "$cache_file" ]]; then
        local cached
        cached=$(grep -i "^${component}-${build}:" "$cache_file" 2>/dev/null | head -1 | cut -d: -f2- | xargs || true)
        if [[ -n "$cached" ]]; then
            printf '%s\n' "$cached"; return 0
        fi
    fi

    local fb="${DECRYPT_KEYS_FALLBACK[${product}_${build}_${component}]:-}"
    if [[ -n "$fb" ]]; then
        printf '%s\n' "$fb"; return 0
    fi
    return 1
}

fetch_research_key() {
    local product="$1" build="$2" component="$3"
    local cache_file="$KEYS_DIR/${product}.txt"

    if [[ "$component" == "iBEC" ]]; then
        local jv
        if jv="$(fetch_keys_from_json "$product" "$build" research)"; then
            echo "  [i] JSON(research): iBEC-$build" >&2
            printf '%s\n' "$jv"; return 0
        fi
    fi

    if [[ -f "$cache_file" ]]; then
        local c
        c=$(grep -i "^${component}_research-${build}:" "$cache_file" 2>/dev/null \
            | head -1 | cut -d: -f2- | xargs || true)
        [[ -n "$c" ]] && { printf '%s\n' "$c"; return 0; }
    fi

    local fb="${DECRYPT_KEYS_FALLBACK[${product}_${build}_${component}_research]:-}"
    if [[ -n "$fb" ]]; then
        printf '%s\n' "$fb"; return 0
    fi
    return 1
}

decrypt_im4p() {
    local in_im4p="$1" out_raw="$2" product="$3" build="$4" component="$5"
    [[ -n "$IMG4TOOL" ]] || { echo "  [!] img4tool недоступен" >&2; return 1; }

    local iv_key=""
    if iv_key="$(fetch_applewiki_keys "$product" "$build" "$component")"; then
        local iv="${iv_key%%:*}" key="${iv_key##*:}"
        echo "  [i] decrypt $component (RELEASE) IV=$iv"
        if "$IMG4TOOL" -e --iv "$iv" --key "$key" -o "$out_raw" "$in_im4p" >/dev/null 2>&1; then
            local mg; mg="$(xxd -p -l4 "$out_raw" 2>/dev/null || echo "")"
            if _im4p_magic_ok "$mg"; then
                echo "  [✓] RELEASE-ключ сработал (magic=$mg)"
                return 0
            fi
            echo "  [!] RELEASE-ключ дал мусор (magic=${mg:-?}) — пробую RESEARCH…"
        else
            echo "  [!] img4tool RELEASE-прогон упал — пробую RESEARCH…"
        fi
    else
        echo "  [!] RELEASE-ключ не найден для $product/$build/$component"
    fi

    local rk=""
    if rk="$(fetch_research_key "$product" "$build" "$component")"; then
        local iv="${rk%%:*}" key="${rk##*:}"
        echo "  [i] decrypt $component (RESEARCH) IV=$iv"
        rm -f "$out_raw"
        if "$IMG4TOOL" -e --iv "$iv" --key "$key" -o "$out_raw" "$in_im4p" >/dev/null 2>&1; then
            local mg; mg="$(xxd -p -l4 "$out_raw" 2>/dev/null || echo "")"
            if _im4p_magic_ok "$mg"; then
                echo "  [✓] RESEARCH-ключ сработал (magic=$mg)"
                return 0
            fi
            echo "  [!] RESEARCH-ключ тоже дал мусор (magic=${mg:-?})"
        fi
    fi

    echo "  [!] ни RELEASE, ни RESEARCH ключ не подошли для $product/$build/$component" >&2
    return 1
}

ensure_decrypted() {
    local raw_path="$1" im4p_path="$2" product="$3" build="$4" component="$5"
    local magic
    magic="$(xxd -p -l4 "$raw_path" 2>/dev/null || echo "")"

    if _im4p_magic_ok "$magic"; then
        echo "  [i] $component.raw уже валидный payload (magic=$magic)"; return 0
    fi

    echo "  [!] $component.raw: magic=${magic:-?} — расшифровываем…"
    rm -f "$raw_path"
    decrypt_im4p "$im4p_path" "$raw_path" "$product" "$build" "$component" || return 1
    local size; size="$(stat -f%z "$raw_path" 2>/dev/null || echo 0)"
    (( size < 100000 )) && { echo "  [!] $component слишком мал" >&2; return 1; }
    echo "  [✓] $component → iBoot payload"
    return 0
}

# ════════════════════════════════════════════════════════════════
# patch_iboot_python — БЕЗ kairos
#   Порядок: iboot_patchfinder.py (+finalize) → iBoot64Patcher
# ════════════════════════════════════════════════════════════════
patch_iboot_python() {
    local raw_in="$1" patched_raw="$2" out_bin="$3" mode="$4"
    local tmp_patch; tmp_patch="$(mktemp)"

    if [[ ! -s "$raw_in" ]]; then
        echo "  [!] $mode: входной файл пуст: $raw_in" >&2
        rm -f "$tmp_patch"; return 1
    fi

    local pf_extra=""
    [[ "${NR_NO_BOOTARGS:-0}" == "1" ]] && pf_extra+=" --no-bootargs"
    [[ "${NR_NO_IMAGE4:-0}"   == "1" ]] && pf_extra+=" --no-image4"
    [[ "${NR_PASS_J:-0}"      == "1" ]] && pf_extra+=" --pass-j"
    [[ -n "${NR_SEP_VERSION:-}" ]]      && pf_extra+=" --sep-version ${NR_SEP_VERSION}"

    # ── 1) iboot_patchfinder.py ─────────────────────────────────
    if [[ -f "$NR_PATCH/iboot_patchfinder.py" ]]; then
        [[ -n "$pf_extra" ]] && echo "  [i] patchfinder flags:$pf_extra" >&2
        echo "  [i] trying iboot_patchfinder.py (primary)…" >&2
        if python3 "$NR_PATCH/iboot_patchfinder.py" \
                "$raw_in" "$tmp_patch" \
                --mode "$mode" --ios "${major_ios:-0}" \
                --cpid "${CPID:-0x8030}" $pf_extra; then
            if [[ -s "$tmp_patch" ]]; then
                local stock_size patch_size
                stock_size=$(_nr_size "$raw_in")
                patch_size=$(_nr_size "$tmp_patch")
                if [[ "$stock_size" -eq "$patch_size" ]]; then
                    if [[ -f "$NR_PATCH/finalize_iboot.py" ]]; then
                        local b
                        for b in "$MODEL" "${MODEL}ap"; do
                            if python3 "$NR_PATCH/finalize_iboot.py" \
                                    --stock "$raw_in" --input "$tmp_patch" \
                                    --output "$out_bin" --board "$b"; then
                                echo "  [✓] $mode patched (--board $b)"
                                rm -f "$tmp_patch"; return 0
                            fi
                        done
                    fi
                    cp "$tmp_patch" "$out_bin"
                    [[ -s "$out_bin" ]] && { echo "  [✓] $mode patched (Python)"; rm -f "$tmp_patch"; return 0; }
                else
                    echo "  [!] iboot_patchfinder.py: size mismatch ($stock_size vs $patch_size)" >&2
                fi
            fi
        fi
        echo "  [!] iboot_patchfinder.py failed" >&2
    fi

    # ── 2) iBoot64Patcher ───────────────────────────────────────
    if [[ -x "$ROOT/bin/iBoot64Patcher" ]]; then
        echo "  [i] trying iBoot64Patcher…" >&2
        if "$ROOT/bin/iBoot64Patcher" "$raw_in" "$tmp_patch" \
                -b "rd=md0 debug=0x2014e -v" -n 2>/dev/null; then
            if [[ -s "$tmp_patch" ]]; then
                cp "$tmp_patch" "$out_bin"
                echo "  [✓] $mode patched (iBoot64Patcher)"
                rm -f "$tmp_patch"; return 0
            fi
        fi
        echo "  [!] iBoot64Patcher failed" >&2
    fi

    rm -f "$tmp_patch"
    echo "  [!] все патчеры не сработали для $mode" >&2
    return 1
}

# ════════════════════════════════════════════════════════════════
# Режим: 15.0–17.3.1 → iBSS ; иначе → iBEC
# ════════════════════════════════════════════════════════════════
use_ibss_mode() {
    local ver="${1:-}"
    local maj min pat
    maj=$(echo "$ver" | cut -d. -f1)
    min=$(echo "$ver" | cut -d. -f2)
    pat=$(echo "$ver" | cut -d. -f3)
    [[ -z "$min" || "$min" == "$ver" ]] && min=0
    [[ -z "$pat" ]] && pat=0

    # iOS 15.x, 16.x → iBSS
    if [[ "$maj" -ge 15 && "$maj" -le 16 ]]; then return 0; fi
    # iOS 17.0–17.3.1 → iBSS
    if [[ "$maj" -eq 17 ]]; then
        (( min < 3 )) && return 0
        (( min == 3 && pat <= 1 )) && return 0
    fi
    # iOS 17.4+ и 18+ → iBEC
    return 1
}

# ════════════════════════════════════════════════════════════════
# Аргументы
# ════════════════════════════════════════════════════════════════
SELECTION=""
WITH_FW=1
DRY_RUN=0
LIST_ONLY=0
DIRECT_URL=""
IM4M_OVERRIDE=""
KERNEL_MODE="patched"
KPF_SET="auto"
INTERACTIVE=0
USER_PRODUCT=""
USER_MODEL=""
USER_CPID=""
NO_DEVICE=0

get_model_for_product() {
    local product="$1"
    case "$product" in
        iPhone11,2) echo "d321" ;;
        iPhone11,4|iPhone11,6) echo "d331" ;;
        iPhone11,8) echo "n841" ;;
        iPhone12,1) echo "n104" ;;
        iPhone12,3) echo "d421" ;;
        iPhone12,5) echo "d431" ;;
        iPhone12,8) echo "d79" ;;
        iPad11,1) echo "j210a" ;;
        iPad11,2) echo "j210b" ;;
        iPad11,3) echo "j217a" ;;
        iPad11,4) echo "j218a" ;;
        iPad11,6) echo "j171a" ;;
        iPad11,7) echo "j172a" ;;
        *) echo "" ;;
    esac
}

get_board_short() {
    local product="$1"
    case "$product" in
        iPhone12,1) echo "n104" ;;
        iPhone12,3) echo "d421" ;;
        iPhone12,5) echo "d431" ;;
        iPhone12,8) echo "d79" ;;
        iPhone11,2) echo "d321" ;;
        iPhone11,4|iPhone11,6) echo "d331" ;;
        iPhone11,8) echo "n841" ;;
        iPad11,1|iPad11,2) echo "j210" ;;
        iPad11,3|iPad11,4) echo "j217" ;;
        iPad11,6) echo "j171" ;;
        iPad11,7) echo "j172" ;;
        *) echo "" ;;
    esac
}

get_cpid_for_product() {
    local product="$1"
    case "$product" in
        iPhone11,*) echo "0x8020" ;;
        iPhone12,*) echo "0x8030" ;;
        iPad11,*)   echo "0x8020" ;;
        *) echo "" ;;
    esac
}

usage() {
    cat <<'EOF'
usage: ./build5.sh [--version VERSION|--build BUILD|--url IPSW_URL]
                   [--list] [--im4m PATH]
                   [--kernel stock|patched] [--kpf-set SET]
                   [--with-fw|--no-fw] [--dry-run]
                   [--product PRODUCT] [--model BOARD] [--cpid CPID]

Диапазоны:
  iOS 15.0–17.3.1 → iBSS + iBootPatch (SSHRD-style)
  iOS 17.4+       → iBEC + iboot_patchfinder/iBoot64Patcher
EOF
}

while (($#)); do
    case "$1" in
        --build|--version) (($# >= 2)) || { usage >&2; exit 64; }; SELECTION="$2"; shift 2 ;;
        --url)             (($# >= 2)) || { usage >&2; exit 64; }; DIRECT_URL="$2"; shift 2 ;;
        --im4m)            (($# >= 2)) || { usage >&2; exit 64; }; IM4M_OVERRIDE="$2"; shift 2 ;;
        --kernel)          (($# >= 2)) || { usage >&2; exit 64; }
                           KERNEL_MODE="$2"
                           case "$KERNEL_MODE" in stock|patched) ;; *) echo "bad kernel" >&2; exit 64 ;; esac
                           shift 2 ;;
        --kpf-set)         (($# >= 2)) || { usage >&2; exit 64; }; KPF_SET="$2"; shift 2 ;;
        --with-fw) WITH_FW=1; shift ;;
        --no-fw)   WITH_FW=0; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        --list) LIST_ONLY=1; shift ;;
        --product) (($# >= 2)) || { usage >&2; exit 64; }; USER_PRODUCT="$2"; shift 2 ;;
        --model)   (($# >= 2)) || { usage >&2; exit 64; }; USER_MODEL="$2"; shift 2 ;;
        --cpid)    (($# >= 2)) || { usage >&2; exit 64; }; USER_CPID="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 64 ;;
    esac
done

if [[ -n "$USER_PRODUCT" ]]; then
    NO_DEVICE=1
    [[ -z "$USER_MODEL" ]] && USER_MODEL="$(get_model_for_product "$USER_PRODUCT")"
    [[ -z "$USER_CPID"  ]] && USER_CPID="$(get_cpid_for_product  "$USER_PRODUCT")"
    [[ -z "$USER_MODEL" || -z "$USER_CPID" ]] && { echo "unknown product $USER_PRODUCT" >&2; exit 1; }
    echo "auto-detected model: $USER_MODEL"
    echo "auto-detected cpid: $USER_CPID"
fi

require() { command -v "$1" >/dev/null || { echo "missing: $1" >&2; exit 1; }; }
for tool in "$IRECOVERY" "$PZB" "$IMG4" "$GTAR" "$TC" "$JQ" curl ipsw python3 hdiutil diskutil; do
    if [[ "$tool" == */* ]]; then
        [[ -x "$tool" ]] || { echo "missing: $tool" >&2; exit 1; }
    else require "$tool"; fi
done

mkdir -p "$ROOT/bin"
[[ -x "$IB_IMG4" ]] || {
    curl -L -o "$ROOT/bin/img4" \
        https://github.com/pwnerblu/surrealra1n/raw/refs/heads/main/bin/img4
    chmod +x "$ROOT/bin/img4"
}

if ((NO_DEVICE)); then
    PRODUCT="$USER_PRODUCT"; MODEL="$USER_MODEL"; CPID="$USER_CPID"
    MODE="manual"; PWND="manual"; ECID="unknown"; NAME="manual"
else
    DEVICE_INFO="$("$IRECOVERY" -q)" || { echo "irecovery failed" >&2; exit 1; }
    field() { awk -F': ' -v key="$1" '$1 == key { print $2; exit }' <<<"$DEVICE_INFO"; }
    PRODUCT="$(field PRODUCT)"; MODEL="$(field MODEL)"; CPID="$(field CPID)"
    MODE="$(field MODE)"; PWND="$(field PWND)"; ECID="$(field ECID)"; NAME="$(field NAME)"
    [[ -n "$PRODUCT" && -n "$MODEL" && -n "$CPID" ]] || { echo "irecovery bad info" >&2; exit 1; }
    [[ "$MODE" == "DFU" && "$PWND" == "usbliter8" ]] || { echo "need pwned DFU" >&2; exit 1; }
fi

CHIP="unknown"
[[ -n "$CPID" ]] && nr_is_supported_cpid "$CPID" && CHIP="$(nr_chip_for_cpid "$CPID")"

echo "=== device ==="
echo "  name:     ${NAME:-unknown}"
echo "  product:  $PRODUCT"
echo "  board:    $MODEL"
echo "  cpid:     ${CPID:-unknown} (${CHIP:-unknown})"
echo "  mode:     $MODE"

API_JSON="$(curl --fail --silent --show-error --location \
    "https://api.ipsw.me/v4/device/$PRODUCT?type=ipsw")"

if ((LIST_ONLY)); then
    "$JQ" -r '.firmwares[] | "\(.version)\t\(.buildid)\t\(.releasedate // "")"' <<<"$API_JSON" | sort -V | column -t -s $'\t'
    exit 0
fi

if [[ -z "$SELECTION" && -z "$DIRECT_URL" ]]; then
    INTERACTIVE=1
    FIRM_TMP="$(mktemp)"
    "$JQ" -r '[.firmwares | sort_by(.releasedate // "") | reverse[] | "\(.version)|\(.buildid)|\(.url)"][0:25][]' <<<"$API_JSON" > "$FIRM_TMP"
    i=1
    while IFS= read -r line; do
        ver="${line%%|*}"; rest="${line#*|}"; build="${rest%%|*}"
        printf "  %2d) iOS %-12s  %s\n" "$i" "$ver" "$build"
        i=$((i + 1))
    done < "$FIRM_TMP"
    read -r -p "Firmware: " SELECTION
    if [[ "$SELECTION" =~ ^[0-9]+$ ]]; then
        line="$(sed -n "${SELECTION}p" "$FIRM_TMP")"
        ver="${line%%|*}"; rest="${line#*|}"; BUILD="${rest%%|*}"; IPSW_URL="${rest#*|}"
        VERSION="$ver"; SELECTION="$BUILD"
    fi
    rm -f "$FIRM_TMP"
fi

if [[ -n "$DIRECT_URL" ]]; then
    IPSW_URL="$DIRECT_URL"; BUILD="${SELECTION:-custom}"; VERSION="unknown"
elif [[ -z "${IPSW_URL:-}" ]]; then
    MATCH="$("$JQ" -cer --arg s "$SELECTION" '[.firmwares[] | select(.buildid == $s or .version == $s)][0] // empty' <<<"$API_JSON")" || {
        echo "no match" >&2; exit 1
    }
    IPSW_URL="$("$JQ" -r '.url' <<<"$MATCH")"
    BUILD="$("$JQ" -r '.buildid' <<<"$MATCH")"
    VERSION="$("$JQ" -r '.version' <<<"$MATCH")"
fi

[[ "$IPSW_URL" =~ ^https?:// ]] || { echo "bad URL" >&2; exit 1; }

CACHE="$NR_CACHE/$PRODUCT-$BUILD"
MANIFEST="$CACHE/BuildManifest.plist"
mkdir -p "$CACHE"
[[ -s "$MANIFEST" ]] || ( cd "$CACHE" && "$PZB" -g BuildManifest.plist "$IPSW_URL" )

MANIFEST_INFO="$(python3 - "$MANIFEST" "$MODEL" "$PRODUCT" <<'PY'
import plistlib, sys
from pathlib import Path

manifest = plistlib.loads(Path(sys.argv[1]).read_bytes())
requested_board   = sys.argv[2]
requested_product = sys.argv[3]

def norm(s: str) -> str:
    return (s or "").lower().replace("ap", "").replace(",", "") \
                           .replace("-", "").replace("_", "").replace(" ", "")

wanted = {norm(requested_board), norm(requested_product)}

identity = None
for it in manifest.get("BuildIdentities", []):
    info = it.get("Info", {})
    dc = info.get("DeviceClass", "") or ""
    pt = info.get("ProductType", "") or ""
    if norm(dc) in wanted or norm(pt) in wanted:
        identity = it; break

if identity is None:
    for it in manifest.get("BuildIdentities", []):
        info = it.get("Info", {})
        dc = norm(info.get("DeviceClass", "") or "")
        pt = norm(info.get("ProductType", "") or "")
        for w in wanted:
            if w and (dc.startswith(w) or pt.startswith(w) or w.startswith(dc) and dc):
                identity = it; break
        if identity is not None: break

if identity is None:
    raise SystemExit(f"no identity for board={requested_board} product={requested_product}")

required = {"iBEC":"iBEC","DeviceTree":"DeviceTree","KernelCache":"KernelCache",
            "RestoreRamDisk":"RestoreRamDisk","RestoreTrustCache":"RestoreTrustCache"}
optional = {"iBSS":("iBSS",), "RestoreSEP":("RestoreSEP",),
            "SPTM":("SPTM","Ap,SPTM","SecurePageTableMonitor","RestoreSPTM"),
            "TXM":("TXM","Ap,TXM","TrustedExecutionMonitor","Ap,TrustedExecutionMonitor"),
            "AOP":("AOP",),"ANE":("ANE",),"AVE":("AVE",),"ISP":("ISP",),
            "GFX":("GFX",),"SIO":("SIO",),"PMP":("PMP","Ap,PMP")}
images = identity["Manifest"]
for k,v in required.items():
    p = images.get(v,{}).get("Info",{}).get("Path")
    if p is None: raise SystemExit(f"no {v}")
    print(f"{k}={p}")
for k,cands in optional.items():
    p=None
    for c in cands:
        p = images.get(c,{}).get("Info",{}).get("Path")
        if p: break
    if p: print(f"{k}={p}")
print(f"ManifestBuild={identity['Info'].get('BuildNumber','')}")
PY
)"

manifest_path() { awk -F= -v key="$1" '$1 == key { print substr($0, length(key) + 2); exit }' <<<"$MANIFEST_INFO"; }

MANIFEST_BUILD="$(manifest_path ManifestBuild)"
if [[ "$VERSION" != "unknown" && -n "$MANIFEST_BUILD" && "$MANIFEST_BUILD" != "$BUILD" ]]; then
    echo "BuildManifest mismatch: $MANIFEST_BUILD != $BUILD" >&2; exit 1
fi
[[ -n "$MANIFEST_BUILD" ]] && BUILD="$MANIFEST_BUILD"

HAS_IBSS=0; HAS_SPTM=0; HAS_TXM=0
[[ -n "$(manifest_path iBSS)" ]] && HAS_IBSS=1
[[ -n "$(manifest_path SPTM)" ]] && HAS_SPTM=1
[[ -n "$(manifest_path TXM)"  ]] && HAS_TXM=1

major_ios=0; minor_ios=0
if [[ -n "$VERSION" && "$VERSION" != "unknown" ]]; then
    major_ios=$(echo "$VERSION" | cut -d. -f1)
    minor_ios=$(echo "$VERSION" | cut -d. -f2)
    [[ -z "$minor_ios" || "$minor_ios" == "$VERSION" ]] && minor_ios=0
fi

USE_IBSS=0
if use_ibss_mode "$VERSION"; then
    USE_IBSS=1
    echo "  [i] iOS $VERSION ∈ [15.0, 17.3.1] → режим iBSS (iBootPatch)"
    (( HAS_IBSS )) || { echo "[!] нужен iBSS, но его нет в BuildManifest" >&2; exit 1; }
else
    echo "  [i] iOS $VERSION ≥ 17.4 (или < 15.0) → режим iBEC"
fi

# ── iBSS member (только для use_ibss_mode) ────────────────────
IBSS_MEMBER=""
if ((USE_IBSS)); then
    BOARD_SHORT="$(get_board_short "$PRODUCT")"
    if [[ -n "$BOARD_SHORT" ]]; then
        RELEASE_IBSS="Firmware/dfu/iBSS.${BOARD_SHORT}.RELEASE.im4p"
        if [[ -s "$CACHE/$(basename "$RELEASE_IBSS")" ]]; then
            IBSS_MEMBER="$RELEASE_IBSS"
        else
            echo "  [i] пробую RELEASE iBSS: $RELEASE_IBSS"
            if ( cd "$CACHE" && "$PZB" -g "$RELEASE_IBSS" "$IPSW_URL" >/dev/null 2>&1 ) \
               && [[ -s "$CACHE/$(basename "$RELEASE_IBSS")" ]]; then
                IBSS_MEMBER="$RELEASE_IBSS"
                echo "  [✓] RELEASE iBSS скачан"
            else
                echo "  [!] RELEASE iBSS не найден — fallback на манифест"
            fi
        fi
    fi
    if [[ -z "$IBSS_MEMBER" ]]; then
        IBSS_MEMBER="$(manifest_path iBSS)"
        echo "  [i] iBSS из манифеста: $IBSS_MEMBER"
    fi
fi

resolve_kpf_set() {
    local ver="$1" has_txm="$2" major=""
    [[ "$ver" =~ ^([0-9]+) ]] && major="${BASH_REMATCH[1]}"
    if ((has_txm)) || [[ -n "$major" && "$major" -ge 27 ]]; then echo "ios27"
    elif [[ -n "$major" && "$major" -ge 17 ]]; then echo "ios18"
    else echo "ios18"; fi
}
[[ "$KPF_SET" == "auto" ]] && {
    KPF_SET="$(resolve_kpf_set "$VERSION" "$HAS_TXM")"
    echo "kpf-set auto → $KPF_SET"
}

echo
echo "=== firmware ==="
echo "  iOS:      $VERSION ($BUILD)"
echo "  IPSW:     $IPSW_URL"
echo "  kernel:   $KERNEL_MODE (kpf-set=$KPF_SET)"
if ((USE_IBSS)); then
    echo "  boot:     iBSS ($IBSS_MEMBER)"
else
    echo "  boot:     iBEC ($(manifest_path iBEC))"
fi

if ((DRY_RUN)); then
    sed '/^ManifestBuild=/d;s/^/  /;s/=/:\ /' <<<"$MANIFEST_INFO" | sort
    exit 0
fi

if ((INTERACTIVE)); then
    read -r -p "Build this bootchain? [Y/n] " ans
    case "${ans:-Y}" in Y|y|yes|YES) ;; *) echo "aborted"; exit 1 ;; esac
fi

IM4M="${IM4M_OVERRIDE:-$NR_RESOURCES/IM4M_$CPID}"
[[ -f "$IM4M" ]] || { echo "missing IM4M: $IM4M" >&2; exit 1; }
[[ -f "$NR_RESOURCES/ssh.tar.gz"     ]] || { echo "missing ssh.tar.gz" >&2; exit 1; }
[[ -f "$NR_RESOURCES/sshtarlist.txt" ]] || { echo "missing sshtarlist.txt" >&2; exit 1; }

fetch_member() {
    local member="$1"
    local dst="$CACHE/$(basename "$member")"
    [[ -s "$dst" ]] || ( cd "$CACHE" && "$PZB" -g "$member" "$IPSW_URL" )
    [[ -s "$dst" ]] || { echo "pzb fail: $(basename "$member")" >&2; exit 1; }
    printf '%s\n' "$dst"
}

if ((USE_IBSS)); then
    fetch_member "$IBSS_MEMBER" >/dev/null
fi

for key in iBEC DeviceTree KernelCache RestoreRamDisk RestoreTrustCache; do
    fetch_member "$(manifest_path "$key")" >/dev/null
done
((HAS_SPTM)) && fetch_member "$(manifest_path SPTM)" >/dev/null
((HAS_TXM))  && fetch_member "$(manifest_path TXM)"  >/dev/null
if ((WITH_FW)); then
    for key in AOP ANE AVE ISP GFX SIO; do
        [[ -n "$(manifest_path "$key")" ]] || { echo "missing $key" >&2; exit 1; }
        fetch_member "$(manifest_path "$key")" >/dev/null
    done
    [[ -n "$(manifest_path PMP)" ]] && fetch_member "$(manifest_path PMP)" >/dev/null
fi
[[ -n "$(manifest_path RestoreSEP)" ]] && fetch_member "$(manifest_path RestoreSEP)" >/dev/null

WORK="$NR_WORK/$PRODUCT-$BUILD"
OUT="$NR_WORK/out-$PRODUCT-$BUILD"
BOOTCHAIN_NAME="$MODEL-$VERSION-$BUILD-ramdisk"
BOOTCHAIN="$NR_BOOTCHAIN_ROOT/$BOOTCHAIN_NAME"
rm -rf "$WORK" "$OUT" "$BOOTCHAIN"
mkdir -p "$WORK" "$OUT" "$BOOTCHAIN" "$NR_WORK/sshtar"

if ((USE_IBSS)); then
    cp "$CACHE/$(basename "$IBSS_MEMBER")" "$WORK/iBSS.im4p"
fi
for key in iBEC DeviceTree KernelCache RestoreRamDisk RestoreTrustCache; do
    cp "$CACHE/$(basename "$(manifest_path "$key")")" "$WORK/$key.im4p"
done
((HAS_SPTM)) && cp "$CACHE/$(basename "$(manifest_path SPTM)")" "$WORK/SPTM.im4p"
((HAS_TXM))  && cp "$CACHE/$(basename "$(manifest_path TXM)")"  "$WORK/TXM.im4p"
if ((WITH_FW)); then
    for key in PMP AOP ANE AVE ISP GFX SIO; do
        [[ -n "$(manifest_path "$key")" ]] || continue
        cp "$CACHE/$(basename "$(manifest_path "$key")")" "$WORK/$key.im4p"
    done
fi
[[ -n "$(manifest_path RestoreSEP)" ]] && \
    cp "$CACHE/$(basename "$(manifest_path RestoreSEP)")" "$WORK/RestoreSEP.im4p"

ipsw img4 im4p extract -o "$WORK/kernelcache.raw" "$WORK/KernelCache.im4p" 2>/dev/null \
      || "$IB_IMG4" -i "$WORK/KernelCache.im4p" -o "$WORK/kernelcache.raw" 2>/dev/null || true
"$IMG4" -i "$WORK/RestoreRamDisk.im4p" -o "$WORK/ramdisk.dmg"

legacy_kernel=0
if [[ -n "$VERSION" && "$VERSION" != "unknown" ]]; then
    major=$(echo "$VERSION" | cut -d. -f1)
    if [[ $major -ge 13 && $major -le 17 ]]; then
        legacy_kernel=1
    fi
fi

# ════════════════════════════════════════════════════════════════
# ГЛАВНАЯ РАЗВИЛКА: iBSS (15.0–17.3.1) vs iBEC (17.4+)
# ════════════════════════════════════════════════════════════════
USE_IBSS_CHAIN=0

if ((USE_IBSS)); then
    echo
    echo "=== iBSS (iBootPatch, iOS ${VERSION}) ==="
    if decrypt_ibss "$WORK/iBSS.im4p" "$WORK/iBSS.raw" "$PRODUCT" "$BUILD"; then
        if patch_ibss "$WORK/iBSS.raw" "$BOOTCHAIN/iBSS.patched.bin"; then
            USE_IBSS_CHAIN=1
            printf '1\n' > "$BOOTCHAIN/use-ibss"
        else
            echo "[!] iBSS не пропатчен — сборка невозможна" >&2
            exit 1
        fi
    else
        echo "[!] iBSS decrypt провален — сборка невозможна" >&2
        exit 1
    fi
else
    echo
    echo "=== iBEC (iboot_patchfinder / iBoot64Patcher, iOS ${VERSION}) ==="
    ipsw img4 im4p extract -o "$WORK/iBEC.raw" "$WORK/iBEC.im4p" 2>/dev/null \
          || "$IB_IMG4" -i "$WORK/iBEC.im4p" -o "$WORK/iBEC.raw" 2>/dev/null || true

    if [[ "$major_ios" -ge 18 ]]; then
        echo "  [i] iOS $VERSION ≥ 18 — iBEC не зашифрован"
        magic="$(xxd -p -l4 "$WORK/iBEC.raw" 2>/dev/null || echo "")"
        echo "  [i] iBEC.raw: magic=$magic"
    else
        ensure_decrypted "$WORK/iBEC.raw" "$WORK/iBEC.im4p" "$PRODUCT" "$BUILD" "iBEC" \
            || { echo "[!] iBEC still encrypted" >&2; exit 1; }
    fi

    patch_iboot_python "$WORK/iBEC.raw" "$OUT/iBEC.patched.raw" \
        "$OUT/iBoot.patched.bin" ibec \
        || { echo "[!] iBEC patch failed" >&2; exit 1; }
    cp "$OUT/iBoot.patched.bin" "$BOOTCHAIN/iBoot.patched.bin"
    "$IMG4" -i "$OUT/iBoot.patched.bin" -o "$BOOTCHAIN/iBEC.img4" -A -T ibec -M "$IM4M"
    USE_IBSS_CHAIN=0
fi

# ════════════════════════════════════════════════════════════════
# DeviceTree
# ════════════════════════════════════════════════════════════════
if [[ -f "$WORK/DeviceTree.im4p" ]]; then
    "$IMG4" -i "$WORK/DeviceTree.im4p" -o "$WORK/DeviceTree.raw" 2>/dev/null || \
        ipsw img4 im4p extract -o "$WORK/DeviceTree.raw" "$WORK/DeviceTree.im4p" 2>/dev/null || true
    [[ ! -s "$WORK/DeviceTree.raw" ]] && { echo "[!] DeviceTree extract failed" >&2; exit 1; }
    if ((legacy_kernel)); then
        cp "$WORK/DeviceTree.raw" "$WORK/DeviceTree.patched.raw"
        perl -pi -e 's/content-protect/content-protecV/g' "$WORK/DeviceTree.patched.raw"
    else
        cp "$WORK/DeviceTree.raw" "$WORK/DeviceTree.patched.raw"
    fi
    "$IMG4" -i "$WORK/DeviceTree.patched.raw" -o "$BOOTCHAIN/devicetree.img4" \
        -A -T rdtr -M "$IM4M"
else
    echo "[!] DeviceTree.im4p missing" >&2
    exit 1
fi

# ════════════════════════════════════════════════════════════════
# SPTM / TXM (iOS 18+)
# ════════════════════════════════════════════════════════════════
if ((HAS_SPTM)); then
    ipsw img4 im4p extract -o "$WORK/SPTM.raw" "$WORK/SPTM.im4p"
    python3 "$NR_PATCH/sptm_patchfinder.py" "$WORK/SPTM.raw" "$OUT/SPTM.patched.raw"
    "$IMG4" -i "$OUT/SPTM.patched.raw" -o "$BOOTCHAIN/sptm.img4" -A -T sptm -M "$IM4M"
fi
if ((HAS_TXM)); then
    ipsw img4 im4p extract -o "$WORK/TXM.raw" "$WORK/TXM.im4p"
    python3 "$NR_PATCH/txm_patchfinder.py" "$WORK/TXM.raw" "$OUT/TXM.patched.raw"
    "$IMG4" -i "$OUT/TXM.patched.raw" -o "$BOOTCHAIN/txm.img4" -A -T trst -M "$IM4M" \
        || "$IMG4" -i "$OUT/TXM.patched.raw" -o "$BOOTCHAIN/txm.img4" -A -M "$IM4M"
fi

# ════════════════════════════════════════════════════════════════
# Ramdisk
# ════════════════════════════════════════════════════════════════
trap 'hdiutil detach -force /tmp/NewRamdiskRD >/dev/null 2>&1 || true' EXIT
nr_expand_inject_ramdisk "$WORK/ramdisk.dmg" "$NR_RESOURCES/ssh.tar.gz" /tmp/NewRamdiskRD "$GTAR"
trap - EXIT

"$IMG4" -i "$WORK/RestoreTrustCache.im4p" -o "$NR_WORK/trustcache.bin"
rm -rf "$NR_WORK/sshtar"; mkdir -p "$NR_WORK/sshtar"
"$GTAR" -x --no-overwrite-dir -f "$NR_RESOURCES/ssh.tar.gz" -C "$NR_WORK/sshtar"

if [[ -f "$NR_RESOURCES/restored_external" ]]; then
    if ! grep -qxF "/usr/local/bin/restored_external" "$NR_RESOURCES/sshtarlist.txt"; then
        printf '/usr/local/bin/restored_external\n' >> "$NR_RESOURCES/sshtarlist.txt"
    fi
fi

(
    cd "$ROOT"
    "$TC" append work/trustcache.bin $(<"resources/sshtarlist.txt")
)
cp "$NR_WORK/trustcache.bin" "$WORK/trustcache.bin"

"$IMG4" -i "$WORK/trustcache.bin" -o "$BOOTCHAIN/trustcache.img4" -A -T rtsc -M "$IM4M"
"$IMG4" -i "$WORK/ramdisk.dmg" -o "$BOOTCHAIN/ramdisk.img4" -A -T rdsk -M "$IM4M"

# ════════════════════════════════════════════════════════════════
# Kernel
# ════════════════════════════════════════════════════════════════
if ((legacy_kernel)); then
    echo "Patching kernel with Kernel64Patcher (iOS 13-17)"
    [[ -x "$ROOT/bin/Kernel64Patcher" ]] || {
        curl -L -o "$ROOT/bin/Kernel64Patcher" \
            "https://github.com/pwnerblu/surrealra1n/raw/refs/heads/main/bin/Kernel64Patcher"
        chmod +x "$ROOT/bin/Kernel64Patcher"
    }
    if [[ ! -f "$WORK/kernelcache.raw" ]]; then
        if [[ -n "$IMG4TOOL" ]]; then
            "$IMG4TOOL" -e "$WORK/KernelCache.im4p" -o "$WORK/kernelcache.raw" 2>/dev/null || true
        fi
        [[ -s "$WORK/kernelcache.raw" ]] || \
            "$IB_IMG4" -i "$WORK/KernelCache.im4p" -o "$WORK/kernelcache.raw" 2>/dev/null || true
        [[ -s "$WORK/kernelcache.raw" ]] || { echo "extract kernel failed" >&2; exit 1; }
    fi
    "$ROOT/bin/Kernel64Patcher" "$WORK/kernelcache.raw" "$OUT/kernelcache.patched.raw" -a -d -e -o
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
    echo "Kernel patched (Kernel64Patcher only)"
else
    wrap_kernel() {
        local raw_path="$1" output_path="$2"
        python3 - "$raw_path" "$WORK/KernelCache.im4p" "$output_path" "$IM4M" <<'PY'
from pathlib import Path
import sys
from pyimg4 import Compression, IMG4, IM4M, IM4P, PayloadProperty
raw, original_path, output, im4m_path = map(Path, sys.argv[1:])
original = IM4P(original_path.read_bytes())
image = IM4P(fourcc="rkrn", description=original.description, payload=raw.read_bytes())
for prop in original.properties or []:
    image.add_property(PayloadProperty(fourcc=prop.fourcc, value=prop.value))
image.payload.compress(Compression.LZFSE)
output.write_bytes(IMG4(im4p=image, im4m=IM4M(im4m_path.read_bytes())).output())
PY
    }
    wrap_kernel "$WORK/kernelcache.raw" "$BOOTCHAIN/kernelcache.img4.stock"

    python3 "$NR_PATCH/apply_kernel_patches.py" \
        "$WORK/kernelcache.raw" \
        --output "$OUT/kernelcache.patched.raw" \
        --kpf-set "$KPF_SET"
    [[ -f "$OUT/kernelcache.patched.raw" ]] || { echo "apply_kernel_patches failed" >&2; exit 1; }

    wrap_kernel "$OUT/kernelcache.patched.raw" "$BOOTCHAIN/kernelcache.img4.patched"
    if [[ "$KERNEL_MODE" == "patched" ]]; then
        cp "$BOOTCHAIN/kernelcache.img4.patched" "$BOOTCHAIN/kernelcache.img4"
    else
        cp "$BOOTCHAIN/kernelcache.img4.stock" "$BOOTCHAIN/kernelcache.img4"
    fi
fi

# ════════════════════════════════════════════════════════════════
# Firmware
# ════════════════════════════════════════════════════════════════
if ((WITH_FW)); then
    for component in PMP AOP ANE AVE ISP GFX SIO; do
        [[ -f "$WORK/$component.im4p" ]] || continue
        "$IMG4" -i "$WORK/$component.im4p" -o "$BOOTCHAIN/$component.img4" -M "$IM4M"
    done
    printf '1\n' > "$BOOTCHAIN/with-fw.enabled"
fi

[[ -f "$WORK/RestoreSEP.im4p" ]] && \
    "$IMG4" -i "$WORK/RestoreSEP.im4p" -o "$BOOTCHAIN/sep-firmware.img4" -M "$IM4M"

{
    echo "product=$PRODUCT"
    echo "model=$MODEL"
    echo "cpid=$CPID"
    echo "chip=$CHIP"
    echo "version=$VERSION"
    echo "build=$BUILD"
    if ((USE_IBSS)); then
        echo "ibss_member=$IBSS_MEMBER"
        echo "bootstage=ibss"
    else
        echo "bootstage=ibec"
    fi
    echo "use_ibss=$USE_IBSS_CHAIN"
    echo "kernel=$KERNEL_MODE"
    echo "kpf_set=$KPF_SET"
    echo "with_fw=$WITH_FW"
} > "$BOOTCHAIN/chain.info"

rm -rf "$WORK" "$OUT" "$NR_WORK" "$CACHE" "$NR_CACHE"
printf '%s\n' "$BOOTCHAIN_NAME" > "$NR_LAST_BOOTCHAIN_FILE"

echo
echo "Built: $BOOTCHAIN"
echo "Files:"
ls -la "$BOOTCHAIN" | sed 's/^/  /'
echo
echo "Boot:  ./boot.sh"
nr_footer