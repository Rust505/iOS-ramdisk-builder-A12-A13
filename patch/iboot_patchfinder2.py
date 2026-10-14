#!/usr/bin/env python3
"""
iboot_patchfinder.py — Universal iBoot/iBSS/iBEC patchfinder for A12/A13.

═══════════════════════════════════════════════════════════════════════════════
  МАТРИЦА СОВМЕСТИМОСТИ (v15.7)
═══════════════════════════════════════════════════════════════════════════════

  iOS              image4 callback     boot-args        Pass N   Итог
  ───────────────  ──────────────────  ───────────────  ───────  ─────────────
  26.x             ✅ Pass A           ✅ ADR           ✅       полностью
  18.4 – 18.x      ✅ Pass B           ✅ ADR           ✅       полностью
  18.0 – 18.3.2    ⚠️  A/B не находят   ✅ ADR           ✅       частично (N)
  17.4 – 17.7      ✅ Pass B           ✅ ADR           ✅       полностью
  17.0 – 17.3      ⚠️  Pass D/H        ✅ ADR           ✅       частично
  15.x             ⚠️  Pass D/H        ⚠️  ADR паника    ✅       частично
  14.0 – 14.x      ⚠️  Pass H          ❌ нет refs       ✅       частично

  Pass N — универсальный обход: NOP ветки на error-блок
  'Kernelcache image not valid'. Работает независимо от image4 callback.
  На iOS 18.0 – 18.3.2 это ЕДИНСТВЕННЫЙ шанс, т.к. A/B не находят callback.

═══════════════════════════════════════════════════════════════════════════════

v15.7 (Pass N — kernelcache bypass):
  * NEW: Pass N — find "Kernelcache image not valid" → ADRP+ADD xref →
    NOP ветку (B.cond/CBZ/CBNZ/B/BL) в пределах 0x400 назад.
    Универсальный фикс для iOS 18.0 – 18.3.2 и вообще для всех версий.
  * Вызывается ПЕРВЫМ в find_image4_callback, но печатается как [0].
  * v15.6 без изменений (A/B/C/F/D/H/E + boot-args).

Usage:
    iboot_patchfinder.py <input.raw> [output.raw] [--mode ibss|ibec|llb]
"""

import argparse
import struct
import subprocess
import sys
import tempfile
import os
import shutil
from pathlib import Path
from collections import defaultdict

# ─── ARM64 opcodes ───
NOP_U32      = 0xD503201F
RET_U32      = 0xD65F03C0
RETAA_U32    = 0xD65F0BFF
RETAB_U32    = 0xD65F0FFF
PACIBSP_U32  = 0xD503237F
BTI_C_U32    = 0xD503245F
MOV_X0_0_U32 = 0xD2800000
MOV_W0_0_U32 = 0x52800000

ADRP_MASK = 0x9F000000
ADRP_VAL  = 0x90000000
ADR_MASK  = 0x9F000000
ADR_VAL   = 0x10000000
ADD_MASK  = 0xFF800000
ADD_VAL   = 0x91000000
BL_MASK   = 0xFC000000
BL_VAL    = 0x94000000
B_MASK    = 0xFC000000
B_VAL     = 0x14000000
B_OR_BL_MASK = 0x7C000000
B_OR_BL_VAL  = 0x14000000

CBZ_MASK  = 0xFF000000
CBZ_VAL   = 0x34000000
CBNZ_VAL  = 0x35000000
BCOND_MASK = 0xFF000010
BCOND_VAL  = 0x54000000

LDR_LIT_MASK = 0xFF000000
LDR_LIT_VAL  = 0x58000000

ADRP_ADD_WINDOW = 0x84
EARLY_CODE_CUTOFF = 0x10000
FUNC_START_MAX_DIST = 0x8000

BASE_A13_DEFAULT = 0x19C000000
BASE_A12_DEFAULT = 0x180000000

CANDIDATE_BASES = [
    0x19C030000, 0x19C040000, 0x19C000000, 0x19C080000, 0x19C220000,
    0x19C1C8000, 0x19C100000, 0x19C180000, 0x19C194000, 0x19C1CC000,
    0x180000000, 0x180040000, 0x180080000, 0x1800C0000,
    0x1A0000000, 0x1A0040000,
]


def p32(v): return struct.pack('<I', v & 0xFFFFFFFF)
def rd32(d, o): return struct.unpack_from('<I', d, o)[0]


def decode_adrp_imm(w):
    immhi = (w >> 5) & 0x7FFFF
    immlo = (w >> 29) & 0x3
    imm = (immhi << 2) | immlo
    if imm & (1 << 20): imm -= (1 << 21)
    return imm


def decode_adr_imm(w):
    immhi = (w >> 5) & 0x7FFFF
    immlo = (w >> 29) & 0x3
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= (1 << 21)
    return imm


def decode_ldr_lit_imm(w):
    imm19 = (w >> 5) & 0x7FFFF
    if imm19 & (1 << 18):
        imm19 -= (1 << 19)
    return imm19 << 2


def decode_bl_target(w, pc_va):
    imm26 = w & 0x03FFFFFF
    if imm26 & (1 << 25):
        imm26 -= (1 << 26)
    return pc_va + (imm26 << 2)


def decode_bcond_target(w, pc_va):
    imm19 = (w >> 5) & 0x7FFFF
    if imm19 & (1 << 18):
        imm19 -= (1 << 19)
    return pc_va + (imm19 << 2)


def encode_adrp(rd, pc, target_page):
    delta = (target_page - (pc & ~0xFFF)) >> 12
    immlo = delta & 0x3
    immhi = (delta >> 2) & 0x7FFFF
    return 0x90000000 | (immlo << 29) | (immhi << 5) | (rd & 0x1F)


def encode_add_imm(rd, rn, imm12):
    return 0x91000000 | ((imm12 & 0xFFF) << 10) | ((rn & 0x1F) << 5) | (rd & 0x1F)


def encode_adr(rd, pc, target):
    imm = target - pc
    if imm < -(1 << 20) or imm >= (1 << 20):
        raise ValueError(f"ADR imm out of range: {imm}")
    immlo = imm & 0x3
    immhi = (imm >> 2) & 0x7FFFF
    return 0x10000000 | (immlo << 29) | (immhi << 5) | (rd & 0x1F)


# ═══════════════════════════════════════════════════════════════
# Base detection
# ═══════════════════════════════════════════════════════════════

def _is_string(data, off, min_len=4):
    if off < 0 or off + min_len >= len(data):
        return False
    for i in range(min_len):
        b = data[off + i]
        if b < 0x20 or b > 0x7E:
            return False
    return True


def _score_base(data, base, scan_limit=0x400000):
    n = len(data)
    scan_limit = min(scan_limit, n - 8)
    str_hits = ptr_hits = total = 0
    for i in range(0, scan_limit, 4):
        w1 = rd32(data, i)
        if (w1 & ADRP_MASK) != ADRP_VAL:
            continue
        rd1 = w1 & 0x1F
        imm_adrp = decode_adrp_imm(w1)
        for d in (4, 8, 12, 16, 20):
            j = i + d
            if j + 4 > n: break
            w2 = rd32(data, j)
            if (w2 & ADD_MASK) != ADD_VAL: continue
            if ((w2 >> 5) & 0x1F) != rd1: continue
            imm12 = (w2 >> 10) & 0xFFF
            pc_va = base + i
            page_va = (pc_va & ~0xFFF) + (imm_adrp << 12)
            target_off = (page_va + imm12) - base
            total += 1
            if 0 <= target_off < n - 4:
                if _is_string(data, target_off):
                    str_hits += 1
                elif target_off + 8 <= n:
                    val = struct.unpack_from('<Q', data, target_off)[0]
                    if 0x100000000 <= val <= 0x1000000000:
                        ptr_hits += 1
            break
    return str_hits * 10 + ptr_hits * 2, str_hits, ptr_hits, total


def detect_base(data, ios_major=None, cpid=None, verbose=True):
    def log(m):
        if verbose: print(m, file=sys.stderr)

    for off_val in (0x318, 0x300, 0x2F8, 0x320, 0x330, 0x2E0, 0x308, 0x310):
        if len(data) >= off_val + 8:
            v8 = struct.unpack_from('<Q', data, off_val)[0]
            if 0x100000000 <= v8 <= 0x300000000 and (v8 & 0xFFF) == 0:
                log(f"  [i] base from header[0x{off_val:X}]: 0x{v8:X}")
                return v8, "header-u64"

    results = []
    for c in CANDIDATE_BASES:
        sc, strs, ptrs, tot = _score_base(data, c)
        results.append((c, sc, strs, ptrs, tot))
    results.sort(key=lambda x: -x[1])

    if verbose:
        log("  [i] base scoring (top 5):")
        for c, s, strs, ptrs, tot in results[:5]:
            log(f"       0x{c:X}  score={s}  strs={strs}  ptrs={ptrs}  total={tot}")

    best = results[0]
    if best[1] > 0:
        log(f"  [i] base selected: 0x{best[0]:X} (score={best[1]})")
        return best[0], "scored"

    if cpid == 0x8030:
        log("  [i] base fallback (A13)")
        return BASE_A13_DEFAULT, "cpid-a13"
    if cpid == 0x8020:
        log("  [i] base fallback (A12)")
        return BASE_A12_DEFAULT, "cpid-a12"
    return BASE_A13_DEFAULT, "default"


# ═══════════════════════════════════════════════════════════════
# Decompression
# ═══════════════════════════════════════════════════════════════

def _acompress_cli(data):
    if not shutil.which("acompress"):
        return None
    with tempfile.NamedTemporaryFile(delete=False, suffix=".lz") as f:
        f.write(data); in_path = f.name
    out_path = in_path + ".out"
    try:
        r = subprocess.run(
            ["acompress", "-d", "-b", "-i", in_path, "-o", out_path],
            capture_output=True, timeout=60)
        if r.returncode == 0 and os.path.exists(out_path):
            with open(out_path, "rb") as f:
                return f.read()
    except Exception:
        pass
    finally:
        for p in (in_path, out_path):
            try: os.unlink(p)
            except OSError: pass
    return None


def maybe_decompress(data, verbose=True):
    magic = data[:4]
    LZFSE_IBOOT_MAGICS = (b'\x0d\xf7\x4f\x6e', b'\x6e\x4f\xf7\x0d')
    LZFSE_MAGICS = (b'bvx2', b'bvx-', b'bvxn')
    if magic not in LZFSE_IBOOT_MAGICS and magic not in LZFSE_MAGICS:
        if verbose:
            print(f"  [i] input is raw (magic={magic.hex()}) — no decompression",
                  file=sys.stderr)
        return data
    if verbose:
        print(f"  [i] compressed input detected (magic={magic.hex()})", file=sys.stderr)
    payload = data
    for m in (b'bvx2', b'bvx-', b'bvxn'):
        idx = data.find(m)
        if 0 <= idx < 0x2000:
            payload = data[idx:]; break
    out = _acompress_cli(payload) or _acompress_cli(data)
    if out is not None:
        if verbose:
            print(f"  [✓] decompressed: {len(data)} -> {len(out)} B", file=sys.stderr)
        return out
    if verbose:
        print("  [!] decompression failed — proceeding with raw input", file=sys.stderr)
    return data


# ═══════════════════════════════════════════════════════════════
# Patchfinder
# ═══════════════════════════════════════════════════════════════

class IBootPatchfinder:
    def __init__(self, data, base=0x19C220000, mode='ibec', verbose=True,
                 ios_major=None):
        self.data = bytearray(data)
        self.size = len(data)
        self.base = base
        self.mode = mode
        self.verbose = verbose
        self.ios_major = ios_major
        self.patches = []
        self.results = {}

        self.code_end = self.size
        for i in range(self.size - 4, 0, -4):
            w = rd32(self.data, i)
            if w in (PACIBSP_U32, BTI_C_U32):
                self.code_end = min(self.size, i + 0x4000)
                break

        limit = self.size - 8
        self.adrp_index = defaultdict(list)
        self.adrp_add_pairs = []
        for off in range(0, limit, 4):
            w = rd32(self.data, off)
            if (w & ADRP_MASK) != ADRP_VAL: continue
            imm = decode_adrp_imm(w)
            rd = w & 0x1F
            page = ((self.base + off) & ~0xFFF) + (imm << 12)
            self.adrp_index[page].append((off, rd))
            for d in range(4, ADRP_ADD_WINDOW + 1, 4):
                j = off + d
                if j + 4 > self.size: break
                w2 = rd32(self.data, j)
                if (w2 & ADD_MASK) != ADD_VAL: continue
                if ((w2 >> 5) & 0x1F) != rd: continue
                imm12 = (w2 >> 10) & 0xFFF
                self.adrp_add_pairs.append((off, j, page + imm12))
                break

        self.adr_index = defaultdict(list)
        for off in range(0, limit, 4):
            w = rd32(self.data, off)
            if (w & ADR_MASK) != ADR_VAL: continue
            imm = decode_adr_imm(w)
            rd = w & 0x1F
            target = (self.base + off) + imm
            self.adr_index[target].append((off, rd))

    def log(self, msg):
        if self.verbose: print(msg)

    def emit(self, off, patch_bytes, desc):
        orig = bytes(self.data[off:off + len(patch_bytes)])
        self.data[off:off + len(patch_bytes)] = patch_bytes
        self.patches.append((off, self.base + off, orig, patch_bytes, desc))
        self.log(f"  0x{off:06X} (VA 0x{self.base+off:X}): {desc}")

    def find_string(self, needle):
        if isinstance(needle, str): needle = needle.encode()
        idx = self.data.find(needle)
        return idx if idx >= 0 else None

    def find_adrp_add_refs(self, target_off):
        target_va = self.base + target_off
        return [(a, d) for a, d, t in self.adrp_add_pairs if t == target_va]

    def find_adr_refs(self, target_off):
        target_va = self.base + target_off
        return [off for off, _ in self.adr_index.get(target_va, [])]

    def find_ptr_to_string(self, target_off, max_hits=16):
        ptr_bytes = struct.pack('<Q', self.base + target_off)
        out = []
        pos = 0
        while True:
            i = self.data.find(ptr_bytes, pos)
            if i < 0: break
            out.append(i)
            pos = i + 1
            if len(out) >= max_hits: break
        return out

    def find_ldr_literal_refs(self, target_off):
        target_va = self.base + target_off
        out = []
        limit = self.size - 4
        for off in range(0, limit, 4):
            w = rd32(self.data, off)
            if (w & LDR_LIT_MASK) != LDR_LIT_VAL: continue
            imm = decode_ldr_lit_imm(w)
            literal_va = self.base + off + imm
            literal_off = literal_va - self.base
            if 0 <= literal_off < self.size - 8:
                val = struct.unpack_from('<Q', self.data, literal_off)[0]
                if val == target_va:
                    out.append((off, literal_off))
        return out

    def find_func_start(self, off, max_back=0x8000):
        if off >= self.size: off = self.size - 4
        for i in range(off & ~3, max(0, off - max_back), -4):
            w = rd32(self.data, i)
            if w in (PACIBSP_U32, BTI_C_U32,
                     0xA9BF7BFD, 0xA9BE7BFD, 0xA9BA7BFD):
                return i
        return None

    def _find_panic_addr(self):
        s = self.find_string(b"double panic in")
        if s is None:
            return None
        refs = self.find_adrp_add_refs(s)
        if not refs:
            return None
        fs = self.find_func_start(refs[0][0])
        if fs is None:
            return None
        return self.base + fs

    def _dump_insns(self, center_off, n_before=20, n_after=2):
        lo = max(0, center_off - n_before * 4)
        hi = min(self.size, center_off + (n_after + 1) * 4)
        for off in range(lo & ~3, hi, 4):
            w = rd32(self.data, off)
            mark = " <<<" if off == center_off else ""
            self.log(f"        {off:06X}: {w:08X}{mark}")

    # ─────────────────────────────────────────────
    # v15.7: Pass N — kernelcache error bypass
    # ─────────────────────────────────────────────
    def _pass_N_kernelcache_bypass(self):
        """
        NOP ветки, ведущей на error-блок "Kernelcache image not valid".

        Универсальный фикс: не зависит от image4 callback.
        Работает на всех версиях, но особенно нужен для iOS 18.0–18.3.2,
        где Pass A/B не находят callback.
        """
        err_off = None
        err_str = None
        for s in [b"Kernelcache image not valid\x00",
                  b"Kernelcache image not valid",
                  b"kernelcache image not valid"]:
            err_off = self.find_string(s)
            if err_off is not None:
                err_str = s
                break
        if err_off is None:
            self.log("  [N] 'Kernelcache image not valid' not found")
            return False

        display = err_str.rstrip(b'\x00').decode(errors='replace')
        self.log(f"  [N] '{display}' @ 0x{err_off:X}")

        refs = self.find_adrp_add_refs(err_off)
        if not refs:
            self.log("  [N] no ADRP+ADD ref to error string")
            return False

        err_xref = refs[0][0]
        err_block_va = self.base + err_xref
        self.log(f"  [N] error block @ 0x{err_xref:X} (VA 0x{err_block_va:X})")

        # Сканируем назад до 0x400, ищем ветку на error-блок
        lo = max(0, err_xref - 0x400)
        found = []
        for o in range(err_xref - 4, lo - 1, -4):
            w = rd32(self.data, o)
            target_va = None
            kind = None

            # B.cond (imm19)
            if (w & BCOND_MASK) == BCOND_VAL:
                target_va = decode_bcond_target(w, self.base + o)
                kind = "B.cond"
            # CBZ / CBNZ (imm19)
            elif (w & CBZ_MASK) in (CBZ_VAL, CBNZ_VAL):
                target_va = decode_bcond_target(w, self.base + o)
                kind = "CBZ" if (w & CBZ_MASK) == CBZ_VAL else "CBNZ"
            # B / BL (imm26)
            elif (w & B_OR_BL_MASK) == B_OR_BL_VAL:
                target_va = decode_bl_target(w, self.base + o)
                kind = "B" if (w & B_MASK) == B_VAL else "BL"

            if target_va is None: continue
            if err_block_va <= target_va < err_block_va + 0x80:
                found.append((o, w, target_va, kind))
                if len(found) >= 4:
                    break

        if not found:
            self.log("  [N] no branch to error block found in 0x400")
            return False

        # Берём ближайшую ветку к error-блоку
        found.sort(key=lambda x: err_block_va - x[2])
        o, w, target_va, kind = found[0]
        self.log(f"  [N] found {kind} @ 0x{o:X} (0x{w:08X}) → 0x{target_va:X}")
        self.emit(o, p32(NOP_U32), f"NOP kernelcache error ({kind})")
        self.results['kernelcache_pass_N'] = o
        return True

    # ─────────────────────────────────────────────
    # Forward tracking регистра
    # ─────────────────────────────────────────────

    def _forward_track_reg(self, reg, func_off, target_off):
        reg_va = [None] * 32
        reg = reg & 0x1F
        cur = func_off & ~3
        end = target_off & ~3
        while cur < end:
            w = rd32(self.data, cur)
            if (w & 0x9F000000) == 0x10000000:
                rd = w & 0x1F
                reg_va[rd] = (self.base + cur) + decode_adr_imm(w)
                cur += 4; continue
            if (w & 0x9F000000) == 0x90000000:
                rd = w & 0x1F
                reg_va[rd] = ((self.base + cur) & ~0xFFF) + (decode_adrp_imm(w) << 12)
                cur += 4; continue
            if (w & 0xFF800000) == 0x91000000:
                rd = w & 0x1F; rn = (w >> 5) & 0x1F; imm12 = (w >> 10) & 0xFFF
                if rn != 31 and reg_va[rn] is not None:
                    reg_va[rd] = reg_va[rn] + imm12
                else:
                    reg_va[rd] = None
                cur += 4; continue
            if (w & 0xFF000000) == 0x58000000:
                rd = w & 0x1F
                reg_va[rd] = (self.base + cur) + decode_ldr_lit_imm(w)
                cur += 4; continue
            if (w & 0xFFE0FFE0) == 0xAA0003E0:
                rd = w & 0x1F; rm = (w >> 16) & 0x1F
                reg_va[rd] = reg_va[rm] if rm < 31 else None
                cur += 4; continue
            if (w & 0x7F800000) == 0x52800000:
                rd = w & 0x1F; imm16 = (w >> 5) & 0xFFFF
                shift = ((w >> 21) & 0x3) * 16
                reg_va[rd] = imm16 << shift
                cur += 4; continue
            if (w & 0x7F800000) == 0x72800000:
                rd = w & 0x1F; imm16 = (w >> 5) & 0xFFFF
                shift = ((w >> 21) & 0x3) * 16
                old = reg_va[rd] or 0
                reg_va[rd] = (old & ~(0xFFFF << shift)) | (imm16 << shift)
                cur += 4; continue
            cur += 4
        return reg_va[reg]

    # ─────────────────────────────────────────────
    # Диагностический фильтр ADR
    # ─────────────────────────────────────────────

    def _filter_adr_by_bootargs_context(self, adr_refs, rd_md0):
        diag = []
        markers = set()
        for _, off in self.find_adrp_add_refs(rd_md0):
            markers.add(off)
        for off in self.find_adr_refs(rd_md0):
            markers.add(off)
        markers.add(rd_md0)
        ba = self.find_string(b"boot-args\x00")
        if ba is not None:
            for _, off in self.find_adrp_add_refs(ba):
                markers.add(off)
            for off in self.find_adr_refs(ba):
                markers.add(off)

        in_context = []
        for adr_off in adr_refs:
            func = self.find_func_start(adr_off, max_back=0x4000)
            if func is None:
                diag.append(f"        ADR@0x{adr_off:X}: no func_start")
                continue
            fsize = 0x4000
            for k in range(func + 4, min(func + 0x4000, self.size), 4):
                w = rd32(self.data, k)
                if w in (PACIBSP_U32, BTI_C_U32):
                    fsize = k - func
                    break
            hit = any(func <= m < func + fsize for m in markers)
            diag.append(f"        ADR@0x{adr_off:X}  func@0x{func:X}  "
                        f"size=0x{fsize:X}  ctx={'yes' if hit else 'no'}")
            if hit:
                in_context.append(adr_off)

        if not in_context:
            diag.append("        (нет ADR в boot-args контексте)")
            return [], diag
        return in_context, diag

    # ─────────────────────────────────────────────
    # 1. image4 callback
    # ─────────────────────────────────────────────

    def _collect_image4_anchors(self):
        anchor_strings = [
            b"Unknown ASN1 type", b"Unknown ASN1", b"ASN1 type", b"ASN1",
            b"Unknown property type", b"invalid ASN1",
            b"image4_validate", b"image4:", b"property callback",
        ]
        anchors, ref_sites = [], set()
        for s in anchor_strings:
            p = self.find_string(s)
            if p is not None and p not in anchors:
                anchors.append(p)
                self.log(f"  [i] anchor '{s.decode(errors='replace')}' @ 0x{p:X}")

        for a in anchors:
            for adrp_off, add_off in self.find_adrp_add_refs(a):
                ref_sites.add(adrp_off); ref_sites.add(add_off)
            for adr_off in self.find_adr_refs(a):
                ref_sites.add(adr_off)
            for ptr in self.find_ptr_to_string(a):
                ref_sites.add(ptr)

        self.log(f"  [i] xref sites: {len(ref_sites)}")
        return anchors, ref_sites

    def _pass_A_outlined(self, anchors):
        if not anchors: return False
        best, best_dist = None, 10**9
        for anchor in anchors:
            lo = max(0, anchor - 0x300)
            hi = min(self.size - 12, anchor + 0x100)
            for off in range(lo, hi, 4):
                bl   = rd32(self.data, off)
                bne  = rd32(self.data, off + 4)
                mov  = rd32(self.data, off + 8)
                if (bl >> 26) != 0b100101:                continue
                if (bne & 0xFF00001F) != 0x54000001:      continue
                if (mov & 0xFFE0FFE0) != 0xAA0003E0:      continue
                dist = abs((off + 4) - anchor)
                if dist < best_dist:
                    best_dist = dist; best = off + 4
        if best is None or best_dist >= 0x300:
            return False
        self.log(f"  [A] outlined canary @ 0x{best:X} (dist=0x{best_dist:X})")
        self.results["image4_callback_bne"] = best
        self.results["image4_callback_mov"] = best + 4
        self.emit(best,     p32(NOP_U32),      "NOP b.ne (image4 A outlined)")
        self.emit(best + 4, p32(MOV_X0_0_U32), "MOV X0, #0 (force image4 success)")
        return True

    def _collect_inline_sites(self, require_movn=False):
        sites = []
        CHUNK = 0x2000
        for start in range(0, min(self.size, self.code_end), CHUNK - 0x100):
            end = min(start + CHUNK, self.size)
            for off in range(start, end - 8, 4):
                w = rd32(self.data, off)
                if (w & 0xFF00001F) != 0x54000001:        continue
                nxt = rd32(self.data, off + 4)
                if (nxt & 0xFFE0FFE0) != 0xAA0003E0:      continue
                src_reg = (nxt >> 16) & 0x1F
                if src_reg == 31: continue
                has_cmp = any(
                    (rd32(self.data, off - k * 4) & 0xFFE0FC1F) == 0xEB00001F
                    or (rd32(self.data, off - k * 4) & 0x7F20001F) == 0x6B00001F
                    for k in range(1, 9) if off - k * 4 >= 0)
                if not has_cmp: continue
                if require_movn:
                    has_movn = False
                    for k in range(1, 65):
                        if off - k * 4 < 0: break
                        prev = rd32(self.data, off - k * 4)
                        if (prev & 0xFFE0001F) == (0x12800000 | src_reg):
                            has_movn = True; break
                    if not has_movn: continue
                sites.append(off)
        return sites

    def _pass_B_inline_strict(self, anchors):
        sites = self._collect_inline_sites(require_movn=True)
        if not sites: return False
        if not anchors:
            self.log(f"  [B] {len(sites)} strict hits but 0 anchors")
            return False
        chosen, best_dist = sites[0], 10**9
        for off in sites:
            for a in anchors:
                d = abs(off - a)
                if d < best_dist:
                    best_dist = d; chosen = off
        if best_dist >= 0x1000:
            self.log(f"  [B] no ASN1-near inline canary (best dist=0x{best_dist:X})")
            return False
        self.log(f"  [B] strict inline @ 0x{chosen:X} "
                 f"(dist=0x{best_dist:X}, {len(sites)} hits)")
        self.results["image4_callback_bne"] = chosen
        self.results["image4_callback_mov"] = chosen + 4
        self.emit(chosen,     p32(NOP_U32),      "NOP b.ne (image4 B inline)")
        self.emit(chosen + 4, p32(MOV_X0_0_U32), "MOV X0, #0 (force image4 success)")
        return True

    def _pass_C_inline_relaxed(self, anchors):
        if not anchors: return False
        sites = []
        for a in anchors:
            lo = max(0, a - 0x800)
            hi = min(self.size - 8, a + 0x200)
            for off in range(lo, hi, 4):
                w = rd32(self.data, off)
                if (w & 0xFF00001F) != 0x54000001:        continue
                nxt = rd32(self.data, off + 4)
                if (nxt & 0xFFE0FFE0) != 0xAA0003E0:      continue
                src_reg = (nxt >> 16) & 0x1F
                if src_reg == 31: continue
                has_cmp = any(
                    (rd32(self.data, off - k * 4) & 0xFFE0FC1F) == 0xEB00001F
                    or (rd32(self.data, off - k * 4) & 0x7F20001F) == 0x6B00001F
                    for k in range(1, 9) if off - k * 4 >= 0)
                if has_cmp:
                    sites.append((off, a, abs(off - a)))
        if not sites: return False
        sites.sort(key=lambda x: x[2])
        chosen, anchor, dist = sites[0]
        if dist >= 0x800:
            self.log(f"  [C] nearest relaxed hit too far (dist=0x{dist:X})")
            return False
        self.log(f"  [C] relaxed inline @ 0x{chosen:X} "
                 f"(anchor 0x{anchor:X}, dist=0x{dist:X})")
        self.results["image4_callback_bne"] = chosen
        self.results["image4_callback_mov"] = chosen + 4
        self.emit(chosen,     p32(NOP_U32),      "NOP b.ne (image4 C relaxed)")
        self.emit(chosen + 4, p32(MOV_X0_0_U32), "MOV X0, #0 (force image4 success)")
        return True

    def _pass_D_func_entry(self, ref_sites):
        funcs = {}
        for r in ref_sites:
            fs = self.find_func_start(r)
            if fs is None: continue
            dist = abs(r - fs)
            if fs not in funcs or dist < funcs[fs]:
                funcs[fs] = dist
        self.log(f"  [D] candidate functions: {len(funcs)}")

        accepted = []
        for fs, dist in funcs.items():
            if dist > FUNC_START_MAX_DIST:
                self.log(f"  [D] отклоняю @0x{fs:X} (dist=0x{dist:X} > "
                         f"0x{FUNC_START_MAX_DIST:X})")
                continue
            fend = min(fs + 0x4000, self.size)
            has_ret = any(rd32(self.data, c) in (RET_U32, RETAB_U32, RETAA_U32)
                          for c in range(fs, fend, 4))
            if not has_ret:
                continue
            accepted.append((fs, dist))

        if not accepted:
            self.log("  [D] нет подходящих функций")
            return False

        accepted.sort(key=lambda x: x[1])
        fs, dist = accepted[0]
        self.emit(fs,     p32(MOV_W0_0_U32), "MOV W0, #0 (image4 D entry)")
        self.emit(fs + 4, p32(RET_U32),      "RET (early-return)")
        self.results['image4_callback_func'] = fs
        self.log(f"  [D] function entry @ 0x{fs:X} (dist=0x{dist:X})")
        return True

    def _pass_F_kairos_rsa(self):
        img4_off = self.find_string(b"IMG4\x00")
        if img4_off is None:
            self.log("  [F] 'IMG4' string not found")
            return False
        self.log(f"  [F] 'IMG4' @ 0x{img4_off:X}")

        img4_xref = None
        adrp_refs = self.find_adrp_add_refs(img4_off)
        if adrp_refs:
            img4_xref = adrp_refs[0][0]
            self.log(f"  [F] IMG4 ADRP+ADD xref @ 0x{img4_xref:X}")
        else:
            adr_refs = self.find_adr_refs(img4_off)
            if adr_refs:
                img4_xref = adr_refs[0]
                self.log(f"  [F] IMG4 ADR xref @ 0x{img4_xref:X}")
        if img4_xref is None:
            self.log("  [F] no xref to IMG4")
            return False

        partial = self.find_func_start(img4_xref, max_back=0x20000)
        if partial is None:
            self.log("  [F] no func start for IMG4 xref")
            return False
        self.log(f"  [F] _image4_get_partial @ 0x{partial:X}")

        partial_va = self.base + partial
        callers = []
        for off in range(0, min(self.code_end, self.size - 4), 4):
            w = rd32(self.data, off)
            if (w & B_OR_BL_MASK) != B_OR_BL_VAL: continue
            if decode_bl_target(w, self.base + off) == partial_va:
                callers.append(off)
        if not callers:
            self.log("  [F] no callers of _image4_get_partial")
            return False
        self.log(f"  [F] {len(callers)} callers")

        for call_off in callers:
            func = self.find_func_start(call_off, max_back=0x10000)
            if func is None:
                self.log(f"  [F] caller @ 0x{call_off:X}: no func_start — skip")
                continue

            self.log(f"  [F] caller @ 0x{call_off:X}: func @ 0x{func:X} "
                     f"(size 0x{call_off-func:X})")

            x2_va = self._forward_track_reg(2, func, call_off)
            if x2_va is None:
                self.log(f"  [F]   X2 не трассируется — skip")
                continue

            self.log(f"  [F]   X2 = 0x{x2_va:X}")

            x2_off_file = x2_va - self.base
            cb_target = x2_va
            if 0 <= x2_off_file < self.size - 8:
                val = struct.unpack_from('<Q', self.data, x2_off_file)[0]
                if self.base <= val <= self.base + self.size:
                    cb_target = val
                    self.log(f"  [F]   *0x{x2_va:X} = 0x{val:X} (deref)")

            cb_off = cb_target - self.base
            if cb_off < 0 or cb_off + 8 > self.size:
                self.log(f"  [F]   callback 0x{cb_target:X} out of range — skip")
                continue

            self.log(f"  [F]   → callback @ 0x{cb_target:X} (file 0x{cb_off:X})")
            self.emit(cb_off,     p32(MOV_W0_0_U32), "MOV W0, #0 (image4 F fwd-track)")
            self.emit(cb_off + 4, p32(RET_U32),      "RET (image4 F fwd-track)")
            self.results['image4_callback_func'] = cb_off
            self.log(f"  [F] patched callback @ 0x{cb_off:X}")
            return True

        self.log("  [F] no matching caller pattern found")
        return False

    def _pass_H_nop_post_check(self):
        img4_off = self.find_string(b"IMG4\x00")
        if img4_off is None:
            self.log("  [H] 'IMG4' string not found")
            return False

        img4_xref = None
        ar = self.find_adrp_add_refs(img4_off)
        if ar:
            img4_xref = ar[0][0]
        else:
            arr = self.find_adr_refs(img4_off)
            if arr:
                img4_xref = arr[0]
        if img4_xref is None:
            self.log("  [H] no xref to IMG4")
            return False

        partial = self.find_func_start(img4_xref, max_back=0x20000)
        if partial is None:
            self.log("  [H] no func_start for IMG4 xref")
            return False
        partial_va = self.base + partial
        self.log(f"  [H] _image4_get_partial @ 0x{partial:X}")

        callers = []
        for off in range(0, min(self.code_end, self.size - 4), 4):
            w = rd32(self.data, off)
            if (w & B_OR_BL_MASK) != B_OR_BL_VAL: continue
            if decode_bl_target(w, self.base + off) == partial_va:
                callers.append(off)
        if not callers:
            self.log("  [H] no callers of _image4_get_partial")
            return False
        self.log(f"  [H] {len(callers)} callers")

        n = 0
        for call_off in callers:
            if call_off + 8 > self.size: continue
            w_next = rd32(self.data, call_off + 4)
            opc = w_next & CBZ_MASK
            if opc in (CBZ_VAL, CBNZ_VAL):
                rt = w_next & 0x1F
                if rt == 0:
                    name = "CBZ" if opc == CBZ_VAL else "CBNZ"
                    self.log(f"  [H] NOP {name} W0 after call @ 0x{call_off:X} "
                             f"→ NOP @ 0x{call_off+4:X}")
                    self.emit(call_off + 4, p32(NOP_U32),
                              f"NOP post-BL check (pass H)")
                    n += 1
        if n == 0:
            self.log("  [H] no CBZ/CBNZ W0 immediately after call")
        else:
            self.results['image4_pass_H'] = n
            self.log(f"  [H] applied {n} NOP(s)")
        return n > 0

    def _pass_E_panic_caller(self):
        panic_va = self._find_panic_addr()
        if panic_va is None:
            self.log("  [E] _panic not located")
            return False
        self.log(f"  [E] _panic @ 0x{panic_va:X}")

        callers = set()
        limit = min(self.code_end, self.size - 4)
        for off in range(0, limit, 4):
            w = rd32(self.data, off)
            if (w & B_OR_BL_MASK) != B_OR_BL_VAL: continue
            if decode_bl_target(w, self.base + off) == panic_va:
                fs = self.find_func_start(off)
                if fs is not None and fs >= EARLY_CODE_CUTOFF:
                    callers.add(fs)
        self.log(f"  [E] _panic callers (>=0x{EARLY_CODE_CUTOFF:X}): {len(callers)}")
        if not callers:
            return False

        inline_sites = set(self._collect_inline_sites(require_movn=False))
        if not inline_sites:
            self.log("  [E] no inline canary candidates at all")
            return False

        magic_strings = [
            b"IMG4", b"img4", b"IM4M", b"im4m", b"IM4P", b"im4p",
            b"image4:", b"image4", b"ticket.der", b"ticket",
            b"manifest", b"ASN1", b"property", b"cpfc", b"tbmr",
            b"SecureRoot", b"iBoot", b"iBEC",
        ]
        magic_str_offsets = []
        for s in magic_strings:
            so = self.find_string(s)
            if so is not None:
                magic_str_offsets.append(so)

        scored = []
        for fs in callers:
            fend = min(fs + 0x8000, self.size)
            size = fend - fs
            has_canary = any(fs <= s < fend for s in inline_sites)
            if not has_canary:
                continue
            magic = 0
            for so in magic_str_offsets:
                for adrp_off, add_off in self.find_adrp_add_refs(so):
                    if fs <= adrp_off < fend:
                        magic += 1
                        break
            n_pan = 0
            for off in range(fs, fend - 4, 4):
                w = rd32(self.data, off)
                if (w & B_OR_BL_MASK) != B_OR_BL_VAL: continue
                if decode_bl_target(w, self.base + off) == panic_va:
                    n_pan += 1
            scored.append((fs, size, magic, n_pan))

        if not scored:
            self.log("  [E] no canary-bearing panic caller (after cutoff)")
            return False

        scored.sort(key=lambda x: (-x[2], -x[3], -x[1]))
        self.log("  [E] top candidates (magic-ranked):")
        for fs, size, magic, n_pan in scored[:10]:
            self.log(f"        @0x{fs:X}  size=0x{size:X}  magic={magic}  "
                     f"_panic_calls={n_pan}")

        best = None
        for fs, size, magic, n_pan in scored:
            if magic >= 2:
                best = (fs, size, magic, n_pan)
                break
        if best is None:
            self.log("  [E] no candidate with magic>=2 — refusing blind patch")
            return False

        fs, size, magic, n_pan = best
        fend = min(fs + 0x8000, self.size)
        cand = None
        for off in range(fs, fend - 8, 4):
            if off in inline_sites:
                cand = off; break
        if cand is None:
            return False

        self.log(f"  [E] canary @ 0x{cand:X} inside panic-caller @ 0x{fs:X} "
                 f"(size=0x{size:X}, magic={magic}, _panic_calls={n_pan})")
        self.results["image4_callback_bne"] = cand
        self.results["image4_callback_mov"] = cand + 4
        self.emit(cand,     p32(NOP_U32),      "NOP b.ne (image4 E panic-caller)")
        self.emit(cand + 4, p32(MOV_X0_0_U32), "MOV X0, #0 (force image4 success)")
        return True

    def find_image4_callback(self):
        self.log("\n[1] image4_validate_property_callback")
        self.log("  [i] матрица: 26.x=A  18.4+=B  18.0-18.3=N  17.4-17.7=B")
        self.log("  [i] 17.0-17.3=D/H  15.x=D/H  14.x=H")

        # Pass N первым — универсальный обход kernelcache error.
        # Особенно нужен на iOS 18.0–18.3.2, где A/B не находят callback.
        self.log("\n  [N] kernelcache error bypass (universal):")
        self._pass_N_kernelcache_bypass()

        anchors, ref_sites = self._collect_image4_anchors()

        if self._pass_A_outlined(anchors):       return True
        if self._pass_B_inline_strict(anchors):  return True
        if self._pass_C_inline_relaxed(anchors): return True
        if self._pass_F_kairos_rsa():            return True
        if self._pass_D_func_entry(ref_sites):   return True
        if self._pass_H_nop_post_check():        return True
        if self._pass_E_panic_caller():          return True

        self.log("  [!] image4 callback not located (all passes failed)")
        self.log("  [!] но Pass N может обойти это — пробуй bootx")
        return False

    # ─────────────────────────────────────────────
    # 2. CTRR
    # ─────────────────────────────────────────────

    def find_ctrr_lockdown(self):
        self.log("\n[2] CTRR lockdown")
        count = 0
        for off in range(0, min(self.code_end, self.size - 4), 4):
            w = rd32(self.data, off)
            if (w & 0xFFF00000) != 0xD5100000: continue
            op0 = 2 + ((w >> 19) & 1)
            op1 = (w >> 16) & 0x7
            crn = (w >> 12) & 0xF
            crm = (w >> 8) & 0xF
            op2 = (w >> 5) & 0x7
            if op0 == 3 and op1 in (0, 4) and crn == 15 and crm == 2 and op2 in (2, 5):
                el = "EL1" if op1 == 0 else "EL2"
                name = f"CTRR_{'LOCK' if op2 == 5 else 'CTL'}_{el}"
                self.results[f'ctrr_{off:X}'] = off
                self.emit(off, p32(NOP_U32), f"NOP MSR {name}")
                count += 1
        if count == 0:
            self.log("  [-] No CTRR MSR found (норма для iOS 14.x)")
        return count > 0

    # ─────────────────────────────────────────────
    # 3. Boot-args
    # ─────────────────────────────────────────────

    def find_boot_args(self):
        if self.mode == 'ibss':
            return False

        self.log("\n[3] Boot-args")
        self.log("  [i] матрица: 14.x=❌ нет refs  15+=ADRP/ADR/LDR")
        new_args = b"serial=3 -v debug=0x2014e %s\x00"

        rd_md0 = self.find_string("rd=md0")
        if rd_md0 is None:
            self.log("  [-] 'rd=md0' not found")
            return False
        self.log(f"  [i] 'rd=md0' @ 0x{rd_md0:X}")

        candidates = []
        for delta in range(0, 0x400):
            for d in (-delta, delta):
                o = rd_md0 + d
                if 0 <= o < self.size - 3 and self.data[o:o+3] == b'%s\x00':
                    if o not in candidates:
                        candidates.append(o)
        if not candidates:
            self.log("  [-] '%s' format near rd=md0 not found")
            return False

        scored = []
        for c in candidates:
            n_adrp = len(self.find_adrp_add_refs(c))
            n_adr  = len(self.find_adr_refs(c))
            n_ldr  = len(self.find_ldr_literal_refs(c))
            n_ptr  = len(self.find_ptr_to_string(c))
            total = n_adrp * 4 + n_adr * 3 + n_ldr * 2 + n_ptr
            scored.append((c, total, n_adrp, n_adr, n_ldr, n_ptr))

        scored.sort(key=lambda x: -x[1])
        self.log(f"  [i] {len(candidates)} '%s' candidates near rd=md0:")
        for c, total, na, nadr, nl, nptr in scored:
            self.log(f"        @0x{c:X}  adrp+add={na}  adr={nadr}  "
                     f"ldr={nl}  ptr={nptr}  (score={total})")

        for fmt_s, total, na, nadr, nl, nptr in scored:
            if total == 0:
                continue
            self.log(f"  [i] пробую '%s' @ 0x{fmt_s:X} (score={total})")

            refs = self.find_adrp_add_refs(fmt_s)
            if refs:
                if self._inject_boot_args(refs, new_args,
                                          f"Strategy 1: ADRP+ADD → %s"):
                    return True

            adr_refs = self.find_adr_refs(fmt_s)
            if adr_refs:
                filtered, diag = self._filter_adr_by_bootargs_context(
                    adr_refs, rd_md0)
                self.log(f"  [i] ADR-контекст (диагностика):")
                for line in diag:
                    self.log(line)
                if filtered:
                    self.log(f"  [i] применяю {len(filtered)} ADR из boot-args ctx")
                    if self._inject_boot_args_adr(filtered, new_args,
                                                  f"Strategy 2a: ADR(boot-args ctx) → %s"):
                        return True
                else:
                    first_adr = [adr_refs[0]]
                    self.log(f"  [!] контекст пуст, применяю только "
                             f"1 ADR @0x{first_adr[0]:X} (минимум)")
                    if self._inject_boot_args_adr(first_adr, new_args,
                                                  f"Strategy 2b: ADR(first) → %s"):
                        return True

            ldr_refs = self.find_ldr_literal_refs(fmt_s)
            if ldr_refs:
                if self._inject_boot_args_literal(ldr_refs, new_args,
                                                  f"Strategy 3: LDR literal → %s"):
                    return True

            ptr_locs = self.find_ptr_to_string(fmt_s)
            if ptr_locs:
                if self._inject_boot_args_raw_ptr(ptr_locs, new_args,
                                                  f"Strategy 4: raw ptr → %s"):
                    return True

        self.log("  [-] Boot-args injection failed")
        self.log("  [!] для iOS 14.x: у '%s' нет refs — нужен др. подход (TODO)")
        return False

    def _find_nul_slot(self, size_needed=64, prefer_reachable_from=None):
        candidates = []
        for off in range(0x14000, self.size - size_needed):
            if off % 16: continue
            if self.data[off:off + size_needed] == b'\x00' * size_needed:
                candidates.append(off)
                if prefer_reachable_from is None and len(candidates) >= 1:
                    break
        if not candidates: return None
        if not prefer_reachable_from: return candidates[0]
        for slot in candidates:
            ok = True
            for adr_off in prefer_reachable_from:
                imm = (self.base + slot) - (self.base + adr_off)
                if imm < -(1 << 20) or imm >= (1 << 20):
                    ok = False; break
            if ok: return slot
        return None

    def _inject_boot_args_adr(self, adr_offs, new_args, strategy):
        slot = self._find_nul_slot(64, prefer_reachable_from=adr_offs)
        if slot is None:
            self.log("  [-] No ADR-reachable NUL slot found")
            return False
        self.log(f"  {strategy}")
        self.emit(slot, new_args, f"Write boot-args @ 0x{slot:X}")
        self.results['boot_args_string'] = slot
        slot_va = self.base + slot
        for adr_off in adr_offs:
            w = rd32(self.data, adr_off)
            rd = w & 0x1F
            pc = self.base + adr_off
            try:
                new_w = encode_adr(rd, pc, slot_va)
            except ValueError as e:
                self.log(f"  [-] ADR redirect failed @ 0x{adr_off:X}: {e}")
                return False
            self.emit(adr_off, p32(new_w), f"ADR redirect → boot-args @ 0x{adr_off:X}")
        return True

    def _inject_boot_args(self, refs, new_args, strategy):
        slot = self._find_nul_slot(64)
        if slot is None:
            self.log("  [-] No NUL slot found")
            return False
        self.log(f"  {strategy}")
        self.emit(slot, new_args, f"Write boot-args @ 0x{slot:X}")
        self.results['boot_args_string'] = slot
        slot_va = self.base + slot
        slot_page = slot_va & ~0xFFF
        slot_lo   = slot_va & 0xFFF
        for adrp_off, add_off in refs:
            adrp_w = rd32(self.data, adrp_off)
            rd = adrp_w & 0x1F
            pc = self.base + adrp_off
            self.emit(adrp_off, p32(encode_adrp(rd, pc, slot_page)),
                      "ADRP → boot-args")
            add_w = rd32(self.data, add_off)
            add_rd = add_w & 0x1F
            add_rn = (add_w >> 5) & 0x1F
            self.emit(add_off, p32(encode_add_imm(add_rd, add_rn, slot_lo)),
                      "ADD → boot-args lo12")
        return True

    def _inject_boot_args_literal(self, ldr_refs, new_args, strategy):
        slot = self._find_nul_slot(64)
        if slot is None:
            self.log("  [-] No NUL slot found")
            return False
        self.log(f"  {strategy}")
        self.emit(slot, new_args, f"Write boot-args @ 0x{slot:X}")
        self.results['boot_args_string'] = slot
        slot_va = self.base + slot
        seen_lit = set()
        for ldr_off, lit_off in ldr_refs:
            if lit_off in seen_lit:
                continue
            seen_lit.add(lit_off)
            self.emit(lit_off, struct.pack('<Q', slot_va),
                      f"Literal ptr → boot-args @ 0x{lit_off:X} (LDR@0x{ldr_off:X})")
        return len(seen_lit) > 0

    def _inject_boot_args_raw_ptr(self, ptr_locs, new_args, strategy):
        slot = self._find_nul_slot(64)
        if slot is None:
            self.log("  [-] No NUL slot found")
            return False
        self.log(f"  {strategy}")
        self.emit(slot, new_args, f"Write boot-args @ 0x{slot:X}")
        self.results['boot_args_string'] = slot
        slot_va = self.base + slot
        for po in ptr_locs:
            self.emit(po, struct.pack('<Q', slot_va),
                      f"Raw ptr → boot-args @ 0x{po:X}")
        return True

    # ─────────────────────────────────────────────
    # 4. Key functions
    # ─────────────────────────────────────────────

    def find_key_functions(self):
        self.log("\n[4] Key function discovery")
        string_names = {
            "double panic in": "_panic",
            "debug-uarts":     "_main_task",
            "aborting autoboot": "_check_autoboot",
            "boot-command":    "_sys_setup_default_environment",
            "ticket.der":      "_ticket_verify",
            "Ramdisk image not valid": "_do_ramdisk",
            "Device Tree image not valid": "_do_devicetree",
        }
        for needle, name in string_names.items():
            str_off = self.find_string(needle)
            if str_off is None: continue
            refs = self.find_adrp_add_refs(str_off)
            if not refs: continue
            func = self.find_func_start(refs[0][0])
            if func is not None:
                self.results[name] = func
                self.log(f"  {name:<40s} 0x{self.base+func:X}")

    def find_all(self):
        self.log(f"=== iBoot Patchfinder v15.7-passN "
                 f"(mode={self.mode}, base=0x{self.base:X}"
                 f"{f', ios={self.ios_major}' if self.ios_major else ''}) ===")
        self.log(f"Size: {self.size} bytes ({self.size/1024:.0f} KB), "
                 f"code_end≈0x{self.code_end:X}")

        ver = self.find_string(b"iBoot for")
        if ver:
            end = self.data.find(b'\x00', ver)
            self.log(f"Banner: {self.data[ver:end].decode('ascii', errors='replace')}")

        self.find_image4_callback()
        self.find_ctrr_lockdown()
        self.find_boot_args()
        self.find_key_functions()

        self.log(f"\n==== {len(self.patches)} patches applied ====")
        return self.data


# ═══════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(
        description="Universal iBoot patchfinder for A12/A13 "
                    "(iOS 12-27, см. матрицу совместимости в docstring)")
    ap.add_argument("input", type=Path)
    ap.add_argument("output", type=Path, nargs='?')
    ap.add_argument("--base", default=None)
    ap.add_argument("--cpid", default=None)
    ap.add_argument("--ios", type=int, default=None,
                    help="iOS major version (12..27)")
    ap.add_argument("--mode", choices=["ibss", "ibec", "llb"], default="ibec")
    ap.add_argument("-q", "--quiet", action="store_true")
    ap.add_argument("--no-decompress", action="store_true")
    args = ap.parse_args()

    raw = args.input.read_bytes()
    if not args.no_decompress:
        raw = maybe_decompress(raw, verbose=not args.quiet)

    if args.base:
        base = int(args.base, 0)
        if not args.quiet:
            print(f"  [i] base from CLI: 0x{base:X}", file=sys.stderr)
    else:
        cpid_int = int(args.cpid, 0) if args.cpid else None
        base, _src = detect_base(raw, ios_major=args.ios,
                                 cpid=cpid_int, verbose=not args.quiet)

    pf = IBootPatchfinder(raw, base=base, mode=args.mode,
                          verbose=not args.quiet, ios_major=args.ios)
    patched = pf.find_all()

    if args.output:
        args.output.write_bytes(bytes(patched))
        print(f"\n  [i] wrote {len(patched)} B to {args.output}", file=sys.stderr)

    useful = any(k in pf.results for k in
                 ("image4_callback_bne", "image4_callback_mov",
                  "image4_callback_func", "image4_pass_H",
                  "kernelcache_pass_N",
                  "boot_args_string"))
    if not useful:
        print("  [!] no useful patches applied", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())