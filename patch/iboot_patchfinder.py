#!/usr/bin/env python3
"""
iboot_patchfinder.py — iBoot/iBSS/iBEC patchfinder для A12/A13.

v15.8 (Pass Q — SEP override):
  * NEW: `--sep-version X.Y` CLI + Pass Q.
    Когда SEP-файл от другой iOS (тот же BORD/CHIP, но другой build),
    iBEC может отклонить его. Pass Q ищет функции, содержащие строки
    'sep-firmware' / 'loading sep' / 'SEP load' и NOP'ит canary
    (CMP; B.NE; MOV X0, Xn) внутри них.
  * Сохранены Pass N (kernelcache error bypass) и Pass D/A/B/C/F/H/E.
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

NOP_U32      = 0xD503201F
RET_U32      = 0xD65F03C0
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
B_OR_BL_MASK = 0x7C000000
B_OR_BL_VAL  = 0x14000000
BCOND_MASK = 0xFF000010
BCOND_VAL  = 0x54000000
CBZ_MASK = 0xFF000000
CBZ_VAL  = 0x34000000
CBNZ_VAL = 0x35000000
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
    if imm & (1 << 20): imm -= (1 << 21)
    return imm


def decode_ldr_lit_imm(w):
    imm19 = (w >> 5) & 0x7FFFF
    if imm19 & (1 << 18): imm19 -= (1 << 19)
    return imm19 << 2


def decode_bl_target(w, pc_va):
    imm26 = w & 0x03FFFFFF
    if imm26 & (1 << 25): imm26 -= (1 << 26)
    return pc_va + (imm26 << 2)


def decode_bcond_target(w, pc_va):
    imm19 = (w >> 5) & 0x7FFFF
    if imm19 & (1 << 18): imm19 -= (1 << 19)
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
    if off < 0 or off + min_len >= len(data): return False
    for i in range(min_len):
        b = data[off + i]
        if b < 0x20 or b > 0x7E: return False
    return True


def _score_base(data, base, scan_limit=0x400000):
    n = len(data)
    scan_limit = min(scan_limit, n - 8)
    str_hits = ptr_hits = total = 0
    for i in range(0, scan_limit, 4):
        w1 = rd32(data, i)
        if (w1 & ADRP_MASK) != ADRP_VAL: continue
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
                if _is_string(data, target_off): str_hits += 1
                elif target_off + 8 <= n:
                    val = struct.unpack_from('<Q', data, target_off)[0]
                    if 0x100000000 <= val <= 0x1000000000: ptr_hits += 1
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
    if cpid == 0x8030: return BASE_A13_DEFAULT, "cpid-a13"
    if cpid == 0x8020: return BASE_A12_DEFAULT, "cpid-a12"
    return BASE_A13_DEFAULT, "default"


# ═══════════════════════════════════════════════════════════════
# Decompression
# ═══════════════════════════════════════════════════════════════

def _acompress_cli(data):
    if not shutil.which("acompress"): return None
    with tempfile.NamedTemporaryFile(delete=False, suffix=".lz") as f:
        f.write(data); in_path = f.name
    out_path = in_path + ".out"
    try:
        r = subprocess.run(["acompress", "-d", "-b", "-i", in_path, "-o", out_path],
                           capture_output=True, timeout=60)
        if r.returncode == 0 and os.path.exists(out_path):
            with open(out_path, "rb") as f: return f.read()
    except Exception: pass
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
    payload = data
    for m in (b'bvx2', b'bvx-', b'bvxn'):
        idx = data.find(m)
        if 0 <= idx < 0x2000:
            payload = data[idx:]; break
    out = _acompress_cli(payload) or _acompress_cli(data)
    if out is not None:
        if verbose: print(f"  [✓] decompressed: {len(data)} -> {len(out)} B",
                          file=sys.stderr)
        return out
    return data


# ═══════════════════════════════════════════════════════════════
# Patchfinder
# ═══════════════════════════════════════════════════════════════

class IBootPatchfinder:
    def __init__(self, data, base=0x19C220000, mode='ibec', verbose=True,
                 ios_major=None, sep_version=None):
        self.data = bytearray(data)
        self.size = len(data)
        self.base = base
        self.mode = mode
        self.verbose = verbose
        self.ios_major = ios_major
        self.sep_version = sep_version
        self.patches = []
        self.results = {}

        self.code_end = self.size
        for i in range(self.size - 4, 0, -4):
            w = rd32(self.data, i)
            if w in (PACIBSP_U32, BTI_C_U32):
                self.code_end = min(self.size, i + 0x1000)
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
            out.append(i); pos = i + 1
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
            lit_off = (self.base + off + imm) - self.base
            if 0 <= lit_off < self.size - 8:
                val = struct.unpack_from('<Q', self.data, lit_off)[0]
                if val == target_va:
                    out.append((off, lit_off))
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
        if s is None: return None
        refs = self.find_adrp_add_refs(s)
        if not refs: return None
        fs = self.find_func_start(refs[0][0])
        if fs is None: return None
        return self.base + fs

    # ─── Pass N ───
    def _pass_N_kernelcache_bypass(self):
        err_off = None
        err_str = None
        for s in [b"Kernelcache image not valid\x00",
                  b"Kernelcache image not valid",
                  b"kernelcache image not valid"]:
            err_off = self.find_string(s)
            if err_off is not None:
                err_str = s; break
        if err_off is None:
            self.log("  [N] 'Kernelcache image not valid' not found")
            return False
        display = err_str.rstrip(b'\x00').decode(errors='replace')
        self.log(f"  [N] '{display}' @ 0x{err_off:X}")

        # Собираем ВСЕ виды refs
        refs = set()
        for adrp_off, add_off in self.find_adrp_add_refs(err_off):
            refs.add(adrp_off)
        for adr_off in self.find_adr_refs(err_off):
            refs.add(adr_off)
        for ldr_off, lit_off in self.find_ldr_literal_refs(err_off):
            refs.add(ldr_off)
        for ptr_off in self.find_ptr_to_string(err_off):
            refs.add(ptr_off)

        if not refs:
            self.log("  [N] no refs (ADRP+ADD / ADR / LDR / ptr)")
            return False
        self.log(f"  [N] {len(refs)} ref site(s)")

        for ref_off in sorted(refs):
            err_block_va = self.base + ref_off
            lo = max(0, ref_off - 0x600)
            found = []
            for o in range(ref_off - 4, lo - 1, -4):
                w = rd32(self.data, o)
                target_va = None; kind = None
                if (w & BCOND_MASK) == BCOND_VAL:
                    target_va = decode_bcond_target(w, self.base + o); kind = "B.cond"
                elif (w & CBZ_MASK) in (CBZ_VAL, CBNZ_VAL):
                    target_va = decode_bcond_target(w, self.base + o)
                    kind = "CBZ" if (w & CBZ_MASK) == CBZ_VAL else "CBNZ"
                elif (w & B_OR_BL_MASK) == B_OR_BL_VAL:
                    target_va = decode_bl_target(w, self.base + o)
                    kind = "B" if (w & 0xFC000000) == 0x14000000 else "BL"
                if target_va is None: continue
                if err_block_va <= target_va < err_block_va + 0x100:
                    found.append((o, w, target_va, kind))
                    if len(found) >= 4: break
            if not found: continue
            found.sort(key=lambda x: err_block_va - x[2])
            o, w, target_va, kind = found[0]
            self.log(f"  [N] ref@0x{ref_off:X}: {kind} @ 0x{o:X} → 0x{target_va:X}")
            self.emit(o, p32(NOP_U32), f"NOP kernelcache error ({kind})")
            self.results['kernelcache_pass_N'] = o
            return True

        self.log("  [N] no branch to error block found")
        return False

    # ─── Pass Q — SEP bypass ───
    def _pass_Q_sep_bypass(self):
        """
        NOP canary в функциях, связанных с SEP.

        Когда SEP-файл от другой iOS (тот же BORD/CHIP, другой build),
        iBEC может отклонить его. Ищем функции, содержащие строки
        'sep-firmware' / 'loading sep' / 'SEP load' / 'sep:'
        и NOP'им canary (CMP; B.NE; MOV X0, Xn) внутри них.
        """
        self.log(f"\n[0b] SEP bypass (Pass Q, sep_version={self.sep_version})")

        sep_anchors = [
            b"sep-firmware", b"sep firmware",
            b"loading sep", b"loading SEP",
            b"SEP load", b"sep load",
            b"sep: ", b"SEP: ",
            b"SEP\n", b"SEP\x00",
            b"sep_init", b"SEP init",
            b"sep_image", b"SEP image",
            b"sep_verify", b"SEP verify",
        ]

        anchor_offsets = []
        for s in sep_anchors:
            o = self.find_string(s)
            if o is not None and o not in [x[1] for x in anchor_offsets]:
                anchor_offsets.append((s, o))
                self.log(f"  [Q] '{s.decode(errors='replace')}' @ 0x{o:X}")

        if not anchor_offsets:
            self.log("  [Q] no SEP anchors found")
            return False

        ref_sites = set()
        for _, a in anchor_offsets:
            for adrp_off, _ in self.find_adrp_add_refs(a):
                ref_sites.add(adrp_off)
            for adr_off in self.find_adr_refs(a):
                ref_sites.add(adr_off)
            for ptr_off in self.find_ptr_to_string(a):
                ref_sites.add(ptr_off)

        self.log(f"  [Q] total ref sites: {len(ref_sites)}")
        if not ref_sites:
            return False

        funcs = set()
        for r in ref_sites:
            fs = self.find_func_start(r, max_back=0x8000)
            if fs is not None:
                funcs.add(fs)
        self.log(f"  [Q] candidate functions: {len(funcs)}")

        n = 0
        for fs in sorted(funcs):
            fend = min(fs + 0x2000, self.size)
            for off in range(fs, fend - 8, 4):
                w = rd32(self.data, off)
                if (w & 0xFF00001F) != 0x54000001: continue  # B.NE
                nxt = rd32(self.data, off + 4)
                if (nxt & 0xFFE0FFE0) != 0xAA0003E0: continue  # MOV X0, Xn
                src_reg = (nxt >> 16) & 0x1F
                if src_reg == 31: continue
                has_cmp = any(
                    (rd32(self.data, off - k * 4) & 0xFFE0FC1F) == 0xEB00001F
                    or (rd32(self.data, off - k * 4) & 0x7F20001F) == 0x6B00001F
                    for k in range(1, 9) if off - k * 4 >= 0)
                if not has_cmp: continue
                self.log(f"  [Q] canary @ 0x{off:X} in SEP func @ 0x{fs:X}")
                self.emit(off,     p32(NOP_U32),      "NOP b.ne (SEP Q)")
                self.emit(off + 4, p32(MOV_X0_0_U32), "MOV X0, #0 (SEP Q)")
                self.results['sep_pass_Q'] = off
                n += 1
                if n >= 4: break
            if n >= 4: break

        if n == 0:
            self.log("  [Q] no canary in SEP functions")
        return n > 0

    # ─── image4 (Pass D из v15.7) ───
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
                self.log(f"  [D] отклоняю @0x{fs:X} (dist=0x{dist:X})")
                continue
            fend = min(fs + 0x4000, self.size)
            has_ret = any(rd32(self.data, c) in (RET_U32, RETAB_U32)
                          for c in range(fs, fend, 4))
            if not has_ret: continue
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

    def find_image4_callback(self):
        self.log("\n[1] image4_validate_property_callback")
        anchors, ref_sites = self._collect_image4_anchors()
        if self._pass_D_func_entry(ref_sites):
            return True
        self.log("  [!] image4 callback not located")
        return False

    # ─── CTRR ───
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
                self.emit(off, p32(NOP_U32), f"NOP MSR {name}")
                count += 1
        if count == 0:
            self.log("  [-] No CTRR MSR found")
        return count > 0

    # ─── Boot-args ───
    def find_boot_args(self):
        if self.mode == 'ibss': return False
        self.log("\n[3] Boot-args")
        new_args = b"serial=3 -v debug=0x2014e %s\x00"
        rd_md0 = self.find_string("rd=md0")
        if rd_md0 is None:
            self.log("  [-] 'rd=md0' not found"); return False
        self.log(f"  [i] 'rd=md0' @ 0x{rd_md0:X}")

        fmt_s = None
        for off in range(max(0, rd_md0 - 0x100), min(rd_md0 + 0x100, self.size)):
            if self.data[off:off+3] == b'%s\x00':
                fmt_s = off; break
        if fmt_s is None:
            self.log("  [-] '%s' near rd=md0 not found"); return False
        self.log(f"  [i] '%%s' @ 0x{fmt_s:X}")

        # ADRP+ADD
        refs = self.find_adrp_add_refs(fmt_s)
        if refs:
            return self._inject_boot_args(refs, new_args, "S1: ADRP+ADD")

        # ADR (контекстно)
        adr_refs = self.find_adr_refs(fmt_s)
        if adr_refs:
            filtered = []
            markers = set()
            for _, off in self.find_adrp_add_refs(rd_md0): markers.add(off)
            for off in self.find_adr_refs(rd_md0): markers.add(off)
            for adr_off in adr_refs:
                func = self.find_func_start(adr_off, max_back=0x4000)
                if func is None: continue
                fend = func + 0x4000
                for m in markers:
                    if func <= m < fend:
                        filtered.append(adr_off); break
            if filtered:
                self.log(f"  [i] ADR-контекст: {len(filtered)}/{len(adr_refs)}")
                return self._inject_boot_args_adr(filtered, new_args, "S2a: ADR(ctx)")
            else:
                self.log(f"  [!] контекст пуст — применяю 1 ADR")
                return self._inject_boot_args_adr(adr_refs[:1], new_args, "S2b: ADR(1)")

        # LDR literal
        ldr_refs = self.find_ldr_literal_refs(fmt_s)
        if ldr_refs:
            return self._inject_boot_args_literal(ldr_refs, new_args, "S3: LDR")

        # raw ptr
        ptr_locs = self.find_ptr_to_string(fmt_s)
        if ptr_locs:
            return self._inject_boot_args_raw_ptr(ptr_locs, new_args, "S4: ptr")

        self.log("  [-] Boot-args not found")
        return False

    def _find_nul_slot(self, size_needed=64, prefer_reachable_from=None):
        candidates = []
        for off in range(0x14000, self.size - size_needed):
            if off % 16: continue
            if self.data[off:off + size_needed] == b'\x00' * size_needed:
                candidates.append(off)
                if prefer_reachable_from is None and len(candidates) >= 1: break
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
        if slot is None: return False
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
                self.log(f"  [-] ADR fail @ 0x{adr_off:X}: {e}"); return False
            self.emit(adr_off, p32(new_w), f"ADR redirect @ 0x{adr_off:X}")
        return True

    def _inject_boot_args(self, refs, new_args, strategy):
        slot = self._find_nul_slot(64)
        if slot is None: return False
        self.log(f"  {strategy}")
        self.emit(slot, new_args, f"Write boot-args @ 0x{slot:X}")
        self.results['boot_args_string'] = slot
        slot_va = self.base + slot
        slot_page = slot_va & ~0xFFF
        slot_lo = slot_va & 0xFFF
        for adrp_off, add_off in refs:
            adrp_w = rd32(self.data, adrp_off)
            rd = adrp_w & 0x1F
            pc = self.base + adrp_off
            self.emit(adrp_off, p32(encode_adrp(rd, pc, slot_page)), "ADRP → b/a")
            add_w = rd32(self.data, add_off)
            add_rd = add_w & 0x1F; add_rn = (add_w >> 5) & 0x1F
            self.emit(add_off, p32(encode_add_imm(add_rd, add_rn, slot_lo)), "ADD → b/a")
        return True

    def _inject_boot_args_literal(self, ldr_refs, new_args, strategy):
        slot = self._find_nul_slot(64)
        if slot is None: return False
        self.log(f"  {strategy}")
        self.emit(slot, new_args, f"Write boot-args @ 0x{slot:X}")
        self.results['boot_args_string'] = slot
        slot_va = self.base + slot
        seen = set()
        for ldr_off, lit_off in ldr_refs:
            if lit_off in seen: continue
            seen.add(lit_off)
            self.emit(lit_off, struct.pack('<Q', slot_va), f"lit ptr @ 0x{lit_off:X}")
        return len(seen) > 0

    def _inject_boot_args_raw_ptr(self, ptr_locs, new_args, strategy):
        slot = self._find_nul_slot(64)
        if slot is None: return False
        self.log(f"  {strategy}")
        self.emit(slot, new_args, f"Write boot-args @ 0x{slot:X}")
        self.results['boot_args_string'] = slot
        slot_va = self.base + slot
        for po in ptr_locs:
            self.emit(po, struct.pack('<Q', slot_va), f"raw ptr @ 0x{po:X}")
        return True

    def find_key_functions(self):
        self.log("\n[4] Key function discovery")
        for needle, name in {
            "double panic in": "_panic",
            "debug-uarts": "_main_task",
            "aborting autoboot": "_check_autoboot",
        }.items():
            so = self.find_string(needle)
            if so is None: continue
            refs = self.find_adrp_add_refs(so)
            if not refs: continue
            func = self.find_func_start(refs[0][0])
            if func is not None:
                self.results[name] = func
                self.log(f"  {name:<40s} 0x{self.base+func:X}")

    def find_all(self):
        self.log(f"=== iBoot Patchfinder v15.8-passNQ "
                 f"(mode={self.mode}, base=0x{self.base:X}"
                 f"{f', ios={self.ios_major}' if self.ios_major else ''}"
                 f"{f', sep={self.sep_version}' if self.sep_version else ''}) ===")
        self.log(f"Size: {self.size} bytes ({self.size/1024:.0f} KB), "
                 f"code_end≈0x{self.code_end:X}")

        ver = self.find_string(b"iBoot for")
        if ver:
            end = self.data.find(b'\x00', ver)
            self.log(f"Banner: {self.data[ver:end].decode('ascii', errors='replace')}")

        self.log("\n[0] Kernelcache error path (Pass N)")
        self._pass_N_kernelcache_bypass()

        if self.sep_version:
            self._pass_Q_sep_bypass()

        self.find_image4_callback()
        self.find_ctrr_lockdown()
        self.find_boot_args()
        self.find_key_functions()

        self.log(f"\n==== {len(self.patches)} patches applied ====")
        return self.data


# ═══════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(
        description="iBoot patchfinder for A12/A13")
    ap.add_argument("input", type=Path)
    ap.add_argument("output", type=Path, nargs='?')
    ap.add_argument("--base", default=None)
    ap.add_argument("--cpid", default=None)
    ap.add_argument("--ios", type=int, default=None)
    ap.add_argument("--sep-version", default=None,
                    help="версия SEP для Pass Q (например 16.1)")
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
                          verbose=not args.quiet, ios_major=args.ios,
                          sep_version=args.sep_version)
    patched = pf.find_all()

    if args.output:
        args.output.write_bytes(bytes(patched))
        print(f"\n  [i] wrote {len(patched)} B to {args.output}", file=sys.stderr)

    useful = any(k in pf.results for k in
                 ("image4_callback_func", "kernelcache_pass_N",
                  "sep_pass_Q", "boot_args_string"))
    if not useful:
        print("  [!] no useful patches applied", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())