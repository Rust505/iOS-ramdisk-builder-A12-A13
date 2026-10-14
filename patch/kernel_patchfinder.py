#!/usr/bin/env python3
"""
kernel_patchfinder.py — arm64e kernelcache patchfinder for A12/A13 (iOS 17+).

v8.3: + --cs-enforcement: best-effort патч cs_enforcement_disable global.
      + find_all сохраняет якорь cs_enforcement.
v8.2: строгая валидация MACF bypass:
      - is_blr_x10: исправлена ARM64-энкодировка (только BLR Xn)
      - has_macf_aggregator_shape: требуется И LDR X10, И BLR X10
      - patch_iouc_failed_macf: проверка слитного BL+CBZ, направления
        ветки и расположения ADRP со строкой MACF ВНУТРИ error-пути
v8.1: MACF bypass вынесен из-под with_apfs_mount.
v8:   --macf-bypass.
v7:   точечный crypto bypass.
v6:   безопасный crypto bypass.
v4:   --ssv-only.
v2:   --apfs-mount.
"""

import argparse
import struct
import sys
import time
from pathlib import Path
from collections import defaultdict

NOP_U32       = 0xD503201F
RET_U32       = 0xD65F03C0
RETAB_U32     = 0xD65F0FFF
PACIBSP_U32   = 0xD503237F
BTI_C_U32     = 0xD503245F
MOV_X0_0_U32  = 0xD2800000
MOV_X0_1_U32  = 0xD2800020
MOV_W0_0_U32  = 0x52800000
MOV_W0_1_U32  = 0x52800020
CBZ_X2_8_U32  = 0xB4000042
STR_X0_X2_U32 = 0xF9000040
B_U32         = 0x14000000

FUNC_BOUNDARIES = {RET_U32, RETAB_U32, PACIBSP_U32, BTI_C_U32, NOP_U32}
FUNC_STARTS     = {PACIBSP_U32, BTI_C_U32}


def p32(v):
    return struct.pack('<I', v & 0xFFFFFFFF)


def rd32(d, o):
    return struct.unpack_from('<I', d, o)[0]


def rd64(d, o):
    return struct.unpack_from('<Q', d, o)[0]


def decode_adrp_imm(insn_word):
    immhi = (insn_word >> 5) & 0x7FFFF
    immlo = (insn_word >> 29) & 0x3
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= (1 << 21)
    return imm


def is_adrp(w):
    return (w & 0x9F000000) == 0x90000000


def is_bl(w):
    return (w >> 26) == 0b100101


def bl_target(off, w):
    imm26 = w & 0x3FFFFFF
    if imm26 & (1 << 25):
        imm26 -= (1 << 26)
    return off + imm26 * 4


def is_add_imm(w):
    return (w & 0xFF800000) == 0x91000000


def add_imm12(w):
    return (w >> 10) & 0xFFF


def is_cond_branch(w):
    op = w & 0x7E000000
    return op in (0x34000000, 0x35000000, 0x36000000, 0x37000000)


class KernelPatchfinder:
    def __init__(self, data, verbose=True):
        self.data = bytearray(data)
        self.size = len(data)
        self.verbose = verbose
        self.patches = []
        self.base_va = 0
        self.segments = []
        self.code_ranges = []
        self.adrp_index = defaultdict(list)
        self.bl_index = defaultdict(list)
        self.panic_offset = None

    def log(self, msg):
        if self.verbose:
            print(msg)

    def emit(self, off, patch_bytes, desc):
        self.data[off:off + len(patch_bytes)] = patch_bytes
        self.patches.append((off, desc))
        self.log(f"  0x{off:08X}: {desc}")

    # ───────────────────────────────────────────────
    # Mach-O parsing
    # ───────────────────────────────────────────────

    def parse_macho(self):
        if rd32(self.data, 0) != 0xFEEDFACF:
            raise ValueError("Not Mach-O 64")
        ncmds = rd32(self.data, 16)
        off = 32
        for _ in range(ncmds):
            cmd, cmdsize = rd32(self.data, off), rd32(self.data, off + 4)
            if cmd == 0x19:
                name = self.data[off+8:off+24].split(b'\x00')[0].decode(errors='replace')
                seg = {
                    'name': name,
                    'vmaddr':   rd64(self.data, off + 24),
                    'vmsize':   rd64(self.data, off + 32),
                    'fileoff':  rd64(self.data, off + 40),
                    'filesize': rd64(self.data, off + 48),
                }
                self.segments.append(seg)
                if name == '__TEXT':
                    self.base_va = seg['vmaddr']
                if name in ('__TEXT_EXEC', '__PRELINK_TEXT'):
                    if seg['filesize'] > 0x1000:
                        self.code_ranges.append(
                            (int(seg['fileoff']),
                             int(seg['fileoff'] + seg['filesize'])))
            off += cmdsize
        self.log(f"  Base VA: 0x{self.base_va:X}, Segments: {len(self.segments)}")
        for s, e in self.code_ranges:
            self.log(f"  Code range: 0x{s:X}-0x{e:X} ({(e-s)/1024/1024:.1f} MB)")

    # ───────────────────────────────────────────────
    # VA ↔ file offset
    # ───────────────────────────────────────────────

    def va_to_foff(self, va):
        for s in self.segments:
            if s['vmaddr'] <= va < s['vmaddr'] + s['vmsize']:
                return int(va - s['vmaddr'] + s['fileoff'])
        return None

    def foff_to_va(self, foff):
        for s in self.segments:
            so, se = int(s['fileoff']), int(s['fileoff'] + s['filesize'])
            if so <= foff < se:
                return s['vmaddr'] + (foff - so)
        return None

    def main_code_range(self):
        return max(self.code_ranges, key=lambda r: r[1] - r[0])

    def kext_code_ranges(self):
        ranges = []
        for s in self.segments:
            if s['name'] == '__PRELINK_TEXT' and s['filesize'] > 0x1000:
                so, se = int(s['fileoff']), int(s['fileoff'] + s['filesize'])
                ranges.append((so, se))
        return ranges

    # ───────────────────────────────────────────────
    # Index building
    # ───────────────────────────────────────────────

    def build_adrp_index(self):
        t0 = time.time()
        self.adrp_index.clear()
        count = 0
        for start, end in self.code_ranges:
            for off in range(start, end, 4):
                w = rd32(self.data, off)
                if not is_adrp(w):
                    continue
                imm = decode_adrp_imm(w)
                va = self.foff_to_va(off)
                base = va if va else off
                page = ((base & ~0xFFF) + (imm << 12)) & 0xFFFFFFFFFFFFFFFF
                self.adrp_index[page].append(off)
                count += 1
        self.log(f"  ADRP index: {count} entries, {len(self.adrp_index)} pages "
                 f"({time.time()-t0:.1f}s)")

    def build_bl_index(self):
        t0 = time.time()
        self.bl_index.clear()
        count = 0
        for start, end in self.code_ranges:
            for off in range(start, end, 4):
                w = rd32(self.data, off)
                if not is_bl(w):
                    continue
                self.bl_index[bl_target(off, w)].append(off)
                count += 1
        self.log(f"  BL index: {count} entries, {len(self.bl_index)} targets "
                 f"({time.time()-t0:.1f}s)")

    # ───────────────────────────────────────────────
    # String helpers
    # ───────────────────────────────────────────────

    def find_string(self, needle):
        if isinstance(needle, str):
            needle = needle.encode()
        idx = self.data.find(needle)
        return idx if idx >= 0 else None

    def find_string_refs(self, string_foff):
        va = self.foff_to_va(string_foff)
        if va is None:
            return []
        page = va & ~0xFFF
        page_off = va & 0xFFF
        refs = []
        for adrp_off in self.adrp_index.get(page, []):
            for delta in range(4, 36, 4):
                add_off = adrp_off + delta
                if add_off + 4 > self.size:
                    break
                w = rd32(self.data, add_off)
                if is_add_imm(w) and add_imm12(w) == page_off:
                    adrp_rd = rd32(self.data, adrp_off) & 0x1F
                    add_rn = (w >> 5) & 0x1F
                    if adrp_rd == add_rn:
                        refs.append((adrp_off, add_off))
                        break
        return refs

    def find_func_by_string(self, needle, label=None):
        soff = self.find_string(needle)
        if soff is None:
            self.log(f"  {label or needle}: string NOT FOUND")
            return None
        refs = self.find_string_refs(soff)
        if not refs:
            self.log(f"  {label or needle}: str@0x{soff:X} no xrefs")
            return None
        func = self.find_func_start(refs[0][0])
        if func is not None:
            self.log(f"  {label or needle}: func=0x{func:X}")
        return func

    def find_func_start(self, off, max_back=0x4000):
        for i in range(off & ~3, max(0, off - max_back), -4):
            w = rd32(self.data, i)
            if w in FUNC_STARTS:
                return i
            if (w & 0x7FC07FFF) == 0x29007BFD:
                return i
        return None

    def find_func_end(self, off, max_fwd=0x8000):
        for i in range(off, min(off + max_fwd, self.size - 4), 4):
            w = rd32(self.data, i)
            if w in (RET_U32, RETAB_U32):
                return i + 4
        return None

    # ───────────────────────────────────────────────
    # _panic
    # ───────────────────────────────────────────────

    def find_panic(self):
        for target, callers in sorted(self.bl_index.items(),
                                      key=lambda x: -len(x[1]))[:15]:
            if len(callers) < 2000:
                break
            confirmed = 0
            for c in callers[:30]:
                for back in range(c - 4, max(c - 32, 0), -4):
                    w = rd32(self.data, back)
                    if (w & 0xFFC003E0) != 0x91000000:
                        continue
                    add_imm = (w >> 10) & 0xFFF
                    if back < 4:
                        break
                    aw = rd32(self.data, back - 4)
                    if (aw & 0x9F00001F) != 0x90000000:
                        break
                    imm = decode_adrp_imm(aw)
                    foff = ((back - 4) & ~0xFFF) + (imm << 12) + add_imm
                    if 0 <= foff < self.size - 60:
                        if b"%s:%d" in self.data[foff:foff+60]:
                            confirmed += 1
                    break
                if confirmed >= 3:
                    break
            if confirmed >= 3:
                self.panic_offset = target
                self.log(f"  _panic @ 0x{target:X} ({len(callers)} callers)")
                return
        top = sorted(self.bl_index.items(), key=lambda x: -len(x[1]))
        if len(top) > 2:
            self.panic_offset = top[2][0]
            self.log(f"  _panic (fallback) @ 0x{self.panic_offset:X}")

    # ───────────────────────────────────────────────
    # PE_i_can_has_debugger
    # ───────────────────────────────────────────────

    def find_pe_debugger(self):
        init = self.find_func_by_string("debug-enabled\x00", "PE_init(debug-enabled)")
        if init:
            end = self.find_func_end(init) or init + 0x1000
            globals_written = set()
            for off in range(init, end, 4):
                w = rd32(self.data, off)
                if not is_adrp(w) or off + 4 >= end:
                    continue
                nxt = rd32(self.data, off + 4)
                if (nxt & 0xFFC00000) in (0xB9000000, 0xF9000000):
                    imm = decode_adrp_imm(w)
                    page = (off & ~0xFFF) + (imm << 12)
                    scale = 4 if (nxt & 0xFFC00000) == 0xB9000000 else 8
                    str_imm = ((nxt >> 10) & 0xFFF) * scale
                    globals_written.add((page + str_imm) & 0xFFFFFFFFFFFFFFFF)
            best = None
            for g in globals_written:
                for adrp_off in self.adrp_index.get(g & ~0xFFF, []):
                    func = self.find_func_start(adrp_off)
                    if func is None:
                        continue
                    fend = self.find_func_end(func)
                    if fend is None or fend - func > 48:
                        continue
                    callers = len(self.bl_index.get(func, []))
                    if callers > 100 and (best is None or callers > best[1]):
                        best = (func, callers)
            if best:
                self.log(f"  PE_i_can_has_debugger (global): func=0x{best[0]:X} "
                         f"callers={best[1]}")
                return best[0]
        best_off, best_n = None, 0
        for target, callers in self.bl_index.items():
            n = len(callers)
            if not (50 <= n <= 300) or target + 16 > self.size or target & 3:
                continue
            first = rd32(self.data, target)
            adrp_at = None
            if (first & 0x9F00001F) == 0x90000008:
                adrp_at = target
            elif first == BTI_C_U32 and \
                    (rd32(self.data, target + 4) & 0x9F00001F) == 0x90000008:
                adrp_at = target + 4
            if adrp_at is None:
                continue
            if target >= 4 and rd32(self.data, target - 4) not in FUNC_BOUNDARIES:
                continue
            if not any((rd32(self.data, adrp_at + k*4) & 0xFFC00000) == 0xB9400000
                       and ((rd32(self.data, adrp_at + k*4) >> 5) & 0x1F) == 8
                       for k in range(1, 9) if adrp_at + k*4 + 4 <= self.size):
                continue
            if n > best_n:
                best_n = n
                best_off = target
        if best_off is not None:
            self.log(f"  PE_i_can_has_debugger (histogram): func=0x{best_off:X} "
                     f"callers={best_n}")
            return best_off
        return None

    # ───────────────────────────────────────────────
    # AMFIIsCDHashInTrustCache
    # ───────────────────────────────────────────────

    def find_amfi_trustcache(self):
        code_start, code_end = self.main_code_range()
        self.log(f"  AMFI scan range: 0x{code_start:X}-0x{code_end:X}")
        MOV_X19_X2 = 0xAA0203F3
        MOV_X2_SP  = 0x910003E2
        STP_MASK, STP_VAL = 0xFFC07FFF, 0xA9007FFF
        BL_MASK,  BL_VAL  = 0xFC000000, 0x94000000
        MOV_X20_X0 = 0xAA0003F4
        CBNZ_W0_M, CBNZ_W0_V = 0x7F00001F, 0x35000000
        CBZ_X19_M, CBZ_X19_V = 0xFF00001F, 0xB4000013
        hits = []
        off = code_start
        while off < code_end - 4:
            w = rd32(self.data, off)
            if w not in FUNC_STARTS:
                off += 4
                continue
            fs = off
            fe = min(fs + 0x200, code_end)
            p = fs + 4
            while p < fe:
                if rd32(self.data, p) in FUNC_STARTS:
                    fe = p
                    break
                p += 4
            insns = [rd32(self.data, i) for i in range(fs, fe, 4)]
            try:
                i1 = next(i for i, w in enumerate(insns) if w == MOV_X19_X2)
                i2 = next(i for i in range(i1+1, len(insns))
                          if (insns[i] & STP_MASK) == STP_VAL)
                i3 = next(i for i in range(i2+1, len(insns)) if insns[i] == MOV_X2_SP)
                i4 = next(i for i in range(i3+1, len(insns))
                          if (insns[i] & BL_MASK) == BL_VAL)
                i5 = next(i for i in range(i4+1, len(insns)) if insns[i] == MOV_X20_X0)
                next(i for i in range(i5+1, len(insns))
                     if (insns[i] & CBNZ_W0_M) == CBNZ_W0_V)
                next(i for i in range(i5+1, len(insns))
                     if (insns[i] & CBZ_X19_M) == CBZ_X19_V)
                hits.append(('strict', fs))
            except StopIteration:
                pass
            if not any(h[1] == fs for h in hits):
                try:
                    i3 = next(i for i, w in enumerate(insns) if w == MOV_X2_SP)
                    next(i for i in range(max(0, i3-6), i3)
                         if (insns[i] & STP_MASK) == STP_VAL)
                    i4 = next(i for i in range(i3+1, min(i3+4, len(insns)))
                              if (insns[i] & BL_MASK) == BL_VAL)
                    next(i for i in range(i4+1, min(i4+3, len(insns)))
                         if (insns[i] & CBNZ_W0_M) == CBNZ_W0_V)
                    if len(insns) <= 64:
                        hits.append(('relaxed', fs))
                except StopIteration:
                    pass
            off = fe
        if not hits:
            self.log("  AMFIIsCDHashInTrustCache: 0 hits")
            return None
        strict = [h[1] for h in hits if h[0] == 'strict']
        result = strict[0] if strict else hits[0][1]
        self.log(f"  AMFIIsCDHashInTrustCache: {len(hits)} hits "
                 f"({len(strict)} strict), using 0x{result:X}")
        return result

    # ───────────────────────────────────────────────
    # vm_fault_enter
    # ───────────────────────────────────────────────

    def find_vm_fault_enter(self):
        for needle in ["vm_fault_enter_prepare", "vm_fault_enter("]:
            func = self.find_func_by_string(needle, "vm_fault_enter(str)")
            if func:
                return func
        self.log("  vm_fault_enter: trying advanced heuristics...")
        code_start, code_end = self.main_code_range()
        for off in range(code_start, min(code_end, self.size - 16), 4):
            w = rd32(self.data, off)
            if (w & 0xFFC00000) != 0xB9400000 and (w & 0xFFC00000) != 0xF9400000:
                continue
            rt = w & 0x1F
            for fwd in range(off + 4, min(off + 128, code_end), 4):
                tw = rd32(self.data, fwd)
                if (tw & 0x7F000000) != 0x36000000:
                    continue
                if (tw & 0x1F) != rt:
                    continue
                bit = ((tw >> 31) << 5) | ((tw >> 19) & 0x1F)
                if bit != 3:
                    continue
                mw = rd32(self.data, fwd + 4)
                if (mw & 0xFFFFFFE0) == 0x52800000:
                    bw = rd32(self.data, fwd + 8)
                    if (bw & 0xFC000000) == 0x14000000:
                        func = self.find_func_start(off)
                        if func:
                            self.log(f"  vm_fault_enter (pattern): func=0x{func:X} "
                                     f"tbz@0x{fwd:X}")
                            return func
        return None

    # ───────────────────────────────────────────────
    # mac_policy
    # ───────────────────────────────────────────────

    def find_mac_policy_register(self):
        for needle in ["mac_policy_register\x00", "mac_policy_register failed"]:
            func = self.find_func_by_string(needle, f"mac_policy({needle[:25]})")
            if func:
                return func
        self.log("  mac_policy: BL frequency heuristic...")
        code_start, code_end = self.main_code_range()
        for target, callers in sorted(self.bl_index.items(), key=lambda x: len(x[1])):
            n = len(callers)
            if not (3 <= n <= 15) or target < code_start or target >= code_end:
                continue
            fe = self.find_func_end(target)
            if fe is None:
                continue
            fsize = fe - target
            if not (100 <= fsize <= 800):
                continue
            for off in range(target, min(target + fsize, self.size - 4), 4):
                w = rd32(self.data, off)
                if not is_adrp(w):
                    continue
                va = self.foff_to_va(off)
                if va is None:
                    continue
                imm = decode_adrp_imm(w)
                page = (va & ~0xFFF) + (imm << 12)
                pfoff = self.va_to_foff(page)
                if pfoff and 0 <= pfoff < self.size - 20:
                    if b'mac_policy' in self.data[pfoff:pfoff+0x1000]:
                        caller_func = self.find_func_start(callers[0]) if callers else None
                        result = caller_func or target
                        self.log(f"  mac_policy (BL heuristic): func=0x{result:X}")
                        return result
        return None

    # ───────────────────────────────────────────────
    # apfs_vfsop_mount
    # ───────────────────────────────────────────────

    def find_apfs_vfsop_mount(self):
        for needle in [
            "apfs_vfsop_mount",
            "apfs_vfsop_mount:",
            "apfs: mount failed",
            "apfs_vfsop_mount: root snapshot",
        ]:
            func = self.find_func_by_string(needle, f"apfs_vfsop_mount({needle[:25]})")
            if func:
                return func
        func = self.find_func_by_string("apfs_mount\x00", "apfs_mount")
        if func:
            return func
        return None

    def patch_apfs_vfsop_mount(self, func_off):
        n = 0
        fe = self.find_func_end(func_off)
        if fe is None:
            self.log(f"  [!] apfs_vfsop_mount: cannot find function end at 0x{func_off:X}")
            return 0
        scan_end = min(fe, func_off + 0x600)
        for off in range(func_off, scan_end, 4):
            w = rd32(self.data, off)
            if not is_bl(w):
                continue
            if off + 8 > self.size:
                break
            nxt = rd32(self.data, off + 4)
            if (nxt & 0xFF000000) in (0x34000000, 0x35000000) and (nxt & 0x1F) == 0:
                self.emit(off + 4, p32(NOP_U32),
                    f"apfs_vfsop_mount → NOP CBZ/CBNZ W0 (snapshot) @0x{off+4:X}")
                n += 1
                if n >= 4: break
            if (nxt & 0xFF000000) in (0xB4000000, 0xB5000000) and (nxt & 0x1F) == 0:
                self.emit(off + 4, p32(NOP_U32),
                    f"apfs_vfsop_mount → NOP CBZ/CBNZ X0 (snapshot) @0x{off+4:X}")
                n += 1
                if n >= 4: break
            if (nxt & 0x7F000000) == 0x36000000 and (nxt & 0x1F) == 0:
                self.emit(off + 4, p32(NOP_U32),
                    f"apfs_vfsop_mount → NOP TBZ/TBNZ W0 @0x{off+4:X}")
                n += 1
                if n >= 4: break
        if n == 0:
            self.log("  [!] apfs_vfsop_mount: no snapshot checks patched")
        else:
            self.log(f"  apfs_vfsop_mount: {n} patches applied")
        return n

    # ───────────────────────────────────────────────
    # KEXT panic scan
    # ───────────────────────────────────────────────

    def find_kext_panic_branches(self, verbose_label="kext-panic"):
        if self.panic_offset is None:
            self.log(f"  {verbose_label}: _panic not found, skip")
            return []
        ranges = self.kext_code_ranges()
        if not ranges:
            self.log(f"  {verbose_label}: no __PRELINK_TEXT ranges, skip")
            return []
        hits = []
        panic_off = self.panic_offset
        for start, end in ranges:
            for off in range(start, end - 4, 4):
                w = rd32(self.data, off)
                if not (is_bl(w) and bl_target(off, w) == panic_off):
                    continue
                for back in range(off - 4, max(off - 28, start), -4):
                    bw = rd32(self.data, back)
                    if is_cond_branch(bw):
                        hits.append((back, off))
                        break
        if hits:
            self.log(f"  {verbose_label}: {len(hits)} conditional branches → _panic")
        else:
            self.log(f"  {verbose_label}: no conditional branches → _panic")
        return hits

    def patch_kext_panic_branches(self):
        hits = self.find_kext_panic_branches("kext-panic")
        n = 0
        for patch_off, bl_off in hits[:200]:
            self.emit(patch_off, p32(NOP_U32),
                f"kext-panic: NOP cond @0x{patch_off:X} → bl _panic @0x{bl_off:X}")
            n += 1
        return n

    # ───────────────────────────────────────────────
    # Display drivers
    # ───────────────────────────────────────────────

    def find_display_driver_functions(self):
        results = {}
        needles = {
            "AppleCLCD": ["AppleCLCD::", "AppleCLCD init", "AppleCLCD::start",
                          "AppleCLCD: no video"],
            "IOMobileFramebuffer": ["IOMobileFramebuffer::", "IOMobileFramebuffer start",
                                    "IOMobileFramebuffer: "],
            "IOSurface": ["IOSurface::", "IOSurfaceRoot::", "IOSurface init failed",
                          "IOSurface: ", "IOSurface is not locked"],
        }
        for label, strings in needles.items():
            for s in strings:
                soff = self.find_string(s)
                if soff is None:
                    continue
                refs = self.find_string_refs(soff)
                if refs:
                    func = self.find_func_start(refs[0][0])
                    if func:
                        results[label] = func
                        self.log(f"  display[{label}]: func=0x{func:X} (str={s!r})")
                        break
            if label not in results:
                for s in strings:
                    if self.find_string(s) is not None:
                        results[label] = None
                        self.log(f"  display[{label}]: str present, no xref")
                        break
        return results

    def patch_display_driver_panics(self, driver_funcs):
        if self.panic_offset is None:
            return 0
        panic_off = self.panic_offset
        n = 0
        for label, func_off in driver_funcs.items():
            if func_off is None:
                continue
            fe = self.find_func_end(func_off, max_fwd=0x2000)
            if fe is None:
                continue
            for off in range(func_off, fe - 4, 4):
                w = rd32(self.data, off)
                if not (is_bl(w) and bl_target(off, w) == panic_off):
                    continue
                for back in range(off - 4, max(off - 28, func_off), -4):
                    bw = rd32(self.data, back)
                    if is_cond_branch(bw):
                        self.emit(back, p32(NOP_U32),
                            f"{label}: NOP cond → panic @0x{off:X}")
                        n += 1
                        break
        return n

    # ═══════════════════════════════════════════════
    # v6: базовый crypto bypass
    # ═══════════════════════════════════════════════

    def patch_panics_in_function(self, func_off, label="", max_scan=0x2000):
        if self.panic_offset is None:
            return 0
        panic_off = self.panic_offset
        fe = self.find_func_end(func_off, max_fwd=max_scan)
        if fe is None:
            return 0

        n = 0
        for off in range(func_off, fe - 4, 4):
            w = rd32(self.data, off)
            if not (is_bl(w) and bl_target(off, w) == panic_off):
                continue
            for back in range(off - 4, max(off - 32, func_off), -4):
                bw = rd32(self.data, back)
                if is_cond_branch(bw):
                    self.emit(
                        back, p32(NOP_U32),
                        f"{label}: NOP cond→panic @0x{back:X}"
                    )
                    n += 1
                    break
        if n == 0:
            self.log(f"  {label}: no panics patched")
        else:
            self.log(f"  {label}: {n} panic-checks NOP'd")
        return n

    # ═══════════════════════════════════════════════
    # v7: crypto bypass по строкам
    # ═══════════════════════════════════════════════

    def find_panics_with_string(self, needles, func_off, max_scan=0x4000):
        if self.panic_offset is None:
            return []
        panic_off = self.panic_offset
        fe = self.find_func_end(func_off, max_fwd=max_scan)
        if fe is None:
            return []

        hits = []
        for off in range(func_off, fe - 4, 4):
            w = rd32(self.data, off)
            if not (is_bl(w) and bl_target(off, w) == panic_off):
                continue

            matched = None
            for back in range(off - 4, max(off - 48, func_off), -4):
                bw = rd32(self.data, back)
                if not is_adrp(bw):
                    continue
                for delta in (4, 8, 12, 16):
                    if back + delta + 4 > off:
                        break
                    w2 = rd32(self.data, back + delta)
                    if (w2 & 0xFF800000) != 0x91000000:
                        continue
                    adrp_rd = bw & 0x1F
                    add_rn = (w2 >> 5) & 0x1F
                    if add_rn != adrp_rd:
                        continue
                    imm12 = (w2 >> 10) & 0xFFF
                    imm = decode_adrp_imm(bw)
                    va = self.foff_to_va(back)
                    if va is None:
                        continue
                    page = (va & ~0xFFF) + (imm << 12)
                    str_va = page + imm12
                    str_off = self.va_to_foff(str_va)
                    if str_off is None or str_off >= self.size - 128:
                        continue
                    chunk = self.data[str_off:str_off + 128]
                    for needle in needles:
                        nb = needle.encode() if isinstance(needle, str) else needle
                        if chunk.startswith(nb):
                            matched = needle
                            break
                    if matched:
                        break
                if matched:
                    break

            if not matched:
                continue

            for back in range(off - 4, max(off - 32, func_off), -4):
                bw = rd32(self.data, back)
                if is_cond_branch(bw):
                    hits.append((back, off, matched))
                    break

        return hits

    def patch_crypto_panics_by_string(self):
        n = 0
        crypto_needles = [
            "apfs: failed to get crypto",
            "apfs_mount_crypto",
            "apfs: failed to get key",
            "apfs: no crypto",
            "sep_get_crypto",
            "CryptoUser",
            "crypto user",
            "getCryptoUserKey",
            "SEPManager::getCryptoUserKey",
            "sep: failed to get key",
            "sep: crypto",
            "failed to get crypto key",
            "apfs_mount: crypto",
        ]

        targets = []
        for needle in ("apfs_vfsop_mount\x00", "apfs_mount\x00",
                       "apfs_mount_crypto", "cryptouser",
                       "getCryptoUserKey"):
            f = self.find_func_by_string(needle)
            if f:
                targets.append((needle, f))

        for needle, func_off in targets:
            hits = self.find_panics_with_string(crypto_needles, func_off)
            if hits:
                self.log(f"  crypto[{needle}]: {len(hits)} panic-checks matched")
                for cond_off, bl_off, matched in hits:
                    self.emit(
                        cond_off, p32(NOP_U32),
                        f"crypto[{needle}]: NOP cond→panic @0x{cond_off:X} "
                        f"(str='{matched[:40]}')"
                    )
                    n += 1
            else:
                self.log(f"  crypto[{needle}]: no matching panic-checks")

        return n

    def find_sep_crypto_functions(self):
        results = {}
        needles = {
            "SEPManager_getCryptoUserKey": [
                "getCryptoUserKey",
                "AppleSEPManager::getCryptoUserKey",
                "SEPManager::getCryptoUserKey",
            ],
            "apfs_mount_crypto": [
                "apfs_mount_crypto",
                "apfs_mount: crypto",
                "apfs_mount: failed to get key",
                "apfs: failed to get crypto",
                "apfs_vfsop_mount: crypto",
            ],
            "sep_crypto_user": [
                "sep_crypto_user",
                "sep: crypto user",
                "cryptouser",
                "CryptoUser",
                "sep_load_cryptouser",
            ],
            "gigalocker": [
                "gigalocker",
                "Gigalocker",
                "sep_load_gigalocker",
            ],
            "keybag": [
                "AppleKeyStore",
                "keybag",
                "AKS_",
            ],
        }
        for label, strings in needles.items():
            for s in strings:
                soff = self.find_string(s)
                if soff is None:
                    continue
                refs = self.find_string_refs(soff)
                if refs:
                    func = self.find_func_start(refs[0][0])
                    if func:
                        results[label] = func
                        self.log(f"  crypto[{label}]: func=0x{func:X} (str={s!r})")
                        break
            if label not in results:
                for s in strings:
                    if self.find_string(s) is not None:
                        results[label] = None
                        self.log(f"  crypto[{label}]: str present, no xref")
                        break
        return results

    def patch_crypto_bypass(self):
        n = 0

        self.log("\n[crypto] Точечный scan panic-checks со crypto-строками...")
        n += self.patch_crypto_panics_by_string()

        self.log("\n[crypto] apfs_vfsop_mount snapshot-checks (SSV bypass)...")
        apfs_off = self.find_apfs_vfsop_mount()
        if apfs_off:
            n += self.patch_apfs_vfsop_mount(apfs_off)

        self.log(f"\n[crypto] total crypto-bypass patches: {n}")
        return n

    # ═══════════════════════════════════════════════
    # v8.3: cs_enforcement_disable (best-effort)
    # ═══════════════════════════════════════════════

    def patch_cs_enforcement_disable(self):
        """
        Force cs_enforcement_disable global to be treated as '1' at every check site.

        Strategy:
          1) find string "cs_enforcement_disable"
          2) find xref (boot-args parser); from the same function, find
             ADRP+ADD that loads a *global* address (2nd arg to boot-args parser)
          3) for that global, find every ADRP+ADD+LDRB reader in the code
          4) NOP the conditional branch that immediately follows the read
             (or the read itself if no branch within window)
        """
        needle = b"cs_enforcement_disable\x00"
        soff = self.find_string(needle)
        if soff is None:
            self.log("  [cs] string not found")
            return 0
        self.log(f"  [cs] string @ foff=0x{soff:X}")
        refs = self.find_string_refs(soff)
        if not refs:
            self.log("  [cs] no xref to string")
            return 0

        str_va = self.foff_to_va(soff)
        globals_found = set()

        for adrp_off, add_off in refs:
            func_start = self.find_func_start(add_off)
            if func_start is None:
                continue
            func_end = self.find_func_end(func_start, max_fwd=0x600)
            if func_end is None:
                func_end = min(self.size, add_off + 0x400)

            # look for another ADRP+ADD inside the same function; the target
            # is a candidate global variable
            for off in range(func_start, min(func_end - 8, add_off + 0x200), 4):
                w = rd32(self.data, off)
                if not is_adrp(w):
                    continue
                w2 = rd32(self.data, off + 4)
                if not is_add_imm(w2):
                    continue
                adrp_rd = w & 0x1F
                add_rn = (w2 >> 5) & 0x1F
                if adrp_rd != add_rn:
                    continue
                imm = decode_adrp_imm(w)
                va = self.foff_to_va(off)
                if va is None:
                    continue
                page = (va & ~0xFFF) + (imm << 12)
                target_va = page + add_imm12(w2)
                # skip the string itself
                if str_va is not None and target_va == str_va:
                    continue
                # skip obvious pointer constants to strings (very high VA range)
                globals_found.add(target_va)

        if not globals_found:
            self.log("  [cs] global address not identified")
            return 0
        self.log(f"  [cs] candidate globals: {len(globals_found)}")

        n = 0
        for gva in globals_found:
            page = gva & ~0xFFF
            page_off = gva & 0xFFF
            for adrp_off in self.adrp_index.get(page, []):
                # find the matching ADD that loads gva
                add_off_match = None
                for delta in range(4, 32, 4):
                    check_off = adrp_off + delta
                    if check_off + 4 > self.size:
                        break
                    w2 = rd32(self.data, check_off)
                    if not is_add_imm(w2):
                        continue
                    adrp_rd = rd32(self.data, adrp_off) & 0x1F
                    add_rn = (w2 >> 5) & 0x1F
                    if adrp_rd != add_rn or add_imm12(w2) != page_off:
                        continue
                    add_off_match = check_off
                    break
                if add_off_match is None:
                    continue

                # find the following LDRB/LDR W and conditional branch
                for k in range(1, 8):
                    inst_off = add_off_match + k * 4
                    if inst_off + 4 > self.size:
                        break
                    wi = rd32(self.data, inst_off)
                    if is_cond_branch(wi):
                        self.emit(inst_off, p32(NOP_U32),
                                  f"cs_enforcement_disable: NOP check @0x{inst_off:X}")
                        n += 1
                        break

        self.log(f"  [cs] total patches: {n}")
        return n

    # ═══════════════════════════════════════════════
    # v8.2: MACF bypass
    # ═══════════════════════════════════════════════

    def is_cbz_w0(self, w):
        return (w & 0x7F000000) == 0x34000000 and (w & 0x1F) == 0

    def is_cbnz_w0(self, w):
        return (w & 0x7F000000) == 0x35000000 and (w & 0x1F) == 0

    def is_blr_x10(self, w):
        """BLR Xn = 0xD63F0000 | (Rn << 5). Строго BLR X10."""
        if (w & 0xFFFFFC1F) != 0xD63F0000:
            return False
        return ((w >> 5) & 0x1F) == 10

    def has_macf_aggregator_shape(self, func_off):
        """Требуется И LDR X10,[X10,#imm], И BLR X10."""
        if func_off is None or func_off < 0 or func_off >= self.size:
            return False
        fe = self.find_func_end(func_off, max_fwd=0x2000)
        if fe is None:
            return False

        found_ldr = False
        found_blr = False
        for off in range(func_off, fe - 4, 4):
            w = rd32(self.data, off)
            if (w & 0xFFC00000) == 0xF9400000:
                rt = w & 0x1F
                rn = (w >> 5) & 0x1F
                if rt == 10 and rn == 10:
                    imm12 = (w >> 10) & 0xFFF
                    if 0x100 <= imm12 <= 0x2000:
                        found_ldr = True
            if self.is_blr_x10(w):
                found_blr = True
            if found_ldr and found_blr:
                return True
        return False

    def patch_iouc_failed_macf(self):
        n = 0

        needle_candidates = [
            b"IOUC %s failed MACF in process %s",
            b"IOUC %s failed MACF",
            b"failed MACF in process %s",
            b"failed MACF in process",
            b"MACF in process %s",
            b"IOUC: MACF",
            b"mac_iokit_check_open",
            b"MacPolicy:",
        ]

        str_off = None
        used_needle = None
        for needle in needle_candidates:
            off = self.find_string(needle)
            if off is not None:
                str_off = off
                used_needle = needle
                break

        if str_off is None:
            self.log("  [macf] строка MACF не найдена")
            return 0

        self.log(f"  [macf] строка @ foff=0x{str_off:X} ({used_needle!r})")
        refs = self.find_string_refs(str_off)
        if not refs:
            self.log("  [macf] нет xref на строку")
            return 0

        self.log(f"  [macf] xref: {len(refs)}")

        for adrp_off, add_off in refs:
            func_start = self.find_func_start(add_off)
            if func_start is None:
                self.log(f"  [macf] xref @0x{adrp_off:X}: no func start")
                continue
            func_end = self.find_func_end(func_start, max_fwd=0x8000)
            if func_end is None:
                self.log(f"  [macf] xref @0x{adrp_off:X}: no func end")
                continue

            self.log(f"  [macf] func 0x{func_start:X}-0x{func_end:X}, "
                     f"string ADRP @0x{adrp_off:X}")

            win_start = max(func_start, adrp_off - 0x200)
            found = False
            for off in range(win_start, adrp_off - 8, 4):
                w = rd32(self.data, off)
                if not is_bl(w):
                    continue
                next_w = rd32(self.data, off + 4)

                if not self.is_cbz_w0(next_w):
                    continue

                target = bl_target(off, w)
                if not self.has_macf_aggregator_shape(target):
                    continue

                cbz_off = off + 4

                cbz_w = rd32(self.data, cbz_off)
                imm19 = (cbz_w >> 5) & 0x7FFFF
                if imm19 & (1 << 18):
                    imm19 -= (1 << 19)
                cbz_target_off = cbz_off + imm19 * 4

                if not (func_start <= cbz_target_off <= func_end):
                    self.log(f"  [macf] @0x{off:X}: CBZ target 0x{cbz_target_off:X} "
                             f"вне функции")
                    continue
                if cbz_target_off <= cbz_off:
                    self.log(f"  [macf] @0x{off:X}: CBZ назад, пропускаем")
                    continue

                if not (cbz_off < adrp_off < cbz_target_off):
                    self.log(f"  [macf] @0x{off:X}: ADRP 0x{adrp_off:X} "
                             f"вне [0x{cbz_off:X}, 0x{cbz_target_off:X}]")
                    continue

                if cbz_target_off - cbz_off < 16:
                    continue

                delta = cbz_target_off - cbz_off
                if delta % 4 != 0:
                    continue
                imm26 = delta >> 2
                if imm26 < -(1 << 25) or imm26 >= (1 << 25):
                    continue
                b_insn = 0x14000000 | (imm26 & 0x3FFFFFF)

                self.emit(
                    cbz_off,
                    p32(b_insn),
                    f"macf: CBZ W0 -> B @0x{cbz_off:X} "
                    f"(BL@0x{off:X}->0x{target:X}, skip err to 0x{cbz_target_off:X})"
                )
                n += 1
                found = True
                break

            if not found:
                self.log(f"  [macf] в функции @0x{func_start:X} не найден "
                         f"подходящий BL+CBZ паттерн")

        if n == 0:
            self.log("  [macf] патч не применён")
        else:
            self.log(f"  [macf] применено патчей: {n}")
        return n

    # ═══════════════════════════════════════════════
    # Диагностика
    # ═══════════════════════════════════════════════

    def dump_function_disasm(self, func_off, max_scan=0x800):
        fe = self.find_func_end(func_off, max_fwd=max_scan)
        if fe is None:
            print(f"[dump] cannot find end of function @ 0x{func_off:X}")
            return
        va = self.foff_to_va(func_off)
        size = fe - func_off
        print(f"\n[dump] function @ foff=0x{func_off:X} VA=0x{va:X} "
              f"size={size} bytes ({size//4} insn)")
        chunk = self.data[func_off:fe]
        for i in range(0, len(chunk), 16):
            row = chunk[i:i+16]
            hexs = ' '.join(f'{int.from_bytes(row[j:j+4], "little"):08x}'
                            for j in range(0, len(row), 4))
            print(f"  +0x{i:03X}: {hexs}")

    # ═══════════════════════════════════════════════
    # find_all / patch_all
    # ═══════════════════════════════════════════════

    def find_all(self, with_apfs_mount=False, ssv_only=False):
        self.log(f"=== Kernel Patchfinder ({self.size/1024/1024:.1f} MB) ===")
        t0 = time.time()
        self.log("\n[1] Parsing Mach-O...")
        self.parse_macho()
        self.log("[2] Building ADRP index...")
        self.build_adrp_index()
        self.log("[3] Building BL index...")
        self.build_bl_index()
        self.log("[4] Finding _panic...")
        self.find_panic()
        self.log(f"    Index build: {time.time()-t0:.1f}s\n")
        results = {}

        if not ssv_only:
            self.log("[5] String-anchored targets:")
            for needle, label in [
                ("rootvp not authenticated", "bsd_init"),
                ("SecureRootName\x00", "SecureRootName"),
                ("/usr/lib/dyld\x00", "load_dylinker"),
                ("imageboot_needed", "imageboot"),
                ("debug-enabled\x00", "debug_enabled_init"),
                ("get-task-allow\x00", "get_task_allow"),
                ("developer-mode\x00", "developer_mode"),
                ("cs_enforcement_disable", "cs_enforcement"),
                ("apfs_vfsop_mount\x00", "apfs_vfsop_mount"),
                ("apfs_graft\x00", "apfs_graft"),
                ("proc_ro_ref_task\x00", "task_for_pid"),
                ("vm_map_protect(", "vm_map_protect_func"),
                ("nvram-proxy-data\x00", "nvram_verify"),
            ]:
                func = self.find_func_by_string(needle, label)
                if func is not None:
                    results[label] = func
            self.log("\n[6] Pattern-matched targets:")
            func = self.find_pe_debugger()
            if func:
                results['PE_i_can_has_debugger'] = func
            func = self.find_amfi_trustcache()
            if func:
                results['AMFIIsCDHashInTrustCache'] = func
            self.log("\n[7] Complex finders:")
            func = self.find_vm_fault_enter()
            if func:
                results['vm_fault_enter'] = func
            func = self.find_mac_policy_register()
            if func:
                results['mac_policy'] = func
        else:
            self.log("[5/6/7] skipped (--ssv-only mode)")

        if with_apfs_mount:
            self.log("\n[8] apfs_vfsop_mount (SSV bypass)...")
            func = self.find_apfs_vfsop_mount()
            if func:
                results['apfs_vfsop_mount'] = func

        if with_apfs_mount:
            self.log("\n[9] Display drivers (KEXT scan)...")
            driver_funcs = self.find_display_driver_functions()
            for k, v in driver_funcs.items():
                if v is not None:
                    results[f"display_{k}"] = v

            if not ssv_only:
                self.log("\n[10] KEXT panic-branch scan...")
                kext_hits = self.find_kext_panic_branches("kext-panic")
                results['_kext_panic_hits_count'] = len(kext_hits)
            else:
                self.log("\n[10] KEXT panic-branch scan... skipped")

            results['_display_funcs'] = driver_funcs

            self.log("\n[11] SEP/crypto functions...")
            crypto_funcs = self.find_sep_crypto_functions()
            results['_crypto_funcs'] = crypto_funcs

        if not ssv_only:
            fallbacks = [
                ("dounmount", ["MNT_ROOTFS", "vfs_iterate\x00", "coveredvp\x00"]),
                ("thid_should_crash", ["thid_should_crash"]),
                ("launch_constraints_func", ["amfi_check_launch_constraint",
                                             "AMFI: launch constraint",
                                             "constraint_category",
                                             "launch constraint violated",
                                             "com.apple.private.amfi.can-execute-cdhash"]),
                ("seal_broken", ["seal_is_broken"]),
            ]
            for label, needles in fallbacks:
                if label in results:
                    continue
                for needle in needles:
                    func = self.find_func_by_string(needle, f"{label}({needle[:20]})")
                    if func:
                        results[label] = func
                        break
            if 'dounmount' not in results:
                for target, callers in self.bl_index.items():
                    n = len(callers)
                    if not (5 <= n <= 20):
                        continue
                    fe = self.find_func_end(target)
                    if fe and 400 <= fe - target <= 1500:
                        results['dounmount'] = target
                        self.log(f"  dounmount (heuristic): func=0x{target:X} callers={n}")
                        break
            if self.panic_offset:
                results['_panic'] = self.panic_offset

        self.log(f"\n{'='*60}")
        self.log(f"  FOUND: {len(results)} targets")
        self.log(f"{'='*60}")
        for label, foff in sorted(results.items()):
            if label.startswith('_'):
                continue
            if foff is None:
                continue
            va = self.foff_to_va(foff)
            va_s = f"VA=0x{va:X}" if va else ""
            self.log(f"  {label:<35s} foff=0x{foff:08X}  {va_s}")
        return results

    def patch_all(self, results, with_apfs_mount=False, ssv_only=False,
                  crypto_bypass=False, macf_bypass=False,
                  cs_enforcement=False):
        n = 0

        # ── PE / AMFI / launch_constraints — только если не ssv-only ──
        if not ssv_only:
            if 'PE_i_can_has_debugger' in results:
                off = results['PE_i_can_has_debugger']
                self.emit(off, p32(MOV_W0_1_U32), "PE_i_can_has_debugger → MOV W0, #1")
                self.emit(off + 4, p32(RETAB_U32), "PE_i_can_has_debugger → RETAB")
                n += 2
            if 'AMFIIsCDHashInTrustCache' in results:
                off = results['AMFIIsCDHashInTrustCache']
                self.emit(off,      p32(MOV_X0_1_U32),  "AMFI trustcache → MOV X0, #1")
                self.emit(off + 4,  p32(CBZ_X2_8_U32),  "AMFI trustcache → CBZ X2, +8")
                self.emit(off + 8,  p32(STR_X0_X2_U32), "AMFI trustcache → STR X0, [X2]")
                self.emit(off + 12, p32(RET_U32),        "AMFI trustcache → RET")
                n += 4
            if 'launch_constraints_func' in results:
                off = results['launch_constraints_func']
                self.emit(off, p32(MOV_W0_0_U32), "launch_constraints → MOV W0, #0")
                self.emit(off + 4, p32(RETAB_U32), "launch_constraints → RETAB")
                n += 2

        # ── APFS snapshot-checks ──
        if with_apfs_mount and 'apfs_vfsop_mount' in results:
            off = results['apfs_vfsop_mount']
            n += self.patch_apfs_vfsop_mount(off)

        if with_apfs_mount:
            driver_funcs = results.get('_display_funcs', {}) or {}
            if driver_funcs:
                n += self.patch_display_driver_panics(driver_funcs)
            if not ssv_only:
                n += self.patch_kext_panic_branches()

        # ── v8.3: cs_enforcement_disable ──
        if cs_enforcement and not ssv_only:
            self.log("\n[cs] cs_enforcement_disable best-effort patch...")
            n += self.patch_cs_enforcement_disable()

        # ── v8.2: MACF bypass ──
        if macf_bypass:
            self.log("\n[macf] MACF bypass для IOUC (SEP/APFS userclient)...")
            n += self.patch_iouc_failed_macf()

        # ── v8.2: Crypto bypass ──
        if crypto_bypass:
            n += self.patch_crypto_bypass()

        for k in list(results.keys()):
            if k.startswith('_'):
                del results[k]
        self.log(f"\n  [{n} patches applied]")
        return n


def main():
    ap = argparse.ArgumentParser(description="arm64e kernelcache patchfinder")
    ap.add_argument("input", type=Path)
    ap.add_argument("--apply", type=Path, help="write patched output")
    ap.add_argument("--apfs-mount", action="store_true",
                    help="enable SSV bypass (patch apfs_vfsop_mount) — АГРЕССИВНО")
    ap.add_argument("--display-bypass", action="store_true",
                    help="NOP conditional branches to _panic in KEXT/display drivers")
    ap.add_argument("--crypto-bypass", action="store_true",
                    help="Точечный crypto bypass")
    ap.add_argument("--macf-bypass", action="store_true",
                    help="Обход MACF для IOUC (SEP/APFS userclient)")
    ap.add_argument("--cs-enforcement", action="store_true",
                    help="Best-effort патч cs_enforcement_disable global "
                         "(закрывает -e из Kernel64Patcher)")
    ap.add_argument("--ssv-only", action="store_true",
                    help="skip PE/AMFI/launch_constraints/cs_enforcement "
                         "(базовые патчи уже применены)")
    ap.add_argument("--dump-function", action="append", default=[],
                    metavar="SYMBOL",
                    help="Печатает hex-дизасм функции и выходит")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args()

    data = args.input.read_bytes()
    pf = KernelPatchfinder(data, verbose=not args.quiet)

    if args.dump_function:
        pf.parse_macho()
        pf.build_adrp_index()
        pf.find_panic()
        for needle in args.dump_function:
            f = pf.find_func_by_string(needle.encode() + b"\x00")
            if f is None:
                f = pf.find_func_by_string(needle)
            if f:
                pf.dump_function_disasm(f)
            else:
                print(f"[!] function '{needle}' not found")
        return

    with_bypass = (args.apfs_mount or args.display_bypass
                   or args.crypto_bypass or args.macf_bypass)

    results = pf.find_all(with_apfs_mount=with_bypass, ssv_only=args.ssv_only)

    if args.apply:
        pf.patch_all(results, with_apfs_mount=with_bypass,
                     ssv_only=args.ssv_only,
                     crypto_bypass=args.crypto_bypass,
                     macf_bypass=args.macf_bypass,
                     cs_enforcement=args.cs_enforcement)
        args.apply.write_bytes(bytes(pf.data))
        print(f"\nSaved to {args.apply}")


if __name__ == "__main__":
    main()