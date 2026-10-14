#!/usr/bin/env python3
"""Finalize Leeksov-patched iBEC: rd=md0 boot-args + board-safe IMG4 wrappers."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

# Verified n841 / iBoot-11881 remote-boot wrapper (XR 18.7.9).
N841_FALSE_POSITIVE_OFFSET = 0xE10
N841_FALSE_POSITIVE_LENGTH = 8
N841_IMAGE4_CANARY_BRANCH = 0x2C194
N841_IMAGE4_CALLBACK_RESULT = 0x2C198
N841_UPDATE_DEVICE_TREE_TRAMPOLINE = 0x2C8DC

# Early false-positive epilogues the Leeksov heuristic hits first.
# 18.1 d321: 0x10CC; 18.6+ d321: 0xE10 (same shape as n841).
D321_EARLY_FALSE_POSITIVES = (0xE10, 0x10CC)

NOP = bytes.fromhex("1f2003d5")
MOV_X0_ZERO = bytes.fromhex("000080d2")

# Leeksov iboot_patchfinder writes this slot (29 bytes incl. NUL).
# Finalize replaces it with rd=md0 *without* trailing "%s" — the Jul 23
# working XS iBoot had no %s; baking "%s" left a literal format token and
# broke NAND bring-up (disk0 not configured / mount failures).
LEEKSOV_BOOT_ARGS = b"serial=3 -v debug=0x2014e %s\x00"
RAMDISK_BOOT_ARGS = b"rd=md0 -v debug=0x2014e\x00\x00\x00\x00\x00\x00"


def _u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def _collect_canary_sites(data: bytes) -> list[int]:
    """Same B.NE + MOV + CMP + MOVN heuristic as iboot_patchfinder."""
    sites: list[int] = []
    limit = min(len(data) - 8, 0x200000)
    for off in range(0, limit, 4):
        w = _u32(data, off)
        if (w & 0xFF00001F) != 0x54000001:  # B.NE
            continue
        nxt = _u32(data, off + 4)
        if (nxt & 0xFFE0FFE0) != 0xAA0003E0:  # MOV X0, Xn
            continue
        src_reg = (nxt >> 16) & 0x1F
        has_cmp = any(
            (_u32(data, off - k * 4) & 0xFFE0FC1F) == 0xEB00001F
            or (_u32(data, off - k * 4) & 0x7F20001F) == 0x6B00001F
            for k in range(1, 9)
            if off - k * 4 >= 0
        )
        if not has_cmp:
            continue
        has_movn = False
        for k in range(1, 65):
            if off - k * 4 < 0:
                break
            prev = _u32(data, off - k * 4)
            if (prev & 0xFFE0001F) == (0x12800000 | src_reg):
                has_movn = True
                break
        if has_movn:
            sites.append(off)
    return sites


def _asn1_anchors(data: bytes, base: int = 0x870000000) -> list[int]:
    asn1 = data.find(b"Unknown ASN1 type")
    if asn1 < 0:
        return []
    anchors: list[int] = []
    # ADR
    for off in range(0, min(len(data) - 4, 0x200000), 4):
        w = _u32(data, off)
        if (w & 0x9F000000) != 0x10000000:
            continue
        immhi = (w >> 5) & 0x7FFFF
        immlo = (w >> 29) & 0x3
        imm = (immhi << 2) | immlo
        if imm & (1 << 20):
            imm -= 1 << 21
        if (base + off) + imm == base + asn1:
            anchors.append(off)
    # ADRP + ADD
    asn1_page = (base + asn1) & ~0xFFF
    page_off = (base + asn1) & 0xFFF
    for off in range(0, min(len(data) - 8, 0x200000), 4):
        w = _u32(data, off)
        if (w & 0x9F000000) != 0x90000000:
            continue
        immhi = (w >> 5) & 0x7FFFF
        immlo = (w >> 29) & 0x3
        imm = (immhi << 2) | immlo
        if imm & (1 << 20):
            imm -= 1 << 21
        page = ((base + off) & ~0xFFF) + (imm << 12)
        if page != asn1_page:
            continue
        rd = w & 0x1F
        for d in range(4, 20, 4):
            add_off = off + d
            aw = _u32(data, add_off)
            if (aw & 0xFF800000) != 0x91000000:
                continue
            if ((aw >> 5) & 0x1F) != rd:
                continue
            if ((aw >> 10) & 0xFFF) == page_off:
                anchors.append(off)
                break
    return anchors or [asn1]


def find_d321_image4_canary(stock: bytes) -> int:
    sites = _collect_canary_sites(stock)
    if not sites:
        raise SystemExit("d321: no image4 canary heuristic sites")
    anchors = _asn1_anchors(stock)
    best = sites[0]
    best_dist = 10**9
    for off in sites:
        for a in anchors:
            dist = abs(off - a)
            if dist < best_dist:
                best_dist = dist
                best = off
    if best_dist >= 0x1000:
        raise SystemExit(
            f"d321: no ASN1-near image4 canary (best 0x{best:X} dist 0x{best_dist:X})"
        )
    return best


def apply_boot_args(data: bytearray) -> None:
    if data.count(RAMDISK_BOOT_ARGS) == 1:
        print("boot-args already set to ramdisk form")
        return
    # Try Leeksov format (with %s placeholder) first
    if data.count(LEEKSOV_BOOT_ARGS) == 1:
        idx = data.index(LEEKSOV_BOOT_ARGS)
        data[idx : idx + len(LEEKSOV_BOOT_ARGS)] = RAMDISK_BOOT_ARGS
        print(f"boot-args → rd=md0 @ 0x{idx:X}")
        return
    # Try patchfinder v16 format (rd=md0 already embedded)
    for needle in [b"serial=3 -v debug=0x2014e rd=md0\x00",
                   b"rd=md0 -v debug=0x2014e\x00"]:
        if data.count(needle) == 1:
            print(f"boot-args already correct (found '{needle.decode().strip(chr(0))}')")
            return
    # Fallback: search for any boot-args-like string
    for off in range(0, len(data) - 32, 4):
        chunk = data[off:off+32]
        if b"rd=md0" in chunk and b"debug" in chunk:
            print(f"boot-args found at 0x{off:X} (already has rd=md0)")
            return
    raise SystemExit(
        "no boot-args slot found; expected one of: "
        f"{LEEKSOV_BOOT_ARGS!r} or 'serial=3 -v debug=0x2014e rd=md0'"
    )


def apply_n841_wrapper(stock: bytes, patched: bytearray) -> None:
    if len(stock) != len(patched):
        raise SystemExit("stock and patched iBoot sizes differ")
    patched[
        N841_FALSE_POSITIVE_OFFSET : N841_FALSE_POSITIVE_OFFSET
        + N841_FALSE_POSITIVE_LENGTH
    ] = stock[
        N841_FALSE_POSITIVE_OFFSET : N841_FALSE_POSITIVE_OFFSET
        + N841_FALSE_POSITIVE_LENGTH
    ]
    patched[N841_IMAGE4_CANARY_BRANCH : N841_IMAGE4_CANARY_BRANCH + 4] = NOP
    patched[N841_IMAGE4_CALLBACK_RESULT : N841_IMAGE4_CALLBACK_RESULT + 4] = MOV_X0_ZERO
    patched[
        N841_UPDATE_DEVICE_TREE_TRAMPOLINE : N841_UPDATE_DEVICE_TREE_TRAMPOLINE + 4
    ] = stock[
        N841_UPDATE_DEVICE_TREE_TRAMPOLINE : N841_UPDATE_DEVICE_TREE_TRAMPOLINE + 4
    ]
    print("applied n841ap safe IMG4 / UpdateDeviceTree wrapper")


def apply_d321_wrapper(stock: bytes, patched: bytearray) -> None:
    if len(stock) != len(patched):
        raise SystemExit("stock and patched iBoot sizes differ")
    # Undo early false-positive epilogues (build-dependent: 0xE10 and/or 0x10CC).
    for fp in D321_EARLY_FALSE_POSITIVES:
        if fp + 8 <= len(stock):
            patched[fp : fp + 8] = stock[fp : fp + 8]
    site = find_d321_image4_canary(stock)
    patched[site : site + 4] = NOP
    patched[site + 4 : site + 8] = MOV_X0_ZERO
    print(
        "applied d321ap safe IMG4 wrapper "
        f"(real canary @ 0x{site:X}, restored early FPs {[hex(x) for x in D321_EARLY_FALSE_POSITIVES]})"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stock", required=True, type=Path)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--board", required=True, help="DeviceClass / boardconfig")
    args = parser.parse_args()

    stock = args.stock.read_bytes()
    patched = bytearray(args.input.read_bytes())
    apply_boot_args(patched)
    if args.board == "n841ap":
        apply_n841_wrapper(stock, patched)
    elif args.board == "d321ap":
        apply_d321_wrapper(stock, patched)
    else:
        print(
            f"board {args.board}: no board-specific IMG4 wrapper "
            "(relying on ASN1-near image4 site from patchfinder)"
        )
    args.output.write_bytes(patched)
    print(f"wrote {args.output}")


if __name__ == "__main__":
    main()
