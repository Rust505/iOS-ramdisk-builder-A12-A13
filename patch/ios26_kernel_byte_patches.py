#!/usr/bin/env python3
"""iOS 26–only kernel byte patches (build-specific file offsets).

Format per entry: (file_offset, old_byte, new_byte).
old_byte may be None to force-write without checking (used for the
RETAB middle byte that was missing from the source list).

These offsets are NOT valid on iOS 17/18 kernels — use the string/ADR
kernel_patchfinder path for those.
"""

from __future__ import annotations

from pathlib import Path

# Signed 0xffffffxx values from the source list normalized to 0..255.
# Site @0x24b2981 was omitted in the source list; RETAB needs 0x03 there
# (… c0 03 5f d6). We force that byte when applying.
IOS26_BYTE_PATCHES: list[tuple[int, int | None, int]] = [
    # BL → B #+0x44 (skip check)
    (0x15359DC, 0x21, 0x11),
    (0x15359DD, 0x6F, 0x00),
    (0x15359DE, 0xEF, 0x00),
    (0x15359DF, 0x97, 0x14),
    # PACIBSP… → MOV W0,#0 ; RETAB
    (0x24B297C, 0x7F, 0x00),
    (0x24B297D, 0x23, 0x00),
    (0x24B297E, 0x03, 0x80),
    (0x24B297F, 0xD5, 0x52),
    (0x24B2980, 0xFF, 0xC0),
    (0x24B2981, None, 0x03),  # forced for RETAB
    (0x24B2982, 0x06, 0x5F),
    (0x24B2983, 0xD1, 0xD6),
    # small mid-insn poke
    (0x24B7DC1, 0x01, 0x00),
    (0x24B7DC2, 0x09, 0x00),
    # PACIBSP… → MOV W0,#0 ; RETAB
    (0x35789A0, 0x7F, 0x00),
    (0x35789A1, 0x23, 0x00),
    (0x35789A2, 0x03, 0x80),
    (0x35789A3, 0xD5, 0x52),
    (0x35789A4, 0xFF, 0xC0),
    (0x35789A5, 0x43, 0x03),
    (0x35789A6, 0x01, 0x5F),
    (0x35789A7, 0xD1, 0xD6),
]


def apply_ios26_byte_patches(data: bytearray, *, force: bool = False) -> int:
    """Apply IOS26_BYTE_PATCHES in-place. Returns number of bytes written.

    Raises SystemExit if an expected old_byte mismatches (unless force=True).
    """
    size = len(data)
    applied = 0
    mismatches: list[str] = []
    for off, old, new in IOS26_BYTE_PATCHES:
        if off < 0 or off >= size:
            mismatches.append(f"0x{off:X} out of range (kernel {size} bytes)")
            continue
        cur = data[off]
        if old is not None and cur != old:
            mismatches.append(
                f"0x{off:X}: expected old 0x{old:02X}, found 0x{cur:02X}"
            )
            if not force:
                continue
        data[off] = new & 0xFF
        applied += 1

    if mismatches and not force:
        preview = "; ".join(mismatches[:8])
        more = f" (+{len(mismatches) - 8} more)" if len(mismatches) > 8 else ""
        raise SystemExit(
            "iOS 26 byte patches do not match this kernelcache "
            f"(wrong build?). {preview}{more}. "
            "Re-run with matching iOS 26 kernel, or use --kpf-set ios18 "
            "finder path / --ios26-force to override."
        )
    if mismatches and force:
        print(f"warning: forced iOS 26 patches despite {len(mismatches)} mismatches")
    return applied


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("input", type=Path)
    ap.add_argument("-o", "--output", type=Path, required=True)
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()
    data = bytearray(args.input.read_bytes())
    n = apply_ios26_byte_patches(data, force=args.force)
    args.output.write_bytes(data)
    print(f"applied {n} iOS 26 byte patches → {args.output}")


if __name__ == "__main__":
    main()
