#!/usr/bin/env python3
"""Embed custom boot-args into an iBoot raw binary (iBEC / iBSS).

Ищет в бинарнике дефолтную строку "rd=md0" (или "rd=md") и заменяет её
на указанные boot-args. Работает in-place, если out не задан.

Использование:
    embed_bootargs.py <raw-iboot> <boot-args> [<output>]

Пример:
    embed_bootargs.py work/iBEC.raw "rd=md0 nand-enable-reformat=1 -v"
"""
from __future__ import annotations

import sys
from pathlib import Path

# Маркеры по убыванию специфичности.
DEFAULT_MARKERS = (b"rd=md0", b"rd=md")

def _find_printable_strings(data: bytes, marker: bytes):
    """Yield (offset, old_bytes) for every printable string starting with marker."""
    pos = 0
    while True:
        i = data.find(marker, pos)
        if i < 0:
            return
        end = i
        while end < len(data) and 0x20 <= data[end] < 0x7f:
            end += 1
        yield i, bytes(data[i:end])
        pos = i + 1

def embed(raw_path: Path, args: str, out_path: Path) -> int:
    data = bytearray(raw_path.read_bytes())
    new_bytes = args.encode("ascii")
    patched = 0

    for marker in DEFAULT_MARKERS:
        for off, old in _find_printable_strings(data, marker):
            avail = len(old)

            # Случай A: наше новое значение влезает вместо старого
            if len(new_bytes) <= avail:
                data[off:off + len(new_bytes)] = new_bytes
                for i in range(off + len(new_bytes), off + avail):
                    data[i] = 0x20  # pad spaces
                print(f"  embed @ 0x{off:x}: {old!r} -> {new_bytes!r} "
                      f"(fits in {avail} bytes)")
                patched += 1
                continue

            # Случай B: не влезает, но после строки идут нули — расширяемся
            end = off + avail
            zero_end = end
            while zero_end < len(data) and data[zero_end] == 0:
                zero_end += 1
            extended = zero_end - off

            if len(new_bytes) <= extended:
                data[off:off + len(new_bytes)] = new_bytes
                for i in range(off + len(new_bytes), zero_end):
                    data[i] = 0
                print(f"  embed @ 0x{off:x}: {old!r} -> {new_bytes!r} "
                      f"(extended to {extended} bytes)")
                patched += 1
                continue

            print(f"  skip  @ 0x{off:x}: {old!r} — needs {len(new_bytes)}, "
                  f"only {extended} available", file=sys.stderr)

        if patched:
            break  # не пытаемся короткий маркер, если уже пропатчили

    if patched == 0:
        raise SystemExit("no matching 'rd=md0' string with enough room found")

    out_path.write_bytes(bytes(data))
    print(f"  wrote {out_path} ({patched} patch(es))")
    return patched

def main() -> None:
    if len(sys.argv) not in (3, 4):
        print(__doc__, file=sys.stderr)
        sys.exit(64)
    raw = Path(sys.argv[1])
    args = sys.argv[2]
    out = Path(sys.argv[3]) if len(sys.argv) == 4 else raw
    if not raw.is_file():
        raise SystemExit(f"input not found: {raw}")
    embed(raw, args, out)

if __name__ == "__main__":
    main()