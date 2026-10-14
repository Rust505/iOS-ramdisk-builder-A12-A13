#!/usr/bin/env python3
"""Apply kernel patches for ICH A12/A13 ramdisk.

iOS 17/18/26: Leeksov kernel_patchfinder (debugger + AMFI) — proven path.
iOS 27:       finder + launch_constraints (TXM-era).

Legacy: --kpf-set ios26-bytes applies ios26_kernel_byte_patches.py (build-specific;
fails closed on mismatch — not used by build.sh auto).
"""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
KPF_PATH = ROOT / "kernel_patchfinder.py"

SETS = {
    "debugger": ("PE_i_can_has_debugger",),
    "amfi": ("AMFIIsCDHashInTrustCache",),
    "launch": ("launch_constraints_func",),
}

# Finder profiles (Leeksov pattern finder — same AMFI+debugger for 17/18/26).
PROFILES = {
    "ios17": ("debugger", "amfi"),
    "ios18": ("debugger", "amfi"),
    "ios26": ("debugger", "amfi"),
    "ios27": ("debugger", "amfi", "launch"),
    "amfi": ("amfi",),
    "amfi+debugger": ("debugger", "amfi"),
    "debugger+amfi": ("debugger", "amfi"),
}

ALL_KEYS = (
    "PE_i_can_has_debugger",
    "AMFIIsCDHashInTrustCache",
    "launch_constraints_func",
)

REQUIRED_ALWAYS = {"AMFIIsCDHashInTrustCache"}


def load_kpf():
    spec = importlib.util.spec_from_file_location("kernel_patchfinder", KPF_PATH)
    if spec is None or spec.loader is None:
        raise SystemExit(f"unable to load {KPF_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["kernel_patchfinder"] = module
    spec.loader.exec_module(module)
    return module


def parse_kpf_set(value: str) -> set[str]:
    value = value.strip().lower()
    if value in ("all", "*"):
        return set(ALL_KEYS)
    if value in PROFILES:
        keys: set[str] = set()
        for name in PROFILES[value]:
            keys.update(SETS[name])
        return keys
    keys = set()
    for part in value.replace(",", "+").split("+"):
        part = part.strip()
        if not part:
            continue
        if part in PROFILES:
            for name in PROFILES[part]:
                keys.update(SETS[name])
            continue
        if part not in SETS:
            raise SystemExit(
                f"unknown kpf set {part!r}; expected all|ios17|ios18|ios26|ios27|"
                + "|".join(SETS)
                + "|debugger+amfi|..."
            )
        keys.update(SETS[part])
    if not keys:
        raise SystemExit("empty --kpf-set")
    return keys


def apply_subset(pf, results: dict, wanted: set[str]) -> int:
    kpf = sys.modules["kernel_patchfinder"]
    n = 0
    if "PE_i_can_has_debugger" in wanted and "PE_i_can_has_debugger" in results:
        off = results["PE_i_can_has_debugger"]
        pf.emit(off, kpf.p32(kpf.MOV_W0_1_U32), "PE_i_can_has_debugger → MOV W0, #1")
        pf.emit(off + 4, kpf.p32(kpf.RETAB_U32), "PE_i_can_has_debugger → RETAB")
        n += 2
    if "AMFIIsCDHashInTrustCache" in wanted and "AMFIIsCDHashInTrustCache" in results:
        off = results["AMFIIsCDHashInTrustCache"]
        pf.emit(off, kpf.p32(kpf.MOV_X0_1_U32), "AMFI trustcache → MOV X0, #1")
        pf.emit(off + 4, kpf.p32(kpf.CBZ_X2_8_U32), "AMFI trustcache → CBZ X2, +8")
        pf.emit(off + 8, kpf.p32(kpf.STR_X0_X2_U32), "AMFI trustcache → STR X0, [X2]")
        pf.emit(off + 12, kpf.p32(kpf.RET_U32), "AMFI trustcache → RET")
        n += 4
    if "launch_constraints_func" in wanted and "launch_constraints_func" in results:
        off = results["launch_constraints_func"]
        pf.emit(off, kpf.p32(kpf.MOV_W0_0_U32), "launch_constraints → MOV W0, #0")
        pf.emit(off + 4, kpf.p32(kpf.RETAB_U32), "launch_constraints → RETAB")
        n += 2
    return n


def apply_ios18_finder(data: bytes, wanted: set[str], *, quiet: bool, allow_missing: bool) -> bytes:
    """Proven iOS 17/18 path: locate AMFI + debugger via patchfinder."""
    kpf = load_kpf()
    pf = kpf.KernelPatchfinder(data, verbose=not quiet)
    results = pf.find_all()

    missing = sorted(key for key in wanted if key not in results)
    hard_missing = [k for k in missing if k in REQUIRED_ALWAYS or not allow_missing]
    soft_missing = [k for k in missing if k not in hard_missing]
    if hard_missing:
        raise SystemExit(f"kernel patchfinder did not locate: {', '.join(hard_missing)}")
    if soft_missing:
        print(f"note: skipping missing optional targets: {', '.join(soft_missing)}")
        wanted = set(wanted) - set(soft_missing)

    if "AMFIIsCDHashInTrustCache" not in results:
        raise SystemExit("AMFIIsCDHashInTrustCache not found — cannot patch for SSH")
    wanted = set(wanted)
    wanted.add("AMFIIsCDHashInTrustCache")

    count = apply_subset(pf, results, wanted)
    print(f"applied {count} instructions (iOS 17/18 finder) for {{{', '.join(sorted(wanted))}}}")
    return bytes(pf.data)


def apply_ios26_bytes(data: bytes, *, force: bool) -> bytes:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from ios26_kernel_byte_patches import apply_ios26_byte_patches

    buf = bytearray(data)
    n = apply_ios26_byte_patches(buf, force=force)
    print(f"applied {n} bytes (iOS 26 fixed offset table)")
    return bytes(buf)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="stock kernelcache.raw")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--kpf-set",
        default="ios18",
        help="ios17|ios18|ios26|ios27|all|debugger+amfi|...",
    )
    parser.add_argument(
        "--allow-missing",
        action="store_true",
        help="skip optional finder targets not found (AMFI still required)",
    )
    parser.add_argument(
        "--ios26-force",
        action="store_true",
        help="apply iOS 26 byte table even if old bytes mismatch",
    )
    parser.add_argument("-q", "--quiet", action="store_true")
    args = parser.parse_args()

    raw = args.input.read_bytes()
    kpf_set = args.kpf_set.strip().lower()

    if kpf_set in ("ios26-bytes", "26-bytes", "ios26_bytes"):
        print("kernel path: legacy iOS 26 byte patches (build-specific)")
        out = apply_ios26_bytes(raw, force=args.ios26_force)
    else:
        # ios17 / ios18 / ios26 / debugger+amfi / ios27 / explicit sets → finder
        if kpf_set in ("ios17", "ios18", "ios26", "26", "debugger+amfi", "amfi+debugger") or kpf_set.startswith(
            "ios18"
        ):
            print("kernel path: Leeksov patchfinder (AMFI + debugger)")
        wanted = parse_kpf_set("ios18" if kpf_set in ("26",) else kpf_set)
        out = apply_ios18_finder(
            raw, wanted, quiet=args.quiet, allow_missing=args.allow_missing
        )

    args.output.write_bytes(out)
    print(f"wrote {args.output}")


if __name__ == "__main__":
    main()
