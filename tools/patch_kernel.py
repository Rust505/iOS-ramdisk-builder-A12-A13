#!/usr/bin/env python3
"""
Improved kernel patcher for iOS 17.6.1 A13.
Combines kernel_patchfinder.py with additional verified patches.
"""

import subprocess
import sys
import re
import os
import struct
from pathlib import Path

def run_kpf(kernel_path, output_path):
    """Run kernel_patchfinder.py and return its stdout."""
    kpf_script = Path(__file__).parent / "kernel_patchfinder.py"
    if not kpf_script.exists():
        print("[!] kernel_patchfinder.py not found in tools/", file=sys.stderr)
        sys.exit(1)
    cmd = [sys.executable, str(kpf_script), str(kernel_path), "--apply", str(output_path)]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print("[!] kernel_patchfinder.py failed:", result.stderr, file=sys.stderr)
        sys.exit(1)
    return result.stdout

def parse_offsets(log_text):
    offsets = {}
    for line in log_text.splitlines():
        m = re.search(r'\s{2}([a-zA-Z_]+)\s+foff=(0x[0-9A-Fa-f]+)', line)
        if m:
            name = m.group(1)
            foff = int(m.group(2), 16)
            offsets[name] = foff
    return offsets

def patch_at_offset(data, offset, patch_bytes):
    if offset + len(patch_bytes) > len(data):
        print(f"[!] Offset 0x{offset:X} out of range", file=sys.stderr)
        return False
    data[offset:offset+len(patch_bytes)] = patch_bytes
    return True

def apply_extra_patches(data, offsets):
    patches_applied = 0

    # apfs_mount: MOV X0, #1; RET
    if 'apfs_mount' in offsets:
        off = offsets['apfs_mount']
        patch_at_offset(data, off, b'\x20\x00\x80\xD2\xC0\x03\x5F\xD6')
        print(f"  [+] apfs_mount: patched at 0x{off:X} (MOV X0, #1; RET)")
        patches_applied += 1

    # apfs_graft: MOV X0, #1; RET
    if 'apfs_graft' in offsets:
        off = offsets['apfs_graft']
        patch_at_offset(data, off, b'\x20\x00\x80\xD2\xC0\x03\x5F\xD6')
        print(f"  [+] apfs_graft: patched at 0x{off:X} (MOV X0, #1; RET)")
        patches_applied += 1

    # dounmount: MOV X0, #0; RET
    if 'dounmount' in offsets:
        off = offsets['dounmount']
        patch_at_offset(data, off, b'\x00\x00\x80\xD2\xC0\x03\x5F\xD6')
        print(f"  [+] dounmount: patched at 0x{off:X}")
        patches_applied += 1

    # vm_fault_enter: MOV X0, #0; RET
    if 'vm_fault_enter' in offsets:
        off = offsets['vm_fault_enter']
        patch_at_offset(data, off, b'\x00\x00\x80\xD2\xC0\x03\x5F\xD6')
        print(f"  [+] vm_fault_enter: patched at 0x{off:X}")
        patches_applied += 1

    # vm_map_protect_func: MOV X0, #0; RET
    if 'vm_map_protect_func' in offsets:
        off = offsets['vm_map_protect_func']
        patch_at_offset(data, off, b'\x00\x00\x80\xD2\xC0\x03\x5F\xD6')
        print(f"  [+] vm_map_protect_func: patched at 0x{off:X}")
        patches_applied += 1

    # task_for_pid: MOV X0, #0; RET
    if 'task_for_pid' in offsets:
        off = offsets['task_for_pid']
        patch_at_offset(data, off, b'\x00\x00\x80\xD2\xC0\x03\x5F\xD6')
        print(f"  [+] task_for_pid: patched at 0x{off:X}")
        patches_applied += 1

    return patches_applied

def main():
    if len(sys.argv) < 3:
        print("Usage: patch_kernel.py <kernel.raw> <output.raw>", file=sys.stderr)
        sys.exit(1)

    kernel_path = Path(sys.argv[1])
    out_path = Path(sys.argv[2])

    if not kernel_path.exists():
        print(f"[!] Input file not found: {kernel_path}", file=sys.stderr)
        sys.exit(1)

    print("[*] Running kernel_patchfinder.py...")
    log = run_kpf(kernel_path, out_path)

    print("[*] Parsing offsets...")
    offsets = parse_offsets(log)
    if not offsets:
        print("[!] No offsets found.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Found {len(offsets)} offsets.")

    with open(out_path, 'rb') as f:
        data = bytearray(f.read())

    print("[*] Applying extra patches...")
    applied = apply_extra_patches(data, offsets)
    print(f"[*] Applied {applied} extra patches.")

    with open(out_path, 'wb') as f:
        f.write(data)

    print(f"[+] Patched kernel written to {out_path}")

if __name__ == "__main__":
    main()