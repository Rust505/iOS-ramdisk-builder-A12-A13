#!/usr/bin/env python3
"""Live iBoot version from a connected DFU/Recovery device (pymobiledevice3).

  python3 scripts/check_iboot_version.py

Needs: pip install pymobiledevice3
"""

from __future__ import annotations

import sys


def _clean(raw) -> str | None:
    if raw is None:
        return None
    if isinstance(raw, (bytes, bytearray)):
        text = bytes(raw).split(b"\x00", 1)[0].decode("utf-8", "replace").strip()
    else:
        text = str(raw).strip()
    if not text or text.lower() in {"n/a", "na", "(null)", "null"}:
        return None
    return text


def main() -> int:
    try:
        from pymobiledevice3.exceptions import IRecvNoDeviceConnectedError
        from pymobiledevice3.irecv import IRecv
    except ImportError:
        print("install: python3 -m pip install --user pymobiledevice3", file=sys.stderr)
        return 1

    try:
        irecv = IRecv()
    except IRecvNoDeviceConnectedError:
        print("no device in DFU or Recovery", file=sys.stderr)
        return 1

    info = dict(irecv._device_info)
    srtg = _clean(info.get("SRTG"))
    build_version = None
    build_style = None
    if irecv.mode.is_recovery:
        build_version = _clean(irecv.getenv("build-version"))
        build_style = _clean(irecv.getenv("build-style"))

    # Recovery: getenv is the running iBEC. DFU: SRTG is usually SecureROM.
    version = build_version or srtg

    print(f"mode:           {irecv.mode.name}")
    print(f"product:        {irecv.product_type}")
    print(f"model:          {irecv.hardware_model}")
    print(f"cpid:           0x{irecv.chip_id:04x}")
    print(f"ecid:           0x{irecv.ecid:016x}")
    print(f"srtg (usb):     {srtg or 'N/A'}")
    if irecv.mode.is_recovery:
        print(f"build-version:  {build_version or '(empty)'}")
        print(f"build-style:    {build_style or '(empty)'}")
    print(f"iboot:          {version or 'N/A'}")

    if not version:
        print("device exported no iBoot tag (SRTG + getenv empty)", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
