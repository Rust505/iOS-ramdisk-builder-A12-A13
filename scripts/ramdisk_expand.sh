#!/usr/bin/env bash
# Expand stock RestoreRamDisk and inject SSH payload.
# Method A: grow in place (truncate + apfs resizeContainer)
# Method B: mount stock, create new APFS raw image via srcfolder copy

nr_expand_inject_ramdisk() {
    local stock_dmg="$1"
    local ssh_tar="$2"
    local mount_pt="${3:-/tmp/NewRamdiskRD}"
    local gtar_bin="${4:-}"

    # ── Защита от неверных аргументов и авто-детект tar ──
    if [[ -z "$gtar_bin" || ! -x "$gtar_bin" ]]; then
        if [[ -n "$gtar_bin" && -d "$gtar_bin" ]]; then
            echo "ramdisk expand: ERROR: gtar_bin is a directory ('$gtar_bin'), not an executable!" >&2
            echo "ramdisk expand: Check argument order in build.sh call." >&2
            return 1
        fi
        if command -v gtar &>/dev/null; then
            gtar_bin="gtar"
        elif command -v tar &>/dev/null; then
            gtar_bin="tar"
            echo "ramdisk expand: gtar not found, falling back to system tar"
        else
            echo "ramdisk expand: ERROR: neither gtar nor tar found" >&2
            return 1
        fi
    fi

    [[ -s "$stock_dmg" ]] || { echo "ramdisk expand: missing $stock_dmg" >&2; return 1; }
    [[ -s "$ssh_tar" ]]   || { echo "ramdisk expand: missing $ssh_tar" >&2; return 1; }

    local stock_bytes headroom max_bytes target_bytes size_m
    stock_bytes="$(stat -f%z "$stock_dmg")"
    headroom=$((80 * 1024 * 1024))
    max_bytes=$((280 * 1024 * 1024))
    target_bytes=$((stock_bytes + headroom))

    (( target_bytes < 256 * 1024 * 1024 )) && target_bytes=$((256 * 1024 * 1024))
    (( target_bytes > max_bytes ))         && target_bytes=$max_bytes

    if (( target_bytes <= stock_bytes )); then
        target_bytes=$((stock_bytes + 32 * 1024 * 1024))
        if (( target_bytes > max_bytes )); then
            echo "ramdisk expand: stock ${stock_bytes} already near max ${max_bytes}" >&2
            target_bytes=$stock_bytes
        fi
    fi

    size_m=$(( (target_bytes + 1024 * 1024 - 1) / (1024 * 1024) ))
    echo "ramdisk expand: stock=${stock_bytes} bytes → target≈${size_m}m (using $gtar_bin)"

    _nr_force_detach_mp() {
        hdiutil detach -force "$1" >/dev/null 2>&1 || true
    }

    _nr_inject_at() {
        local mp="$1"
        echo "ramdisk expand: injecting SSH payload into $mp"
        if ! "$gtar_bin" -x --no-overwrite-dir -f "$ssh_tar" -C "$mp"; then
            echo "ramdisk expand: FAILED to extract ssh_tar with $gtar_bin" >&2
            return 1
        fi

        if [[ -f "$mp/usr/bin/mount_ich" ]]; then
            chmod 755 "$mp/usr/bin/mount_ich"
            echo "ramdisk expand: mount_ich installed from ssh.tar.gz"
        else
            echo "ramdisk expand: WARNING: usr/bin/mount_ich missing from ssh.tar.gz" >&2
        fi
        return 0
    }

    _nr_find_apfs() {
        awk '
            /EF57347C-0000-11AA-AA11-0030654/ { print $1; exit }
            /Apple_APFS/ { print $1; exit }
        '
    }

    # ── Method A: truncate + resizeContainer ──
    if (( target_bytes > stock_bytes )); then
        cp "$stock_dmg" "${stock_dmg}.bak"
        truncate -s "$target_bytes" "$stock_dmg"
    fi

    local attach_out apfs_disk
    if attach_out="$(hdiutil attach -nomount -owners off \
        -imagekey diskimage-class=CRawDiskImage "$stock_dmg" 2>/dev/null)"; then

        apfs_disk="$(_nr_find_apfs <<<"$attach_out")"

        if [[ -n "$apfs_disk" ]] && diskutil apfs resizeContainer "$apfs_disk" 0; then
            hdiutil detach -force "$apfs_disk" >/dev/null 2>&1 || true
            rm -f "${stock_dmg}.bak"
            echo "ramdisk expand: method A (resizeContainer) OK"

            _nr_force_detach_mp "$mount_pt"
            mkdir -p "$mount_pt"

            if hdiutil attach -mountpoint "$mount_pt" -owners off \
                -imagekey diskimage-class=CRawDiskImage "$stock_dmg"; then
                _nr_inject_at "$mount_pt"
                _nr_force_detach_mp "$mount_pt"
                return 0
            else
                echo "ramdisk expand: method A mount-after-resize failed" >&2
                _nr_force_detach_mp "$mount_pt"
            fi
        fi

        # cleanup failed A
        local d
        d="$(awk '/^\/dev\//{print $1; exit}' <<<"$attach_out")"
        [[ -n "$d" ]] && hdiutil detach -force "$d" >/dev/null 2>&1 || true
        echo "ramdisk expand: method A failed — trying method B"
    else
        echo "ramdisk expand: method A attach failed — trying method B"
    fi

    # restore backup before B
    [[ -f "${stock_dmg}.bak" ]] && mv -f "${stock_dmg}.bak" "$stock_dmg"

    # ── Method B: srcfolder copy into new raw APFS ──
    local stock_mp="/tmp/NewRamdiskStock$$"
    local out_base="/tmp/NewRamdiskOut$$"
    _nr_force_detach_mp "$stock_mp"
    rm -rf "$stock_mp"
    mkdir -p "$stock_mp"

    if ! hdiutil attach -mountpoint "$stock_mp" -owners off \
        -imagekey diskimage-class=CRawDiskImage "$stock_dmg" 2>/dev/null \
        && ! hdiutil attach -mountpoint "$stock_mp" -owners off "$stock_dmg" 2>/dev/null; then
        echo "ramdisk expand: cannot mount stock ramdisk" >&2
        rmdir "$stock_mp" 2>/dev/null || true
        return 1
    fi

    rm -f "${out_base}.dmg" "$out_base"
    if ! hdiutil create \
        -size "${size_m}m" \
        -imagekey diskimage-class=CRawDiskImage \
        -format UDRW \
        -fs APFS \
        -layout NONE \
        -srcfolder "$stock_mp" \
        -copyuid root \
        "$out_base"; then
        _nr_force_detach_mp "$stock_mp"
        rm -rf "$stock_mp"
        echo "ramdisk expand: method B hdiutil create failed" >&2
        return 1
    fi
    _nr_force_detach_mp "$stock_mp"
    rm -rf "$stock_mp"

    local created=""
    for cand in "${out_base}.dmg" "$out_base" "${out_base}.sparseimage"; do
        [[ -f "$cand" ]] && { created="$cand"; break; }
    done
    [[ -n "$created" ]] || { echo "ramdisk expand: method B produced no image" >&2; return 1; }

    local converted="/tmp/NewRamdiskConv$$"
    rm -f "${converted}.dmg" "$converted"
    if hdiutil convert "$created" -format UDRW -o "$converted" >/dev/null; then
        rm -f "$created"
        [[ -f "${converted}.dmg" ]] && mv -f "${converted}.dmg" "$stock_dmg" || mv -f "$converted" "$stock_dmg"
    else
        mv -f "$created" "$stock_dmg"
    fi

    echo "ramdisk expand: method B (srcfolder) OK (${size_m}m)"

    _nr_force_detach_mp "$mount_pt"
    mkdir -p "$mount_pt"

    if ! hdiutil attach -mountpoint "$mount_pt" -owners off \
        -imagekey diskimage-class=CRawDiskImage "$stock_dmg" 2>/dev/null \
        && ! hdiutil attach -mountpoint "$mount_pt" -owners off "$stock_dmg" 2>/dev/null; then
        echo "ramdisk expand: cannot mount expanded ramdisk for inject" >&2
        return 1
    fi

    _nr_inject_at "$mount_pt"
    _nr_force_detach_mp "$mount_pt"
    return 0
}