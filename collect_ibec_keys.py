#!/usr/bin/env python3
"""
collect_ibec_keys.py — Сборщик ключей iBEC + iBSS с theapplewiki.com

v1.7 (iBSS support):
  + NEW: сбор ключей iBSS (не только iBEC)
  + NEW: --component {ibec,ibss,both} — что собирать (default: both)
  + NEW: --ibss-only / --ibec-only — алиасы
  + NEW: в JSON сохраняются ключи:
      release / research          → iBEC (backward compat)
      iBSS_release / iBSS_research → iBSS
  + NEW: --build3-fallback-iBSS — печатает DECRYPT_KEYS_FALLBACK для iBSS
  + v1.6: rate-limit safe — retry/backoff, кэш, фильтр iOS

Использование:
    ./collect_ibec_keys.py --product iPhone12,1 --min-ios 14 --max-ios 15
    ./collect_ibec_keys.py --product iPhone12,1 --build 18E199
    ./collect_ibec_keys.py --product iPhone12,1 --ibss-only
    ./collect_ibec_keys.py --product iPhone12,1 --build3-fallback-iBSS
"""

import argparse
import hashlib
import json
import re
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

WIKI  = "https://theapplewiki.com"
UA    = ("collect_ibec_keys/1.7 (https://github.com/yourname/collect_ibec_keys) "
         "contact: example@example.com")


# ════════════════════════════════════════════════════════════════
# HTTP с retry/backoff
# ════════════════════════════════════════════════════════════════

def _http_json(url, timeout=60, max_retries=5, verbose=False):
    """GET → JSON с экспоненциальным backoff на 429/503."""
    delay = 2.0
    for attempt in range(max_retries):
        if verbose:
            short = url[:120] + ("…" if len(url) > 120 else "")
            print(f"    GET[{attempt+1}] {short}", file=sys.stderr)
        req = urllib.request.Request(url, headers={
            "User-Agent": UA,
            "Accept": "application/json",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "identity",
        })
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read()
            return json.loads(raw.decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            if e.code in (429, 503):
                if attempt < max_retries - 1:
                    if verbose:
                        print(f"    HTTP {e.code} — sleep {delay}s", file=sys.stderr)
                    time.sleep(delay)
                    delay = min(delay * 2, 60)
                    continue
                if verbose:
                    print(f"    HTTP {e.code} — сдаёмся после "
                          f"{max_retries} попыток", file=sys.stderr)
                return None
            if verbose:
                print(f"    HTTP {e.code}", file=sys.stderr)
            return None
        except Exception as e:
            if verbose:
                print(f"    ERR {type(e).__name__}: {e}", file=sys.stderr)
            return None
    return None


# ════════════════════════════════════════════════════════════════
# SMW URL builders
# ════════════════════════════════════════════════════════════════

def _ask_url_pages(product=None, version=None, build=None, limit=200, offset=0):
    parts = ["-5B-5B-3AKeys-3A-2B-5D-5D"]
    if product:
        parts.append(f"-5B-5BHas-20firmware-20device::{product}-5D-5D")
    if version:
        parts.append(f"-5B-5BHas-20firmware-20version::{version}-5D-5D")
    if build:
        parts.append(f"-5B-5BHas-20firmware-20build::{build}-5D-5D")
    parts += [
        "-3FHas-20firmware-20build=build",
        "-3FHas-20firmware-20device=device",
        "-3FHas-20firmware-20version=version",
        "-3FHas-20download-20URL=url",
        "mainlabel=name",
        f"limit={limit}",
        f"offset={offset}",
        "format=json",
        "type=simple",
    ]
    return f"{WIKI}/wiki/Special:Ask/" + "/".join(parts)


def _ask_url_subobjects(page_title, limit=200, offset=0):
    enc = page_title.replace(" ", "-20")
    parts = [
        f"-5B-5B-2DHas-20subobject::{enc}-5D-5D",
        "-3FHas-20filename=filename",
        "-3FHas-20key=key",
        "-3FHas-20key-20IV=iv",
        "mainlabel=filename",
        f"limit={limit}",
        f"offset={offset}",
        "format=json",
        "type=simple",
    ]
    return f"{WIKI}/wiki/Special:Ask/" + "/".join(parts)


# ════════════════════════════════════════════════════════════════
# Кэш
# ════════════════════════════════════════════════════════════════

class Cache:
    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.failed_file = self.root / "_failed.json"
        self.failed = self._load_failed()

    def _key(self, s):
        return hashlib.md5(s.encode()).hexdigest()[:16]

    def get(self, kind, key):
        f = self.root / f"{kind}_{self._key(key)}.json"
        if f.exists():
            try:
                return json.loads(f.read_text(encoding="utf-8"))
            except Exception:
                return None
        return None

    def set(self, kind, key, value):
        f = self.root / f"{kind}_{self._key(key)}.json"
        f.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")

    def _load_failed(self):
        if self.failed_file.exists():
            try:
                return set(json.loads(self.failed_file.read_text()))
            except Exception:
                pass
        return set()

    def mark_failed(self, key):
        self.failed.add(key)
        self.failed_file.write_text(json.dumps(sorted(self.failed)))

    def mark_ok(self, key):
        if key in self.failed:
            self.failed.discard(key)
            self.failed_file.write_text(json.dumps(sorted(self.failed)))


# ════════════════════════════════════════════════════════════════
# Запросы
# ════════════════════════════════════════════════════════════════

def ask_pages(cache, product, version=None, build=None, verbose=True):
    ck = f"pages|{product}|{version}|{build}"
    cached = cache.get("pages", ck)
    if cached:
        if verbose:
            print(f"  [i] страниц из кэша: {len(cached)}", file=sys.stderr)
        return cached

    pages = []
    offset = 0
    limit = 200
    for _ in range(50):
        url = _ask_url_pages(product=product, version=version, build=build,
                             limit=limit, offset=offset)
        data = _http_json(url, verbose=verbose)
        if not data:
            break
        batch = 0
        for key, fields in data.items():
            if "#_QUERY" in key:
                continue
            n = fields.get("name", [])
            if not n:
                continue
            pages.append({
                "page":    n[0],
                "build":   (fields.get("build")   or [""])[0],
                "version": (fields.get("version") or [""])[0],
                "device":  (fields.get("device")  or [""])[0],
                "url":     (fields.get("url")     or [""])[0],
            })
            batch += 1
        if batch < limit:
            break
        offset += limit
        time.sleep(2.0)

    cache.set("pages", ck, pages)
    if verbose:
        print(f"  [i] страниц всего: {len(pages)}", file=sys.stderr)
    return pages


def ask_subobjects(cache, page_title, verbose=True, delay=1.5,
                   dump_raw_holder=None):
    ck = page_title
    cached = cache.get("subs", ck)
    if cached is not None:
        return cached

    if delay > 0:
        time.sleep(delay)

    url = _ask_url_subobjects(page_title)
    data = _http_json(url, verbose=verbose)

    if data is None:
        cache.mark_failed(page_title)
        return []

    if dump_raw_holder is not None and dump_raw_holder.get("raw") is None:
        dump_raw_holder["raw"] = data

    out = []
    for key, fields in data.items():
        if "#_QUERY" in key:
            continue

        printouts = fields.get("printouts", fields)

        def _vals(name_list):
            out_vals = []
            for v in (name_list or []):
                if isinstance(v, dict):
                    out_vals.append(v.get("fulltext", ""))
                else:
                    out_vals.append(str(v))
            return out_vals

        fnames = _vals(printouts.get("filename")
                       or printouts.get("Has filename"))
        keys   = _vals(printouts.get("key")
                       or printouts.get("Has key"))
        ivs    = _vals(printouts.get("iv")
                       or printouts.get("Has key IV"))

        n = max(len(fnames), len(keys), len(ivs))
        for i in range(n):
            fn = fnames[i] if i < len(fnames) else ""
            k  = keys[i]   if i < len(keys)   else ""
            iv = ivs[i]    if i < len(ivs)    else ""
            if fn and k and iv:
                out.append({
                    "filename": fn.strip(),
                    "key":      k.strip(),
                    "iv":       iv.strip(),
                })

    cache.set("subs", ck, out)
    if out:
        cache.mark_ok(page_title)
    return out


# ════════════════════════════════════════════════════════════════
# Фильтры и агрегация
# ════════════════════════════════════════════════════════════════

def _parse_ios_version(v_str):
    m = re.search(r"(\d+\.\d+(?:\.\d+)?)", v_str or "")
    return m.group(1) if m else ""

def _ios_key(v):
    try:
        return tuple(int(x) for x in v.split("."))
    except Exception:
        return (0,)

def in_range(ver, min_v, max_v):
    if not ver:
        return False
    k = _ios_key(ver)
    if min_v:
        mn = _ios_key(min_v)
        if k < mn:
            return False
    if max_v:
        mx = _ios_key(max_v)
        if k > mx:
            return False
    return True


# ════════════════════════════════════════════════════════════════
# Классификация filename → компонент + release/research
# ════════════════════════════════════════════════════════════════

def classify_filename(fn):
    """
    Возвращает (component, kind) или (None, None):
      component: "iBEC" | "iBSS" | "iBoot" | ...
      kind:      "release" | "research"
    Пример: 'iBEC.n104.RESEARCH_RELEASE.im4p' → ('iBEC', 'research')
    """
    low = fn.lower()
    # компонент по префиксу
    comp = None
    if low.startswith("ibec."):
        comp = "iBEC"
    elif low.startswith("ibss."):
        comp = "iBSS"
    elif low.startswith("iboot."):
        comp = "iBoot"
    elif low.startswith("llb."):
        comp = "LLB"
    else:
        # пропускаем всё остальное (kernelcache, devicetree, sep, etc.)
        return None, None

    kind = "research" if "RESEARCH" in fn.upper() else "release"
    return comp, kind


def collect(product, version=None, build=None,
            min_ios=None, max_ios=None,
            cache_dir=".keys_cache", delay=1.5,
            retry_failed=False, verbose=True,
            dump_raw_holder=None,
            want_ibec=True, want_ibss=True):
    """
    Возвращает структуру:
    {
      "14.5": {
        "18E199": {
          "release": {...},           # iBEC release   (backward compat)
          "research": {...},          # iBEC research  (backward compat)
          "iBSS_release": {...},      # iBSS release
          "iBSS_research": {...},     # iBSS research
          "_meta": {...}
        }
      }
    }
    """
    cache = Cache(Path(cache_dir))

    pages = ask_pages(cache, product, version=version, build=build,
                      verbose=verbose)
    if not pages:
        return {}

    filtered = []
    for p in pages:
        ios = _parse_ios_version(p.get("version", ""))
        if min_ios or max_ios:
            if not in_range(ios, min_ios, max_ios):
                continue
        filtered.append((p, ios))
    if verbose and (min_ios or max_ios):
        print(f"  [i] после фильтра iOS {min_ios or '*'}..{max_ios or '*'}: "
              f"{len(filtered)}", file=sys.stderr)

    if retry_failed:
        only = cache.failed
        filtered = [(p, ios) for (p, ios) in filtered if p["page"] in only]
        if verbose:
            print(f"  [i] retry-failed: {len(filtered)} страниц",
                  file=sys.stderr)

    out = {}
    stats = {"iBEC": 0, "iBSS": 0, "skipped": 0}

    for p, ios in filtered:
        if verbose:
            print(f"  → {p['page']}", file=sys.stderr)
        subs = ask_subobjects(cache, p["page"], verbose=verbose,
                              delay=delay, dump_raw_holder=dump_raw_holder)
        if not subs:
            continue
        bld = p.get("build") or ""
        if not bld:
            continue

        for s in subs:
            fn = s["filename"]
            comp, kind = classify_filename(fn)
            if comp is None:
                stats["skipped"] += 1
                continue

            # Фильтр по желаемым компонентам
            if comp == "iBEC" and not want_ibec:
                continue
            if comp == "iBSS" and not want_ibss:
                continue
            if comp not in ("iBEC", "iBSS"):
                continue  # пока собираем только iBEC/iBSS

            slot = out.setdefault(ios or "unknown", {}).setdefault(bld, {})

            # Ключ в JSON
            if comp == "iBEC":
                # backward compat: "release" / "research"
                json_key = kind
            else:
                json_key = f"{comp}_{kind}"

            slot[json_key] = {
                "filename": fn,
                "iv":  s["iv"].lower(),
                "key": s["key"].lower(),
            }
            slot.setdefault("_meta", {
                "page": p["page"],
                "device": p.get("device", ""),
                "url": p.get("url", ""),
            })
            stats[comp] += 1

    if verbose:
        print(f"  [i] собрано: iBEC={stats['iBEC']}, iBSS={stats['iBSS']}, "
              f"пропущено (не ibec/ibss)={stats['skipped']}", file=sys.stderr)
    return out


# ════════════════════════════════════════════════════════════════
# Вывод
# ════════════════════════════════════════════════════════════════

def print_summary(data, product):
    if not data:
        print(f"\n[!] ничего не найдено для {product}")
        return
    total = sum(len(b) for b in data.values())
    print(f"\n=== iBEC + iBSS keys для {product} ===")
    print(f"iOS версий: {len(data)}, всего сборок: {total}\n")
    for ios in sorted(data, key=_ios_key):
        for build in sorted(data[ios]):
            d = data[ios][build]
            ibec_rel = d.get("release")
            ibec_res = d.get("research")
            ibss_rel = d.get("iBSS_release")
            ibss_res = d.get("iBSS_research")

            base = f"  iOS {ios:<8}  {build:<12}"
            print(base + "─" * 40)
            if ibec_rel:
                print(f"      iBEC REL  IV={ibec_rel['iv'][:12]}… Key={ibec_rel['key'][:12]}…")
            if ibec_res:
                print(f"      iBEC RES  IV={ibec_res['iv'][:12]}… Key={ibec_res['key'][:12]}…")
            if ibss_rel:
                print(f"      iBSS REL  IV={ibss_rel['iv'][:12]}… Key={ibss_rel['key'][:12]}…")
            if ibss_res:
                print(f"      iBSS RES  IV={ibss_res['iv'][:12]}… Key={ibss_res['key'][:12]}…")
            if not (ibec_rel or ibec_res or ibss_rel or ibss_res):
                print("      (пусто)")


def to_build3_fallback(data, product, component="iBEC"):
    """
    Возвращает строки для build3.sh:
      component="iBEC"  → DECRYPT_KEYS_FALLBACK["<prod>_<build>_iBEC"]...
      component="iBSS"  → DECRYPT_KEYS_FALLBACK["<prod>_<build>_iBSS"]...
    """
    lines = []
    for ios, builds in data.items():
        for build, d in builds.items():
            if component == "iBEC":
                rel = d.get("release")
                res = d.get("research")
                if rel:
                    lines.append(
                        f'DECRYPT_KEYS_FALLBACK["{product}_{build}_iBEC"]='
                        f'"{rel["iv"]}:{rel["key"]}"'
                    )
                if res:
                    lines.append(
                        f'DECRYPT_KEYS_FALLBACK["{product}_{build}_iBEC_research"]='
                        f'"{res["iv"]}:{res["key"]}"'
                    )
            elif component == "iBSS":
                rel = d.get("iBSS_release")
                res = d.get("iBSS_research")
                if rel:
                    lines.append(
                        f'DECRYPT_KEYS_FALLBACK["{product}_{build}_iBSS"]='
                        f'"{rel["iv"]}:{rel["key"]}"'
                    )
                if res:
                    lines.append(
                        f'DECRYPT_KEYS_FALLBACK["{product}_{build}_iBSS_research"]='
                        f'"{res["iv"]}:{res["key"]}"'
                    )
    return "\n".join(lines)


# ════════════════════════════════════════════════════════════════
# CLI
# ════════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(
        description="Сборщик iBEC + iBSS ключей с theapplewiki.com (rate-limit safe)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--product", required=True)
    ap.add_argument("--version", default=None, help="точная версия iOS")
    ap.add_argument("--build", default=None, help="точный build")
    ap.add_argument("--min-ios", default=None, help="мин. версия, напр. 14")
    ap.add_argument("--max-ios", default=None, help="макс. версия, напр. 15")
    ap.add_argument("--delay", type=float, default=1.5,
                    help="пауза между запросами subobjects (сек)")
    ap.add_argument("--cache-dir", default=".keys_cache")
    ap.add_argument("--retry-failed", action="store_true")
    ap.add_argument("--dump-raw", action="store_true",
                    help="напечатать первый сырой subobject-ответ")
    ap.add_argument("--output", "-o", default=None,
                    help="путь для JSON (по умолчанию ibec_keys_<product>.json)")
    ap.add_argument("--build3-fallback", action="store_true",
                    help="печатать DECRYPT_KEYS_FALLBACK для iBEC")
    ap.add_argument("--build3-fallback-iBSS", action="store_true",
                    help="печатать DECRYPT_KEYS_FALLBACK для iBSS")
    ap.add_argument("--build3-fallback-both", action="store_true",
                    help="печатать DECRYPT_KEYS_FALLBACK и для iBEC, и для iBSS")

    # Фильтр по компоненту
    grp = ap.add_mutually_exclusive_group()
    grp.add_argument("--component", choices=["ibec", "ibss", "both"],
                     default="both", help="что собирать (default: both)")
    grp.add_argument("--ibss-only", action="store_true",
                     help="алиас для --component ibss")
    grp.add_argument("--ibec-only", action="store_true",
                     help="алиас для --component ibec")

    ap.add_argument("-v", "--verbose-http", action="store_true")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args()

    # Разбираем component
    if args.ibss_only:
        want_ibec, want_ibss = False, True
        comp_label = "iBSS only"
    elif args.ibec_only:
        want_ibec, want_ibss = True, False
        comp_label = "iBEC only"
    elif args.component == "ibec":
        want_ibec, want_ibss = True, False
        comp_label = "iBEC only"
    elif args.component == "ibss":
        want_ibec, want_ibss = False, True
        comp_label = "iBSS only"
    else:
        want_ibec, want_ibss = True, True
        comp_label = "iBEC + iBSS"

    dump_raw = {}
    print(f"[*] Сбор ключей для {args.product} ({comp_label})…",
          file=sys.stderr)

    data = collect(
        args.product,
        version=args.version, build=args.build,
        min_ios=args.min_ios, max_ios=args.max_ios,
        cache_dir=args.cache_dir, delay=args.delay,
        retry_failed=args.retry_failed,
        verbose=not args.quiet,
        dump_raw_holder=dump_raw,
        want_ibec=want_ibec, want_ibss=want_ibss,
    )

    if args.dump_raw and dump_raw.get("raw"):
        print("\n=== RAW subobject response ===")
        print(json.dumps(dump_raw["raw"], indent=2, ensure_ascii=False)[:4000])
        print("=== /RAW ===\n")

    print_summary(data, args.product)

    out_path = args.output or \
        f"ibec_keys_{args.product.replace(',', '_')}.json"
    Path(out_path).write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"\n[i] сохранено: {out_path}")

    if args.build3_fallback or args.build3_fallback_both:
        print("\n# ── DECRYPT_KEYS_FALLBACK для iBEC (build3.sh) ──")
        print(to_build3_fallback(data, args.product, "iBEC"))

    if args.build3_fallback_iBSS or args.build3_fallback_both:
        print("\n# ── DECRYPT_KEYS_FALLBACK для iBSS (build3.sh) ──")
        print(to_build3_fallback(data, args.product, "iBSS"))


if __name__ == "__main__":
    main()