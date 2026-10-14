#!/usr/bin/env python3
"""
parse_applewiki_keys.py — извлекает IV/Key для компонентов iBoot из HTML-страниц
TheAppleWiki (Keys:*).

Использует стабильные HTML-ID шаблона {{Keys}}:
  - <span class="keypage-filename" id="keypage-<component>">filename</span>
  - <code id="keypage-<component>-iv">IV</code>
  - <code id="keypage-<component>-key">KEY</code>

Компоненты:
  iBEC, iBoot, iBSS, LLB, SEP-Firmware
  + RESEARCH-варианты: iBEC (Research), iBoot (Research) и т.д.

Использование:
    # Скачать и вывести пару IV:KEY для iBEC (RELEASE):
    ./parse_applewiki_keys.py \
        --url 'https://theapplewiki.com/wiki/Keys:DawnF_21F79_(iPhone12,1)' \
        --component iBEC --quiet

    # Из stdin:
    curl -sL 'https://theapplewiki.com/wiki/Keys:DawnF_21F79_(iPhone12,1)' \
        | ./parse_applewiki_keys.py --component iBEC --quiet

    # Все компоненты страницы:
    ./parse_applewiki_keys.py --url '...' --all

    # Только RESEARCH:
    ./parse_applewiki_keys.py --url '...' --component iBEC --variant RESEARCH --quiet

    # Проверка board (n104, d431, d79):
    ./parse_applewiki_keys.py --url '...' --component iBEC --board n104 --quiet

Exit codes:
    0  успех
    1  ошибка загрузки/чтения
    2  компонент не найден или неполный
    3  board mismatch
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
      "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15")


def normalize_component(name: str) -> str:
    """iBEC → ibec; SEP-Firmware → sepfirmware; iBEC (Research) → ibecresearch."""
    return re.sub(r'[^a-z0-9]', '', name.lower())


def page_id_for(component: str, variant: str) -> str:
    """
    Возвращает HTML-ID блока keypage-*.

    component: 'iBEC' / 'iBSS' / 'iBoot' / 'LLB' / 'SEP-Firmware'
    variant:   'RELEASE' / 'RESEARCH'
    """
    base = normalize_component(component)
    if variant.upper() == 'RESEARCH':
        # если суффикс research уже в component — не дублируем
        if not base.endswith('research'):
            base += 'research'
    return f'keypage-{base}'


def fetch_html(url: str) -> str:
    """Скачать HTML страницы через curl (тот же TLS-стек, что использует build4.sh)."""
    try:
        r = subprocess.run(
            ['curl', '-sL', '--max-time', '30',
             '-H', f'User-Agent: {UA}',
             '--compressed', url],
            capture_output=True, text=True, check=True,
        )
        return r.stdout
    except subprocess.CalledProcessError as e:
        print(f"[!] curl failed: {e}", file=sys.stderr)
        return ''
    except FileNotFoundError:
        print("[!] curl не найден в PATH", file=sys.stderr)
        return ''


def extract_key(html: str, component: str, variant: str):
    """
    Возвращает (filename, iv, key) для указанного компонента/варианта.

    Любой из элементов может быть None:
        (None, None, None)       — блок не найден
        (filename, None, None)   — найден filename, но нет IV/Key
    """
    page_id = page_id_for(component, variant)

    fn_re = re.compile(
        rf'<span\s+class="keypage-filename"\s+id="{re.escape(page_id)}">([^<]+)</span>'
    )
    fn_m = fn_re.search(html)
    if not fn_m:
        return None, None, None
    filename = fn_m.group(1).strip()

    iv_re = re.compile(
        rf'<code\s+id="{re.escape(page_id)}-iv">([0-9a-fA-F]+)</code>'
    )
    iv_m = iv_re.search(html)
    iv = iv_m.group(1).lower() if iv_m else None

    key_re = re.compile(
        rf'<code\s+id="{re.escape(page_id)}-key">([0-9a-fA-F]+)</code>'
    )
    key_m = key_re.search(html)
    key = key_m.group(1).lower() if key_m else None

    return filename, iv, key


def extract_all(html: str):
    """
    Возвращает словарь {page_id: {filename, iv, key}} для всех блоков на странице.
    Пропускает блоки без IV или Key.
    """
    results = {}
    fn_re = re.compile(
        r'<span\s+class="keypage-filename"\s+id="(keypage-[a-z0-9]+)">([^<]+)</span>'
    )
    for m in fn_re.finditer(html):
        page_id, filename = m.group(1), m.group(2).strip()
        iv_re = re.compile(rf'<code\s+id="{re.escape(page_id)}-iv">([0-9a-fA-F]+)</code>')
        key_re = re.compile(rf'<code\s+id="{re.escape(page_id)}-key">([0-9a-fA-F]+)</code>')
        iv_m = iv_re.search(html)
        key_m = key_re.search(html)
        if not iv_m or not key_m:
            continue
        results[page_id] = {
            'filename': filename,
            'iv': iv_m.group(1).lower(),
            'key': key_m.group(1).lower(),
        }
    return results


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    src = ap.add_mutually_exclusive_group()
    src.add_argument('--url', help='URL страницы Keys:*')
    src.add_argument('--file', help='Читать HTML из файла')

    ap.add_argument('--component', help='iBEC | iBoot | iBSS | LLB | SEP-Firmware')
    ap.add_argument('--variant', default='RELEASE',
                    choices=['RELEASE', 'RESEARCH', 'release', 'research'])
    ap.add_argument('--board', help='Проверить, что filename содержит board (n104, d431, d79)')
    ap.add_argument('--all', action='store_true',
                    help='Извлечь все компоненты со страницы')
    ap.add_argument('--list', action='store_true',
                    help='Только перечислить найденные page_id (используется с --all)')
    ap.add_argument('-q', '--quiet', action='store_true',
                    help='Только "iv:key" (для shell)')

    args = ap.parse_args()

    # ── источник HTML ─────────────────────────────────────────────
    if args.file:
        try:
            html = Path(args.file).read_text(errors='replace')
        except Exception as e:
            print(f"[!] не удалось прочитать файл: {e}", file=sys.stderr)
            sys.exit(1)
    elif args.url:
        html = fetch_html(args.url)
        if not html:
            sys.exit(1)
    elif not sys.stdin.isatty():
        html = sys.stdin.read()
    else:
        ap.print_help()
        sys.exit(1)

    if not html:
        print("[!] пустой HTML", file=sys.stderr)
        sys.exit(1)

    # ── режим --all ──────────────────────────────────────────────
    if args.all:
        results = extract_all(html)
        if not results:
            print("[!] на странице не найдено блоков keypage-*", file=sys.stderr)
            sys.exit(2)
        if args.list:
            for page_id in results:
                print(page_id)
        else:
            for page_id, data in results.items():
                print(f"{data['filename']}\t{data['iv']}:{data['key']}")
        return

    # ── обычный режим ────────────────────────────────────────────
    if not args.component:
        ap.error("--component или --all обязателен")

    variant = args.variant.upper()
    filename, iv, key = extract_key(html, args.component, variant)

    if not filename:
        if not args.quiet:
            print(f"[!] {args.component} ({variant}) не найден на странице", file=sys.stderr)
        sys.exit(2)

    if iv is None or key is None:
        if not args.quiet:
            print(f"[!] неполный блок: filename={filename} iv={iv} key={key}",
                  file=sys.stderr)
        sys.exit(2)

    if args.board and args.board.lower() not in filename.lower():
        if not args.quiet:
            print(f"[!] board mismatch: '{args.board}' не встречается в '{filename}'",
                  file=sys.stderr)
        sys.exit(3)

    if args.quiet:
        print(f"{iv}:{key}")
    else:
        print(f"{filename}\t{iv}:{key}")


if __name__ == '__main__':
    main()