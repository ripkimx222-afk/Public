#!/usr/bin/env python3
# Собирает несколько подписок igareck/vpn-configs-for-russia в один файл.
# Перед каждым списком вставляется пустой сервер-разделитель с названием.

import base64
import re
import sys
import time
import urllib.request
from urllib.parse import quote

BASE = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/"
OUT = "all_subs.txt"

# (название разделителя, файл в репозитории)
# Ненужный список можно удалить или закомментировать.
# Порядок важен: повторы убираются, остаются в первом списке,
# поэтому короткие списки стоят перед полными.
SOURCES = [
    ("Черные списки ТОП-150👇", "BLACK_VLESS_RUS_mobile.txt"),
    ("Черные списки VLESS👇", "BLACK_VLESS_RUS.txt"),
    ("Черные списки SS+ALL👇", "BLACK_SS+All_RUS.txt"),
    ("Белые списки CIDR ТОП-150 №1👇", "Vless-Reality-White-Lists-Rus-Mobile.txt"),
    ("Белые списки CIDR ТОП-150 №2👇", "Vless-Reality-White-Lists-Rus-Mobile-2.txt"),
    ("Белые списки CIDR VK Yandex Beeline👇", "WHITE-CIDR-RU-checked.txt"),
    ("Белые списки CIDR полная👇", "WHITE-CIDR-RU-all.txt"),
    ("Белые списки SNI👇", "WHITE-SNI-RU-all.txt"),
]

HEADER = [
    "#profile-title: VPN-RU-ALL",
    "#profile-update-interval: 1",
]

DUMMY = "vless://00000000-0000-0000-0000-000000000000@127.0.0.1:1?encryption=none&security=none&type=tcp#"
LINK = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://\S+")


def fetch(url, tries=3):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    last = None
    for i in range(tries):
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.read().decode("utf-8", "ignore")
        except Exception as exc:
            last = exc
            time.sleep(3 * (i + 1))
    raise RuntimeError("не удалось скачать %s: %s" % (url, last))


def decode_body(text):
    text = text.strip()
    if "://" in text:
        return text
    try:
        raw = re.sub(r"\s+", "", text).replace("-", "+").replace("_", "/")
        raw += "=" * (-len(raw) % 4)
        return base64.b64decode(raw).decode("utf-8", "ignore")
    except Exception:
        return text


def parse_links(text):
    result = []
    for line in decode_body(text).splitlines():
        line = line.strip()
        if line and not line.startswith("#") and LINK.match(line):
            result.append(line)
    return result


def separator(title):
    return DUMMY + quote(title)


def build(sections):
    seen = set()
    lines = list(HEADER)
    total = 0
    for title, links in sections:
        fresh = []
        for link in links:
            if link not in seen:
                seen.add(link)
                fresh.append(link)
        if not fresh:
            continue
        lines.append(separator(title))
        lines.extend(fresh)
        total += len(fresh)
    return "\n".join(lines) + "\n", total


def main():
    sections = []
    for title, name in SOURCES:
        links = parse_links(fetch(BASE + quote(name)))
        if not links:
            raise RuntimeError("пустой список: %s" % name)
        print("%s: %d" % (name, len(links)))
        sections.append((title, links))
    text, total = build(sections)
    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    print("итого серверов: %d" % total)


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as exc:
        sys.exit(str(exc))
