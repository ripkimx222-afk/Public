#!/usr/bin/env python3
# Собирает JSON-подписку для Happ: группы серверов с автовыбором по задержке.
# Каждая запись это отдельный конфиг Xray с балансировщиком leastPing.

import base64
import ipaddress
import json
import re
import sys
import time
import urllib.request
from urllib.parse import quote, unquote

BASE = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/"
OUT = "auto_subs.json"

# (тип списка, файл в репозитории)
SOURCES = [
    ("black", "BLACK_VLESS_RUS_mobile.txt"),
    ("black", "BLACK_VLESS_RUS.txt"),
    ("black", "BLACK_SS+All_RUS.txt"),
    ("white", "Vless-Reality-White-Lists-Rus-Mobile.txt"),
    ("white", "WHITE-CIDR-RU-checked.txt"),
    ("white", "WHITE-CIDR-RU-all.txt"),
    ("white", "WHITE-SNI-RU-all.txt"),
]

COUNTRY_PACK = 10       # серверов в одной записи страны
COUNTRY_MAX_PACKS = 3   # записей на одну страну
MIN_EXTRA_PACK = 5      # вторая и следующие записи только если в них не меньше стольких серверов
MAX_COUNTRIES = 500     # сколько стран показывать (500 это все)
LIST_PACK = 20          # серверов в записях Blacklist и Whitelist
ALL_PART = 15           # серверов из каждого списка в записи "все"
PROFILE_TITLE = ""   # название подписки в Happ, до 25 символов; пусто убирает строку
PROBE_URL = "https://www.gstatic.com/generate_204"
PROBE_INTERVAL = "2m"

RU_NAMES = {
    "RU": "Россия", "US": "США", "DE": "Германия", "FR": "Франция",
    "NL": "Нидерланды", "FI": "Финляндия", "SE": "Швеция", "PL": "Польша",
    "GB": "Великобритания", "CA": "Канада", "JP": "Япония", "SG": "Сингапур",
    "HK": "Гонконг", "KR": "Южная Корея", "TR": "Турция", "AE": "ОАЭ",
    "KZ": "Казахстан", "LT": "Литва", "LV": "Латвия", "EE": "Эстония",
    "UA": "Украина", "CH": "Швейцария", "AT": "Австрия", "IT": "Италия",
    "ES": "Испания", "CZ": "Чехия", "RO": "Румыния", "BG": "Болгария",
    "IN": "Индия", "TH": "Таиланд", "VN": "Вьетнам", "ZA": "ЮАР",
    "AU": "Австралия", "BR": "Бразилия", "IE": "Ирландия", "NO": "Норвегия",
    "DK": "Дания", "IL": "Израиль", "MD": "Молдова", "GE": "Грузия",
    "AM": "Армения", "RS": "Сербия", "HU": "Венгрия", "PT": "Португалия",
    "BE": "Бельгия", "LU": "Люксембург", "TW": "Тайвань", "ID": "Индонезия",
    "MY": "Малайзия", "IR": "Иран", "CN": "Китай", "KG": "Киргизия",
    "UZ": "Узбекистан", "BY": "Беларусь", "GR": "Греция", "SK": "Словакия",
    "SI": "Словения", "HR": "Хорватия", "IS": "Исландия", "MX": "Мексика",
    "AR": "Аргентина", "CL": "Чили", "EG": "Египет", "SA": "Саудовская Аравия",
    "AL": "Албания", "AZ": "Азербайджан", "BA": "Босния и Герцеговина",
    "BD": "Бангладеш", "BH": "Бахрейн", "CO": "Колумбия", "CR": "Коста-Рика",
    "CY": "Кипр", "DZ": "Алжир", "EC": "Эквадор", "IQ": "Ирак", "JO": "Иордания",
    "KE": "Кения", "KH": "Камбоджа", "KW": "Кувейт", "LB": "Ливан",
    "LK": "Шри-Ланка", "MA": "Марокко", "ME": "Черногория", "MK": "Северная Македония",
    "MN": "Монголия", "MT": "Мальта", "NG": "Нигерия", "NP": "Непал",
    "NZ": "Новая Зеландия", "OM": "Оман", "PA": "Панама", "PE": "Перу",
    "PH": "Филиппины", "PK": "Пакистан", "PY": "Парагвай", "QA": "Катар",
    "TN": "Тунис", "UY": "Уругвай", "VE": "Венесуэла", "MO": "Макао",
    "AF": "Афганистан", "LI": "Лихтенштейн", "IM": "Остров Мэн", "JE": "Джерси",
}

FLAG = re.compile(r"^\s*([\U0001F1E6-\U0001F1FF]{2})")
LINK = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://\S+")
FPS = {"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq",
       "random", "randomized"}
SS_METHODS = {
    "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "chacha20-poly1305",
    "xchacha20-ietf-poly1305", "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
}
VMESS_SEC = {"auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"}
XHTTP_MODES = {"auto", "packet-up", "stream-up", "stream-one"}


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


def b64(text):
    try:
        raw = re.sub(r"\s+", "", text).replace("-", "+").replace("_", "/")
        raw += "=" * (-len(raw) % 4)
        return base64.b64decode(raw).decode("utf-8", "ignore")
    except Exception:
        return ""


def parse_links(text):
    text = text.strip()
    if "://" not in text:
        text = b64(text) or text
    result = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and LINK.match(line):
            result.append(line)
    return result


def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def parse_query(query):
    out = {}
    for part in query.split("&"):
        if not part:
            continue
        key, _, val = part.partition("=")
        out.setdefault(key, unquote(val))
    return out


def split_hostport(hp):
    if hp.startswith("["):
        host, _, tail = hp[1:].partition("]")
        port = tail.lstrip(":")
    else:
        host, _, port = hp.rpartition(":")
    if not host or not port.isdigit():
        return None
    num = int(port)
    if not 1 <= num <= 65535:
        return None
    return host, num


def split_url(url):
    scheme, _, rest = url.partition("://")
    rest, _, frag = rest.partition("#")
    rest, _, query = rest.partition("?")
    netloc = rest.partition("/")[0]
    user, at, hostport = netloc.rpartition("@")
    if not at:
        return None
    hp = split_hostport(hostport)
    if not hp:
        return None
    return scheme.lower(), unquote(user), hp[0], hp[1], parse_query(query), unquote(frag)


def fp_of(q):
    value = q.get("fp", "").lower()
    return value if value in FPS else "chrome"


def stream(q, address, default_sec="none"):
    net = (q.get("type") or "tcp").lower()
    if net == "raw":
        net = "tcp"
    sec = (q.get("security") or default_sec).lower()
    if sec in ("false", "none", ""):
        sec = "none"
    if sec not in ("none", "tls", "reality"):
        return None
    host_hdr = q.get("host", "")
    sni = q.get("sni", "")
    addr_name = "" if is_ip(address) else address
    name = sni or host_hdr or addr_name
    ss = {"network": net, "security": sec}
    if sec == "tls":
        tls = {"fingerprint": fp_of(q)}
        if name:
            tls["serverName"] = name
        alpn = [a for a in q.get("alpn", "").split(",") if a]
        if alpn:
            tls["alpn"] = alpn
        ss["tlsSettings"] = tls
    elif sec == "reality":
        if not q.get("pbk") or not name:
            return None
        ss["realitySettings"] = {
            "serverName": name,
            "fingerprint": fp_of(q),
            "publicKey": q["pbk"],
            "shortId": q.get("sid", ""),
            "spiderX": q.get("spx", ""),
        }
    web_host = host_hdr or sni or addr_name
    path = q.get("path", "")
    if net == "tcp":
        if q.get("headerType", "none") not in ("none", ""):
            return None
    elif net == "ws":
        if not path.startswith("/"):
            path = "/" + path
        ws = {"path": path}
        if web_host:
            ws["headers"] = {"Host": web_host}
        ss["wsSettings"] = ws
    elif net == "grpc":
        ss["grpcSettings"] = {
            "serviceName": q.get("serviceName") or path,
            "multiMode": q.get("mode") == "multi",
        }
    elif net == "httpupgrade":
        hu = {"path": path or "/"}
        if web_host:
            hu["host"] = web_host
        ss["httpupgradeSettings"] = hu
    elif net == "xhttp":
        mode = q.get("mode") or "auto"
        xh = {"path": path or "/", "mode": mode if mode in XHTTP_MODES else "auto"}
        if web_host:
            xh["host"] = web_host
        extra = q.get("extra")
        if extra:
            parsed = json.loads(extra)
            if not isinstance(parsed, dict):
                return None
            xh["extra"] = parsed
        ss["xhttpSettings"] = xh
    else:
        return None
    return ss


def conv_vless(parts):
    _, user, host, port, q, frag = parts
    ss = stream(q, host)
    if ss is None or not user:
        return None
    enc = q.get("encryption") or "none"
    if enc != "none" and not enc.startswith("mlkem768x25519plus"):
        enc = "none"
    account = {"id": user, "encryption": enc}
    flow = q.get("flow", "")
    if flow and ss["network"] == "tcp" and ss["security"] in ("tls", "reality"):
        account["flow"] = flow
    ob = {
        "protocol": "vless",
        "settings": {"vnext": [{"address": host, "port": port, "users": [account]}]},
        "streamSettings": ss,
    }
    return ob, user, frag


def conv_trojan(parts):
    _, user, host, port, q, frag = parts
    ss = stream(q, host, default_sec="tls")
    if ss is None or not user:
        return None
    ob = {
        "protocol": "trojan",
        "settings": {"servers": [{"address": host, "port": port, "password": user}]},
        "streamSettings": ss,
    }
    return ob, user, frag


def conv_vmess(link):
    data = json.loads(b64(link[8:].split("#")[0]))
    host = str(data.get("add", ""))
    uid = str(data.get("id", ""))
    port = int(data.get("port", 0))
    if not host or not uid or not 1 <= port <= 65535:
        return None
    q = {
        "type": data.get("net", "tcp"),
        "security": "tls" if data.get("tls") == "tls" else "none",
        "host": data.get("host", ""),
        "path": data.get("path", ""),
        "sni": data.get("sni", ""),
        "alpn": data.get("alpn", ""),
        "fp": data.get("fp", ""),
        "serviceName": data.get("path", ""),
        "headerType": data.get("type", "none"),
    }
    ss = stream(q, host)
    if ss is None:
        return None
    sec = data.get("scy") or "auto"
    if sec not in VMESS_SEC:
        sec = "auto"
    ob = {
        "protocol": "vmess",
        "settings": {"vnext": [{"address": host, "port": port,
                                "users": [{"id": uid, "alterId": 0, "security": sec}]}]},
        "streamSettings": ss,
    }
    return ob, uid, str(data.get("ps", ""))


def conv_ss(link):
    body = link[5:]
    body, _, frag = body.partition("#")
    body, _, query = body.partition("?")
    if "plugin" in query:
        return None
    body = body.rstrip("/")
    if "@" not in body:
        body = b64(body)
        if "@" not in body:
            return None
    userinfo, _, hostport = body.rpartition("@")
    info = unquote(userinfo)
    if info.partition(":")[0] not in SS_METHODS:
        info = b64(info)
    method, _, password = info.partition(":")
    hp = split_hostport(hostport)
    if method not in SS_METHODS or not password or not hp:
        return None
    ob = {
        "protocol": "shadowsocks",
        "settings": {"servers": [{"address": hp[0], "port": hp[1],
                                  "method": method, "password": password}]},
    }
    return ob, password, unquote(frag)


def address_of(ob):
    settings = ob["settings"]
    if "vnext" in settings:
        return settings["vnext"][0]["address"]
    return settings["servers"][0]["address"]


def signature(ob):
    data = json.loads(json.dumps(ob))
    ss = data.get("streamSettings", {})
    if "tlsSettings" in ss:
        ss["tlsSettings"].pop("fingerprint", None)
        ss["tlsSettings"].pop("alpn", None)
    if "realitySettings" in ss:
        ss["realitySettings"].pop("fingerprint", None)
    return json.dumps(data, sort_keys=True)


def backend_of(ob, ident):
    ss = ob.get("streamSettings", {})
    addr = address_of(ob)
    name = addr
    if "tlsSettings" in ss:
        name = ss["tlsSettings"].get("serverName") or addr
    path = ""
    for key in ("wsSettings", "xhttpSettings", "httpupgradeSettings", "grpcSettings"):
        if key in ss:
            path = ss[key].get("path") or ss[key].get("serviceName") or ""
    return (ident, name, path)


def country_of(remark):
    match = FLAG.match(remark)
    if not match:
        return ""
    return "".join(chr(ord(ch) - 0x1F1E6 + 65) for ch in match.group(1))


def convert(link):
    try:
        scheme = link.split("://", 1)[0].lower()
        if scheme == "vmess":
            res = conv_vmess(link)
        elif scheme == "ss":
            res = conv_ss(link)
        elif scheme in ("vless", "trojan"):
            parts = split_url(link)
            if not parts:
                return None
            res = conv_vless(parts) if scheme == "vless" else conv_trojan(parts)
        else:
            return None
        if not res:
            return None
        ob, ident, remark = res
        return {
            "ob": ob,
            "key": signature(ob),
            "backend": backend_of(ob, ident),
            "country": country_of(remark),
        }
    except Exception:
        return None


def pick(entries, count):
    groups = {}
    for item in entries:
        groups.setdefault(item["backend"], []).append(item)
    queues = list(groups.values())
    chosen = []
    while len(chosen) < count and any(queues):
        for queue in queues:
            if queue and len(chosen) < count:
                chosen.append(queue.pop(0))
    return chosen


def without(entries, chosen):
    ids = {id(item) for item in chosen}
    return [item for item in entries if id(item) not in ids]


def flag_of(code):
    return "".join(chr(0x1F1E6 + ord(ch) - 65) for ch in code)


def make_config(remark, items):
    outbounds = []
    for num, item in enumerate(items, 1):
        ob = json.loads(json.dumps(item["ob"]))
        ob["tag"] = "p-%d" % num
        outbounds.append(ob)
    outbounds.append({"tag": "direct", "protocol": "freedom"})
    outbounds.append({"tag": "block", "protocol": "blackhole"})
    return {
        "remarks": remark,
        "meta": {"serverDescription": "Серверов: %d, выбор по минимальной задержке" % len(items)},
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"tag": "socks", "listen": "127.0.0.1", "port": 10808, "protocol": "socks",
             "settings": {"auth": "noauth", "udp": True},
             "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]}},
            {"tag": "http", "listen": "127.0.0.1", "port": 10809, "protocol": "http",
             "settings": {}},
        ],
        "outbounds": outbounds,
        "routing": {
            "domainStrategy": "AsIs",
            "balancers": [{"tag": "auto", "selector": ["p-"],
                           "strategy": {"type": "leastPing"}, "fallbackTag": "p-1"}],
            "rules": [
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
                {"type": "field", "network": "tcp,udp", "balancerTag": "auto"},
            ],
        },
        "burstObservatory": {
            "subjectSelector": ["p-"],
            "pingConfig": {"destination": PROBE_URL, "connectivity": "",
                           "interval": PROBE_INTERVAL, "sampling": 2, "timeout": "6s"},
        },
    }


def build(black, white):
    configs = []
    both = []
    if black and white:
        mixed = pick(black, ALL_PART) + pick(white, ALL_PART)
        configs.append(make_config("🌐 Автовыбор все", mixed))
    elif black or white:
        configs.append(make_config("🌐 Автовыбор все", pick(black or white, ALL_PART * 2)))
    if black:
        configs.append(make_config("⚫ Автовыбор Blacklist", pick(black, LIST_PACK)))
    if white:
        configs.append(make_config("⚪ Автовыбор Whitelist", pick(white, LIST_PACK)))
    both = black + white
    by_country = {}
    for item in both:
        if item["country"]:
            by_country.setdefault(item["country"], []).append(item)
    ranked = sorted(by_country.items(), key=lambda kv: -len(kv[1]))[:MAX_COUNTRIES]
    country_cfgs = []
    for code, items in ranked:
        name = RU_NAMES.get(code, code)
        left = items
        for num in range(1, COUNTRY_MAX_PACKS + 1):
            chosen = pick(left, COUNTRY_PACK)
            if not chosen or (num > 1 and len(chosen) < MIN_EXTRA_PACK):
                break
            left = without(left, chosen)
            remark = "%s %s (автовыбор %d)" % (flag_of(code), name, num)
            country_cfgs.append((name, num, make_config(remark, chosen)))
    country_cfgs.sort(key=lambda row: (row[0], row[1]))
    configs.extend(row[2] for row in country_cfgs)
    return configs


def main():
    black, white = [], []
    seen = set()
    for kind, name in SOURCES:
        try:
            links = parse_links(fetch(BASE + quote(name)))
        except RuntimeError as exc:
            print("пропуск: %s" % exc)
            continue
        added = 0
        for link in links:
            item = convert(link)
            if not item or item["key"] in seen:
                continue
            seen.add(item["key"])
            (black if kind == "black" else white).append(item)
            added += 1
        print("%s: ссылок %d, принято %d" % (name, len(links), added))
    if not black and not white:
        raise RuntimeError("ни один список не скачался")
    configs = build(black, white)
    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        if PROFILE_TITLE:
            fh.write("#profile-title: %s\n" % PROFILE_TITLE)
        json.dump(configs, fh, ensure_ascii=False, separators=(",", ":"))
    print("записей в подписке: %d" % len(configs))


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as exc:
        sys.exit(str(exc))
