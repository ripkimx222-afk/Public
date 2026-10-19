#!/usr/bin/env python3
# Собирает JSON-подписку для Happ из открытых списков серверов.
# Каждая запись это отдельный конфиг Xray с балансировщиком leastPing:
# Happ сам выбирает рабочий сервер с наименьшей задержкой внутри записи.
# Перед сборкой серверы проверяются настоящим Xray: мертвые отбрасываются,
# а тем, кто не открывает YouTube, в название добавляется YT:❌.

import base64
import concurrent.futures
import io
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from collections import Counter
from urllib.parse import quote, unquote

OUT = "auto_subs.json"

# Адреса одного и того же репозитория по очереди: если первый недоступен, берется следующий.
IGARECK = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/",
    "https://gitlab.com/igareck/vpn-configs-for-russia/-/raw/main/",
    "https://codeberg.org/igareck/vpn-configs-for-russia/raw/branch/main/",
    "https://bitbucket.org/igareck/vpn-configs-for-russia/raw/main/",
    "https://raw.githack.com/igareck/vpn-configs-for-russia/main/",
]
GOIDA = [
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/",
    "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/",
    "https://media.githubusercontent.com/media/AvenCores/goida-vpn-configs/main/githubmirror/",
    "https://cdn.jsdelivr.net/gh/AvenCores/goida-vpn-configs@main/githubmirror/",
    "https://gitlab.com/avencores/goida-vpn-configs/-/raw/main/githubmirror/",
]
FLAT447 = [
    "https://raw.githubusercontent.com/FLAT447/v2ray-lists/refs/heads/main/",
    "https://github.com/FLAT447/v2ray-lists/raw/refs/heads/main/",
]
KORT = [
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/githubmirror/",
    "https://github.com/kort0881/vpn-vless-configs-russia/raw/refs/heads/main/githubmirror/",
]

# (тип списка, LTE, адреса, файл).
# Тип black или white нужен для записей Blacklist и Whitelist.
# LTE True означает список для мобильного интернета: из таких серверов собираются записи "LTE".
# Чтобы добавить свой список, допишите строку. Недоступные файлы пропускаются.
SOURCES = [
    ("black", False, IGARECK, "BLACK_VLESS_RUS.txt"),
    ("black", True, IGARECK, "BLACK_VLESS_RUS_mobile.txt"),
    ("black", False, IGARECK, "BLACK_SS+All_RUS.txt"),
    ("white", True, IGARECK, "Vless-Reality-White-Lists-Rus-Mobile.txt"),
    ("white", True, IGARECK, "Vless-Reality-White-Lists-Rus-Mobile-2.txt"),
    ("white", False, IGARECK, "WHITE-CIDR-RU-checked.txt"),
    ("white", False, IGARECK, "WHITE-CIDR-RU-all.txt"),
    ("white", False, IGARECK, "WHITE-SNI-RU-all.txt"),
    ("black", True, FLAT447, "BLACK_LTE.txt"),
    ("black", False, FLAT447, "BLACK_FULL.txt"),
    ("white", True, FLAT447, "WHITE_LITE.txt"),
    ("white", False, FLAT447, "WHITE_FULL.txt"),
    ("white", True, KORT, "ru-sni/vless_ru.txt"),
    ("white", True, KORT, "ru-sni/vmess_ru.txt"),
    ("black", False, KORT, "clean/vless.txt"),
    ("black", False, GOIDA, "1.txt"),
    ("black", False, GOIDA, "6.txt"),
    ("black", False, GOIDA, "22.txt"),
    ("black", False, GOIDA, "24.txt"),
    ("black", False, GOIDA, "25.txt"),
    ("white", True, GOIDA, "26.txt"),
]

MAX_ENTRIES = 45           # сколько всего записей автовыбора в подписке
PACK = 50                  # серверов в одной записи страны
GROUP_PACK = 50            # серверов в записях "Все", "Blacklist", "Whitelist"
MIN_COUNTRY_SERVERS = 3    # у страны меньше рабочих серверов своей записи нет (они остаются в общих)
LTE_TARGET = 200           # сколько рабочих LTE серверов хотим
LTE_MAX = 250              # не больше стольких LTE серверов в подписке
INCLUDE_HYSTERIA2 = True   # False убирает серверы Hysteria2 (в названии записей буква H вместо N)

# Проверка серверов настоящим Xray перед сборкой
CHECK_ENABLED = True       # False пропускает проверку, тогда в подписку идут все серверы без пометок
CHECK_YOUTUBE = True       # проверять, открывается ли YouTube
CHECK_CANDIDATES = 3500    # сколько серверов проверять за один запуск
CHECK_LTE_CANDIDATES = 1200  # из них не больше стольких из LTE списков
CHECK_BATCH = 200          # серверов в одном запуске Xray
CHECK_THREADS = 100        # сколько проверок одновременно
CHECK_TIMEOUT = 8          # секунд на один запрос
CHECK_TIME_BUDGET = 1500   # секунд на всю проверку, дальше непроверенные серверы отбрасываются
XRAY_URL = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
BASE_PORT = 21000

# Как телефон следит за серверами внутри записи.
# Чем чаще проверка, тем быстрее уход с упавшего сервера, но тем больше трафика и батареи.
PROBE_URL = "https://www.gstatic.com/generate_204"
PROBE_INTERVAL = "30s"
PROBE_TIMEOUT = "4s"

# Маршрутизация внутри подписки (профиль "RU + Roblox direct, rest VPN").
# Что в списках, идет напрямую, все остальное через VPN.
ROUTING_ENABLED = True
DIRECT_DOMAINS = [
    "domain:ru", "domain:su", "domain:xn--p1ai",
    "domain:roblox.com", "domain:rbxcdn.com", "domain:roblox.qq.com",
    "domain:robloxlabs.com", "domain:rbxtrk.com",
]
DIRECT_IPS = [
    "geoip:private", "geoip:ru",
    "128.116.0.0/17", "103.140.28.0/23",
    "2620:135:6000::/40", "2620:2b:e000::/48",
]

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
    "UN": "ООН", "EU": "Евросоюз", "XK": "Косово", "SC": "Сейшелы",
    "FM": "Микронезия", "CW": "Кюрасао", "VG": "Британские Виргинские острова",
    "IO": "Британская территория в Индийском океане", "DO": "Доминикана",
    "AO": "Ангола", "BN": "Бруней", "BS": "Багамы", "BW": "Ботсвана", "BZ": "Белиз",
    "CD": "ДР Конго", "CI": "Кот-д'Ивуар", "CM": "Камерун", "CU": "Куба",
    "ET": "Эфиопия", "FJ": "Фиджи", "GH": "Гана", "GT": "Гватемала",
    "HN": "Гондурас", "JM": "Ямайка", "LA": "Лаос", "LY": "Ливия", "MM": "Мьянма",
    "MU": "Маврикий", "MV": "Мальдивы", "MZ": "Мозамбик", "NA": "Намибия",
    "NI": "Никарагуа", "RW": "Руанда", "SN": "Сенегал", "SV": "Сальвадор",
    "SY": "Сирия", "TJ": "Таджикистан", "TM": "Туркменистан",
    "TT": "Тринидад и Тобаго", "TZ": "Танзания", "UG": "Уганда", "YE": "Йемен",
    "ZM": "Замбия", "ZW": "Зимбабве", "PR": "Пуэрто-Рико", "GI": "Гибралтар",
    "GG": "Гернси", "FO": "Фарерские острова", "AX": "Аландские острова",
    "BM": "Бермуды", "KY": "Каймановы острова", "AD": "Андорра", "MC": "Монако",
    "SM": "Сан-Марино", "BB": "Барбадос", "GU": "Гуам", "RE": "Реюньон",
}

EN_NAMES = {
    "US": ["united states", "usa", "united states of america"],
    "DE": ["germany"], "FR": ["france"], "NL": ["netherlands", "the netherlands"],
    "FI": ["finland"], "SE": ["sweden"], "PL": ["poland"],
    "GB": ["united kingdom", "uk", "england", "great britain"],
    "CA": ["canada"], "JP": ["japan"], "SG": ["singapore"], "HK": ["hong kong"],
    "KR": ["south korea", "korea"], "TR": ["turkey", "turkiye", "t\u00fcrkiye"],
    "AE": ["united arab emirates", "uae"], "KZ": ["kazakhstan"],
    "LT": ["lithuania"], "LV": ["latvia"], "EE": ["estonia"], "UA": ["ukraine"],
    "CH": ["switzerland"], "AT": ["austria"], "IT": ["italy"], "ES": ["spain"],
    "CZ": ["czechia", "czech republic"], "RO": ["romania"], "BG": ["bulgaria"],
    "IN": ["india"], "TH": ["thailand"], "VN": ["vietnam"], "ZA": ["south africa"],
    "AU": ["australia"], "BR": ["brazil"], "IE": ["ireland"], "NO": ["norway"],
    "DK": ["denmark"], "IL": ["israel"], "MD": ["moldova"], "GE": ["georgia"],
    "AM": ["armenia"], "RS": ["serbia"], "HU": ["hungary"], "PT": ["portugal"],
    "BE": ["belgium"], "LU": ["luxembourg"], "TW": ["taiwan"], "ID": ["indonesia"],
    "MY": ["malaysia"], "IR": ["iran"], "CN": ["china"], "KG": ["kyrgyzstan"],
    "UZ": ["uzbekistan"], "BY": ["belarus"], "GR": ["greece"], "SK": ["slovakia"],
    "SI": ["slovenia"], "HR": ["croatia"], "IS": ["iceland"], "MX": ["mexico"],
    "AR": ["argentina"], "CL": ["chile"], "EG": ["egypt"], "SA": ["saudi arabia"],
    "RU": ["russia", "russian federation"], "AL": ["albania"], "AZ": ["azerbaijan"],
    "CY": ["cyprus"], "QA": ["qatar"], "KW": ["kuwait"], "BH": ["bahrain"],
    "PH": ["philippines"], "PK": ["pakistan"], "BD": ["bangladesh"],
    "NZ": ["new zealand"], "ME": ["montenegro"], "MT": ["malta"],
}
NAME_TO_ISO = {}
for _code, _names in EN_NAMES.items():
    for _name in _names:
        NAME_TO_ISO[_name] = _code
for _code, _name in RU_NAMES.items():
    NAME_TO_ISO.setdefault(_name.lower(), _code)

FLAG_START = re.compile(r"^\s*([\U0001F1E6-\U0001F1FF]{2})")
FLAG_ANY = re.compile(r"[\U0001F1E6-\U0001F1FF]{2}")
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

SKIPPED = Counter()
LOST = Counter()


def fetch(url, tries=3):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    last = None
    for i in range(tries):
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.read().decode("utf-8", "ignore")
        except urllib.error.HTTPError as exc:
            if exc.code in (403, 404):
                raise RuntimeError("HTTP %d" % exc.code)
            last = "HTTP %d" % exc.code
        except Exception as exc:
            last = exc
        if i + 1 < tries:
            time.sleep(3 * (i + 1))
    raise RuntimeError(str(last))


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


def fetch_list(bases, name):
    errors = []
    for base in bases:
        try:
            text = fetch(base + quote(name), tries=2)
        except RuntimeError as exc:
            errors.append("%s %s" % (base.split("/")[2], exc))
            continue
        return parse_links(text), base
    raise RuntimeError("%s недоступен (%s)" % (name, "; ".join(errors)))


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


def conv_hysteria2(parts):
    _, user, host, port, q, frag = parts
    if not user or q.get("obfs") or q.get("obfs-password"):
        return None
    sni = q.get("sni", "")
    tls = {"alpn": ["h3"]}
    name = sni or ("" if is_ip(host) else host)
    if name:
        tls["serverName"] = name
    if q.get("insecure") in ("1", "true"):
        tls["allowInsecure"] = True
    ob = {
        "protocol": "hysteria",
        "settings": {"version": 2, "address": host, "port": port},
        "streamSettings": {
            "network": "hysteria",
            "security": "tls",
            "tlsSettings": tls,
            "hysteriaSettings": {"version": 2, "auth": user},
        },
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
    if "servers" in settings:
        return settings["servers"][0]["address"]
    return settings["address"]


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


def code_of(pair):
    return "".join(chr(ord(ch) - 0x1F1E6 + 65) for ch in pair)


def country_of(remark):
    match = FLAG_START.match(remark)
    if match:
        return code_of(match.group(1))
    if "anycast" in remark.lower():
        return ""
    flags = set(FLAG_ANY.findall(remark))
    if len(flags) == 1:
        return code_of(next(iter(flags)))
    head = re.split(r"[,|\[(]", remark)[0].strip().lower()
    return NAME_TO_ISO.get(head, "")


def note_skip(link, reason):
    SKIPPED[reason] += 1
    LOST[country_of(unquote(link.partition("#")[2]))] += 1


def convert(link):
    scheme = link.split("://", 1)[0].lower()
    try:
        if scheme == "vmess":
            res = conv_vmess(link)
        elif scheme == "ss":
            res = conv_ss(link)
        elif scheme in ("vless", "trojan"):
            parts = split_url(link)
            if not parts:
                note_skip(link, "параметры " + scheme)
                return None
            res = conv_vless(parts) if scheme == "vless" else conv_trojan(parts)
        elif scheme in ("hysteria2", "hy2"):
            if not INCLUDE_HYSTERIA2:
                note_skip(link, "hysteria2 отключен")
                return None
            parts = split_url(link)
            if not parts:
                note_skip(link, "параметры hysteria2")
                return None
            res = conv_hysteria2(parts)
        else:
            note_skip(link, "протокол " + scheme)
            return None
        if not res:
            note_skip(link, "параметры " + scheme)
            return None
        ob, ident, remark = res
        return {
            "ob": ob,
            "key": signature(ob),
            "backend": backend_of(ob, ident),
            "country": country_of(remark),
            "remark": remark,
            "kind": "hy2" if ob["protocol"] == "hysteria" else "std",
        }
    except Exception:
        note_skip(link, "ошибка " + scheme)
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



def routing_block():
    if ROUTING_ENABLED:
        rules = [
            {"type": "field", "domain": DIRECT_DOMAINS, "outboundTag": "direct"},
            {"type": "field", "ip": DIRECT_IPS, "outboundTag": "direct"},
        ]
        strategy = "IPIfNonMatch"
    else:
        rules = [{"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"}]
        strategy = "AsIs"
    rules.append({"type": "field", "network": "tcp,udp", "balancerTag": "auto"})
    return {
        "domainStrategy": strategy,
        "balancers": [{"tag": "auto", "selector": ["p-"],
                       "strategy": {"type": "leastPing"}, "fallbackTag": "p-1"}],
        "rules": rules,
    }


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
        "meta": {"serverDescription": "Серверов: %d" % len(items)},
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"tag": "socks", "listen": "127.0.0.1", "port": 10808, "protocol": "socks",
             "settings": {"auth": "noauth", "udp": True},
             "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]}},
            {"tag": "http", "listen": "127.0.0.1", "port": 10809, "protocol": "http",
             "settings": {}},
        ],
        "outbounds": outbounds,
        "routing": routing_block(),
        "burstObservatory": {
            "subjectSelector": ["p-"],
            "pingConfig": {"destination": PROBE_URL, "connectivity": "",
                           "interval": PROBE_INTERVAL, "sampling": 1, "timeout": PROBE_TIMEOUT},
        },
    }


# ---------- проверка серверов настоящим Xray ----------

def prepare_xray():
    try:
        req = urllib.request.Request(XRAY_URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=180) as resp:
            data = resp.read()
        workdir = tempfile.mkdtemp()
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            archive.extract("xray", workdir)
        path = os.path.join(workdir, "xray")
        os.chmod(path, 0o755)
        version = subprocess.run([path, "version"], capture_output=True, text=True, timeout=20).stdout
        print("Xray для проверки: " + (version.splitlines() or ["?"])[0])
        return path, workdir
    except Exception as exc:
        print("Xray подготовить не удалось: %s" % exc)
        return None, None


def batch_config(items):
    inbounds, outbounds, rules = [], [], []
    for i, item in enumerate(items):
        ob = json.loads(json.dumps(item["ob"]))
        ob["tag"] = "out%d" % i
        outbounds.append(ob)
        inbounds.append({"tag": "in%d" % i, "listen": "127.0.0.1", "port": BASE_PORT + i,
                         "protocol": "socks", "settings": {"auth": "noauth", "udp": False}})
        rules.append({"type": "field", "inboundTag": ["in%d" % i], "outboundTag": "out%d" % i})
    outbounds.append({"tag": "direct", "protocol": "freedom"})
    return {"log": {"loglevel": "none"}, "inbounds": inbounds, "outbounds": outbounds,
            "routing": {"domainStrategy": "AsIs", "rules": rules}}


def xray_valid(xray, workdir, items):
    path = os.path.join(workdir, "test.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(batch_config(items), fh)
    try:
        result = subprocess.run([xray, "run", "-test", "-c", path],
                                capture_output=True, text=True, timeout=60)
        return result.returncode == 0
    except Exception:
        return False


def filter_valid(xray, workdir, items):
    # Если в пачке есть сервер, который Xray не принимает, пачка делится пополам, пока он не найдется.
    if not items:
        return []
    if xray_valid(xray, workdir, items):
        return items
    if len(items) == 1:
        return []
    mid = len(items) // 2
    return filter_valid(xray, workdir, items[:mid]) + filter_valid(xray, workdir, items[mid:])


def curl(port, url, timeout):
    try:
        result = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-m", str(timeout),
             "--socks5-hostname", "127.0.0.1:%d" % port,
             "-w", "%{http_code} %{time_total}", url],
            capture_output=True, text=True, timeout=timeout + 5)
        code, _, spent = result.stdout.strip().partition(" ")
        return code, float(spent or 0)
    except Exception:
        return "000", 0.0


def check_one(port):
    code, spent = curl(port, PROBE_URL, CHECK_TIMEOUT)
    if code != "204":
        return {"alive": False, "yt": False, "ms": 0}
    yt = True
    if CHECK_YOUTUBE:
        code, _ = curl(port, "https://www.youtube.com/robots.txt", CHECK_TIMEOUT + 4)
        yt = code == "200"
    return {"alive": True, "yt": yt, "ms": int(spent * 1000)}


def wait_port(port, proc):
    for _ in range(40):
        if proc.poll() is not None:
            return False
        try:
            socket.create_connection(("127.0.0.1", port), 0.5).close()
            return True
        except OSError:
            time.sleep(0.5)
    return False


def run_batch(xray, workdir, items):
    path = os.path.join(workdir, "run.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(batch_config(items), fh)
    proc = subprocess.Popen([xray, "run", "-c", path],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_port(BASE_PORT + len(items) - 1, proc):
            return False
        with concurrent.futures.ThreadPoolExecutor(CHECK_THREADS) as pool:
            futures = {pool.submit(check_one, BASE_PORT + i): i for i in range(len(items))}
            for future in concurrent.futures.as_completed(futures):
                items[futures[future]].update(future.result())
        return True
    finally:
        proc.terminate()
        try:
            proc.wait(10)
        except Exception:
            proc.kill()


def check_all(items):
    # Возвращает True, если проверка выполнена и нашлись рабочие серверы.
    for item in items:
        item.update({"alive": False, "yt": False, "ms": 0})
    if not CHECK_ENABLED:
        print("проверка серверов отключена")
        return False
    xray, workdir = prepare_xray()
    if not xray:
        return False
    started = time.time()
    hy2 = [i for i in items if i["kind"] == "hy2"]
    queue = [i for i in items if i["kind"] == "std"]
    if hy2:
        if any(xray_valid(xray, workdir, [i]) for i in hy2[:5]):
            queue += hy2
        else:
            print("Hysteria2 эта версия Xray не принимает, такие серверы убраны")
    invalid = 0
    skipped = 0
    for start in range(0, len(queue), CHECK_BATCH):
        chunk = queue[start:start + CHECK_BATCH]
        if time.time() - started > CHECK_TIME_BUDGET:
            skipped += len(queue) - start
            break
        good = filter_valid(xray, workdir, chunk)
        invalid += len(chunk) - len(good)
        if good and not run_batch(xray, workdir, good):
            print("Xray не запустился на пачке из %d серверов" % len(good))
            for item in good:
                item["alive"] = False
    alive = [i for i in items if i["alive"]]
    print("проверено серверов: %d, Xray не принял: %d, не успели проверить: %d, рабочих: %d, из них с YouTube: %d" % (
        len(queue) - skipped, invalid, skipped, len(alive), sum(1 for i in alive if i["yt"])))
    return bool(alive)


# ---------- сборка записей ----------

def order_key(item):
    return (0 if item.get("yt", True) else 1, item.get("ms", 0))


def by_country_map(items):
    result = {}
    for item in items:
        result.setdefault(item["country"], []).append(item)
    return result


def diverse(items, count):
    # По кругу берет серверы из разных стран и разных хостов.
    if len(items) <= count:
        return list(items)
    queues = sorted((pick(v, len(v)) for v in by_country_map(items).values()), key=len, reverse=True)
    out = []
    while len(out) < count and any(queues):
        for queue in queues:
            if queue and len(out) < count:
                out.append(queue.pop(0))
    return out


def top_diverse(items, count):
    groups = by_country_map(sorted(items, key=order_key))
    queues = sorted(groups.values(), key=lambda g: order_key(g[0]))
    out = []
    while len(out) < count and any(queues):
        for queue in queues:
            if queue and len(out) < count:
                out.append(queue.pop(0))
    return sorted(out, key=order_key)


def make_packs(items, size):
    ok = sorted([i for i in items if i.get("yt", True)], key=order_key)
    bad = sorted([i for i in items if not i.get("yt", True)], key=order_key)
    packs = [(ok[i:i + size], True) for i in range(0, len(ok), size)]
    packs += [(bad[i:i + size], False) for i in range(0, len(bad), size)]
    return packs


def pack_name(prefix, num, yt, letter="N"):
    return "%s %s%d%s" % (prefix, letter, num, "" if yt else " YT:❌")


def select_candidates(items):
    lte = [i for i in items if i["lte"]]
    small = [i for i in items if not i["lte"] and not i["big"]]
    big = [i for i in items if not i["lte"] and i["big"]]
    lte = diverse(lte, CHECK_LTE_CANDIDATES)
    room = max(CHECK_CANDIDATES - len(lte) - len(small), 0)
    return lte + small + diverse(big, room)


def build(items):
    std = [i for i in items if i["kind"] == "std"]
    hy2 = [i for i in items if i["kind"] == "hy2"]
    ok_std = [i for i in std if i.get("yt", True)] or std

    head = []
    if ok_std:
        head.append(make_config("🌐 Все", top_diverse(ok_std, GROUP_PACK)))
    black = [i for i in ok_std if "black" in i["srcs"]]
    white = [i for i in ok_std if "white" in i["srcs"]]
    if black:
        head.append(make_config("⚫ Blacklist", top_diverse(black, GROUP_PACK)))
    if white:
        head.append(make_config("⚪ Whitelist", top_diverse(white, GROUP_PACK)))

    lte_pool = sorted([i for i in std if i["lte"]], key=order_key)[:LTE_MAX]
    lte_cfgs = []
    for num, (chunk, yt) in enumerate(make_packs(lte_pool, PACK), 1):
        lte_cfgs.append(make_config(pack_name("📶 LTE", num, yt), chunk))

    budget = max(MAX_ENTRIES - len(head) - len(lte_cfgs), 0)
    plist = {}
    for kind_items, letter in ((std, "N"), (hy2, "H")):
        for code, part in by_country_map(kind_items).items():
            for num, (chunk, yt) in enumerate(make_packs(part, PACK), 1):
                plist.setdefault(code, []).append((chunk, yt, num, letter))
    totals = {code: sum(len(c) for c, _, _, _ in lst) for code, lst in plist.items()}
    codes = [c for c in sorted(totals, key=lambda c: (c == "", -totals[c])) if totals[c] >= MIN_COUNTRY_SERVERS]

    chosen = []
    rnd = 0
    while len(chosen) < budget:
        moved = False
        for code in codes:
            if rnd < len(plist[code]) and len(chosen) < budget:
                chosen.append((code, rnd, plist[code][rnd]))
                moved = True
        if not moved:
            break
        rnd += 1

    rows = []
    for code, rnd, (chunk, yt, num, letter) in chosen:
        name = RU_NAMES.get(code, code) if code else "\uffff"
        prefix = flag_of(code) if code else "🌐"
        rows.append((name, rnd, make_config(pack_name(prefix, num, yt, letter), chunk)))
    rows.sort(key=lambda row: row[:2])
    configs = head + lte_cfgs + [row[2] for row in rows]
    print("записей: групп %d, LTE %d (серверов %d), стран и прочих %d" % (
        len(head), len(lte_cfgs), len(lte_pool), len(rows)))
    if len(lte_pool) < LTE_TARGET:
        print("LTE серверов меньше желаемых %d, рабочих найдено %d" % (LTE_TARGET, len(lte_pool)))
    return configs


def report(items):
    print("серверов в расчете: %d" % len(items))
    kinds = Counter(i["ob"]["protocol"] for i in items)
    print("протоколы: " + ", ".join("%s %d" % kv for kv in kinds.most_common()))
    by_c = Counter(i["country"] for i in items if i["country"])
    print("стран: %d, без страны: %d" % (len(by_c), sum(1 for i in items if not i["country"])))
    print("по странам: " + ", ".join("%s %d" % (RU_NAMES.get(c, c), n) for c, n in by_c.most_common()))
    if SKIPPED:
        print("пропущено при разборе: " + ", ".join("%s %d" % (k, v) for k, v in SKIPPED.most_common()))


def main():
    items = []
    by_key = {}
    for src, lte, bases, name in SOURCES:
        try:
            links, base = fetch_list(bases, name)
        except RuntimeError as exc:
            print("пропуск: %s" % exc)
            continue
        added = 0
        for link in links:
            item = convert(link)
            if not item:
                continue
            old = by_key.get(item["key"])
            if old:
                old["lte"] = old["lte"] or lte
                old["srcs"].add(src)
                continue
            item["srcs"] = {src}
            item["lte"] = lte
            item["big"] = bases is GOIDA
            by_key[item["key"]] = item
            items.append(item)
            added += 1
        print("%s: ссылок %d, новых %d (%s)" % (name, len(links), added, base.split("/")[2]))
    if not items:
        raise RuntimeError("ни один список не скачался")
    candidates = select_candidates(items)
    print("к проверке отобрано серверов: %d из %d" % (len(candidates), len(items)))
    if check_all(candidates):
        items = [i for i in candidates if i["alive"]]
    else:
        print("проверка не выполнена, в подписку идут серверы без проверки")
        for item in candidates:
            item["yt"] = True
        items = candidates
    configs = build(items)
    report(items)
    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(configs, fh, ensure_ascii=False, separators=(",", ":"))
    print("записей в подписке: %d" % len(configs))


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as exc:
        sys.exit(str(exc))
