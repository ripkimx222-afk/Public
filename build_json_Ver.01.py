#!/usr/bin/env python3
# Собирает JSON-подписку для Happ из списков igareck/vpn-configs-for-russia.
# Каждая запись это отдельный конфиг Xray с балансировщиком leastPing:
# Happ сам выбирает сервер с наименьшей задержкой внутри записи.

import base64
import ipaddress
import json
import re
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from urllib.parse import quote, unquote

# Источники по очереди: если первый недоступен, берется следующий.
# Это полные копии одного и того же репозитория.
MIRRORS = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/",
    "https://gitlab.com/igareck/vpn-configs-for-russia/-/raw/main/",
    "https://codeberg.org/igareck/vpn-configs-for-russia/raw/branch/main/",
    "https://bitbucket.org/igareck/vpn-configs-for-russia/raw/main/",
    "https://raw.githack.com/igareck/vpn-configs-for-russia/main/",
]
OUT = "auto_subs.json"

# (тип списка, файл в репозитории). Недоступные файлы просто пропускаются.
SOURCES = [
    ("black", "BLACK_VLESS_RUS_mobile.txt"),
    ("black", "BLACK_VLESS_RUS.txt"),
    ("black", "BLACK_SS+All_RUS.txt"),
    ("white", "Vless-Reality-White-Lists-Rus-Mobile.txt"),
    ("white", "Vless-Reality-White-Lists-Rus-Mobile-2.txt"),
    ("white", "WHITE-CIDR-RU-checked.txt"),
    ("white", "WHITE-CIDR-RU-all.txt"),
    ("white", "WHITE-SNI-RU-all.txt"),
]

COUNTRY_PACK = 10          # серверов в одной записи страны
COUNTRY_MAX_PACKS = 5      # записей на одну страну (автовыбор 1, 2, 3...)
MIN_EXTRA_PACK = 5         # вторая и следующие записи только если в них не меньше стольких серверов
NAMELESS_MAX_PACKS = 5     # записей для серверов без страны
HY2_MAX_PACKS = 1          # записей Hysteria2 на страну
INCLUDE_HYSTERIA2 = True   # False убирает все записи Hysteria2
LIST_PACK = 30             # серверов в записях Blacklist и Whitelist
ALL_PART = 20              # серверов из чёрных и из белых списков в записи "все"
PROBE_URL = "https://www.gstatic.com/generate_204"

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
                raise RuntimeError("%s: HTTP %d" % (url, exc.code))
            last = exc
        except Exception as exc:
            last = exc
        if i + 1 < tries:
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


def fetch_list(name):
    errors = []
    for base in MIRRORS:
        try:
            text = fetch(base + quote(name), tries=2)
        except RuntimeError as exc:
            errors.append(str(exc))
            continue
        return parse_links(text), base
    raise RuntimeError("%s недоступен ни в одном зеркале" % name)


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
        "routing": routing_block(),
        "burstObservatory": {
            "subjectSelector": ["p-"],
            "pingConfig": {"destination": PROBE_URL, "connectivity": "",
                           "interval": PROBE_INTERVAL, "sampling": 2, "timeout": "6s"},
        },
    }


def packs(items, max_packs, label, flag, min_extra=MIN_EXTRA_PACK):
    # Режет список на записи по COUNTRY_PACK серверов, возвращает (номер, конфиг).
    result = []
    left = items
    for num in range(1, max_packs + 1):
        chosen = pick(left, COUNTRY_PACK)
        if not chosen or (num > 1 and len(chosen) < min_extra):
            break
        left = without(left, chosen)
        result.append((num, make_config("%s %s" % (flag, label % num), chosen)))
    return result


def build(black, white):
    std_b = [i for i in black if i["kind"] == "std"]
    std_w = [i for i in white if i["kind"] == "std"]
    std = std_b + std_w
    hy2 = [i for i in black + white if i["kind"] == "hy2"]
    configs = []
    if std_b and std_w:
        configs.append(make_config("🌐 Автовыбор все", pick(std_b, ALL_PART) + pick(std_w, ALL_PART)))
    elif std:
        configs.append(make_config("🌐 Автовыбор все", pick(std, ALL_PART * 2)))
    if std_b:
        configs.append(make_config("⚫ Автовыбор Blacklist", pick(std_b, LIST_PACK)))
    if std_w:
        configs.append(make_config("⚪ Автовыбор Whitelist", pick(std_w, LIST_PACK)))

    by_country = {}
    for item in std:
        if item["country"]:
            by_country.setdefault(item["country"], []).append(item)
    hy2_by_country = {}
    hy2_nameless = []
    for item in hy2:
        if item["country"]:
            hy2_by_country.setdefault(item["country"], []).append(item)
        else:
            hy2_nameless.append(item)

    rows = []
    for code in set(by_country) | set(hy2_by_country):
        name = RU_NAMES.get(code, code)
        flag = flag_of(code)
        for num, cfg in packs(by_country.get(code, []), COUNTRY_MAX_PACKS,
                              name + " (автовыбор %d)", flag):
            rows.append((name, 0, num, cfg))
        for num, cfg in packs(hy2_by_country.get(code, []), HY2_MAX_PACKS,
                              name + " (Hy2 автовыбор %d)", flag, min_extra=1):
            rows.append((name, 1, num, cfg))
    rows.sort(key=lambda row: row[:3])
    configs.extend(row[3] for row in rows)

    nameless = [i for i in std if not i["country"]]
    for num, cfg in packs(nameless, NAMELESS_MAX_PACKS, "Без страны (автовыбор %d)", "🌐"):
        configs.append(cfg)
    for num, cfg in packs(hy2_nameless, HY2_MAX_PACKS, "Без страны (Hy2 автовыбор %d)", "🌐", min_extra=1):
        configs.append(cfg)
    return configs


def report(items):
    by_c = Counter(i["country"] for i in items if i["country"])
    nameless = [i for i in items if not i["country"]]
    kinds = Counter(i["ob"]["protocol"] for i in items)
    print("принято серверов: %d (%s)" % (len(items), ", ".join("%s %d" % kv for kv in kinds.most_common())))
    print("стран с серверами: %d, серверов без страны: %d" % (len(by_c), len(nameless)))
    print("по странам: " + ", ".join("%s %d" % (RU_NAMES.get(c, c), n) for c, n in by_c.most_common()))
    if SKIPPED:
        print("пропущено: " + ", ".join("%s %d" % (k, v) for k, v in SKIPPED.most_common()))
    lost = [c for c in LOST if c and c not in by_c]
    if lost:
        print("страны только среди пропущенных: " + ", ".join("%s %d" % (c, LOST[c]) for c in lost))
    heads = []
    for item in nameless:
        head = item["remark"][:30]
        if head not in heads:
            heads.append(head)
    if heads:
        print("серверы без страны, примеры названий: " + " | ".join(heads[:8]))


def main():
    black, white = [], []
    seen = set()
    for kind, name in SOURCES:
        try:
            links, base = fetch_list(name)
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
        print("%s: ссылок %d, принято %d (источник %s)" % (name, len(links), added, base.split("/")[2]))
    if not black and not white:
        raise RuntimeError("ни один список не скачался")
    configs = build(black, white)
    report(black + white)
    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(configs, fh, ensure_ascii=False, separators=(",", ":"))
    print("записей в подписке: %d" % len(configs))


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as exc:
        sys.exit(str(exc))