# --- Selector de idioma global ---
LANG = "en"  # por defecto


def select_language():
    global LANG
    print(
        """
=======================================
  Selecciona idioma / Choose language
=======================================
1) Español
2) English
"""
    )
    opt = input("Opción / Option [1/2]: ").strip()
    if opt == "2":
        LANG = "en"
    else:
        LANG = "es"


# -*- coding: utf-8 -*-
import os
import sys
import subprocess
import csv
import json
import time
import requests
from datetime import datetime, timezone
from urllib.parse import quote
import re
from tqdm import tqdm
import random
import ipaddress
import hashlib
from email.utils import parsedate_to_datetime
import glob
import gzip
import bisect
import pickle
import shutil


# === IOCs of Spades — MOTÖRHEAD EDITION ======================================
APP_NAME = "IOCs of Spades"
APP_VERSION = '2.0 "Lemmy"'
APP_SHORT = "IOS"
APP_COPY = " BORN TO SCAN // LIVE TO WIN"

# === Engine Notes =============================================================
# ACE OF SPADES • KAOS EDITION
# Anti‑MITM • Anti‑Zscaler • Anti‑ForwardTrust • Anti‑Mancos
# Full OSINT automation with VirusTotal, PassiveDNS & Tor support
# Booting IOCs of Spades 2.0 "Lemmy"...
# Loading core modules... Everything louder than everything else.
# Dedicated to Lemmy Kilmister — the loudest man that ever lived.

BANNER = r"""
╔══════════════════════════════════════════════════════╗
║                 IOCs OF SPADES                       ║
║         ♠  BORN TO SCAN // LIVE TO WIN  ♠            ║
║       EVERYTHING LOUDER THAN EVERYTHING ELSE         ║
╚══════════════════════════════════════════════════════╝
"""


# -------- Rutas / salidas
IP_LIST_FILE = "list_ip.txt"
DOMAIN_LIST_FILE = "list_domains.txt"
HASH_LIST_FILE = "list_hashes.txt"  # default; auto-detectaremos hash.txt / hashlist.txt
API_KEYS_FILE = "IOCS-apikeys.txt"
formatted_time = datetime.now().strftime("%Y%m%d-%H%M")
OUTPUT_IPS_CSV = f"{formatted_time}_ULTRA.csv"
OUTPUT_DOMAINS_CSV = f"{formatted_time}_DOMAINS.csv"
OUTPUT_FILES_CSV = f"{formatted_time}_DOMAINS_FILES.csv"


FAST_DOMAINS_MAX = int(os.getenv("FAST_DOMAINS_MAX", "0") or 0)  # 0 = sin límite
FAST_FILES_MAX = int(os.getenv("FAST_FILES_MAX", "0") or 0)


def resolve_ip_list_file(path: str = None):
    if path and os.path.exists(path):
        return path
    for cand in (IP_LIST_FILE, "iplist.txt", "list_ips.txt", "ips.txt"):
        if os.path.exists(cand):
            return cand
    return path or IP_LIST_FILE


# -------- Parámetros
IP_RES_LIMIT = 40
FAST_PROFILE = False
CKPT_FILE = ".iocs_checkpoint.json"

# ====== TOR / Onionoo ======
ONIONOO_BASE = "https://onionoo.torproject.org"
TOR_TIMEOUT = 18

# ====== Política VPN ======
# is_vpn se decide solo por etiqueta de VirusTotal (vt_ip_tags contains "vpn").
# Las heurísticas por owner quedan como pista separada en vpn_suspect.

# -------- Campos CSV (IPs)
CANON_IP_FIELDS = [
    "canon_indicator_type",
    "canon_verdict",
    "canon_threat_type_primary",
    "canon_threat_type_tags",
    "canon_confidence",
    "canon_is_vpn_confirmed",
    "canon_vpn_hint_owner",
    "canon_decision_trace",
]

ALL_FIELDS = [
    "owner",
    "asn",
    "asn_full",
    "CDIR",
    "country",
    "reputation",
    "malicious",
    "harmless",
    "suspicious",
    "undetected",
    "vendors_malicious",
    "vt_ip_tags",
    "vt_vpn",
    "vpn_suspect",
    "vt_categories",
    "vt_labels",
    "vt_crowdsourced_tags",
    "whois",
    "is_vpn",
    "vpn_source",
    "heuristic_tags",
    "cluster_flag",
    "cluster_reason",
    "c2_suspect",
    "c2_reason",
    "risk_score",
    "link",
    "gui",
    "tor_exit",
    "tor_source",
    "tor_nickname",
    "tor_fingerprint",
] + CANON_IP_FIELDS

VPN_KEYWORDS = [
    "vpn",
    "m247",
    "hostinger",
    "ovh",
    "choopa",
    "digitalocean",
    "contabo",
    "hetzner",
    "leaseweb",
    "linode",
    "scaleway",
    "voxility",
    "nforce",
    "private internet access",
    "nord",
    "expressvpn",
    "proton",
    "torguard",
    "cloud",
    "colo",
    "hosting",
]

HOSTING_CLUSTERS = [
    "OVH",
    "Hetzner",
    "Contabo",
    "M247",
    "DigitalOcean",
    "Linode",
    "Leaseweb",
    "Scaleway",
    "Vultr",
    "Choopa",
    "Akamai",
    "Cloudflare",
]

SUSPICIOUS_TLDS = [
    ".xyz",
    ".top",
    ".quest",
    ".click",
    ".monster",
    ".info",
    ".shop",
    ".link",
    ".cyou",
    ".icu",
    ".rest",
    ".cam",
    ".live",
]

# === PROGRESO Y RITMO =========================================================
try:
    from tqdm import tqdm
except Exception:

    def tqdm(iterable=None, **kwargs):
        return iterable if iterable is not None else []


# === SSL check (manual desde menú principal)
def auto_check_ssl():
    import ssl, socket

    if LANG == "en":
        print("\n=== VPN / SSL CHECK ===\n")
    else:
        print("\n=== CHEQUEO VPN / SSL ===\n")
    try:
        import ssl, socket

        ctx = ssl.create_default_context()
        with socket.create_connection(("www.google.com", 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname="www.google.com") as ssock:
                cert = ssock.getpeercert()
                issuer = cert.get("issuer")
                print("Issuer:", issuer)
                issuer_str = str(issuer).lower().replace(" ", "").replace("-", "")
                vpn_indicators = [
                    "kyndrylforwardtrust",
                    "forwardtrust",
                    "zscalerrootca",
                    "netskope",
                    "globalprotect",
                    "proxy",
                ]
                if any(ind in issuer_str for ind in vpn_indicators):
                    if LANG == "en":
                        print("\n⚠️ Corporate proxy / SSL Intercept detected.\n")
                    else:
                        print("\n⚠️ Se detecta proxy corporativo / SSL Intercept.\n")
                    return "mitm"
                else:
                    if LANG == "en":
                        print("\n✔ No SSL interception detected.\n")
                    else:
                        print("\n✔ No parece haber interceptación SSL.\n")
                    return "ok"
    except Exception as e:
        if LANG == "en":
            print(f"⚠ Possible SSL inspection (MITM) or error\nDetails: {e}")
        else:
            print(f"⚠ Posible inspección SSL (MITM) o error\nDetalle: {e}")
        return "mitm"


def _hb_every(i: int, step: int = 50) -> bool:
    """Heartbeat textual cada 'step' unidades."""
    return (i % step == 0) and i > 0


def _sleep_rate(last_ts: list, rpm: int = 4):
    """
    Control soft de ritmo tipo free-tier VT (~4/min). 'last_ts' es una lista [ts]
    que mutamos para conservar estado entre llamadas.
    """
    import time

    if not last_ts or last_ts[0] is None:
        last_ts[:] = [time.time()]
        return
    min_interval = 60.0 / max(1, rpm)
    elapsed = time.time() - last_ts[0]
    if elapsed < min_interval:
        time.sleep(min_interval - elapsed)
    last_ts[0] = time.time()


FRASES_EPICAS = [
    "🔥 The firewall's screaming for vengeance.",
    "🔊 Deafening logs: The noise is the signal.",
    "👊 Dark traffic crushed by the Iron Fist.",
    "💨 Packet sniffing at max volume.",
    "🤘 The IDS is vibrating. Good job, bastard.",
    "⛓️ Heavy machinery: The SIEM gears are grinding fine.",
    "🛰️ SIEM satellites aligned: The Chase is on.",
    "🪢 Threat intel threads woven into a noose.",
    "🃏 The IR compass points to the Joker.",
    "⚗️ Data Alchemy: Turning noise into pure Iron.",
    "💰 Enrichment pipeline: Coming back with Silver and Gold.",
    "🗜️ Relationship map reveals the Bastard’s lair.",
    "🔇 Correlation sirens silenced. Target destroyed.",
    "💡 Artifacts confessed under the spotlight.",
    "🚬 Fire contained. The Playbooks are smoking.",
    "🎯 IOC hunted with a clean shot to the head.",
    "🗡️ Rule tuning: Sharper than a switchblade.",
    "🪓 The IR Axe cuts through false-positives without mercy.",
    "🛡️ YARA agents: No Sleep 'til Detection.",
    "🦴 Malware signature exposed. Dead men tell no tales.",
    "🏰 The perimeter bastion holds the line.",
    "🦾 The hash fits. The vault of truth is open.",
    "🧬 Genetic malware mapping: No place to hide.",
    "🎲 The only card you need is the IOC of Spades."
    "♠ Ace up: the IOC of Spades cuts through the noise.",
    "⚡ Overkill mode: EDR at full throttle, no prisoners.",
    "✈️ Bomber run inbound: alerts on target, payload is containment.",
    "👊 Iron Fist hardening engaged: perimeter stands unbroken.",
    "🛠 Damage Case closed: root cause nailed to the wall.",
    "🛡 Killed by Detection? Not today—blocked at the edge.",
    "🚚 We are the IR crew: playbooks rolling, roads cleared.",
    "🔩 Fast & Loose tuning: false positives throttled.",
    "🛰 Road crew for logs: shipping telemetry like a convoy.",
    "🧨 Bomber lock acquired: C2 beacon knocked from the sky.",
    "🔥 Born to scan, live to win: pipeline green across the board.",
    "🎛 Overkill suppressors armed: signal-to-noise ratio in our favor.",
    "🕵️ Damage Case reopened? Evidence says no—chain of custody intact.",
    "🧲 Threat intel magnets on: TTPs snap into place.",
    "🧪 Forge the rules: Sigma, YARA, Suricata—steel and sparks.",
    "🧷 ATT&CK map stitched tight—no gaps in this patchwork.",
    "🏴‍☠️ Black leather playbooks: lean, loud, and lethal.",
    "📡 Bomber radar: DNS sinkholes lit, sink rate rising.",
    "🧯 Overkill containment: blast radius reduced to zero.",
    "🧰 Toolbelt check: Zeek, PCAP, EDR—everything within reach.",
    "🩻 Memory dump autopsy: DLLs confess under UV light.",
    "🎚 No Sleep ’til Triage: queues empty, dashboards calm.",
    "🧨 Alert detonated in the sandbox—shrapnel tagged as IoCs.",
    "🧭 IR compass points true north—no drift, no doubt.",
    "🔐 Vault of truth: hash verified, signature aligned.",
    "🧬 Genetic malware lineage mapped—family tree bare-boned.",
    "🧱 Another day, another fortress: bastion keeps the line.",
    "📈 Telemetry riff: NetFlow grooves, anomalies off-tempo.",
    "🚀 Rapid-Fire enrichment: context loaded at ludicrous speed.",
    "🎯 Ace of Spades verdict: clean shot, confirmed takedown.",
    "🗜 Correlation engine: clamps tight, case pressure stable.",
    "🛞 Road-crew engineering: SIEM gears oiled, no squeal.",
    "🗡 Switchblade rules: sharp edges only where they matter.",
    "🛰 Satellites aligned: hunting orbit locked on the mark.",
    "🛠 Damage Case toolkit: artifact → timeline → motive.",
    "🧨 Bomber escort: SOAR fighters automate the kill chain.",
    "🌪 Overkill on IOC pivoting: graph explodes in clarity.",
    "📻 Radio on: IDS hums, WAF growls, everyone in tune.",
    "🧲 CTI magnets pull cliques together—clusters speak loud.",
    "🧭 Map-and-compass DFIR: no GPS, still on target.",
    "🪓 False-positive woodpile—split, stacked, and burned.",
    "🕸 Lace the net: eBPF hooks catch what crawls underneath.",
    "🛡 Hash of Spades: one match to rule them all.",
    "🛩 Bomber’s eye: TLS fingerprints painted on the sky.",
    "🧩 Puzzle complete: mutex, pipes, and services snapped in.",
    "♠ All or nothing: play the spade and fold the threat.",
    "📐 Rulesmithing session: signals forged on the anvil.",
    "🧯 Hot swap playbooks—incident cools to a whisper.",
    "🗂 Casefile riff: artifacts in order, story in 4/4 time.",
    "🧨 Detonation diary: sandbox confessions read at dawn.",
    "🧵 Threads pulled—malware’s sweater undone.",
    "🔩 Iron torque on hardening: bolts clicked to spec.",
    "🔎 Peeking under the hood: kernel traces don’t lie.",
    "🔒 Bastion heartbeat steady—keys counted, trust measured.",
    "🧠 ML behaves today—no hallucinations, pure precision.",
    "🎚 Noise floor down: decibels off, detections on.",
    "📦 IOC cargo secured—shipping to blocklists worldwide.",
    "🧭 Pivot with purpose: domains, IPs, hashes—ace every hop.",
    "🧪 Alchemy lab: noise into signal, signal into action.",
    "🛰 Uplink clean—CTI beamed straight to the trigger stack.",
    "🧱 WAF riffs palm-muted: silent but deadly.",
    "🕶 Cool as chrome: EDR drivers standing guard.",
    "🧨 IR artillery: quick isolate, faster remediate.",
    "🧿 Beacon evil-eye’d—no callback, no encore.",
    "📡 Bomber triangulation: geo, ASN, and infra—dead center.",
    "🗡 Spade first: carve the truth from the logstone.",
    "🕰 Stone Dead Forever? Not while CRON says patch now.",
    "🧲 Pull the pin: Intel fuse lit—IOCs in formation.",
    "🎛 Master bus green: pipeline tight, latency low.",
    "🛠 Damage Case notes signed—case closed, lessons learned.",
    "🖤 Loud and clear: SOC runs on grit, caffeine, and spades.",
    "🗡️ Sharper than a switchblade. IOC neutralized.",
    "🛡️ The Iron Fist is coming down on your C2.",
    "🔥 I'm the one who sees. You're the one who dies.",
    "💣 Bomber! Dropping hashes like 1000lb payloads.",
    "🥃 Stay clean? No, we stay dirty and we stay loud.",
    "🦅 Vulture Intelligence: Picking the bones of the malware.",
    "🎰 Ace of Spades found. Your luck just ran out.",
    "🤘 Deafening detection: The only way to scan.",
    "⛓️ Heavy machinery is grinding your botnet to dust.",
    "🎸 Fast and loose. Just the way the IR likes it.",
    "🏍️ Kickstart the scan. Full throttle or nothing.",
    "⚡ 110% Overdrive. Breaking the data barrier.",
    "🌪️ Leaving the road crew behind. Moving at lightspeed.",
    "🔌 We are the road crew. Setting up the stage for the hunt.",
    "🥁 Drumming through the packets. Keeping the beat.",
    "🥃 The road crew is drunk. Connection failed.",
    "🚫 Everything louder than everything else... but no data.",
    "🥀 Killed by Death. The process is a corpse now.",
    "⛈️ Too late, too late! The timeout caught us.",
    "📉 Born to lose. The database just quit the band.",
    "⚙️ Gears jammed. Someone poured whiskey in the SIEM.",
    "🚑 Emergency! The logs are bleeding out.",
    "🚬 We don't want to live forever. Neither does this process.",
    "🔇 Silent night... too quiet. Where's the damn noise?",
    "🧩 Overkill? No, just a total system breakdown.",
    "🛰️ Lost in the ozone. The API is light-years away.",
    "🛠️ Broken! Like a cheap guitar in a bar fight.",
    "🍺 Too much Jack, not enough Data. Try again, bastard.",
    "🚪 Get back in line! Access denied.",
    "🦴 No class. This input file is a disgrace.",
]


def frase_epica_random():
    return random.choice(FRASES_EPICAS)


# === Utilidades ===
# === TTLs con override por variables de entorno (segundos) ===


def _cache_bin_path(cache_key: str, ext: str = "bin"):
    safe = hashlib.sha1(cache_key.encode("utf-8", errors="ignore")).hexdigest()
    return os.path.join(CACHE_DIR, f"{safe}.{ext}")


def fetch_feed_cached_binary(url: str, cache_key: str, ttl_s: int, timeout_s: int = 25):
    """
    Igual que fetch_feed_cached_text, pero devuelve bytes.
    Usa If-Modified-Since si hay meta previa.
    """
    _ensure_cache_dir()
    meta = _load_meta(cache_key)
    now_ts = int(time.time())
    bin_path = _cache_path(cache_key, "bin")
    data = None
    if os.path.exists(bin_path):
        try:
            with open(bin_path, "rb") as fh:
                data = fh.read()
        except Exception:
            data = None
    fetched_at = meta.get("fetched_at", 0)

    # Cache vigente
    if data and (now_ts - fetched_at) < ttl_s:
        return ("cached", data)

    headers = {}
    if "last_modified_hdr" in meta:
        headers["If-Modified-Since"] = meta["last_modified_hdr"]

    try:
        r = requests.get(url, headers=headers, timeout=timeout_s)
        if r.status_code == 304 and data:
            meta["fetched_at"] = now_ts
            _save_meta(cache_key, meta)
            return ("not-modified", data)
        elif r.status_code == 200:
            bin_data = r.content
            with open(bin_path, "wb") as fh:
                fh.write(bin_data)
            lm_hdr = r.headers.get("Last-Modified") or ""
            etag = r.headers.get("ETag") or ""
            meta.update(
                {"fetched_at": now_ts, "last_modified_hdr": lm_hdr, "etag": etag}
            )
            _save_meta(cache_key, meta)
            return ("fresh", bin_data)
        else:
            if data:
                return ("stale-offline", data)
            return ("miss", b"")
    except Exception:
        if data:
            return ("stale-offline", data)
        return ("miss", b"")


# ------------------ IPtoASN index (TSV Gzip → índice en memoria) -------------------

_IP2ASN_IDX = None  # (starts[], ends[], asns[]) + metadata
_IP2ASN_PICKLE = "ip2asn_v4.idx.pkl"  # nombre del índice serializado


def _ip2int(ip: str) -> int:
    return int(ipaddress.ip_address(ip))


def load_ip2asn_index():
    """
    Carga/crea un índice rápido desde el TSV GZIP de IPtoASN.
    Devuelve True si el índice está listo.
    """
    global _IP2ASN_IDX
    _ensure_cache_dir()

    # 1) Intentar cargar índice serializado si existe
    idx_path = os.path.join(CACHE_DIR, _IP2ASN_PICKLE)
    if os.path.exists(idx_path):
        try:
            with open(idx_path, "rb") as fh:
                _IP2ASN_IDX = pickle.load(fh)
            return True
        except Exception:
            _IP2ASN_IDX = None  # forzamos rebuild

    # 2) Asegurar TSV.gz en caché
    CACHE_KEY = "ip2asn-v4.tsv.gz"
    status, gz_bytes = fetch_feed_cached_binary(
        IP2ASN_V4_URL, CACHE_KEY, ttl_s=TTL_IP2ASN
    )
    if status in ("miss",) or not gz_bytes:
        print(
            "[IP2ASN] Could not retrieve dataset (miss)."
            if LANG == "en"
            else "[IP2ASN] No se pudo obtener el dataset (miss)."
        )
        return False
    if status in ("fresh", "not-modified"):
        print(f"[IP2ASN] {status}.")
    elif status == "cached":
        print(
            "[IP2ASN] Using current cache."
            if LANG == "en"
            else "[IP2ASN] usando caché vigente."
        )
    else:
        print(
            "[IP2ASN] Offline mode (stale cache)."
            if LANG == "en"
            else "[IP2ASN] sin red (caché antigua)."
        )

    # 3) Parsear TSV.gz → arrays ordenados por start_int
    try:
        buf = gzip.decompress(gz_bytes)
    except Exception:
        print(
            "[IP2ASN] Error decompressing TSV.gz."
            if LANG == "en"
            else "[IP2ASN] Error descomprimiendo TSV.gz."
        )
        return False

    starts, ends, asns = [], [], []
    lines = buf.splitlines()
    bad = 0
    for ln in lines:
        ln = ln.strip()
        if not ln:
            continue
        try:
            # Formato: start_ip \t end_ip \t asn \t cc \t desc  (IPv4)  [1](https://iptoasn.com/)
            parts = ln.split(b"\t")
            if len(parts) < 3:
                continue
            start_ip = parts[0].decode("ascii", "ignore")
            end_ip = parts[1].decode("ascii", "ignore")
            asn_raw = parts[2].decode("ascii", "ignore")
            # Algunos rangos pueden tener asn=0 (unannounced); lo guardamos como 0
            asn = int(asn_raw) if asn_raw.isdigit() else 0
            starts.append(_ip2int(start_ip))
            ends.append(_ip2int(end_ip))
            asns.append(asn)
        except Exception:
            bad += 1
            continue

    # ordenar por start
    order = sorted(range(len(starts)), key=lambda i: starts[i])
    starts = [starts[i] for i in order]
    ends = [ends[i] for i in order]
    asns = [asns[i] for i in order]
    _IP2ASN_IDX = (starts, ends, asns, {"bad_lines": bad, "entries": len(starts)})

    # 4) Serializar índice para arranque más rápido la próxima vez
    try:
        with open(idx_path, "wb") as fh:
            pickle.dump(_IP2ASN_IDX, fh, protocol=pickle.HIGHEST_PROTOCOL)
    except Exception:
        pass

    if LANG == "en":
        print(f"[IP2ASN] Index ready: {len(starts)} ranges (invalid lines: {bad}).")
    else:
        print(f"[IP2ASN] Índice listo: {len(starts)} rangos (líneas inválidas: {bad}).")
    return True


def ip2asn_lookup(ip: str):
    """
    Búsqueda de ASN para una IP usando el índice IPtoASN (si está cargado).
    Devuelve int ASN o None si no hay dato (o si el ASN es 0 = unannounced).
    """
    global _IP2ASN_IDX
    if not _IP2ASN_IDX:
        return None

    starts, ends, asns, _meta = _IP2ASN_IDX
    try:
        x = _ip2int(ip)  # '1.2.3.4' -> entero
    except Exception:
        return None

    # Encuentra el rango cuyo start <= x (bisect da la primera pos > x, menos 1)
    i = bisect.bisect_right(starts, x) - 1
    if 0 <= i < len(starts) and starts[i] <= x <= ends[i]:
        a = asns[i]
        return a if isinstance(a, int) and a != 0 else None
    return None


def _get_int_env(name: str, default_val: int) -> int:
    try:
        raw = os.getenv(name, "")
        val = int(raw.strip()) if raw else default_val
        return val if val > 0 else default_val
    except Exception:
        return default_val


# TTL por defecto (si no hay env)
DEFAULT_TTL_ASNDROP = 24 * 3600
DEFAULT_TTL_DSHIELD = 60 * 60
DEFAULT_TTL_BLOCKLIST = 60 * 60
DEFAULT_TTL_OPENPHISH = 12 * 3600

# TTL efectivos (con override por variables de entorno)
TTL_ASNDROP = _get_int_env("TTL_ASNDROP_S", DEFAULT_TTL_ASNDROP)
TTL_DSHIELD = _get_int_env("TTL_DSHIELD_S", DEFAULT_TTL_DSHIELD)
TTL_BLOCKLIST = _get_int_env("TTL_BLOCKLISTDE_S", DEFAULT_TTL_BLOCKLIST)
TTL_OPENPHISH = _get_int_env("TTL_OPENPHISH_S", DEFAULT_TTL_OPENPHISH)

# === IPtoASN (dataset TSV GZIP) ===============================================
IP2ASN_V4_URL = "https://iptoasn.com/data/ip2asn-v4.tsv.gz"  # IPv4 → ASN (TSV .gz)  [1](https://iptoasn.com/)


def _get_days_env(name: str, default_days: int) -> int:
    try:
        raw = os.getenv(name, "")
        val = int(raw.strip()) if raw else default_days
        return val if val > 0 else default_days
    except Exception:
        return default_days


DEFAULT_TTL_IP2ASN_DAYS = 7
TTL_IP2ASN = (
    _get_days_env("TTL_IP2ASN_DAYS", DEFAULT_TTL_IP2ASN_DAYS) * 24 * 3600
)  # en segundos


def human_size(num):
    if num in (None, "", 0, "0"):
        return ""
    try:
        n = float(num)
    except:
        return ""
    units = ["bytes", "KB", "MB", "GB", "TB", "PB"]
    i = 0
    while n >= 1024 and i < len(units) - 1:
        n /= 1024.0
        i += 1
    return f"{int(n)} {units[i]}" if i == 0 else f"{n:.1f} {units[i]}"


_IP4_REGEX = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def _extract_ipv4_candidates(line: str):
    return _IP4_REGEX.findall(line)


def _is_public_ipv4(ip_str: str, allow_private: bool = False):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False, "malformed"
    if ip.version != 4:
        return False, "ipv6_not_supported"
    if allow_private:
        return True, None
    if ip.is_global:
        return True, None
    if ip.is_private:
        return False, "private"
    if ip.is_loopback:
        return False, "loopback"
    if ip.is_multicast:
        return False, "multicast"
    if ip.is_link_local:
        return False, "link_local"
    if ip.is_reserved:
        return False, "reserved"
    return False, "non_global"


def filter_valid_public_ips(raw_lines, allow_private: bool = False):
    seen = set()
    valid = []
    skipped = []
    for line in raw_lines:
        for cand in _extract_ipv4_candidates(line):
            if cand in seen:
                continue
            seen.add(cand)
            ok, reason = _is_public_ipv4(cand, allow_private=allow_private)
            if ok:
                valid.append(cand)
            else:
                skipped.append((cand, reason))
    return valid, skipped


# --- Entrada robusta (maneja EOF y Ctrl+C) ------------------------------------
IS_TTY = sys.stdin.isatty() if sys.stdin else False


def safe_input(
    prompt: str, default: str = "", on_interrupt: str = "back"
) -> str | None:
    """
    Devuelve:
      - str con lo tecleado (o default si vacío)
      - None si el usuario interrumpe (Ctrl+C) y on_interrupt == "back"
    Comportamiento:
      - En entorno NO interactivo (stdin no tty) devuelve 'default' sin pedir nada.
      - EOF (Ctrl+Z + Enter en Windows): usa 'default' y notifica suave.
      - Ctrl+C: vuelve hacia atrás si on_interrupt="back" (None), o default si "default".
    """
    if not IS_TTY:
        if LANG == "en":
            print(f"\n[IO] Non-interactive environment → using default: {default}")
        else:
            print(
                f"\n[IO] Entorno no interactivo → usando valor por defecto: {default}"
            )
        return default
    try:
        s = input(prompt)
        return (s.strip() if s is not None else "") or default
    except EOFError:
        if LANG == "en":
            print("\n[IO] EOF received → using default.")
        else:
            print("\n[IO] EOF recibido → usando valor por defecto.")
        return default
    except KeyboardInterrupt:
        if LANG == "en":
            print("\n[IO] User cancelled input.")
        else:
            print("\n[IO] Entrada cancelada por usuario.")
        return None if on_interrupt == "back" else default


# === IO y checkpoint
def read_lines(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [x.strip() for x in f if x.strip()]


# Checkpoint por modo: cada tipo de proceso usa su propio fichero para evitar
# que procesos paralelos (IPs, DOMAINS, FILES…) se sobreescriban entre sí.
_CKPT_BY_MODE: dict[str, str] = {
    "ips":           ".iocs_ckpt_ips.json",
    "ips_tor":       ".iocs_ckpt_ips.json",
    "ip_osint":      ".iocs_ckpt_ips.json",
    "domains":       ".iocs_ckpt_domains.json",
    "domains_osint": ".iocs_ckpt_domains.json",
    "domains_list":  ".iocs_ckpt_domains.json",
    "files":         ".iocs_ckpt_files.json",
    "hash_list":     ".iocs_ckpt_hash.json",
    "hash_osint":    ".iocs_ckpt_hash.json",
}
_ALL_CKPT_FILES: list[str] = list(dict.fromkeys(_CKPT_BY_MODE.values())) + [CKPT_FILE]


def _ckpt_file_for_mode(mode: str) -> str:
    return _CKPT_BY_MODE.get(mode, CKPT_FILE)


def save_ckpt(data: dict):
    try:
        path = _ckpt_file_for_mode(data.get("mode", ""))
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
    except Exception:
        pass


def load_ckpt(mode: str | None = None):
    """Carga checkpoint. Con mode, busca en el fichero específico de ese modo.
    Sin mode, devuelve el más reciente de todos los ficheros disponibles."""
    try:
        if mode is not None:
            path = _ckpt_file_for_mode(mode)
            if not os.path.exists(path):
                path = CKPT_FILE  # fallback legacy
            if not os.path.exists(path):
                return None
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        # Sin mode: devuelve el más reciente entre todos los ficheros
        best, best_ts = None, -1.0
        for f in _ALL_CKPT_FILES:
            if not os.path.exists(f):
                continue
            try:
                with open(f, "r", encoding="utf-8") as fh:
                    d = json.load(fh)
                ts = float(d.get("timestamp", 0))
                if ts > best_ts:
                    best_ts, best = ts, d
            except Exception:
                pass
        return best
    except Exception:
        return None


def _list_available_ckpts(modes: list[str] | None = None) -> list[dict]:
    """Devuelve todos los checkpoints guardados, ordenados por timestamp desc.
    Si modes se especifica, solo devuelve los que tengan un modo de esa lista."""
    result = []
    for f in _ALL_CKPT_FILES:
        if not os.path.exists(f):
            continue
        try:
            with open(f, "r", encoding="utf-8") as fh:
                d = json.load(fh)
            if modes is None or d.get("mode") in modes:
                result.append(d)
        except Exception:
            pass
    result.sort(key=lambda d: float(d.get("timestamp", 0)), reverse=True)
    return result


def clear_ckpt():
    try:
        removed = 0
        for f in _ALL_CKPT_FILES:
            if os.path.exists(f):
                os.remove(f)
                removed += 1
        if removed:
            print("[CKPT] Cleared." if LANG == "en" else "[CKPT] Borrado.")
    except Exception:
        pass


def refresh_osint_feeds_now():
    if LANG == "en":
        print("\n=== REFRESH OSINT FEEDS NOW ===")
    else:
        print("\n=== REFRESCAR FEEDS OSINT AHORA ===")

    # Blindaje: si OPENPHISH_FEED_URL no existe aún, usa el valor por defecto
    openphish_url = globals().get(
        "OPENPHISH_FEED_URL", "https://openphish.com/feed.txt"
    )

    pairs = [
        (DSHIELD_BLOCK_URL, "dshield_block.txt"),
        (BLOCKLISTDE_ALL_URL, "blocklistde_all.txt"),
        (SPAMHAUS_ASNDROP_URL, "spamhaus_asndrop.json"),
        (openphish_url, "openphish_feed.txt"),
    ]
    refreshed = 0
    for url, key in pairs:
        # ttl_s=0 = forzar revalidación condicional (If-Modified-Since)
        status, _ = fetch_feed_cached_text(url, key, ttl_s=0)
        print(f"[REFRESH] {key}: {status}")
        if status in ("fresh", "not-modified"):
            refreshed += 1
    if LANG == "en":
        print(f"[i] Feeds OK/not-modified: {refreshed} / {len(pairs)}\n")
    else:
        print(f"[i] Feeds OK/no modificados: {refreshed} / {len(pairs)}\n")


def quick_osint_probe(ips_to_check):
    """
    Comprobación directa contra feeds ya cargados, para ver si una IP
    marcaría DShield/blocklist.de/ASN-DROP según lo que tenemos en caché.
    """
    print("\n=== Quick OSINT Probe ===")
    dshield = load_dshield_ranges()
    blkde = load_blocklistde_set()
    asns = load_asn_drop_set()

    # Mapa IP->ASN (si existe ULTRA.csv con asn)
    ip2asn = {}
    try:
        ip2asn = load_ip_asn_from_last_ultra_csv()
    except Exception:
        ip2asn = {}

    for ip in ips_to_check:
        ip = ip.strip()
        if not ip:
            continue
        # DShield
        dshield_hit = any(ip_in_range(ip, start, end) for (start, end, _) in dshield)
        # blocklist.de
        blk_hit = ip in blkde
        # ASN-DROP (solo si tenemos ASN de esa IP)
        asn_hit = False
        if ip2asn and asns:
            a = ip2asn.get(ip)
            asn_hit = isinstance(a, int) and a in asns

        print(
            f"{ip:>15}  | DShield:{'YES' if dshield_hit else 'no '}  "
            f"blocklist.de:{'YES' if blk_hit else 'no '}  "
            f"ASN-DROP:{'YES' if asn_hit else 'no '}"
        )


def export_osint_hits_only():
    import glob, csv, os

    cands = sorted(glob.glob("*_ULTRA_OSINT.csv"))
    if not cands:
        print(
            "⚠ No ULTRA_OSINT.csv found to filter."
            if LANG == "en"
            else "⚠ No hay ULTRA_OSINT.csv para filtrar."
        )
        return

    src = cands[-1]
    dst = src.replace("_ULTRA_OSINT.csv", "_ULTRA_OSINT_hits.csv")

    rows = kept = 0
    k_dshield = k_blk = k_asn = 0

    with open(src, "r", encoding="utf-8", newline="") as f, open(
        dst, "w", encoding="utf-8", newline=""
    ) as g:
        r = csv.DictReader(f)
        # sanity mínimo de cabecera
        required = {
            "ip",
            "asn_drop",
            "asn_drop_source",
            "bl_dshield_24",
            "bl_dshield_targets",
            "bl_blocklistde_48h",
        }
        missing = [c for c in required if c not in r.fieldnames]
        if missing:
            print(
                f"⚠ Missing headers in {src}: {missing}. Partial export."
                if LANG == "en"
                else f"⚠ Cabeceras faltantes en {src}: {missing}. Export parcial."
            )
        w = csv.DictWriter(g, fieldnames=r.fieldnames)
        w.writeheader()

        for row in r:
            rows += 1
            d = row.get("bl_dshield_24") == "yes"
            b = row.get("bl_blocklistde_48h") == "yes"
            a = row.get("asn_drop") == "yes"
            if d or b or a:
                w.writerow(row)
                kept += 1
                k_dshield += 1 if d else 0
                k_blk += 1 if b else 0
                k_asn += 1 if a else 0

    try:
        size = os.path.getsize(dst)
    except Exception:
        size = 0

    print(
        f"[hits-only] {kept}/{rows} rows → {dst}  ({size} bytes)"
        if LANG == "en"
        else f"[hits-only] {kept}/{rows} filas → {dst}  ({size} bytes)"
    )
    print(f"[hits-only] DShield:{k_dshield}  blocklist.de:{k_blk}  ASN-DROP:{k_asn}")


# === VT helpers
def vt_get_ip(ip, key):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{quote(ip)}"
    headers = {"accept": "application/json", "x-apikey": key}
    timeout = 12 if FAST_PROFILE else 25
    return requests.get(url, headers=headers, timeout=timeout)


def vt_fetch_ip_resolutions(
    ip: str, api_key: str, cursor: str = None, limit: int = 40, timeout_s: int = 15
):
    """
    Devuelve (items, next_cursor, status, err_msg) para /ip_addresses/{ip}/resolutions.
    """
    base = "https://www.virustotal.com/api/v3"
    url = f"{base}/ip_addresses/{ip}/resolutions"
    params = {"limit": min(40, max(1, int(limit)))}
    if cursor:
        params["cursor"] = cursor

    headers = {
        "x-apikey": api_key,
        "User-Agent": "iocsofspades/domains-export",
        "Accept": "application/json",
    }

    try:
        r = requests.get(url, headers=headers, params=params, timeout=timeout_s)
        if r.status_code == 200:
            j = r.json()
            items = j.get("data") or []
            # cursor puede venir en meta.cursor o en links.next
            nxt = None
            meta = j.get("meta") or {}
            if "cursor" in meta:
                nxt = meta.get("cursor")
            else:
                ln = (j.get("links") or {}).get("next") or ""
                if "cursor=" in ln:
                    try:
                        from urllib.parse import parse_qs, urlparse

                        qs = parse_qs(urlparse(ln).query)
                        nxt = (qs.get("cursor") or [None])[0]
                    except Exception:
                        nxt = None
            return (items, nxt, 200, "")
        else:
            # Detalle de error si existe
            msg = ""
            try:
                j = r.json()
                msg = ((j.get("error") or {}).get("message")) or ""
            except Exception:
                msg = r.text[:200]
            return ([], None, r.status_code, msg)
    except Exception as e:
        return ([], None, 599, str(e))


def vt_fetch_domain_report(domain, key):
    url = f"https://www.virustotal.com/api/v3/domains/{quote(domain)}"
    headers = {"accept": "application/json", "x-apikey": key}
    timeout = 12 if FAST_PROFILE else 25
    return requests.get(url, headers=headers, timeout=timeout)


def vt_fetch_domain_files(domain, key, rel="communicating_files", cursor=None):
    url = f"https://www.virustotal.com/api/v3/domains/{quote(domain)}/relationships/{rel}?limit=40"
    if cursor:
        url += f"&cursor={quote(cursor)}"
    headers = {"accept": "application/json", "x-apikey": key}
    timeout = 12 if FAST_PROFILE else 25
    return requests.get(url, headers=headers, timeout=timeout)


def vt_get_file(hash_id, key):
    url = f"https://www.virustotal.com/api/v3/files/{quote(hash_id)}"
    headers = {"accept": "application/json", "x-apikey": key}
    timeout = 12 if FAST_PROFILE else 25
    return requests.get(url, headers=headers, timeout=timeout)


# --- Fuentes OSINT (IPs / Dominios) ---
DSHIELD_BLOCK_URL = "https://feeds.dshield.org/block.txt"
BLOCKLISTDE_ALL_URL = "https://lists.blocklist.de/lists/all.txt"
SPAMHAUS_ASNDROP_URL = "https://www.spamhaus.org/drop/asndrop.json"

# (NUEVO) OpenPhish community feed (no comercial)
OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"


def load_asn_drop_set():
    """
    Carga Spamhaus ASN-DROP desde caché (o red) y devuelve un set de enteros ASN.
    Soporta:
      - NDJSON (una línea JSON con campo 'asn' por línea)
      - JSON completo (lista/objeto)
      - Texto libre con 'AS 12345'
    """
    CACHE_KEY = "spamhaus_asndrop.json"
    status, text = fetch_feed_cached_text(
        SPAMHAUS_ASNDROP_URL, CACHE_KEY, ttl_s=TTL_ASNDROP
    )
    if status in ("miss",) or not text:
        print(
            "[OSINT] ASN‑DROP: no data (miss)."
            if LANG == "en"
            else "[OSINT] ASN-DROP: sin datos (miss)."
        )
        return set()
    if status in ("fresh", "not-modified"):
        print(f"[OSINT] ASN-DROP: {status}.")
    elif status == "cached":
        print(
            "[OSINT] ASN‑DROP: using current cache."
            if LANG == "en"
            else "[OSINT] ASN-DROP: usando caché vigente."
        )
    else:
        print(
            "[OSINT] ASN‑DROP: offline (stale cache)."
            if LANG == "en"
            else "[OSINT] ASN-DROP: sin red (caché antigua)."
        )

    out = set()
    txt = text.strip()

    # 1) Intento JSON completo (si no es NDJSON)
    try:
        j = json.loads(txt)
        items = j if isinstance(j, list) else (j.get("data") or j.get("asns") or [])
        for it in items or []:
            val = (
                it.get("asn") or it.get("AS") or it.get("number") or it.get("id") or ""
            )
            if isinstance(val, int):
                out.add(val)
                continue
            if isinstance(val, str):
                m = re.search(r"\d+", val)
                if m:
                    out.add(int(m.group(0)))
        if out:
            return out
    except Exception:
        pass

    # 2) NDJSON o texto por línea
    for line in txt.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # NDJSON: JSON por línea
        if line.startswith("{") and line.endswith("}"):
            try:
                obj = json.loads(line)
                val = (
                    obj.get("asn")
                    or obj.get("AS")
                    or obj.get("number")
                    or obj.get("id")
                    or ""
                )
                if isinstance(val, int):
                    out.add(val)
                    continue
                if isinstance(val, str):
                    m = re.search(r"\d+", val)
                    if m:
                        out.add(int(m.group(0)))
                    continue
            except Exception:
                pass
        # Texto con 'AS 12345'
        m = re.search(r"\bAS\s*([0-9]+)\b", line, flags=re.I)
        if m:
            out.add(int(m.group(1)))

    return out


def load_dshield_ranges():
    CACHE_KEY = "dshield_block.txt"
    status, text = fetch_feed_cached_text(
        DSHIELD_BLOCK_URL, CACHE_KEY, ttl_s=TTL_DSHIELD
    )
    if status in ("miss",) or not text:
        print(
            "[OSINT] DShield: no data (miss)."
            if LANG == "en"
            else "[OSINT] DShield: sin datos (miss)."
        )
        return []
    if status in ("fresh", "not-modified"):
        print(f"[OSINT] DShield: {status}.")
    elif status == "cached":
        print(
            "[OSINT] DShield: using current cache."
            if LANG == "en"
            else "[OSINT] DShield: usando caché vigente."
        )
    else:
        print(
            "[OSINT] DShield: offline (stale cache)."
            if LANG == "en"
            else "[OSINT] DShield: sin red (caché antigua)."
        )

    nets = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        start, end, subnet, targets = parts[0], parts[1], parts[2], parts[3]
        try:
            nets.append((start, end, int(targets)))
        except:
            continue
    return nets


def load_blocklistde_set():
    CACHE_KEY = "blocklistde_all.txt"
    status, text = fetch_feed_cached_text(
        BLOCKLISTDE_ALL_URL, CACHE_KEY, ttl_s=TTL_BLOCKLIST
    )
    if status in ("miss",) or not text:
        print(
            "[OSINT] blocklist.de: no data (miss)."
            if LANG == "en"
            else "[OSINT] blocklist.de: sin datos (miss)."
        )
        return set()
    if status in ("fresh", "not-modified"):
        print(f"[OSINT] blocklist.de: {status}.")
    elif status == "cached":
        print(
            "[OSINT] blocklist.de: using current cache."
            if LANG == "en"
            else "[OSINT] blocklist.de: usando caché vigente."
        )
    else:
        print(
            "[OSINT] blocklist.de: offline (stale cache)."
            if LANG == "en"
            else "[OSINT] blocklist.de: sin red (caché antigua)."
        )

    s = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _IP4_REGEX.search(line)
        if not m:
            continue
        try:
            ip_norm = str(ipaddress.ip_address(m.group(0)))  # Canoniza la IP
            s.add(ip_norm)
        except Exception:
            continue
    return s


def ip_in_range(ip_str, start, end):
    try:
        ip = ipaddress.ip_address(ip_str)
        s = ipaddress.ip_address(start)
        e = ipaddress.ip_address(end)
        return s <= ip <= e
    except Exception:
        return False


def load_ip_asn_from_last_ultra_csv():
    """
    Busca el último *_ULTRA.csv (modo VT) y mapea IP -> ASN (int).
    Devuelve dict { '1.2.3.4': 13335, ... }
    """
    try:
        cands = sorted(glob.glob("*_ULTRA.csv"))
        if not cands:
            print(
                "[OSINT] No previous *_ULTRA.csv found to extract ASNs (VT)."
                if LANG == "en"
                else "[OSINT] No hay *_ULTRA.csv previo para extraer ASNs (VT)."
            )
            return {}
        ultra = cands[-1]
        mapping = {}
        with open(ultra, "r", encoding="utf-8", errors="ignore", newline="") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                ip = (row.get("ip") or "").strip()
                asn_raw = (row.get("asn") or "").strip()
                if not ip:
                    continue
                if asn_raw:
                    try:
                        n = int(asn_raw)
                        if n > 0:
                            mapping[ip] = n
                            continue
                    except:
                        pass
                # fallback: intentar extraer desde asn_full "AS 12345 (...)"
                asn_full = row.get("asn_full") or ""
                m = re.search(r"\bAS\s*([0-9]+)\b", asn_full, flags=re.I)
                if m:
                    try:
                        mapping[ip] = int(m.group(1))
                    except:
                        pass
        print(
            f"[OSINT] ASN map from {ultra}: {len(mapping)} IPs with ASN."
            if LANG == "en"
            else f"[OSINT] ASN map desde {ultra}: {len(mapping)} IPs con ASN."
        )
        return mapping
    except Exception as e:
        print(
            f"[OSINT] Error reading *_ULTRA.csv for ASN: {e}"
            if LANG == "en"
            else f"[OSINT] Error leyendo *_ULTRA.csv para ASN: {e}"
        )
        return {}


def run_ip_osint_scan(list_path=IP_LIST_FILE, resume=None):
    print(
        "\n=== ANALYZE IPs IN OTHER SOURCES (OSINT) ==="
        if LANG == "en"
        else "\n=== ANALIZAR IPs en OTRAS FUENTES (OSINT) ==="
    )

    # 1) Carga y filtrado de IPs (públicas IPv4)
    use_path = resolve_ip_list_file(list_path)
    raw = read_lines(use_path) if os.path.exists(use_path) else []
    ip_list, skipped = filter_valid_public_ips(raw, allow_private=False)

    if skipped:
        motivos = {}
        for _, reason in skipped:
            motivos[reason] = motivos.get(reason, 0) + 1
        resumen = ", ".join(f"{k}: {v}" for k, v in motivos.items())
        print(
            f"[OSINT] ⏭️ Skipped IPs: {len(skipped)} ({resumen})"
            if LANG == "en"
            else f"[OSINT] ⏭️ IPs omitidas: {len(skipped)} ({resumen})"
        )

    print(
        f"[OSINT] ✅ Valid IPs: {len(ip_list)}"
        if LANG == "en"
        else f"[OSINT] ✅ IPs válidas: {len(ip_list)}"
    )
    if not ip_list:
        print(
            f"⚠ No valid IPs found in {use_path}.\n"
            if LANG == "en"
            else f"⚠ No hay IPs válidas en {use_path}.\n"
        )
        return

    # 2) Toggles por fuente (si no hay global, ON por defecto)
    osint_toggles = globals().get(
        "OSINT_IP_SOURCES",
        {
            "dshield": True,
            "blocklistde": True,
            "asn_drop": True,
        },
    )

    # 3) Carga de feeds (respetando toggles)
    asn_drop = load_asn_drop_set() if osint_toggles.get("asn_drop", True) else set()
    dshield = load_dshield_ranges() if osint_toggles.get("dshield", True) else []
    blkde = load_blocklistde_set() if osint_toggles.get("blocklistde", True) else set()

    print(
        f"[OSINT] Feeds loaded → DShield:/24={len(dshield)}  blocklist.de={len(blkde)}  ASN-DROP={len(asn_drop)}"
        if LANG == "en"
        else f"[OSINT] Feeds cargados → DShield:/24={len(dshield)}  blocklist.de={len(blkde)}  ASN-DROP={len(asn_drop)}"
    )

    # 3.5) Índice IPtoASN (para resolver ASN sin VT)
    ip2asn_ready = load_ip2asn_index()
    if ip2asn_ready:
        print(
            "[IP2ASN] Index available for resolving ASN without VT."
            if LANG == "en"
            else "[IP2ASN] índice disponible para resolver ASN sin VT."
        )
    else:
        print(
            "[IP2ASN] Index not available (ASN resolution will fallback to VT only)."
            if LANG == "en"
            else "[IP2ASN] índice no disponible (se trabajará sin ASN local)."
        )

    # 4) Mapa IP → ASN (desde el último *_ULTRA.csv) si procede (VT)
    ip2asn_map = {}
    if osint_toggles.get("asn_drop", True) and asn_drop:
        try:
            ip2asn_map = load_ip_asn_from_last_ultra_csv()
            if ip2asn_map:
                print(
                    f"[OSINT] IP→ASN map from *_ULTRA.csv: {len(ip2asn_map)} IPs with ASN"
                    if LANG == "en"
                    else f"[OSINT] Mapa IP→ASN desde *_ULTRA.csv: {len(ip2asn_map)} IPs con ASN"
                )
            else:
                print(
                    "[OSINT] Empty IP→ASN map (have you run IP > 1) VT to generate *_ULTRA.csv?)."
                    if LANG == "en"
                    else "[OSINT] Mapa IP→ASN vacío (¿has corrido IP > 1) VT para generar *_ULTRA.csv?)."
                )
        except Exception as e:
            print(
                f"[OSINT] Error building IP→ASN map: {e}"
                if LANG == "en"
                else f"[OSINT] Error construyendo mapa IP→ASN: {e}"
            )
            ip2asn_map = {}

    # 5) Configuración de salida
    out_csv = f"{formatted_time}_ULTRA_OSINT.csv"
    fields = [
        "ip",
        "asn_drop",
        "asn_drop_source",
        "bl_dshield_24",
        "bl_dshield_targets",
        "bl_blocklistde_48h",
    ]
    start_i = (
        int(resume.get("idx", 0))
        if (resume and resume.get("mode") == "ip_osint")
        else 0
    )
    mode = "a" if start_i > 0 else "w"

    # Contadores de resumen
    hits_any = 0
    hits_dshield = 0
    hits_blkde = 0
    hits_asn = 0

    # 6) Procesado
    with open(out_csv, mode, newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        if start_i == 0:
            w.writeheader()
        try:
            for i, ip in enumerate(tqdm(ip_list, desc="IPs (OSINT)")):
                if i < start_i:
                    continue

                row = {
                    "ip": ip,
                    "asn_drop": "",
                    "asn_drop_source": "",
                    "bl_dshield_24": "no",
                    "bl_dshield_targets": "0",
                    "bl_blocklistde_48h": "no",
                }

                # DShield: si la IP cae en uno de los rangos /24 top de 3 días
                if dshield:
                    for start, end, targets in dshield:
                        if ip_in_range(ip, start, end):
                            row["bl_dshield_24"] = "yes"
                            row["bl_dshield_targets"] = str(targets)
                            hits_dshield += 1
                            break

                # blocklist.de (48h)
                if blkde and ip in blkde:
                    row["bl_blocklistde_48h"] = "yes"
                    hits_blkde += 1

                # ASN-DROP (orden de resolución: VT → IPtoASN)
                asn_num = None
                if asn_drop:
                    # 1) VT (si existe *_ULTRA.csv con mapa ip→asn)
                    if ip2asn_map:
                        asn_num = ip2asn_map.get(ip)

                    # 2) IPtoASN (índice local, sin VT)
                    if asn_num is None and ip2asn_ready:
                        asn_num = ip2asn_lookup(ip)

                    if isinstance(asn_num, int):
                        if asn_num in asn_drop:
                            row["asn_drop"] = "yes"
                            row["asn_drop_source"] = "spamhaus_asn_drop"
                            hits_asn += 1
                        else:
                            row["asn_drop"] = "no"
                            row["asn_drop_source"] = "spamhaus_asn_drop"
                    else:
                        # No pudimos resolver ASN → dejamos vacío
                        row["asn_drop"] = ""
                        row["asn_drop_source"] = ""
                else:
                    # Señal ASN-DROP apagada → vacío
                    row["asn_drop"] = ""
                    row["asn_drop_source"] = ""

                # ¿Alguna señal?
                if (
                    row["bl_dshield_24"] == "yes"
                    or row["bl_blocklistde_48h"] == "yes"
                    or row["asn_drop"] == "yes"
                ):
                    hits_any += 1

                w.writerow(row)
                save_ckpt({"mode": "ip_osint", "idx": i + 1, "timestamp": time.time()})

        except KeyboardInterrupt:
            if LANG == "en":
                print("\n[PAUSE] IP OSINT paused. Resume in IP > 9).\n")
            else:
                print("\n[PAUSA] IP OSINT pausado. Reanuda IP > 9).\n")
            return

    # 7) Resumen final
    if LANG == "en":
        print(f"\nDone. Output: {out_csv}")
        print(f"[i] Processed IPs: {len(ip_list)} | Matches (any signal): {hits_any}")
        print(f"[i]  - DShield (/24): {hits_dshield}")
        print(f"[i]  - blocklist.de : {hits_blkde}")
        print(f"[i]  - ASN-DROP     : {hits_asn}\n")
    else:
        print(f"\nHecho. Salida: {out_csv}")
        print(
            f"[i] IPs procesadas: {len(ip_list)} | Coincidencias (cualquier señal): {hits_any}"
        )
        print(f"[i]  - DShield (/24): {hits_dshield}")
        print(f"[i]  - blocklist.de : {hits_blkde}")
        print(f"[i]  - ASN-DROP     : {hits_asn}\n")
    print("\n" + frase_epica_random() + "\n")


def load_openphish_hosts():
    CACHE_KEY = "openphish_feed.txt"
    status, text = fetch_feed_cached_text(
        OPENPHISH_FEED_URL, CACHE_KEY, ttl_s=TTL_OPENPHISH
    )
    if status in ("miss",) or not text:
        print(
            "[OSINT] OpenPhish: no data (miss)."
            if LANG == "en"
            else "[OSINT] OpenPhish: sin datos (miss)."
        )
        return set()
    if status in ("fresh", "not-modified"):
        print(f"[OSINT] OpenPhish: {status}.")
    elif status == "cached":
        print(
            "[OSINT] OpenPhish: using current cache."
            if LANG == "en"
            else "[OSINT] OpenPhish: usando caché vigente."
        )
    else:
        print(
            "[OSINT] OpenPhish: offline (stale cache)."
            if LANG == "en"
            else "[OSINT] OpenPhish: sin red (caché antigua)."
        )

    hosts = set()
    from urllib.parse import urlparse

    for line in text.splitlines():
        u = line.strip()
        if not u or u.startswith("#"):
            continue
        try:
            host = urlparse(u).netloc.lower()
            if host:
                hosts.add(host)
        except Exception:
            continue
    return hosts


# PhishTank API (opcional, necesitas app_key). Comprueba# PhishTank API (opcional, necesitas app_key). Comprueba una URL concreta (heurística por /)
PHISHTANK_CHECK_URL = (
    "http://checkurl.phishtank.com/checkurl/"  # POST, app_key, format=json
)


def phishtank_status(domain: str, app_key: str = None):
    if not app_key:
        return ""  # sin app_key no lo usamos
    try:
        url = f"http://{domain}/"  # heurística: URL base
        headers = {
            "User-Agent": "iocsofspades/phishtank-lookup",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        data = {"url": url, "format": "json", "app_key": app_key}
        r = requests.post(PHISHTANK_CHECK_URL, data=data, headers=headers, timeout=20)
        if r.status_code != 200:
            return f"HTTP{r.status_code}"
        j = r.json()
        # Estructura: j['results']['in_database'] y 'verified'
        res = j.get("results", {})
        if res.get("in_database") is True:
            return "verified" if res.get("verified") else "in_database"
        return "not_found"
    except Exception as e:
        return f"ERROR:{e}"


# RDAP (ICANN RDAP - información de registro)
def rdap_lookup(domain: str):
    try:
        url = f"https://rdap.org/domain/{domain}"
        r = requests.get(url, timeout=20)
        if r.status_code != 200:
            return {"registrar": "", "created": "", "status": f"HTTP{r.status_code}"}
        j = r.json()
        registrar = ""
        for ent in j.get("entities", []) or []:
            roles = ent.get("roles") or []
            if "registrar" in roles:
                vcard = ent.get("vcardArray") or []
                # intenta extraer "fn" (display name)
                try:
                    for item in vcard[1] if len(vcard) > 1 else []:
                        if item and item[0] == "fn":
                            registrar = item[3]
                            break
                except Exception:
                    pass
                if registrar:
                    break
        created = ""
        for ev in j.get("events", []) or []:
            if ev.get("eventAction") in (
                "registration",
                "registered",
                "domain registration",
            ):
                created = ev.get("eventDate", "")
                break
        status_list = j.get("status") or []
        status = ",".join(status_list) if status_list else ""
        return {"registrar": registrar, "created": created, "status": status}
    except Exception as e:
        return {"registrar": "", "created": "", "status": f"ERROR:{e}"}


# URLhaus (opcional: requiere Auth-Key para bulk fiable) [5](https://virustotal.readme.io/)
def urlhaus_present_for_domain(domain: str, auth_key: str = None):
    # Placeholder: sin Auth-Key, mejor no martillear; si tienes Auth-Key, en la siguiente iteración te enganchamos el RPZ host dump o endpoint adecuado.
    return ""


def run_domain_osint_lookup(list_file: str = DOMAIN_LIST_FILE, resume=None):
    print(
        "\n=== ANALYZE DOMAINS IN OTHER SOURCES (OSINT) ==="
        if LANG == "en"
        else "\n=== ANALIZAR DOMINIOS en OTRAS FUENTES (OSINT) ==="
    )
    if not os.path.exists(list_file):
        print(
            f"⚠ {list_file} does not exist"
            if LANG == "en"
            else f"⚠ No existe {list_file}"
        )
        return
    with open(list_file, "r", encoding="utf-8", errors="ignore") as fh:
        domains = [x.strip().lower() for x in fh if x.strip()]
    domains = list(dict.fromkeys(domains))
    if not domains:
        print(
            "⚠ No domains to process." if LANG == "en" else "⚠ Sin dominios a procesar."
        )
        return

    # Carga feeds/contexto
    openphish_hosts = load_openphish_hosts()
    # opcionales por clave:
    PHISHTANK_APP_KEY = os.getenv("PHISHTANK_APP_KEY") or ""  # si la pones en entorno
    URLHAUS_AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY") or ""  # si dispones de Auth-Key

    out_csv = f"{formatted_time}_DOMAINS_OSINT.csv"
    fields = [
        "domain",
        "ctx_openphish_present",
        "ctx_phishtank_status",
        "ctx_urlhaus_present",
        "rdap_registrar",
        "rdap_created",
        "rdap_status",
    ]
    start_i = (
        int(resume.get("idx", 0))
        if (resume and resume.get("mode") == "domains_osint")
        else 0
    )
    mode = "a" if start_i > 0 else "w"

    hits = 0
    with open(out_csv, mode, newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        if start_i == 0:
            w.writeheader()
        try:
            for i, d in enumerate(
                tqdm(
                    domains,
                    desc=("Domains (OSINT)" if LANG == "en" else "Dominios (OSINT)"),
                )
            ):
                if i < start_i:
                    continue

                op_present = (
                    "yes" if d in openphish_hosts else "no"
                )  # OpenPhish feed (no‑comercial) [9](blob:https://www.microsoft365.com/8b872bb7-586a-415e-9e27-2520f489775a)
                pt_status = (
                    phishtank_status(d, PHISHTANK_APP_KEY) if PHISHTANK_APP_KEY else ""
                )  # PhishTank API (si hay app_key)
                uh_present = urlhaus_present_for_domain(
                    d, URLHAUS_AUTH_KEY
                )  # pendiente de enganchar RPZ/API con Auth-Key [5](https://virustotal.readme.io/)

                rdap = rdap_lookup(d)  # registrar/created/status

                w.writerow(
                    {
                        "domain": d,
                        "ctx_openphish_present": op_present,
                        "ctx_phishtank_status": pt_status,
                        "ctx_urlhaus_present": uh_present,
                        "rdap_registrar": rdap.get("registrar", ""),
                        "rdap_created": rdap.get("created", ""),
                        "rdap_status": rdap.get("status", ""),
                    }
                )

                if (
                    op_present == "yes"
                    or (pt_status and pt_status != "not_found")
                    or uh_present == "yes"
                ):
                    hits += 1

                save_ckpt(
                    {"mode": "domains_osint", "idx": i + 1, "timestamp": time.time()}
                )
        except KeyboardInterrupt:
            if LANG == "en":
                print("\n[PAUSE] Domain OSINT paused. Resume in Domain > 3).\n")
            else:
                print("\n[PAUSA] DOMINIOS OSINT pausado. Reanuda Dominio > 3).\n")
            return

    if LANG == "en":
        print(f"\nDone. Output: {out_csv}")
        print(f"[i] Processed domains: {len(domains)} | Matches (any signal): {hits}")
    else:
        print(f"\nHecho. Salida: {out_csv}")
        print(
            f"[i] Dominios procesados: {len(domains)} | Coincidencias (cualquier señal): {hits}"
        )
    print("\n" + frase_epica_random() + "\n")


# --- Hash OSINT (MalwareBazaar)  [7](blob:https://www.microsoft365.com/ae2b5983-50c6-4317-93c8-fa3b7fc23483)
MB_API_URL = "https://mb-api.abuse.ch/api/v1/"
TTL_MBZ = 24 * 3600  # si cacheas "recent", pero aquí hacemos lookup puntual por hash


def malwarebazaar_lookup(hash_value: str, auth_key: str):
    try:
        headers = {"Auth-Key": auth_key} if auth_key else {}
        data = {"query": "get_info", "hash": hash_value}
        r = requests.post(MB_API_URL, headers=headers, data=data, timeout=25)
        if r.status_code != 200:
            return {
                "mbz_family": "",
                "mbz_first_seen": "",
                "mbz_tags": "",
                "mbz_signature": "",
                "mbz_status": f"HTTP{r.status_code}",
            }
        j = r.json()
        if (j.get("query_status") or "").lower() == "hash_not_found":
            return {
                "mbz_family": "",
                "mbz_first_seen": "",
                "mbz_tags": "",
                "mbz_signature": "",
                "mbz_status": "not_found",
            }
        data0 = (j.get("data") or [{}])[0]
        family = data0.get("family") or data0.get("signature") or ""
        first = data0.get("first_seen") or ""
        tags = ",".join(data0.get("tags") or [])
        sig = data0.get("signature") or ""
        return {
            "mbz_family": family,
            "mbz_first_seen": first,
            "mbz_tags": tags,
            "mbz_signature": sig,
            "mbz_status": "ok",
        }
    except Exception as e:
        return {
            "mbz_family": "",
            "mbz_first_seen": "",
            "mbz_tags": "",
            "mbz_signature": "",
            "mbz_status": f"ERROR:{e}",
        }


def run_hash_osint_lookup(list_file=None, resume=None):
    path = resolve_hash_list_file(list_file)
    if not os.path.exists(path):
        print(f"⚠ {path} does not exist" if LANG == "en" else f"⚠ No existe {path}")
        return
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        hashes = [x.strip() for x in fh if x.strip()]
    hashes = list(dict.fromkeys(hashes))
    if not hashes:
        print("⚠ No hashes to process." if LANG == "en" else "⚠ Sin hashes a procesar.")
        return

    MBZ_AUTH_KEY = (
        os.getenv("MBZ_AUTH_KEY") or ""
    )  # crea tu Auth-Key en abuse.ch (gratis, fair use) [7](blob:https://www.microsoft365.com/ae2b5983-50c6-4317-93c8-fa3b7fc23483)

    out_csv = f"{formatted_time}_FILES_HASH_OSINT.csv"
    fields = [
        "hash",
        "mbz_family",
        "mbz_first_seen",
        "mbz_tags",
        "mbz_signature",
        "mbz_status",
    ]
    start_i = (
        int(resume.get("idx", 0))
        if (resume and resume.get("mode") == "hash_osint")
        else 0
    )
    mode = "a" if start_i > 0 else "w"

    hits = 0
    with open(out_csv, mode, newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        if start_i == 0:
            w.writeheader()
        try:
            for i, h in enumerate(tqdm(hashes, desc="Hashes (OSINT)")):
                if i < start_i:
                    continue
                res = {
                    "mbz_family": "",
                    "mbz_first_seen": "",
                    "mbz_tags": "",
                    "mbz_signature": "",
                    "mbz_status": "",
                }
                if MBZ_AUTH_KEY:
                    res = malwarebazaar_lookup(h, MBZ_AUTH_KEY)
                row = {"hash": h, **res}
                if row.get("mbz_status") == "ok" and (
                    row.get("mbz_family") or row.get("mbz_tags")
                ):
                    hits += 1
                w.writerow(row)
                save_ckpt(
                    {"mode": "hash_osint", "idx": i + 1, "timestamp": time.time()}
                )
        except KeyboardInterrupt:
            if LANG == "en":
                print("\n[PAUSE] HASH OSINT paused. Resume in HASH > 4).\n")
            else:
                print("\n[PAUSA] HASH OSINT pausado. Reanuda Hash > 4).\n")
            return
    if LANG == "en":
        print(f"\nDone. Output: {out_csv}")
        print(f"[i] Processed hashes: {len(hashes)} | Matches (family/tags): {hits}")
    else:
        print(f"\nHecho. Salida: {out_csv}")
        print(
            f"[i] Hashes procesados: {len(hashes)} | Coincidencias (familia/tags): {hits}"
        )
    print("\n" + frase_epica_random() + "\n")


# --- Caché simple en memoria (puedes persistir en .json si quieres)
_OSINT_CACHE = {}  # key -> {"t": timestamp_epoch, "data": object}


def _now():
    return int(time.time())


def fetch_with_cache(key: str, ttl_s: int, getter):
    rec = _OSINT_CACHE.get(key)
    if rec and (_now() - rec["t"] < ttl_s):
        return rec["data"]
    data = getter()
    if data is not None:
        _OSINT_CACHE[key] = {"t": _now(), "data": data}
    return data


# === CACHÉ PERSISTENTE PARA FEEDS OSINT ======================================
import hashlib
from email.utils import parsedate_to_datetime


def _default_cache_dir():
    # Windows → %LOCALAPPDATA%\IOCsOfSpades\.osint_cache
    # Otros   → ./.osint_cache
    if os.name == "nt":
        base = os.getenv("LOCALAPPDATA") or os.path.expanduser("~")
        return os.path.join(base, "IOCsOfSpades", ".osint_cache")
    return ".osint_cache"


CACHE_DIR = os.getenv("OSINT_CACHE_DIR") or _default_cache_dir()


def _default_cache_dir():
    # Windows → %LOCALAPPDATA%\IOCsOfSpades\.osint_cache
    # Otros   → ./.osint_cache
    if os.name == "nt":
        base = os.getenv("LOCALAPPDATA") or os.path.expanduser("~")
        return os.path.join(base, "IOCsOfSpades", ".osint_cache")
    return ".osint_cache"


CACHE_DIR = os.getenv("OSINT_CACHE_DIR") or _default_cache_dir()


def _ensure_cache_dir():
    os.makedirs(CACHE_DIR, exist_ok=True)


def _cache_path(cache_key: str, ext: str = "txt"):
    safe = hashlib.sha1(cache_key.encode("utf-8", errors="ignore")).hexdigest()
    return os.path.join(CACHE_DIR, f"{safe}.{ext}")


def _meta_path(cache_key: str):
    return _cache_path(cache_key, ext="meta.json")


def _utc_ts(dt):
    try:
        return int(dt.replace(tzinfo=timezone.utc).timestamp())
    except Exception:
        return None


def _parse_last_modified(hdr_val: str):
    # Devuelve timestamp epoch int o None
    try:
        dt = parsedate_to_datetime(hdr_val)
        return _utc_ts(dt)
    except Exception:
        return None


def _load_meta(cache_key: str):
    p = _meta_path(cache_key)
    if not os.path.exists(p):
        return {}
    try:
        with open(p, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def _save_meta(cache_key: str, meta: dict):
    try:
        with open(_meta_path(cache_key), "w", encoding="utf-8") as fh:
            json.dump(meta, fh, indent=2)
    except Exception:
        pass


def _load_text(cache_key: str):
    p = _cache_path(cache_key, "txt")
    if not os.path.exists(p):
        return None
    try:
        with open(p, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except Exception:
        return None


def _save_text(cache_key: str, text: str):
    try:
        with open(_cache_path(cache_key, "txt"), "w", encoding="utf-8") as fh:
            fh.write(text)
    except Exception:
        pass


def fetch_feed_cached_text(url: str, cache_key: str, ttl_s: int, timeout_s: int = 25):
    """
    Devuelve (status, text) donde status ∈ {'fresh','not-modified','cached','stale-offline','miss'}.
    Lógica:
      - Si cache < TTL → 'cached'
      - Si cache >= TTL → hace GET con 'If-Modified-Since'
         · 304 → 'not-modified'
         · 200 → guarda y 'fresh'
         · error → si hay cache → 'stale-offline', si no → 'miss'
    Guarda meta: last_modified (ts), etag (solo por referencia), fetched_at.
    """
    _ensure_cache_dir()
    meta = _load_meta(cache_key)
    now_ts = int(time.time())
    txt = _load_text(cache_key)
    fetched_at = meta.get("fetched_at", 0)

    # Si hay caché "no expirada"
    if txt and (now_ts - fetched_at) < ttl_s:
        return ("cached", txt)

    # Toca validar en origen (Conditional GET)
    headers = {}
    if "last_modified_hdr" in meta:
        headers["If-Modified-Since"] = meta["last_modified_hdr"]

    try:
        r = requests.get(url, headers=headers, timeout=timeout_s)
        if r.status_code == 304 and txt:
            # No ha cambiado; refrescamos fetched_at
            meta["fetched_at"] = now_ts
            _save_meta(cache_key, meta)
            return ("not-modified", txt)
        elif r.status_code == 200:
            text = r.text
            _save_text(cache_key, text)
            # last-modified/etag opcional
            lm_hdr = r.headers.get("Last-Modified") or ""
            etag = r.headers.get("ETag") or ""
            meta.update(
                {
                    "fetched_at": now_ts,
                    "last_modified_hdr": lm_hdr,
                    "etag": etag,
                }
            )
            _save_meta(cache_key, meta)
            return ("fresh", text)
        else:
            # Error HTTP; si hay caché, úsala
            if txt:
                return ("stale-offline", txt)
            return ("miss", "")
    except Exception:
        # Error de red; si hay caché, úsala
        if txt:
            return ("stale-offline", txt)
        return ("miss", "")


# === TOR / Onionoo
_tor_cache = {}


def tor_check_onionoo(ip: str):
    try:
        if ip in _tor_cache:
            return _tor_cache[ip]
        url = f"{ONIONOO_BASE}/details?search={quote(ip)}&limit=100"
        r = requests.get(url, timeout=TOR_TIMEOUT)
        if r.status_code != 200:
            out = ("no", f"onionoo:HTTP{r.status_code}", "", "")
            _tor_cache[ip] = out
            return out
        j = r.json() or {}
        for rel in j.get("relays", []) or []:
            flags = set(rel.get("flags", []) or [])
            exits = set(rel.get("exit_addresses", []) or [])
            if ip in exits or any(
                (a.split(":")[0] == ip) for a in (rel.get("or_addresses", []) or [])
            ):
                if "Exit" in flags:
                    out = (
                        "yes",
                        "onionoo",
                        rel.get("nickname", ""),
                        rel.get("fingerprint", ""),
                    )
                    _tor_cache[ip] = out
                    return out
        out = ("no", "onionoo", "", "")
        _tor_cache[ip] = out
        return out
    except Exception as e:
        out = ("no", f"onionoo:ERR:{e}", "", "")
        _tor_cache[ip] = out
        return out


# === CORE (IPs)
def flatten(o):
    if not o:
        return []
    if isinstance(o, list):
        out = []
        [out.extend(flatten(x)) for x in o]
        return out
    if isinstance(o, dict):
        out = []
        [out.extend(flatten(v)) for v in o.values()]
        return out
    return [str(o)]


def extract_fields_ip(data):
    out = {
        "ip": "",
        "owner": "",
        "asn": "",
        "asn_full": "",
        "CDIR": "",
        "country": "",
        "reputation": "",
        "malicious": "",
        "harmless": "",
        "suspicious": "",
        "undetected": "",
        "vendors_malicious": "",
        "vt_ip_tags": "",
        "vt_vpn": "",
        "vpn_suspect": "",
        "vt_labels": "",
        "vt_categories": "",
        "vt_crowdsourced_tags": "",
        "whois": "",
        "is_vpn": "",
        "vpn_source": "",
        "heuristic_tags": "",
        "cluster_flag": "",
        "cluster_reason": "",
        "c2_suspect": "",
        "c2_reason": "",
        "risk_score": "",
        "link": "",
        "gui": "",
    }
    try:
        d = data.get("data", {})
        attrs = d.get("attributes", {})
        out["ip"] = d.get("id", "")
        out["owner"] = attrs.get("as_owner", "")
        out["asn"] = str(attrs.get("asn") or "")
        out["CDIR"] = attrs.get("network", "")
        out["country"] = attrs.get("country", "")
        out["reputation"] = attrs.get("reputation", "")
        st = attrs.get("last_analysis_stats", {}) or {}
        out["malicious"] = st.get("malicious", "")
        out["harmless"] = st.get("harmless", "")
        out["suspicious"] = st.get("suspicious", "")
        out["undetected"] = st.get("undetected", "")

        bad = []
        vendors = attrs.get("last_analysis_results") or {}
        for eng, res in vendors.items():
            try:
                if (res.get("category") or "").lower() == "malicious":
                    bad.append(eng)
            except:
                pass
        if bad:
            out["vendors_malicious"] = ",".join(sorted(bad))

        tags = attrs.get("tags")
        if tags:
            out["vt_ip_tags"] = ",".join(sorted(set(flatten(tags))))
        tag_line_ip = (out.get("vt_ip_tags", "")).lower()

        if attrs.get("labels"):
            out["vt_labels"] = ",".join(sorted(set(flatten(attrs["labels"]))))
        if attrs.get("categories"):
            out["vt_categories"] = ",".join(sorted(set(flatten(attrs["categories"]))))
        if attrs.get("crowdsourced_tags"):
            out["vt_crowdsourced_tags"] = ",".join(
                sorted(set(flatten(attrs["crowdsourced_tags"])))
            )

        w = (attrs.get("whois") or "").replace("\r", "\n").strip()
        if w:
            out["whois"] = w

        if out["asn"] and out["owner"]:
            out["asn_full"] = f"AS {out['asn']} ({out['owner']})"

        owner_l = out["owner"].lower()
        heur_kw_hit = next((kw for kw in VPN_KEYWORDS if kw in owner_l), "")
        vpn_from_heur = bool(heur_kw_hit)
        vpn_from_vt = "vpn" in tag_line_ip

        out["vt_vpn"] = "yes" if vpn_from_vt else "no"
        out["vpn_suspect"] = "yes" if vpn_from_heur else "no"

        # Clasificación VPN estricta: solo VirusTotal marca VPN efectivo.
        out["is_vpn"] = "yes" if vpn_from_vt else "no"
        out["vpn_source"] = "vt_tag" if vpn_from_vt else ""

        if vpn_from_heur:
            out["heuristic_tags"] = ",".join(
                filter(None, [out.get("heuristic_tags", ""), "VPN_OWNER_HINT"])
            )

        out["link"] = d.get("links", {}).get("self", "")
        out["gui"] = f"https://www.virustotal.com/gui/ip-address/{out['ip']}"
    except Exception as e:
        out["owner"] = f"ERROR:{e}"
    return out


def analyze_cluster_and_c2(row):
    cluster_flag = "no"
    cluster_reason = ""
    c2_flag = "no"
    c2_reason = []
    score = 0
    as_owner = row.get("owner", "").lower()
    for h in HOSTING_CLUSTERS:
        if h.lower() in as_owner:
            cluster_flag = "yes"
            cluster_reason = f"Hosting cluster: {h}"
            score += 20
            break
    whois = row.get("whois", "")
    if whois.strip() == "" or "privacy" in whois.lower():
        c2_flag = "yes"
        c2_reason.append("WHOIS empty/obfuscated")
        score += 20
    vm = row.get("vendors_malicious", "")
    vm_count = len(vm.split(",")) if vm else 0
    if vm_count >= 3:
        c2_flag = "yes"
        c2_reason.append(f"{vm_count} AV engines flag malicious")
        score += 30
    if whois:
        m = re.findall(r"Domain Name:\s*(\S+)", whois, flags=re.I)
        if m and any(m[0].lower().endswith(t) for t in SUSPICIOUS_TLDS):
            c2_flag = "yes"
            c2_reason.append("suspicious TLD")
            score += 20
        long_words = [x for x in re.findall(r"[a-zA-Z0-9]{18,}", whois) if x.isalnum()]
        if long_words:
            c2_flag = "yes"
            c2_reason.append("DGA-like patterns in WHOIS")
            score += 25
    if row.get("is_vpn") == "yes" and vm_count > 0:
        c2_flag = "yes"
        c2_reason.append("VPN + malicious reputation")
        score += 10
    if score > 100:
        score = 100
    return (
        cluster_flag,
        cluster_reason,
        ("yes" if c2_flag == "yes" else "no"),
        "; ".join(c2_reason),
        score,
    )


def _canon_int(value):
    try:
        return int(float(str(value or "0").strip()))
    except Exception:
        return 0


def _build_canonical_ip_fields(row):
    malicious = _canon_int(row.get("malicious"))
    suspicious = _canon_int(row.get("suspicious"))
    harmless = _canon_int(row.get("harmless"))
    risk = _canon_int(row.get("risk_score"))
    vendors = [v for v in str(row.get("vendors_malicious", "")).split(",") if v.strip()]
    vm_count = len(vendors)
    c2_yes = str(row.get("c2_suspect", "")).strip().lower() == "yes"
    vpn_yes = str(row.get("is_vpn", "")).strip().lower() == "yes"
    tor_yes = str(row.get("tor_exit", "")).strip().lower() == "yes"

    text_hints = " ".join(
        [
            str(row.get("vt_categories", "") or ""),
            str(row.get("vt_labels", "") or ""),
            str(row.get("vt_crowdsourced_tags", "") or ""),
            str(row.get("vt_ip_tags", "") or ""),
            str(row.get("c2_reason", "") or ""),
            str(row.get("cluster_reason", "") or ""),
        ]
    ).lower()

    tags = []
    if "phish" in text_hints or "credential" in text_hints:
        tags.append("phishing")
    if any(k in text_hints for k in ["malware", "trojan", "stealer", "ransom", "virus", "worm"]):
        tags.append("malware")
    if c2_yes or any(k in text_hints for k in ["c2", "command and control", "beacon"]):
        tags.append("c2")
    if any(k in text_hints for k in ["botnet", "ddos"]):
        tags.append("botnet")
    if any(k in text_hints for k in ["scan", "scanner", "bruteforce", "exploit"]):
        tags.append("scanner")
    if any(k in text_hints for k in ["adware", "malvert", "advert", "ads"]):
        tags.append("adware")
    if vpn_yes or tor_yes or any(k in text_hints for k in ["proxy", "vpn", "tor"]):
        tags.append("proxy")
    if "spam" in text_hints:
        tags.append("spam")

    if malicious > 0 and "malware" not in tags:
        tags.append("malware")

    priority = ["phishing", "malware", "c2", "botnet", "scanner", "adware", "proxy", "spam"]
    ordered_tags = [t for t in priority if t in tags]
    for t in tags:
        if t not in ordered_tags:
            ordered_tags.append(t)
    primary = ordered_tags[0] if ordered_tags else ""

    if malicious > 0 or c2_yes or risk >= 70:
        verdict = "malicious"
    elif suspicious > 0 or risk >= 40:
        verdict = "suspicious"
    elif harmless > 0 and malicious == 0 and suspicious == 0:
        verdict = "clean"
    else:
        verdict = "unknown"

    confidence = 0
    confidence += min(malicious, 10) * 4
    confidence += min(vm_count, 8) * 4
    if c2_yes:
        confidence += 15
    if risk >= 70:
        confidence += 20
    elif risk >= 40:
        confidence += 10
    if verdict == "clean":
        confidence += 15
    if vpn_yes:
        confidence += 5
    confidence = max(0, min(100, confidence))

    trace = []
    if malicious > 0:
        trace.append(f"vt.malicious={malicious}")
    if suspicious > 0:
        trace.append(f"vt.suspicious={suspicious}")
    if vm_count > 0:
        trace.append(f"vt.vendors_malicious={vm_count}")
    if risk > 0:
        trace.append(f"risk_score={risk}")
    if c2_yes:
        trace.append("c2_suspect=yes")
    if vpn_yes:
        trace.append("is_vpn=yes")
    if str(row.get("vpn_suspect", "")).strip().lower() == "yes":
        trace.append("vpn_suspect=yes")
    if tor_yes:
        trace.append("tor_exit=yes")

    return {
        "canon_indicator_type": "ip",
        "canon_verdict": verdict,
        "canon_threat_type_primary": primary,
        "canon_threat_type_tags": ",".join(ordered_tags),
        "canon_confidence": str(confidence),
        "canon_is_vpn_confirmed": "yes" if vpn_yes else "no",
        "canon_vpn_hint_owner": str(row.get("vpn_suspect", "") or "no"),
        "canon_decision_trace": "; ".join(trace),
    }


# === IPs: modo normal
def run_ip_analysis_normal(selected_fields, api_keys, resume=None):
    if LANG == "en":
        print("\n━━━━━━━━  PAUSE / RESUME  ━━━━━━━━")
        print("Ctrl+C → saves checkpoint and exits. Resume from IP > 8).")
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
    else:
        print("\n━━━━━━━━  PAUSA / REANUDAR  ━━━━━━━━")
        print("Ctrl+C → guarda checkpoint y termina. Reanuda desde IP > 8).")
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
    _rpm_str = safe_input(
        "VT requests per minute [default 4, higher=faster]: "
        if LANG == "en"
        else "Peticiones VT por minuto (VT) [por defecto 4, más alto=más rápido]: ",
        default="4",
        on_interrupt="back",
    )
    if _rpm_str is None:
        return
    _user_rpm = max(1, int(_rpm_str) if str(_rpm_str).strip().isdigit() else 4)
    rate = [None]  # estado para _sleep_rate
    ip_list_file = resolve_ip_list_file()
    raw_lines = read_lines(ip_list_file) if os.path.exists(ip_list_file) else []
    ip_list, skipped = filter_valid_public_ips(raw_lines, allow_private=False)
    if skipped:
        motivos = {}
        for _, reason in skipped:
            motivos[reason] = motivos.get(reason, 0) + 1
        resumen = ", ".join(f"{k}: {v}" for k, v in motivos.items())
        print(
            f"⏭️ Skipped IPs: {len(skipped)} ({resumen})"
            if LANG == "en"
            else f"⏭️ IPs omitidas: {len(skipped)} ({resumen})"
        )
        for ip, reason in skipped[:10]:
            print(f"[SKIP] {ip} -> {reason}")
    if not ip_list:
        print(
            f"⚠ No valid IPs found in {ip_list_file}.\n"
            if LANG == "en"
            else f"⚠ No hay IPs válidas en {ip_list_file}.\n"
        )
        return

    fields = selected_fields or (["ip"] + ALL_FIELDS)
    start_idx = (
        int(resume.get("idx", 0)) if (resume and resume.get("mode") == "ips") else 0
    )
    if start_idx > 0:
        if LANG == "en":
            print(
                f"[CKPT] Resuming IP analysis from index {start_idx} of {len(ip_list)}"
            )
        else:
            print(
                f"[CKPT] Reanudando análisis de IPs desde índice {start_idx} de {len(ip_list)}"
            )
    idx_global = 0
    with open(
        OUTPUT_IPS_CSV, "a" if start_idx > 0 else "w", newline="", encoding="utf-8"
    ) as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        if start_idx == 0:
            w.writeheader()
        try:
            for i, ip in enumerate(
                tqdm(
                    ip_list,
                    desc=("Analyzing IPs" if LANG == "en" else "Analizando IPs"),
                )
            ):
                if i < start_idx:
                    continue
                key = api_keys[idx_global % len(api_keys)] if api_keys else None
                idx_global += 1
                row = {f: "" for f in fields}
                row["ip"] = ip
                if key:
                    _sleep_rate(rate, rpm=_user_rpm)
                    r = vt_get_ip(ip, key)
                    if r.status_code == 200:
                        vt_row = extract_fields_ip(r.json())
                        c_flag, c_reason, c2_flag, c2_reason, score = (
                            analyze_cluster_and_c2(vt_row)
                        )
                        vt_row.update(
                            {
                                "cluster_flag": c_flag,
                                "cluster_reason": c_reason,
                                "c2_suspect": c2_flag,
                                "c2_reason": c2_reason,
                                "risk_score": score,
                            }
                        )
                        vt_row.update(_build_canonical_ip_fields(vt_row))
                        for k in vt_row:
                            if k in row:
                                row[k] = vt_row[k]
                    else:
                        row["owner"] = f"HTTP{r.status_code}"
                else:
                    row["owner"] = "NO_API_KEY"
                w.writerow({k: row.get(k, "") for k in fields})
                save_ckpt(
                    {
                        "mode": "ips",
                        "idx": i + 1,
                        "timestamp": time.time(),
                        "params": {
                            "selected_fields": fields,
                        },
                    }
                )
        except KeyboardInterrupt:
            if LANG == "en":
                print(
                    "\n[PAUSE] Interrupt captured. Progress saved. Resume later from menu 9.)\n"
                )
            else:
                print(
                    "\n[PAUSA] Capturada interrupción. Progreso guardado. Reanuda más tarde desde el menú 9.)\n"
                )
            return
        if LANG == "en":
            print(f"\n[✔] Done. Output: {OUTPUT_IPS_CSV}")
        else:
            print(f"\n[✔] Hecho. Salida: {OUTPUT_IPS_CSV}")
        print("\n" + frase_epica_random() + "\n")


# === IPs: +Tor
def run_ip_analysis_tor(selected_fields, api_keys, resume=None):
    if LANG == "en":
        print("\n━━━━━━━━  PAUSE / RESUME  ━━━━━━━━")
        print("Ctrl+C → saves checkpoint and exits safely. Resume with 9) in the menu.")
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
    else:
        print("\n━━━━━━━━  PAUSA / REANUDAR  ━━━━━━━━")
        print(
            "Pulsa Ctrl+C → guarda checkpoint y termina de forma segura. Reanuda con 9) en el menú."
        )
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
    _rpm_str = safe_input(
        "VT requests per minute [default 4, higher=faster]: "
        if LANG == "en"
        else "Peticiones VT por minuto (VT+Tor) [por defecto 4, más alto=más rápido]: ",
        default="4",
        on_interrupt="back",
    )
    if _rpm_str is None:
        return
    _user_rpm = max(1, int(_rpm_str) if str(_rpm_str).strip().isdigit() else 4)
    rate = [None]  # estado para _sleep_rate
    ip_list_file = resolve_ip_list_file()
    raw_lines = read_lines(ip_list_file) if os.path.exists(ip_list_file) else []
    ip_list, skipped = filter_valid_public_ips(raw_lines, allow_private=False)
    if skipped:
        motivos = {}
        for _, reason in skipped:
            motivos[reason] = motivos.get(reason, 0) + 1
        resumen = ", ".join(f"{k}: {v}" for k, v in motivos.items())
        print(
            f"⏭️ Skipped IPs: {len(skipped)} ({resumen})"
            if LANG == "en"
            else f"⏭️ IPs omitidas: {len(skipped)} ({resumen})"
        )
        for ip, reason in skipped[:10]:
            print(f"[SKIP] {ip} -> {reason}")
    if not ip_list:
        print(
            f"⚠ No valid IPs found in {ip_list_file}.\n"
            if LANG == "en"
            else f"⚠ No hay IPs válidas en {ip_list_file}.\n"
        )
        return
    fields = selected_fields or (["ip"] + ALL_FIELDS)
    start_idx = (
        int(resume.get("idx", 0)) if (resume and resume.get("mode") == "ips_tor") else 0
    )
    if start_idx > 0:
        if LANG == "en":
            print(
                f"[CKPT] Resuming IP analysis (+Tor) from index {start_idx} of {len(ip_list)}"
            )
        else:
            print(
                f"[CKPT] Reanudando análisis de IPs (+Tor) desde índice {start_idx} de {len(ip_list)}"
            )
    idx_global = 0
    with open(
        OUTPUT_IPS_CSV, "a" if start_idx > 0 else "w", newline="", encoding="utf-8"
    ) as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        if start_idx == 0:
            w.writeheader()
        try:
            for i, ip in enumerate(
                tqdm(
                    ip_list,
                    desc=(
                        "Analyzing IPs (+Tor)"
                        if LANG == "en"
                        else "Analizando IPs (+Tor)"
                    ),
                )
            ):
                if i < start_idx:
                    continue
                key = api_keys[idx_global % len(api_keys)] if api_keys else None
                idx_global += 1
                row = {f: "" for f in fields}
                row["ip"] = ip
                if key:
                    _sleep_rate(rate, rpm=_user_rpm)
                    r = vt_get_ip(ip, key)
                    if r.status_code == 200:
                        vt_row = extract_fields_ip(r.json())
                        c_flag, c_reason, c2_flag, c2_reason, score = (
                            analyze_cluster_and_c2(vt_row)
                        )
                        vt_row.update(
                            {
                                "cluster_flag": c_flag,
                                "cluster_reason": c_reason,
                                "c2_suspect": c2_flag,
                                "c2_reason": c2_reason,
                                "risk_score": score,
                            }
                        )
                        vt_row.update(_build_canonical_ip_fields(vt_row))
                        for k in vt_row:
                            if k in row:
                                row[k] = vt_row[k]
                    else:
                        row["owner"] = f"HTTP{r.status_code}"
                else:
                    row["owner"] = "NO_API_KEY"
                tor_exit, tor_src, tor_nick, tor_fpr = tor_check_onionoo(ip)
                row["tor_exit"] = tor_exit
                row["tor_source"] = tor_src
                row["tor_nickname"] = tor_nick
                row["tor_fingerprint"] = tor_fpr
                row.update(_build_canonical_ip_fields(row))
                w.writerow({k: row.get(k, "") for k in fields})
                save_ckpt(
                    {
                        "mode": "ips_tor",
                        "idx": i + 1,
                        "timestamp": time.time(),
                        "params": {
                            "selected_fields": fields,
                        },
                    }
                )
        except KeyboardInterrupt:
            if LANG == "en":
                print(
                    "\n[PAUSE] Interrupt captured. Progress saved. Resume later from menu 9.)\n"
                )
            else:
                print(
                    "\n[PAUSA] Capturada interrupción. Progreso guardado. Reanuda más tarde desde el menú 9.)\n"
                )
            return
        if LANG == "en":
            print(f"\n[✔] Done. Output: {OUTPUT_IPS_CSV}")
        else:
            print(f"\n[✔] Hecho. Salida: {OUTPUT_IPS_CSV}")
        print("\n" + frase_epica_random() + "\n")


def run_ipapi_script_standalone():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    script_path = os.path.join(base_dir, "ipapi_enrichment.py")

    print(os.getcwd())
    print(script_path)
    print(os.path.abspath(os.path.join(base_dir, "list_ip.txt")))

    if not os.path.exists(script_path):
        print(
            f"[!] Script not found: {script_path}"
            if LANG == "en"
            else f"[!] Script no encontrado: {script_path}"
        )
        return

    try:
        subprocess.run([sys.executable, script_path], cwd=base_dir, check=False)
    except Exception as exc:
        print(
            f"[!] Error running ipapi_enrichment.py: {exc}"
            if LANG == "en"
            else f"[!] Error ejecutando ipapi_enrichment.py: {exc}"
        )


# === Fechas
FILL_LAST_RESOLVED_WITH_FIRST = True


def _to_iso_utc(ts):
    if not ts:
        return ""
    try:
        n = int(ts)
        if n > 10_000_000_000:
            n = n / 1000.0
        return datetime.fromtimestamp(n, tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
    except:
        return str(ts)


# === DOMINIOS (por IP) — vive en menú IP
def run_domains_export(api_keys, resume=None):
    if LANG == "en":
        print("\n=== EXPORT DOMAINS (Passive DNS + reputation) ===")
    else:
        print("\n=== EXPORTAR DOMINIOS (Passive DNS + reputación) ===")

    # 0) Key
    key = api_keys[0].strip() if api_keys else ""
    if not key:
        if LANG == "en":
            print("⚠ No VT API key found (check IOCS-apikeys.txt).")
        else:
            print("⚠ No encuentro API key VT (revisa IOCS-apikeys.txt).")
        return

    # 0b) Parámetros interactivos (omitir si se reanuda un checkpoint)
    if not resume:
        _max_str = safe_input(
            "Max domains per IP [default 200, 0=unlimited]: "
            if LANG == "en"
            else "Máximo dominios por IP [por defecto 200, 0=sin límite]: ",
            default="200",
            on_interrupt="back",
        )
        if _max_str is None:
            return
        _max_domains = int(_max_str) if str(_max_str).strip().isdigit() else 200
        _rpm_str = safe_input(
            "VT requests per minute (DOMAINS) [default 4, higher=faster]: "
            if LANG == "en"
            else "Peticiones VT por minuto (DOMAINS) [por defecto 4, más alto=más rápido]: ",
            default="4",
            on_interrupt="back",
        )
        if _rpm_str is None:
            return
        _user_rpm = max(1, int(_rpm_str) if str(_rpm_str).strip().isdigit() else 4)
    else:
        _max_domains = int(resume.get("params", {}).get("max_domains", 200) or 200)
        _user_rpm = int(resume.get("params", {}).get("rpm", 4) or 4)

    # 1) Carga lista de IPs (ajusta a tu fuente real)
    ip_list_file = resolve_ip_list_file()
    raw = read_lines(ip_list_file) if os.path.exists(ip_list_file) else []
    ip_list, skipped = filter_valid_public_ips(raw, allow_private=False)
    if not ip_list:
        if LANG == "en":
            print(f"⚠ No valid IPs in {ip_list_file}.\n")
        else:
            print(f"⚠ No hay IPs válidas en {ip_list_file}.\n")
        return
    if skipped:
        motivos = {}
        for _, reason in skipped:
            motivos[reason] = motivos.get(reason, 0) + 1
        if LANG == "en":
            print(
                f"[DOMAINS] ⏭️ Skipped IPs: {len(skipped)} ({', '.join(f'{k}:{v}' for k,v in motivos.items())})"
            )
        else:
            print(
                f"[DOMAINS] ⏭️ IPs omitidas: {len(skipped)} ({', '.join(f'{k}:{v}' for k,v in motivos.items())})"
            )

    # 2) Out y checkpoint
    resume_params = (
        resume.get("params", {}) if (resume and resume.get("mode") == "domains") else {}
    )
    _saved_out = resume_params.get("out_csv")
    out_csv = (
        _saved_out
        if (_saved_out and os.path.exists(_saved_out))
        else f"{formatted_time}_DOMAINS.csv"
    )
    fields = [
        "ip",
        "domain",
        "first_seen",
        "last_resolved",
        "domain_creation_date",
        "vt_harmless",
        "vt_suspicious",
        "vt_malicious",
        "vt_undetected",
        "vt_reputation",
        "vt_categories",
        "vt_malicious_flag",
        "vt_suspicious_flag",
        "vt_verdict",
        "vt_domain_tags",
        "gui",
    ]
    start_i = (
        int(resume.get("idx", 0)) if (resume and resume.get("mode") == "domains") else 0
    )
    mode = "a" if (start_i > 0 and os.path.exists(out_csv)) else "w"

    # 3) Barra principal
    pbar = tqdm(
        range(start_i, len(ip_list)),
        desc="IPs→DOMAINS" if LANG == "en" else "IPs→DOMINIOS",
        unit="ip",
        smoothing=0.1,
        dynamic_ncols=True,
    )
    rate = [None]  # estado para _sleep_rate
    _dom_creation_cache: dict = {}  # cache domain → creation_date para no repetir llamadas

    written = 0
    try:
        with open(out_csv, mode, newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=fields)
            if mode == "w":
                w.writeheader()

            for i in pbar:
                ip = ip_list[i]

                # === Passive DNS paginado ===
                pages = 0
                cursor = None
                total_items = 0

                while True:
                    _sleep_rate(rate, rpm=_user_rpm)
                    items, cursor, status, err = vt_fetch_ip_resolutions(
                        ip, key, cursor=cursor, limit=40, timeout_s=15
                    )

                    if status == 200:
                        pages += 1
                        total_items += len(items)

                        # TODO: tu extracción de atributos (usa _to_iso_utc si hace falta)
                        for it in items:
                            attrs = it.get("attributes", {})
                            domain = (
                                attrs.get("host_name") or it.get("id") or ""
                            ).strip()
                            first_seen_raw = attrs.get("first_seen") or ""
                            last_resolved_raw = (
                                attrs.get("date") or attrs.get("last_resolved") or ""
                            )

                            first_seen = (
                                _to_iso_utc(first_seen_raw) if first_seen_raw else ""
                            )
                            last_resolved = (
                                _to_iso_utc(last_resolved_raw)
                                if last_resolved_raw
                                else ""
                            )

                            # Fecha de creación del dominio (WHOIS via VT, cacheada por dominio único)
                            if domain and domain not in _dom_creation_cache:
                                _sleep_rate(rate, rpm=_user_rpm)
                                try:
                                    dr = vt_fetch_domain_report(domain, key)
                                    if dr.status_code == 200:
                                        da = (dr.json().get("data") or {}).get("attributes") or {}
                                        cd_raw = da.get("creation_date") or ""
                                        _dom_creation_cache[domain] = (
                                            _to_iso_utc(cd_raw) if cd_raw else ""
                                        )
                                    else:
                                        _dom_creation_cache[domain] = ""
                                except Exception:
                                    _dom_creation_cache[domain] = ""
                            domain_creation_date = _dom_creation_cache.get(domain, "")

                            # TODO: stats/flags/categorías (ajusta a tu pipeline)
                            vt_h = vt_s = vt_m = vt_u = 0
                            vt_rep = 0
                            vt_cats = ""
                            vt_m_flag = 0
                            vt_s_flag = 0
                            vt_verdict = "clean"
                            vt_tags = ""

                            w.writerow(
                                {
                                    "ip": ip,
                                    "domain": domain,
                                    "first_seen": first_seen,
                                    "last_resolved": last_resolved,
                                    "domain_creation_date": domain_creation_date,
                                    "vt_harmless": vt_h,
                                    "vt_suspicious": vt_s,
                                    "vt_malicious": vt_m,
                                    "vt_undetected": vt_u,
                                    "vt_reputation": vt_rep,
                                    "vt_categories": vt_cats,
                                    "vt_malicious_flag": vt_m_flag,
                                    "vt_suspicious_flag": vt_s_flag,
                                    "vt_verdict": vt_verdict,
                                    "vt_domain_tags": vt_tags,
                                    "gui": f"https://www.virustotal.com/gui/ip-address/{ip}",
                                }
                            )
                            written += 1

                        # update postfix con “IP actual” y páginas
                        pbar.set_postfix_str(
                            f"ip={ip} pages={pages} items={total_items}"
                        )

                        if not cursor:
                            break  # fin de paginación
                    else:
                        print(
                            f"[WARN] Resolutions HTTP{status} para {ip} → {err or '(sin detalle)'}"
                        )
                        break

                # checkpoint por IP
                save_ckpt(
                    {
                        "mode": "domains",
                        "idx": i + 1,
                        "timestamp": time.time(),
                        "params": {
                            "out_csv": out_csv,
                            "max_domains": _max_domains,
                            "rpm": _user_rpm,
                        },
                    }
                )

                # latido textual si alguien no ve tqdm (logs)
                if _hb_every(i, 50):
                    if LANG == "en":
                        print(
                            f"[DOMAINS] Progress: {i+1}/{len(ip_list)} (output: {out_csv})"
                        )
                    else:
                        print(
                            f"[DOMAINS] Progreso: {i+1}/{len(ip_list)} (salida: {out_csv})"
                        )

    except KeyboardInterrupt:
        if LANG == "en":
            print("\n[PAUSE] DOMAINS paused. Resume with IP > 9).\n")
        else:
            print("\n[PAUSA] DOMAINS pausado. Reanuda IP > 9).\n")
        return

    if LANG == "en":
        print(f"\n[DOMAINS] Done. {written} rows → {out_csv}")
    else:
        print(f"\n[DOMAINS] Hecho. {written} filas → {out_csv}")


def run_files_export(api_keys, resume=None):
    if LANG == "en":
        print("\n=== EXPORT FILES (from recent DOMAINS.csv) ===")
    else:
        print("\n=== EXPORTAR FICHEROS (desde DOMAINS.csv reciente) ===")

    key = api_keys[0].strip() if api_keys else ""
    if not key:
        if LANG == "en":
            print("⚠ No VT API key found (check IOCS-apikeys.txt).")
        else:
            print("⚠ No encuentro API key VT (revisa IOCS-apikeys.txt).")
        return

    # 0b) Parámetros interactivos (omitir si se reanuda)
    if not resume:
        _rpm_str = safe_input(
            "VT requests per minute (FILES) [default 4, higher=faster]: "
            if LANG == "en"
            else "Peticiones VT por minuto (FILES) [por defecto 4, más alto=más rápido]: ",
            default="4",
            on_interrupt="back",
        )
        if _rpm_str is None:
            return
        _user_rpm = max(1, int(_rpm_str) if str(_rpm_str).strip().isdigit() else 4)
    else:
        _user_rpm = int(resume.get("params", {}).get("rpm", 4) or 4)

    # 1) Fuente: último *_DOMAINS.csv
    import glob

    cands = sorted(glob.glob("*_DOMAINS.csv"))
    if not cands:
        if LANG == "en":
            print("⚠ No *_DOMAINS.csv found. Run 'Export DOMAINS' first.")
        else:
            print("⚠ No hay *_DOMAINS.csv. Ejecuta primero 'Exportar DOMINIOS'.")
        return
    src = cands[-1]
    if LANG == "en":
        print(f"[FILES] Source: {src}")
    else:
        print(f"[FILES] Fuente: {src}")

    # 2) Out y checkpoint
    out_csv = src.replace("_DOMAINS.csv", "_DOMAINS_FILES.csv")
    fields = [
        "domain",
        "relationship",
        "file_id",
        "file_gui",
        "file_name",
        "file_size",
        "file_size_human",
        "file_harmless",
        "file_suspicious",
        "file_malicious",
        "file_undetected",
        "file_malicious_flag",
        "file_suspicious_flag",
        "file_verdict",
        "file_first_submission",
        "file_last_submission",
        "file_last_analysis",
    ]
    start_i = (
        int(resume.get("idx", 0)) if (resume and resume.get("mode") == "files") else 0
    )
    mode = "a" if start_i > 0 else "w"

    # 3) Carga dominios en memoria (podrías stream si son muchos)
    rows = []
    with open(src, "r", encoding="utf-8", newline="") as f:
        r = csv.DictReader(f)
        if r.fieldnames and "domain" not in r.fieldnames:
            if LANG == "en":
                print(
                    f"⚠ Source CSV '{src}' is missing the 'domain' header.\n"
                    "   This usually means the DOMAINS export was interrupted before writing any row.\n"
                    "   Re-run Export DOMAINS to regenerate it."
                )
            else:
                print(
                    f"⚠ El CSV '{src}' no tiene columna 'domain' — probablemente le falta la cabecera.\n"
                    "   Esto ocurre si la exportación de DOMINIOS se interrumpió antes de escribir filas.\n"
                    "   Regenera el CSV con 'Exportar DOMINIOS'."
                )
            return False
        rows = list(r)
    if not rows:
        if LANG == "en":
            print("⚠ No domains to process.")
        else:
            print("⚠ No hay dominios que procesar.")
        return

    pbar = tqdm(
        range(start_i, len(rows)),
        desc="DOMAINS→FILES" if LANG == "en" else "DOMINIOS→FICHEROS",
        unit="domain",
        smoothing=0.1,
        dynamic_ncols=True,
    )
    rate = [None]
    written = 0

    try:
        with open(out_csv, mode, newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=fields)
            if start_i == 0:
                w.writeheader()

            for i in pbar:
                rowd = rows[i]
                domain = (rowd.get("domain") or "").strip()
                if not domain:
                    save_ckpt(
                        {
                            "mode": "files",
                            "idx": i + 1,
                            "timestamp": time.time(),
                            "params": {"rpm": _user_rpm},
                        }
                    )
                    continue

                # === VT relations (domain → files) — tres relaciones ===
                base = "https://www.virustotal.com/api/v3"
                req_headers = {"x-apikey": key, "User-Agent": "iocsofspades/files-export"}
                dom_total = 0

                for rel in ("communicating_files", "referrer_files", "downloaded_files"):
                    first_page_url = f"{base}/domains/{domain}/relationships/{rel}"
                    next_url: str | None = first_page_url
                    pages = 0
                    rel_items = 0

                    while next_url:
                        _sleep_rate(rate, rpm=_user_rpm)
                        # Solo en la primera página pasamos params; páginas siguientes
                        # tienen cursor embebido en la URL devuelta por VT.
                        req_params = {"limit": 40} if next_url == first_page_url else None
                        try:
                            resp = requests.get(
                                next_url,
                                headers=req_headers,
                                params=req_params,
                                timeout=15,
                            )
                        except Exception as exc:
                            print(f"[WARN] Files err {domain}/{rel}: {exc}")
                            break

                        if resp.status_code != 200:
                            msg = ""
                            try:
                                ej = resp.json()
                                msg = ((ej.get("error") or {}).get("message")) or ""
                            except Exception:
                                msg = resp.text[:200]
                            print(
                                f"[WARN] Files HTTP{resp.status_code} {domain}/{rel} → {msg}"
                            )
                            break

                        j = resp.json()
                        items = j.get("data") or []
                        rel_items += len(items)
                        pages += 1

                        for it in items:
                            attrs = it.get("attributes", {})
                            fid = it.get("id") or ""
                            mname = attrs.get("meaningful_name") or ""
                            fsize = int(attrs.get("size") or 0)
                            stats = attrs.get("last_analysis_stats") or {}
                            fh_ = int(stats.get("harmless", 0))
                            fs_ = int(stats.get("suspicious", 0))
                            fm_ = int(stats.get("malicious", 0))
                            fu_ = int(stats.get("undetected", 0))
                            fs_raw = attrs.get("first_submission_date") or ""
                            ls_raw = attrs.get("last_submission_date") or ""
                            la_raw = attrs.get("last_analysis_date") or ""
                            file_first = _to_iso_utc(fs_raw) if fs_raw else ""
                            file_last = _to_iso_utc(ls_raw) if ls_raw else ""
                            file_la = _to_iso_utc(la_raw) if la_raw else ""

                            w.writerow(
                                {
                                    "domain": domain,
                                    "relationship": rel,
                                    "file_id": fid,
                                    "file_gui": f"https://www.virustotal.com/gui/file/{fid}",
                                    "file_name": mname,
                                    "file_size": fsize,
                                    "file_size_human": human_size(fsize),
                                    "file_harmless": fh_,
                                    "file_suspicious": fs_,
                                    "file_malicious": fm_,
                                    "file_undetected": fu_,
                                    "file_malicious_flag": int(fm_ > 0),
                                    "file_suspicious_flag": int(fs_ > 0),
                                    "file_verdict": (
                                        "malicious"
                                        if fm_ > 0
                                        else ("suspicious" if fs_ > 0 else "clean")
                                    ),
                                    "file_first_submission": file_first,
                                    "file_last_submission": file_last,
                                    "file_last_analysis": file_la,
                                }
                            )
                            written += 1
                            dom_total += 1

                        next_url = (j.get("links") or {}).get("next")

                    if rel_items > 0:
                        print(
                            f"  [{domain}] {rel}: {rel_items} file(s) across {pages} page(s)"
                        )

                pbar.set_postfix_str(f"domain={domain} total_files={dom_total}")
                if dom_total == 0:
                    print(f"  [{domain}] → 0 files in all 3 relationships (normal for clean domains)")

                save_ckpt(
                    {
                        "mode": "files",
                        "idx": i + 1,
                        "timestamp": time.time(),
                        "params": {"rpm": _user_rpm},
                    }
                )
                if _hb_every(i, 50):
                    if LANG == "en":
                        print(
                            f"[FILES] Progress: {i+1}/{len(rows)} (output: {out_csv})"
                        )
                    else:
                        print(
                            f"[FILES] Progreso: {i+1}/{len(rows)} (salida: {out_csv})"
                        )

    except KeyboardInterrupt:
        if LANG == "en":
            print("\n[PAUSE] FILES paused. Resume with IP > 9).\n")
        else:
            print("\n[PAUSA] FILES pausado. Reanuda IP > 9).\n")
        return

    if LANG == "en":
        print(f"\n[FILES] Done. {written} rows → {out_csv}")
    else:
        print(f"\n[FILES] Hecho. {written} filas → {out_csv}")


# === HASH (VT files) — con checkpoint para lista
def extract_fields_file(data):
    out = {
        "hash": "",
        "meaningful_name": "",
        "size": "",
        "size_human": "",
        "harmless": "",
        "suspicious": "",
        "malicious": "",
        "undetected": "",
        "reputation": "",
        "vt_file_tags": "",
        "vt_crowdsourced_tags": "",
        "file_type": "",
        "gui": "",
    }
    try:
        d = data.get("data", {})
        attrs = d.get("attributes", {})
        out["hash"] = d.get("id", "")
        mn = attrs.get("meaningful_name", "") or (
            (attrs.get("names") or [""])[0] if attrs.get("names") else ""
        )
        out["meaningful_name"] = mn
        sz = attrs.get("size") or 0
        out["size"] = sz
        out["size_human"] = human_size(sz)
        st = attrs.get("last_analysis_stats", {}) or {}
        out["harmless"] = st.get("harmless", 0)
        out["suspicious"] = st.get("suspicious", 0)
        out["malicious"] = st.get("malicious", 0)
        out["undetected"] = st.get("undetected", 0)
        out["reputation"] = attrs.get("reputation", 0)
        tags = attrs.get("tags") or []
        out["vt_file_tags"] = ",".join(sorted(set(flatten(tags)))) if tags else ""
        ctags = attrs.get("crowdsourced_tags") or []
        out["vt_crowdsourced_tags"] = (
            ",".join(sorted(set(flatten(ctags)))) if ctags else ""
        )
        out["file_type"] = (
            attrs.get("type_description", "") or attrs.get("type_tag", "") or ""
        )
        out["gui"] = f"https://www.virustotal.com/gui/file/{out['hash']}"
    except Exception as e:
        out["meaningful_name"] = f"ERROR:{e}"
    return out


def resolve_hash_list_file(path: str = None):
    if path and os.path.exists(path):
        return path
    for cand in ("hash.txt", "hashes.txt", "hashlist.txt"):
        if os.path.exists(cand):
            return cand
    return HASH_LIST_FILE


def run_hash_lookup(api_keys, single_hash=None, list_file=None, resume=None):
    if single_hash:
        hashes = [single_hash.strip()]
        start_idx = 0
    else:
        use_path = resolve_hash_list_file(list_file)
        if not os.path.exists(use_path):
            print(
                f"⚠ {use_path} does not exist"
                if LANG == "en"
                else f"⚠ No existe {use_path}"
            )
            return
        with open(use_path, "r", encoding="utf-8", errors="ignore") as fh:
            hashes = [x.strip() for x in fh if x.strip()]
        hashes = list(dict.fromkeys(hashes))
        start_idx = (
            int(resume.get("idx", 0))
            if (resume and resume.get("mode") == "hash_list")
            else 0
        )
        if start_idx > 0:
            print(
                f"[CKPT] Resuming HASH list from idx {start_idx}"
                if LANG == "en"
                else f"[CKPT] Reanudando HASH lista desde idx {start_idx}"
            )
    if not hashes:
        print("⚠ No hashes to process." if LANG == "en" else "⚠ Sin hashes a procesar.")
        return
    if not api_keys:
        print(
            "⚠ No VT API keys available for hash lookup."
            if LANG == "en"
            else "⚠ No hay API keys VT para lookup de hash."
        )
        return

    out_csv = f"{formatted_time}_FILES_HASH.csv"
    fields = [
        "hash",
        "meaningful_name",
        "size",
        "size_human",
        "harmless",
        "suspicious",
        "malicious",
        "undetected",
        "reputation",
        "vt_file_tags",
        "vt_crowdsourced_tags",
        "file_type",
        "gui",
    ]
    mode = "a" if start_idx > 0 else "w"
    with open(out_csv, mode, newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        if start_idx == 0:
            w.writeheader()
        idx_ptr = 0
        try:
            for i, h in enumerate(
                tqdm(
                    hashes,
                    desc=("Querying HASHes" if LANG == "en" else "Consultando HASHes"),
                )
            ):
                if i < start_idx:
                    continue
                key = api_keys[idx_ptr % len(api_keys)]
                idx_ptr += 1
                try:
                    r = vt_get_file(h, key)
                    if r.status_code == 200:
                        row = extract_fields_file(r.json())
                        w.writerow(row)
                    else:
                        w.writerow(
                            {"hash": h, "meaningful_name": f"HTTP{r.status_code}"}
                        )
                except Exception as e:
                    w.writerow({"hash": h, "meaningful_name": f"ERROR:{e}"})
                save_ckpt({"mode": "hash_list", "idx": i + 1, "timestamp": time.time()})
        except KeyboardInterrupt:
            if LANG == "en":
                print("\n[PAUSE] HASH list paused. Resume in HASH > 4).\n")
            else:
                print("\n[PAUSA] HASH lista pausado. Reanuda HASH > 3).\n")
            return
    if LANG == "en":
        print(f"\nDone. Output: {out_csv}\n{frase_epica_random()}\n")
    else:
        print(f"\nHecho. Salida: {out_csv}\n{frase_epica_random()}\n")


# === DOMINIOS (lista directa) — con checkpoint
def extract_fields_domain(dj: dict):
    out = {
        "domain": "",
        "vt_harmless": 0,
        "vt_suspicious": 0,
        "vt_malicious": 0,
        "vt_undetected": 0,
        "vt_reputation": 0,
        "vt_categories": "",
        "vt_domain_tags": "",
        "vt_malicious_flag": 0,
        "vt_suspicious_flag": 0,
        "vt_verdict": "",
        "gui": "",
    }
    try:
        dat = dj.get("data", {}) or {}
        da = dat.get("attributes", {}) or {}
        out["domain"] = dat.get("id", "") or da.get("host", "") or ""
        st = da.get("last_analysis_stats", {}) or {}
        out["vt_harmless"] = st.get("harmless", 0)
        out["vt_suspicious"] = st.get("suspicious", 0)
        out["vt_malicious"] = st.get("malicious", 0)
        out["vt_undetected"] = st.get("undetected", 0)
        out["vt_reputation"] = da.get("reputation", 0)
        cats_raw = da.get("categories") or {}
        if isinstance(cats_raw, dict):
            out["vt_categories"] = ",".join(sorted(set(cats_raw.values())))
        tags = da.get("tags") or []
        if tags:
            out["vt_domain_tags"] = ",".join(sorted(set(flatten(tags))))
        vflag_m = 1 if out["vt_malicious"] > 0 else 0
        vflag_s = 1 if out["vt_suspicious"] > 0 else 0
        out["vt_malicious_flag"] = vflag_m
        out["vt_suspicious_flag"] = vflag_s
        out["vt_verdict"] = (
            "malicious" if vflag_m else ("suspicious" if vflag_s else "clean")
        )
        if out["domain"]:
            out["gui"] = f"https://www.virustotal.com/gui/domain/{out['domain']}"
    except Exception as e:
        out["vt_categories"] = f"ERROR:{e}"
    return out


def run_domain_list_lookup(api_keys, list_file: str = DOMAIN_LIST_FILE, resume=None):
    if not os.path.exists(list_file):
        print(
            f"⚠ {list_file} does not exist"
            if LANG == "en"
            else f"⚠ No existe {list_file}"
        )
        return
    with open(list_file, "r", encoding="utf-8", errors="ignore") as fh:
        domains = [x.strip() for x in fh if x.strip()]
    domains = list(dict.fromkeys(domains))
    if not domains:
        print(
            "⚠ No domains to process." if LANG == "en" else "⚠ Sin dominios a procesar."
        )
        return
    if not api_keys:
        print(
            "⚠ No VT API keys available for domain lookup."
            if LANG == "en"
            else "⚠ No hay API keys VT para lookup de dominios."
        )
        return

    start_idx = (
        int(resume.get("idx", 0))
        if (resume and resume.get("mode") == "domains_list")
        else 0
    )
    if start_idx > 0:
        print(
            f"[CKPT] Resuming DOMAINS list from idx {start_idx}"
            if LANG == "en"
            else f"[CKPT] Reanudando DOMINIOS lista desde idx {start_idx}"
        )

    out_csv = f"{formatted_time}_DOMAINS_BY_LIST.csv"
    fields = [
        "domain",
        "vt_harmless",
        "vt_suspicious",
        "vt_malicious",
        "vt_undetected",
        "vt_reputation",
        "vt_categories",
        "vt_domain_tags",
        "vt_malicious_flag",
        "vt_suspicious_flag",
        "vt_verdict",
        "gui",
    ]
    mode = "a" if start_idx > 0 else "w"
    with open(out_csv, mode, newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        if start_idx == 0:
            w.writeheader()
        idx_ptr = 0
        try:
            for i, dm in enumerate(
                tqdm(
                    domains,
                    desc=(
                        "Querying domains (list)"
                        if LANG == "en"
                        else "Consultando dominios (lista)"
                    ),
                )
            ):
                if i < start_idx:
                    continue
                key = api_keys[idx_ptr % len(api_keys)]
                idx_ptr += 1
                try:
                    r = vt_fetch_domain_report(dm, key)
                    if r.status_code == 200:
                        row = extract_fields_domain(r.json())
                        if not row.get("domain"):
                            row["domain"] = dm
                        w.writerow(row)
                    else:
                        w.writerow(
                            {
                                "domain": dm,
                                "vt_categories": f"HTTP{r.status_code}",
                                "gui": f"https://www.virustotal.com/gui/domain/{dm}",
                            }
                        )
                except Exception as e:
                    w.writerow(
                        {
                            "domain": dm,
                            "vt_categories": f"ERROR:{e}",
                            "gui": f"https://www.virustotal.com/gui/domain/{dm}",
                        }
                    )
                save_ckpt(
                    {"mode": "domains_list", "idx": i + 1, "timestamp": time.time()}
                )
        except KeyboardInterrupt:
            if LANG == "en":
                print("\n[PAUSE] DOMAINS list paused. Resume in DOMAIN > 3).\n")
            else:
                print("\n[PAUSA] DOMINIOS lista pausado. Reanuda DOMINIO > 2).\n")
            return
    if LANG == "en":
        print(f"\nDone. Output: {out_csv}\n{frase_epica_random()}\n")
    else:
        print(f"\nHecho. Salida: {out_csv}\n{frase_epica_random()}\n")


# === Menús (con estado SSL visible)


def main_menu(ssl_status: str):
    if LANG == "en":
        print(
            "\n=== IOCs Of Spades — MAIN MENU (Everything Louder Than Everything Else) ==="
        )
        print("1) IP — Crank the signal")
        print("2) Domain — Shake the DNS")
        print("3) Hash — Ride the Lightning")
        status_str = ssl_status.upper() if ssl_status else "UNKNOWN"
        print(
            f"4) SSL / VPN / Proxy Check  [status: {status_str}] — No chains, no limits"
        )
        print("5) Refresh OSINT feeds now — Fuel the machine")
        print("6) DEBUG / OSINT BACKSTAGE — Behind the Noise ")
        print("x) Clear checkpoint — Reset the stage")
        print("0) Exit — Leave the battlefield")
        return input("\nChoose your weapon: ").strip()
    else:
        print(f"\n=== {APP_NAME} — MENÚ PRINCIPAL (IOCs) ===")
        print("1) IP")
        print("2) Dominio")
        print("3) Hash")
        print(f"4) Chequear SSL / VPN / Proxy  [estado: {ssl_status.upper()}]")
        print("5) Refrescar feeds OSINT ahora")
        print("6) DEBUG / HERRAMIENTAS OSINT")
        print("x) Borrar checkpoint")
        print("0) Salir")
        return input("\nSelecciona una opción: ").strip()


def debug_menu():
    if LANG == "en":
        print("\n=== DEBUG OSINT MENU ===")
        print("1) Show cache path")
        print("2) Show ASN-DROP header (force revalidation)")
        print("3) Suggest IPs (DShield and blocklist.de) from cache")
        print("4) Quick probe (test current IPs from iplist.txt)")
        print("5) Feed samples (show 5 entries per feed)")
        print("6) List cache files")
        print("7) Refresh OSINT feeds now")
        print("8) Back")
        print("9) Export OSINT hits (last *_ULTRA_OSINT.csv)")
        return input("\nChoose an option: ").strip()
    else:
        print("\n=== MENÚ DEBUG OSINT ===")
        print("1) Ver ruta de caché")
        print("2) Ver cabecera ASN-DROP (forzar revalidación)")
        print("3) Sugerir IPs (DShield y blocklist.de) desde la caché")
        print("4) Quick probe (probar IPs actuales de iplist.txt)")
        print("5) Muestras de feeds (ver 5 entradas por feed)")
        print("6) Listar ficheros de la caché")
        print("7) Refrescar feeds OSINT ahora")
        print("8) Volver")
        print("9) Exportar hits OSINT (último *_ULTRA_OSINT.csv)")
        return input("\nSelecciona una opción: ").strip()


def handle_debug_menu():
    while True:
        sub = (debug_menu() or "").strip().lower()

        if sub == "1":
            print(f"[OSINT] Cache dir: {CACHE_DIR}")

        elif sub == "2":
            debug_asndrop_head()

        elif sub == "3":
            suggest_test_ips_from_cache()

        elif sub == "4":
            ip_list_file = resolve_ip_list_file()
            lst = read_lines(ip_list_file)[-5:] if os.path.exists(ip_list_file) else []
            if not lst:
                print(
                    f"⚠ {ip_list_file} not found. Add test IPs and retry."
                    if LANG == "en"
                    else f"⚠ No hay {ip_list_file}. Añade IPs de prueba y reintenta."
                )
            else:
                quick_osint_probe(lst)

        elif sub == "5":
            print_osint_feed_samples()

        elif sub == "6":
            list_cache_files()

        elif sub == "7":
            refresh_osint_feeds_now()

        elif sub == "8" or sub in ("b", "q"):
            print()
            break  # ← aquí sí salimos del submenú

        elif sub == "9":
            try:
                export_osint_hits_only()  # ← NO salimos; te quedas en DEBUG
            except Exception as e:
                print(f"[DEBUG] Error exportando hits OSINT: {e}")

        else:
            if LANG == "en":
                print("Invalid option.\n")
            else:
                print("Opción no válida.\n")


def ip_menu(fast_flag: bool, ssl_status: str):
    if LANG == "en":
        print(f"\n=== IP MENU  [SSL: {ssl_status.upper()}] ===")
        print("1) Analyze IPs in VirusTotal (VT)")
        print("2) Analyze IPs in OTHER SOURCES (OSINT)")
        print("3) Analyze IPs (+Tor via Onionoo)")
        print("4) Select CSV columns (IPs)")
        print(f"5) FAST MODE: {'ON' if fast_flag else 'OFF'}")
        print("6) Export DOMAINS by IP (Passive DNS + VT reputation)")
        print("7) Export FILES (from the most recent DOMAINS.csv)")
        print("8) Export EVERYTHING (domains by IP + files)")
        print("9) Resume (IPs / DOMAINS / FILES)")
        print("10) IP-API enrichment")
        print("11) Back")
        return safe_input("\nChoose an option: ", default="11", on_interrupt="default")
    else:
        print(f"\n=== MENÚ IPs  [SSL: {ssl_status.upper()}] ===")
        print("1) Analizar IPs en VirusTotal (VT)")
        print("2) Analizar IPs en OTRAS FUENTES (OSINT)")
        print("3) Analizar IPs (+Tor via Onionoo)")
        print("4) Seleccionar columnas del CSV (IPs)")
        print(f"5) Modo RÁPIDO: {'ON' if fast_flag else 'OFF'}")
        print("6) Exportar DOMINIOS por IP (Passive DNS + reputación VT)")
        print("7) Exportar FICHEROS (desde el DOMAINS.csv más reciente)")
        print("8) Exportar TODO (dominios por IP + ficheros)")
        print("9) Reanudar (IPs / DOMAINS / FILES)")
        print("10) IP-API enrichment")
        print("11) Volver")
        return safe_input(
            "\nSelecciona una opción: ", default="11", on_interrupt="default"
        )


def domain_menu(ssl_status: str):
    if LANG == "en":
        print(f"\n=== DOMAIN MENU  [SSL: {ssl_status.upper()}] ===")
        print("1) Check domain list in VirusTotal (domains.txt)")
        print("2) Analyze DOMAINS in OTHER SOURCES (OSINT)")
        print("3) Resume (DOMAIN list / DOMAIN OSINT)")
        print("4) Back")
        return input("\nChoose an option: ").strip()
    else:
        print(f"\n=== MENÚ DOMINIOS  [SSL: {ssl_status.upper()}] ===")
        print("1) Consultar lista de dominios en VirusTotal (dominios.txt)")
        print("2) Analizar DOMINIOS en OTRAS FUENTES (OSINT)")
        print("3) Reanudar (DOMINIOS lista / DOMINIOS OSINT)")
        print("4) Volver")
        return input("\nSelecciona una opción: ").strip()


def hash_menu(ssl_status: str):
    if LANG == "en":
        print(f"\n=== HASH MENU  [SSL: {ssl_status.upper()}] ===")
        print("1) Check a hash in VirusTotal (MD5/SHA1/SHA256)")
        print("2) Check list in VirusTotal (hash.txt / hashes.txt / hashlist.txt)")
        print("3) Analyze HASHES in OTHER SOURCES (OSINT)")
        print("4) Resume (HASH list / HASH OSINT)")
        print("5) Back")
        return input("\nChoose an option: ").strip()
    else:
        print(f"\n=== MENÚ HASH  [SSL: {ssl_status.upper()}] ===")
        print("1) Consultar un hash en VirusTotal (MD5/SHA1/SHA256)")
        print("2) Consultar lista en VirusTotal (hash.txt / hashes.txt / hashlist.txt)")
        print("3) Analizar HASHES en OTRAS FUENTES (OSINT)")
        print("4) Reanudar (HASH lista / HASH OSINT)")
        print("5) Volver")
        return input("\nSelecciona una opción: ").strip()


def vt_check_capabilities(api_key):
    if not api_key:
        if LANG == "en":
            print("⚠ No VT API key to check capabilities.\n")
        else:
            print("⚠ No hay API key para chequear capacidades.\n")
        return
    headers = {"x-apikey": api_key}
    if LANG == "en":
        print("\n=== VirusTotal API Capability Check ===\n")
    else:
        print("\n=== Chequeo de capacidades de la API de VirusTotal ===\n")
    for name, url in [
        ("IP lookup", "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8")
    ]:
        try:
            r = requests.get(url, headers=headers, timeout=10)
            print(f"{name:<30} → HTTP {r.status_code}")
        except Exception as e:
            print(f"{name:<30} → ERROR: {e}")
    if LANG == "en":
        print("\nDone.\n")
    else:
        print("\nHecho.\n")


def select_fields_mode1():
    if LANG == "en":
        print("\n=== SELECT COLUMNS (IPs) ===\n")
        print("The IP will ALWAYS be included.\n")
        for i, f in enumerate(ALL_FIELDS, start=1):
            print(f"{i}) {f}")
        s = input("\nComma-separated numbers (enter = ALL): ").strip()
        if s == "":
            print("\n[✔] ALL columns.\n")
            return ["ip"] + ALL_FIELDS
        try:
            idxs = [int(x.strip()) for x in s.split(",") if x.strip().isdigit()]
        except Exception:
            print("\n[!] Invalid input → ALL columns.\n")
            return ["ip"] + ALL_FIELDS
        sel = []
        for i in idxs:
            if 1 <= i <= len(ALL_FIELDS):
                sel.append(ALL_FIELDS[i - 1])
            else:
                print(f"[!] Option {i} does not exist, ignored.")
        if not sel:
            print("\n[!] No valid selection → ALL.\n")
            return ["ip"] + ALL_FIELDS
        print(f"\n[✔] Columns: {sel}\n")
        return ["ip"] + sel
    else:
        print("\n=== SELECCIÓN DE COLUMNAS (IPs) ===\n")
        print("La IP se incluirá SIEMPRE.\n")
        for i, f in enumerate(ALL_FIELDS, start=1):
            print(f"{i}) {f}")
        s = input("\nNúmeros separados por coma (enter = TODO): ").strip()
        if s == "":
            print("\n[✔] TODAS las columnas.\n")
            return ["ip"] + ALL_FIELDS
        try:
            idxs = [int(x.strip()) for x in s.split(",") if x.strip().isdigit()]
        except Exception:
            print("\n[!] Entrada inválida → TODAS las columnas.\n")
            return ["ip"] + ALL_FIELDS
        sel = []
        for i in idxs:
            if 1 <= i <= len(ALL_FIELDS):
                sel.append(ALL_FIELDS[i - 1])
            else:
                print(f"[!] Opción {i} no existe, ignorada.")
        if not sel:
            print("\n[!] Sin selección válida → TODAS.\n")
            return ["ip"] + ALL_FIELDS
        print(f"\n[✔] Columnas: {sel}\n")
        return ["ip"] + sel


# === UTILIDADES DE DIAGNÓSTICO / PRUEBA OSINT =================================


def debug_asndrop_head():
    """
    Fuerza revalidación del feed ASN-DROP y muestra sus primeros bytes
    para comprobar el formato (NDJSON/JSON) y tamaño real.
    """
    key = "spamhaus_asndrop.json"
    status, text = fetch_feed_cached_text(SPAMHAUS_ASNDROP_URL, key, ttl_s=0)
    print(f"[ASN-DROP] status={status}, bytes={len(text or '')}")
    head = (text or "")[:600]
    print(head if head else "(sin contenido)")


def suggest_test_ips_from_cache():
    """
    Saca una IP de DShield (dentro del primer /24) y una IP de blocklist.de
    a partir de lo que YA tienes en caché. Te las imprime para que las
    pegues en iplist.txt y valides el pipeline OSINT.
    """
    if LANG == "en":
        print("\n=== Suggest test IPs from cache ===")
    else:
        print("\n=== Sugerir IPs de prueba desde la caché ===")
    # DShield → genera una IP dentro del primer /24 del feed
    dsh_ip = None
    status, text = fetch_feed_cached_text(
        DSHIELD_BLOCK_URL, "dshield_block.txt", ttl_s=0
    )
    if text:
        for line in text.splitlines():
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 1:
                start = parts[0].strip()
                try:
                    ip0 = ipaddress.ip_address(start)
                    if ip0.version == 4:
                        dsh_ip = str(
                            ipaddress.ip_address(int(ip0) + 10)
                        )  # p.ej. start+10
                        break
                except Exception:
                    pass

    # blocklist.de → primera IP válida del feed
    bl_ip = None
    status, text = fetch_feed_cached_text(
        BLOCKLISTDE_ALL_URL, "blocklistde_all.txt", ttl_s=0
    )
    if text:
        for line in text.splitlines():
            m = _IP4_REGEX.search(line)
            if m:
                try:
                    bl_ip = str(ipaddress.ip_address(m.group(0)))  # normaliza
                    break
                except Exception:
                    continue

    if LANG == "en":
        print(f"DShield     → {dsh_ip or '(not found)'}")
        print(f"blocklist.de→ {bl_ip or '(not found)'}")
        if dsh_ip or bl_ip:
            print(
                "\nPaste these IPs into your iplist.txt (one per line) and run IP → 2) OSINT.\n"
            )
    else:
        print(f"DShield     → {dsh_ip or '(no encontrada)'}")
        print(f"blocklist.de→ {bl_ip or '(no encontrada)'}")
        if dsh_ip or bl_ip:
            print(
                "\nPega estas IPs en tu iplist.txt (una por línea) y lanza IP → 2) OSINT.\n"
            )


def quick_osint_probe(ips_to_check):
    """
    Comprobación directa contra feeds ya cargados, para ver si una IP
    marcaría DShield/blocklist.de/ASN-DROP según lo que tenemos en caché.
    """
    print("\n=== Quick OSINT Probe ===")
    dshield = load_dshield_ranges()
    blkde = load_blocklistde_set()
    asns = load_asn_drop_set()

    # Mapa IP->ASN (si existe ULTRA.csv con asn)
    ip2asn = {}
    try:
        ip2asn = load_ip_asn_from_last_ultra_csv()
    except Exception:
        ip2asn = {}

    for ip in ips_to_check:
        ip = ip.strip()
        if not ip:
            continue
        dshield_hit = any(ip_in_range(ip, start, end) for (start, end, _) in dshield)
        blk_hit = ip in blkde
        asn_hit = False
        if ip2asn and asns:
            a = ip2asn.get(ip)
            asn_hit = isinstance(a, int) and a in asns

        print(
            f"{ip:>15}  | DShield:{'YES' if dshield_hit else 'no '}  "
            f"blocklist.de:{'YES' if blk_hit else 'no '}  "
            f"ASN-DROP:{'YES' if asn_hit else 'no '}"
        )


def print_osint_feed_samples():
    """
    Muestra 5 entradas por feed para inspección rápida.
    """
    dshield = load_dshield_ranges()
    blkde = load_blocklistde_set()
    asns = load_asn_drop_set()
    if LANG == "en":
        print(f"[feed] DShield /24 total: {len(dshield)}  (showing 5)")
        for start, end, targets in dshield[:5]:
            print(f"  - {start}..{end}  targets={targets}")
        print(f"[feed] blocklist.de total: {len(blkde)}  (showing 5)")
        for ip in list(blkde)[:5]:
            print(f"  - {ip}")
        print(f"[feed] ASN-DROP total: {len(asns)}  (showing 5)")
        for a in list(asns)[:5]:
            print(f"  - AS{a}")
    else:
        print(f"[feed] DShield /24 total: {len(dshield)}  (muestra 5)")
        for start, end, targets in dshield[:5]:
            print(f"  - {start}..{end}  targets={targets}")
        print(f"[feed] blocklist.de total: {len(blkde)}  (muestra 5)")
        for ip in list(blkde)[:5]:
            print(f"  - {ip}")
        print(f"[feed] ASN-DROP total: {len(asns)}  (muestra 5)")
        for a in list(asns)[:5]:
            print(f"  - AS{a}")


def list_cache_files():
    """
    Lista los ficheros de la carpeta de caché persistente.
    """
    if LANG == "en":
        print(f"[OSINT] Cache dir: {CACHE_DIR}")
    else:
        print(f"[OSINT] Cache dir: {CACHE_DIR}")
    try:
        files = os.listdir(CACHE_DIR)
        if not files:
            if LANG == "en":
                print("  (empty)")
            else:
                print("  (vacía)")
            return
        for fn in files:
            p = os.path.join(CACHE_DIR, fn)
            try:
                size = os.path.getsize(p)
            except Exception:
                size = 0
            print(f"  - {fn}  ({size} bytes)")
    except Exception as e:
        if LANG == "en":
            print("Could not list cache:", e)
        else:
            print("No puedo listar la caché:", e)


# === Main
# === Main
def main():
    global FAST_PROFILE
    print(BANNER)
    print(f"[{APP_SHORT}] {APP_NAME} — {APP_VERSION}")
    print(f"[OSINT] Cache dir: {CACHE_DIR}")

    select_language()

    ssl_status = auto_check_ssl()
    api_keys = read_lines(API_KEYS_FILE) if os.path.exists(API_KEYS_FILE) else []
    selected_fields_ips = ["ip"] + ALL_FIELDS

    while True:
        choice = main_menu(ssl_status)

        # El primer condicional debe ser 'if', los siguientes 'elif'
        if choice == "0":
            print("Exiting…" if LANG == "en" else "Saliendo…")
            break

        elif choice == "1":
            while True:
                sub = ip_menu(FAST_PROFILE, ssl_status)

                if ssl_status == "mitm" and sub in ("1", "2", "3", "6", "7", "8", "9"):
                    if LANG == "en":
                        print("\n❌ BLOCKED by SSL intercept.\n")
                    else:
                        print("\n❌ BLOQUEADO por SSL intercept.\n")
                    continue

                if sub == "1":
                    run_ip_analysis_normal(selected_fields_ips, api_keys)
                elif sub == "2":
                    run_ip_osint_scan()
                elif sub == "3":
                    run_ip_analysis_tor(selected_fields_ips, api_keys)
                elif sub == "4":
                    selected_fields_ips = select_fields_mode1()
                elif sub == "5":
                    FAST_PROFILE = not FAST_PROFILE
                    print(f"\n[INFO] FAST MODE: {'ON' if FAST_PROFILE else 'OFF'}\n")
                elif sub == "6":
                    run_domains_export(api_keys)
                elif sub == "7":
                    run_files_export(api_keys)
                elif sub == "8":
                    run_domains_export(api_keys)
                    run_files_export(api_keys)
                elif sub == "9":
                    import datetime as _dt_ckpt
                    _ckpts = _list_available_ckpts(
                        modes=["ips", "ips_tor", "domains", "files"]
                    )
                    if not _ckpts:
                        print(
                            "[CKPT] No checkpoint found.\n"
                            if LANG == "en"
                            else "[CKPT] No hay checkpoint.\n"
                        )
                    elif len(_ckpts) == 1:
                        ck = _ckpts[0]
                        _mode = ck.get("mode")
                        if _mode == "ips":
                            run_ip_analysis_normal(
                                selected_fields_ips, api_keys, resume=ck
                            )
                        elif _mode == "ips_tor":
                            run_ip_analysis_tor(
                                selected_fields_ips, api_keys, resume=ck
                            )
                        elif _mode == "domains":
                            run_domains_export(api_keys, resume=ck)
                        elif _mode == "files":
                            run_files_export(api_keys, resume=ck)
                    else:
                        # Varios checkpoints: mostrar lista para elegir
                        print(
                            "\n[CKPT] Multiple checkpoints found:"
                            if LANG == "en"
                            else "\n[CKPT] Hay varios checkpoints disponibles:"
                        )
                        for _n, _c in enumerate(_ckpts, 1):
                            _ts = _dt_ckpt.datetime.fromtimestamp(
                                float(_c.get("timestamp", 0))
                            ).strftime("%Y-%m-%d %H:%M")
                            print(
                                f"  {_n}) [{_c.get('mode','?')}]  idx={_c.get('idx','?')}  saved: {_ts}"
                                if LANG == "en"
                                else f"  {_n}) [{_c.get('mode','?')}]  idx={_c.get('idx','?')}  guardado: {_ts}"
                            )
                        _pick = safe_input(
                            "\nChoose number (enter=cancel): "
                            if LANG == "en"
                            else "\nElige número (enter=cancelar): ",
                            default="",
                            on_interrupt="back",
                        )
                        if _pick and _pick.strip().isdigit():
                            _num = int(_pick.strip()) - 1
                            if 0 <= _num < len(_ckpts):
                                ck = _ckpts[_num]
                                _mode = ck.get("mode")
                                if _mode == "ips":
                                    run_ip_analysis_normal(
                                        selected_fields_ips, api_keys, resume=ck
                                    )
                                elif _mode == "ips_tor":
                                    run_ip_analysis_tor(
                                        selected_fields_ips, api_keys, resume=ck
                                    )
                                elif _mode == "domains":
                                    run_domains_export(api_keys, resume=ck)
                                elif _mode == "files":
                                    run_files_export(api_keys, resume=ck)
                            else:
                                print(
                                    "Out of range.\n"
                                    if LANG == "en"
                                    else "Número fuera de rango.\n"
                                )
                        else:
                            print("Cancelado.\n")
                elif sub == "10":
                    run_ipapi_script_standalone()
                elif sub == "11" or sub.lower() in ("b", "q"):
                    print()
                    break
                else:
                    if LANG == "en":
                        print("Invalid option.\n")
                    else:
                        print("Opción no válida.\n")

        elif choice == "5":
            refresh_osint_feeds_now()

        elif choice == "6":
            handle_debug_menu()

        elif choice == "x":
            clear_ckpt()

        elif choice == "4":
            ssl_status = auto_check_ssl()

        elif choice == "7":
            suggest_test_ips_from_cache()

        elif choice == "8":
            # Exportar TODO: dominios y ficheros, con checkpoint
            run_domains_export(
                api_keys,
                resume=load_ckpt(mode="domains"),
            )
            run_files_export(
                api_keys,
                resume=load_ckpt(mode="files"),
            )

        # -------------------  MENU DOMINIOS  ---------------------
        elif choice == "2":
            while True:
                sub = domain_menu(ssl_status)

                if ssl_status == "mitm" and sub in ("1", "2", "3"):
                    if LANG == "en":
                        print("\n❌ BLOCKED by SSL intercept.\n")
                    else:
                        print("\n❌ BLOQUEADO por SSL intercept.\n")
                    continue

                if sub == "1":
                    path = safe_input(
                        (
                            "\nDomain file path (enter = 'dominios.txt'): "
                            if LANG == "en"
                            else "\nRuta fichero de dominios (enter = 'dominios.txt'): "
                        ),
                        DOMAIN_LIST_FILE,
                        on_interrupt="back",
                    )
                    if path is None:
                        print(
                            "\n[DOMAINS] Cancelled.\n"
                            if LANG == "en"
                            else "\n[DOMAINS] Cancelado.\n"
                        )
                        continue
                    run_domain_list_lookup(api_keys, list_file=path, resume=None)

                elif sub == "2":
                    path = safe_input(
                        (
                            "\nDomain file path (enter = 'dominios.txt'): "
                            if LANG == "en"
                            else "\nRuta fichero de dominios (enter = 'dominios.txt'): "
                        ),
                        DOMAIN_LIST_FILE,
                        on_interrupt="back",
                    )
                    if path is None:
                        print(
                            "\n[DOMAINS] Cancelled.\n"
                            if LANG == "en"
                            else "\n[DOMAINS] Cancelado.\n"
                        )
                        continue
                    run_domain_osint_lookup(list_file=path, resume=None)

                elif sub == "3":
                    _ckpts_dom = _list_available_ckpts(
                        modes=["domains_list", "domains_osint"]
                    )
                    ck = _ckpts_dom[0] if _ckpts_dom else None
                    if not ck or ck.get("mode") not in (
                        "domains_list",
                        "domains_osint",
                    ):
                        print(
                            "[CKPT] No checkpoint.\n"
                            if LANG == "en"
                            else "[CKPT] No hay checkpoint.\n"
                        )
                    else:
                        path = safe_input(
                            (
                                "\nDomain file path (enter = 'dominios.txt'): "
                                if LANG == "en"
                                else "\nRuta fichero de dominios (enter = 'dominios.txt'): "
                            ),
                            DOMAIN_LIST_FILE,
                            on_interrupt="back",
                        )
                        if path is None:
                            print(
                                "\n[DOMAINS] Cancelled.\n"
                                if LANG == "en"
                                else "\n[DOMAINS] Cancelado.\n"
                            )
                            continue
                        if ck.get("mode") == "domains_list":
                            run_domain_list_lookup(api_keys, list_file=path, resume=ck)
                        else:
                            run_domain_osint_lookup(list_file=path, resume=ck)

                # ⭐⭐⭐ ESTE ES EL ARREGLO REAL
                elif sub == "4":
                    break

                else:
                    print(
                        "Invalid option.\n" if LANG == "en" else "Opción no válida.\n"
                    )

        # ---------------------------------------------------------
        # ----------------------  MENU HASH  -----------------------
        # ---------------------------------------------------------
        elif choice == "3":
            while True:
                sub = hash_menu(ssl_status)

                if ssl_status == "mitm" and sub in ("1", "2", "3", "4"):
                    if LANG == "en":
                        print("\n❌ BLOCKED by SSL intercept.")
                        ans = safe_input(
                            "Press R to re-check now:",
                            default="",
                            on_interrupt="back",
                        )
                    else:
                        print("\n❌ BLOQUEADO por SSL intercept.")
                        ans = safe_input(
                            "Pulsa R para re-chequear ahora:",
                            default="",
                            on_interrupt="back",
                        )
                    if ans and ans.strip().lower().startswith("r"):
                        ssl_status = auto_check_ssl()
                    continue

                if sub == "1":
                    h = safe_input(
                        (
                            "\nEnter hash (MD5/SHA1/SHA256): "
                            if LANG == "en"
                            else "\nIntroduce el hash (MD5/SHA1/SHA256): "
                        ),
                        default="",
                        on_interrupt="back",
                    )
                    if not h:
                        print(
                            "\n[HASH] Cancelled.\n"
                            if LANG == "en"
                            else "\n[HASH] Cancelado.\n"
                        )
                        continue
                    run_hash_lookup(
                        api_keys, single_hash=h, list_file=None, resume=None
                    )

                elif sub == "2":
                    path = safe_input(
                        (
                            "\nHash file path (enter = auto-detect): "
                            if LANG == "en"
                            else "\nRuta fichero de hashes (enter = auto-detect): "
                        ),
                        default="",
                        on_interrupt="back",
                    )
                    if path == "":
                        path = None
                    run_hash_lookup(
                        api_keys, single_hash=None, list_file=path, resume=None
                    )

                elif sub == "3":
                    path = safe_input(
                        (
                            "\nHash file path (enter = auto-detect): "
                            if LANG == "en"
                            else "\nRuta fichero de hashes (enter = auto-detect): "
                        ),
                        default="",
                        on_interrupt="back",
                    )
                    if path == "":
                        path = None
                    run_hash_osint_lookup(list_file=path, resume=None)

                elif sub == "4":
                    ck = load_ckpt()
                    if not ck or ck.get("mode") not in ("hash_list", "hash_osint"):
                        print(
                            "[CKPT] No checkpoint.\n"
                            if LANG == "en"
                            else "[CKPT] No hay checkpoint.\n"
                        )
                    else:
                        path = safe_input(
                            (
                                "\nHash file path (enter = auto-detect): "
                                if LANG == "en"
                                else "\nRuta fichero de hashes (enter = auto-detect): "
                            ),
                            default="",
                            on_interrupt="back",
                        )
                        if path == "":
                            path = None
                        if ck.get("mode") == "hash_list":
                            run_hash_lookup(
                                api_keys, single_hash=None, list_file=path, resume=ck
                            )
                        else:
                            run_hash_osint_lookup(list_file=path, resume=ck)

                elif sub == "5":
                    print(
                        "\nReturning to main menu…\n"
                        if LANG == "en"
                        else "\nVolviendo al menú principal…\n"
                    )
                    break

                else:
                    print(
                        "Invalid option.\n" if LANG == "en" else "Opción no válida.\n"
                    )


# ─────────────────────────────────────────────────────────────
# BLOQUE DE ENTRADA (asegura que el menú arranca siempre)
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(
            "\n[EXIT] Cancelled by user.\n"
            if LANG == "en"
            else "\n[EXIT] Cancelado por usuario.\n"
        )
    except Exception:
        import traceback

        print(
            "\n[UNHANDLED EXCEPTION]\n"
            if LANG == "en"
            else "\n[EXCEPCIÓN NO CONTROLADA]\n"
        )
        traceback.print_exc()
        try:
            input(
                "\nPress ENTER to close…"
                if LANG == "en"
                else "\nPulsa ENTER para cerrar…"
            )
        except Exception:
            pass
