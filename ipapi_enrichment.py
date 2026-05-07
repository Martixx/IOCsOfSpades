import os
import re
import csv
import time
import requests
import ipaddress
from datetime import datetime

INPUT_FILE = "list_ip.txt"
OUTPUT_FILE = f"{datetime.now().strftime('%Y%m%d-%H%M')}_IPAPI.csv"

URL = "http://ip-api.com/batch"
BATCH_SIZE = 100
RPM = 40
SLEEP_TIME = 60 / RPM

FIELDS = ",".join(
    [
        "status",
        "message",
        "query",
        "country",
        "countryCode",
        "region",
        "regionName",
        "city",
        "zip",
        "lat",
        "lon",
        "timezone",
        "isp",
        "org",
        "as",
        "asname",
        "mobile",
        "proxy",
        "hosting",
    ]
)

IPV4_REGEX = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def bool_to_str(v):
    return "yes" if v else "no"


def calculate_score(row):
    score = 0
    reasons = []

    proxy = row.get("proxy") == "yes"
    hosting = row.get("hosting") == "yes"
    mobile = row.get("mobile") == "yes"
    isp = (row.get("isp") or "").lower()
    org = (row.get("org") or "").lower()

    if proxy:
        score += 50
        reasons.append("proxy/vpn")

    if hosting:
        score += 30
        reasons.append("hosting/datacenter")

    if proxy and hosting:
        score += 10
        reasons.append("proxy+hosting")

    hosting_keywords = [
        "ovh",
        "hetzner",
        "contabo",
        "digitalocean",
        "linode",
        "m247",
        "leaseweb",
        "scaleway",
        "vultr",
        "choopa",
        "cloud",
        "akamai",
        "cloudflare",
    ]
    for kw in hosting_keywords:
        if kw in isp or kw in org:
            score += 10
            reasons.append(f"infra:{kw}")
            break

    if mobile:
        score -= 10
        reasons.append("mobile")

    score = max(0, min(100, score))

    if score >= 70:
        level = "high"
    elif score >= 40:
        level = "medium"
    elif score >= 20:
        level = "low"
    else:
        level = "clean"

    return score, level, ",".join(reasons)


def classify_ip(ip: str):
    try:
        obj = ipaddress.ip_address(ip)
        if obj.version != 4:
            return False
        return obj.is_global
    except Exception:
        return False


def load_ips(path: str):
    # Robusto: si hubiera basura, extrae IPv4 con regex.
    ips = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # si la línea es IP limpia, úsala; si no, intenta extraer
            candidates = (
                [line] if IPV4_REGEX.fullmatch(line) else IPV4_REGEX.findall(line)
            )
            for ip in candidates:
                if classify_ip(ip):
                    ips.append(ip)

    # dedup manteniendo orden
    seen = set()
    unique = []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            unique.append(ip)
    return unique


def chunks(lst, size):
    for i in range(0, len(lst), size):
        yield lst[i : i + size]


def query_ipapi(batch):
    for attempt in range(1, 6):
        try:
            r = requests.post(
                URL, params={"fields": FIELDS, "lang": "en"}, json=batch, timeout=25
            )

            if r.status_code == 429:
                sleep_s = min(10, 1.5 * attempt)
                print(f"[!] 429 rate limit. Sleeping {sleep_s:.1f}s...")
                time.sleep(sleep_s)
                continue

            if r.status_code != 200:
                print(f"[!] HTTP {r.status_code}. Writing FAIL rows for this batch.")
                return [
                    {"status": "fail", "message": f"HTTP{r.status_code}", "query": ip}
                    for ip in batch
                ]

            data = r.json() if r.content else []
            if not isinstance(data, list):
                print("[!] Unexpected response format. Writing FAIL rows.")
                return [
                    {"status": "fail", "message": "bad_response", "query": ip}
                    for ip in batch
                ]

            # Si devuelve menos que lo pedido, lo avisamos
            if len(data) != len(batch):
                print(
                    f"[!] Warning: API returned {len(data)}/{len(batch)} results for this batch."
                )

            return data

        except Exception as e:
            sleep_s = min(10, 1.5 * attempt)
            print(f"[!] Network error: {e}. Sleeping {sleep_s:.1f}s...")
            time.sleep(sleep_s)

    print("[!] Giving up after retries. Writing FAIL rows for this batch.")
    return [{"status": "fail", "message": "network_error", "query": ip} for ip in batch]


def main():
    print("\n=== IP-API enrichment (debug + score) ===")
    print(f"[i] CWD: {os.getcwd()}")
    print(f"[i] INPUT_FILE absolute: {os.path.abspath(INPUT_FILE)}")

    if not os.path.exists(INPUT_FILE):
        print(f"[!] File not found: {os.path.abspath(INPUT_FILE)}")
        return

    ips = load_ips(INPUT_FILE)
    print(f"[i] IPs loaded (valid public, dedup): {len(ips)}")

    if not ips:
        print("[!] No valid IPs found.")
        return

    out_fields = [
        "ip",
        "country",
        "region",
        "city",
        "isp",
        "org",
        "as",
        "asname",
        "proxy",
        "hosting",
        "mobile",
        "score",
        "risk_level",
        "reasons",
        "lat",
        "lon",
        "timezone",
        "status",
        "message",
    ]

    written = 0

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=out_fields)
        w.writeheader()

        for b, batch in enumerate(chunks(ips, BATCH_SIZE), start=1):
            print(f"[+] Batch {b}: sending {len(batch)} IPs")
            results = query_ipapi(batch)

            # Construye mapa por IP para cubrir el caso “devuelve menos”
            by_ip = {
                (item.get("query") or "").strip(): item
                for item in results
                if isinstance(item, dict)
            }
            for ip in batch:
                item = by_ip.get(
                    ip, {"status": "fail", "message": "missing_result", "query": ip}
                )

                row = {
                    "ip": item.get("query", ip),
                    "country": item.get("country", ""),
                    "region": item.get("regionName", ""),
                    "city": item.get("city", ""),
                    "isp": item.get("isp", ""),
                    "org": item.get("org", ""),
                    "as": item.get("as", ""),
                    "asname": item.get("asname", ""),
                    "proxy": bool_to_str(item.get("proxy")),
                    "hosting": bool_to_str(item.get("hosting")),
                    "mobile": bool_to_str(item.get("mobile")),
                    "lat": item.get("lat", ""),
                    "lon": item.get("lon", ""),
                    "timezone": item.get("timezone", ""),
                    "status": item.get("status", ""),
                    "message": item.get("message", ""),
                }

                score, level, reasons = calculate_score(row)
                row["score"] = score
                row["risk_level"] = level
                row["reasons"] = reasons

                w.writerow(row)
                written += 1

            time.sleep(SLEEP_TIME)

    print(f"\n[✔] Done. Rows written: {written}")
    print(f"[✔] Output: {os.path.abspath(OUTPUT_FILE)}\n")


if __name__ == "__main__":
    main()
