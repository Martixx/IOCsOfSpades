# ♠️ IOCs of Spades — 2.2 "Lemmy"

**BORN TO SCAN // LIVE TO WIN**  
**🤘 Everything louder than everything else 🤘**

Forged with Lemmy Kilmister blasting in the background. Not the fastest beast on the road, but loud enough to wake the SOC.

**IOCs of Spades** is a no-nonsense Python CLI for investigating and enriching indicators of compromise: **IPs, domains, and file hashes**. It brings OSINT lookups, threat-intelligence APIs, Passive DNS, bulk exports, and resumable jobs into one gloriously noisy toolbox.

Built for SOC analysts, threat hunters, and incident responders who would rather investigate than copy-paste IOCs all day.

## ⚡ What’s under the hood?

- **IP mode:** VirusTotal, Passive DNS, OSINT, ASN information, ASN-DROP, Tor/Onionoo, CSV exports, and checkpoints.
- **Domain mode:** VirusTotal list lookups, OSINT, and resume support.
- **Hash mode:** VirusTotal (single or bulk), MalwareBazaar, and resume support.
- **Threat intel sources:** VirusTotal, AbuseIPDB, abuse.ch, and AlienVault OTX integrations.
- **TLS interception checks:** Warnings for possible corporate proxies, SSL inspection, and VPN-related connection issues. A warning does **not** automatically mean an attack.
- **Local OSINT cache:** Reuse stored results instead of hammering APIs unnecessarily.
- **Pause and resume:** Checkpoints for long-running supported workflows.
- **Extras:** Debug menu, recent IP suggestions, and timestamped CSV output.

Works on **Windows and Linux**. No database, no daemon, no fancy infrastructure. Just Python and a healthy disregard for repetitive work.

## 🔥 Quick setup for the terminally impatient

**Requirements:** Python **3.10+** and two packages:

```bash
python -m pip install requests tqdm
```

On Debian/Ubuntu, install Python and pip first if needed:

```bash
sudo apt install python3 python3-pip
```

On Windows, get Python from [python.org](https://www.python.org/downloads/). Windows Terminal or VS Code's terminal is recommended if the banner looks like it survived a stage dive.

### 1. Get the code

Download or clone [IOCs of Spades](https://github.com/Martixx/IOCsOfSpades/tree/main).

### 2. Bring your own API keys

Copy `IOCS-apikeys.example.txt` to `IOCS-apikeys.txt` in the project directory and add the keys you use:

```text
VT=your_vt_key_1
VT=your_vt_key_2
ABUSEIPDB=your_abuseipdb_key_1,your_abuseipdb_key_2
ABUSECH=your_abusech_key_1,your_abusech_key_2
OTX=your_otx_key_1,your_otx_key_2
```

VirusTotal also accepts the legacy format (one unprefixed key per line). For AbuseIPDB, abuse.ch, and OTX, multiple keys can be separated by commas, semicolons, or spaces.

**Never commit real keys.** Keep `IOCS-apikeys.txt` out of Git, including its history. Without keys, only supported unauthenticated OSINT features are available; VirusTotal requires a valid key.

### 3. Feed the beast

Optionally create these IOC lists in the project directory:

- `iplist.txt`
- `dominios.txt`
- `hashes.txt`

They may be empty until you're ready to investigate.

### 4. Fire it up

Linux:

```bash
python3 IOCsOfSpades.py
```

Windows:

```powershell
python IOCsOfSpades.py
```

Follow the interactive menu. **No guitar lessons required.**

## 🛡️ Don't blame the API (yet)

**TLS / anti-MITM checks:** The tool can flag possible HTTPS interception by corporate proxies, certificate substitution, or VPN-related connectivity problems. These are diagnostic signals, **not proof of malicious MITM**. Check your network environment before drawing conclusions.

**ASN-DROP:** IP-API is the primary source; local IPtoASN data is the fallback. **IP addresses are sent to IP-API** when that lookup is used.

**Cache:** OSINT results are stored locally in `.osint_cache/`.

**Checkpoints:** Supported modes can resume interrupted runs. Handy when a huge IOC list meets a flaky connection.

**CSV:** Exports include timestamps for later filtering, correlation, and investigation.

## ⚠️ API limits: don't kill the drummer

Bulk lookups and Passive DNS can chew through quotas faster than a double-kick pedal.

- Check each provider's API terms, quotas, and allowed use cases.
- Use the local cache and avoid pointless repeat lookups.
- Expect rate limits, timeouts, and service-specific restrictions.
- Multiple API keys are supported, **not** a license to bypass provider limits. In particular, do not use multiple VirusTotal accounts to evade public API quotas.

## 🔒 Privacy, secrets & common sense

This tool sends queried indicators to external services depending on the mode selected. **Do not submit confidential customer IOCs or internal infrastructure details without authorization.** Review provider terms and your organization's data-handling rules first.

Protect your API-key file, cache, checkpoints, and exported CSVs. A bad reputation score is a lead, **not** a verdict. Humans still have to investigate.

## ❓ FAQ for the sleep-deprived

**Can I run it without API keys?** Some OSINT modes, yes. VirusTotal, no.

**Can I stop a long run?** Supported workflows use checkpoints so you can resume.

**Why am I seeing a MITM warning?** A proxy, TLS inspection device, or VPN may be interfering with the connection. Investigate before panicking.

**Does it need a database?** Nope.

**Does it run on Windows?** Yep. Linux too.

**Where's the cache?** `.osint_cache/`.

## 📜 License

Licensed under **Apache License 2.0**. See `LICENSE.txt` for the full terms.

## 🤘 Final words

An independent technical project built for learning, operations, and the occasional very loud incident investigation.

**No bloat. No bullshit. Just IOCs, Python, and rock ’n’ roll.**

**♠️ IOCs OF SPADES ♠️**<br>
**BORN TO SCAN // LIVE TO WIN**
