# IOC Data Model v1 (IOCsOfSpades)

## Goal
Create a stable IOC model that:
- Keeps raw source evidence intact.
- Separates confirmed signals from heuristic hints.
- Produces a clean canonical layer for Master/analytics.
- Preserves current CSV compatibility during migration.

## Core Entities

### 1) indicator
One row per observable.

Fields:
- indicator_id
- indicator_value
- indicator_type (ip, domain, url, hash)
- indicator_value_normalized
- first_seen
- last_seen

### 2) source_observation
One row per source observation for an indicator.

Fields:
- observation_id
- indicator_id
- source_name (virustotal, abuseipdb, threatfox, otx, urlhaus, onionoo, etc)
- observed_at
- source_status
- raw_payload_ref
- source_confidence

### 3) feature_signal
Derived machine-readable flags from one or more observations.

Fields:
- indicator_id
- is_vpn_confirmed
- vpn_hint_owner
- is_tor_exit
- is_c2_suspect
- is_cluster_hosting
- malicious_count
- suspicious_count
- reputation_value
- risk_score
- evidence_trace

### 4) threat_classification
Threat semantics for analytics and filtering.

Fields:
- indicator_id
- threat_type_primary
- threat_type_tags (comma-separated or JSON array)
- verdict_final (malicious, suspicious, clean, unknown)
- confidence_final
- decision_trace

## Threat Type Catalog (v1)
- phishing
- malware
- c2
- botnet
- scanner
- proxy
- spam
- adware

## Mapping: Current IOCsOfSpades -> v1 Canonical

| Current field | v1 destination | Notes |
|---|---|---|
| ip | indicator.indicator_value | indicator_type=ip |
| asn | feature_signal (or source_observation normalized) | Keep as numeric/string |
| asn_full | feature_signal | Human readable ASN |
| owner | feature_signal | Infra owner hint |
| CDIR | feature_signal | Keep as network/cidr |
| country | feature_signal | Country hint |
| reputation | feature_signal.reputation_value | Normalize to int when possible |
| malicious | feature_signal.malicious_count | From VT stats |
| suspicious | feature_signal.suspicious_count | From VT stats |
| harmless | source_observation normalized | Keep for explainability |
| undetected | source_observation normalized | Keep for explainability |
| vendors_malicious | source_observation normalized | Also contributes to risk/decision |
| vt_ip_tags | source_observation normalized | Main input for vpn/tag typing |
| vt_labels | source_observation normalized | Threat typing input |
| vt_categories | source_observation normalized | Threat typing input |
| vt_crowdsourced_tags | source_observation normalized | Threat typing input |
| whois | source_observation normalized | Keep raw/trimmed |
| vt_vpn | feature_signal.is_vpn_confirmed candidate | VT-only evidence |
| is_vpn | feature_signal.is_vpn_confirmed | Confirmed flag |
| vpn_source | feature_signal.evidence_trace | Should be vt_tag only now |
| vpn_suspect | feature_signal.vpn_hint_owner | Heuristic hint only |
| heuristic_tags | feature_signal.evidence_trace | Keep hints (non-confirmed) |
| cluster_flag | feature_signal.is_cluster_hosting | yes/no |
| cluster_reason | feature_signal.evidence_trace | Preserve reason |
| c2_suspect | feature_signal.is_c2_suspect | yes/no |
| c2_reason | feature_signal.evidence_trace | Preserve reason |
| risk_score | feature_signal.risk_score | 0-100 |
| tor_exit | feature_signal.is_tor_exit | yes/no |
| tor_source | source_observation normalized | Onionoo provenance |
| tor_nickname | source_observation normalized | Optional |
| tor_fingerprint | source_observation normalized | Optional |
| link | source_observation.raw_payload_ref | API link |
| gui | source_observation.raw_payload_ref | Analyst link |

## Rules (must hold)
- Confirmed != hinted:
  - is_vpn_confirmed is only true when VT evidence confirms it.
  - owner-based keyword hits remain hints only.
- Raw never overwritten:
  - Source columns stay unchanged in source_observation/raw layer.
- Every consolidated decision has trace:
  - decision_trace/evidence_trace must explain why.

## Migration Plan (safe)

### Phase 0: Compatibility
Keep current CSV columns as they are.

### Phase 1: Add canonical columns
Add new columns (prefixed if needed):
- canon_indicator_type
- canon_verdict
- canon_threat_type_primary
- canon_threat_type_tags
- canon_confidence
- canon_is_vpn_confirmed
- canon_vpn_hint_owner
- canon_decision_trace

### Phase 2: Switch analytics to canonical
Master filters and dashboards read canonical columns first.

### Phase 3: Optional cleanup
Deprecate duplicated legacy columns only after dashboards and exports are stable.

## Minimal SQL-like logical schema (reference)

- indicator(indicator_id PK, indicator_value, indicator_type, indicator_value_normalized, first_seen, last_seen)
- source_observation(observation_id PK, indicator_id FK, source_name, observed_at, source_status, raw_payload_ref, source_confidence, normalized_json)
- feature_signal(indicator_id FK, is_vpn_confirmed, vpn_hint_owner, is_tor_exit, is_c2_suspect, is_cluster_hosting, malicious_count, suspicious_count, reputation_value, risk_score, evidence_trace)
- threat_classification(indicator_id FK, threat_type_primary, threat_type_tags, verdict_final, confidence_final, decision_trace)
