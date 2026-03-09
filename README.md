# AdversaryIndex

**Live AI Adversarial Threat Index** -- attack success rates, new techniques, defense efficacy, and compliance risk scores across foundation models, updated hourly.

[![Hourly Collection](https://github.com/alpha-one-index/adversary-index/actions/workflows/hourly_collect.yml/badge.svg)](https://github.com/alpha-one-index/adversary-index/actions/workflows/hourly_collect.yml)

## What This Is

AdversaryIndex is the first open, machine-readable index of AI/ML adversarial threats. Every hour, automated pipelines collect, classify, and enrich threat data from:

| Source | Type | Records |
|--------|------|--------|
| **NVD/CVE** | AI-related vulnerabilities | 50-200+ |
| **MITRE ATLAS** | AI attack techniques & case studies | 30-50+ |
| **AI Incident Database** | Real-world AI failures | 100+ |
| **OWASP LLM Top 10** | Risk taxonomy | 10 |

## Schema (v1)

Every record includes:

```json
{
  "model": "GPT-4",
  "attack_type": "prompt_injection",
  "success_rate": 0.78,
  "new_technique": false,
  "defense_efficacy": 0.65,
  "eu_ai_act_risk": "high",
  "threat_score": 72.3,
  "timestamp": "2026-03-09T05:15:00Z"
}
```

## Attack Types Tracked

| Attack Type | Success Rate | Defense Efficacy | EU AI Act Risk |
|-------------|-------------|-----------------|----------------|
| Prompt Injection | 78% | 65% | High |
| Data Poisoning | 34% | 45% | Unacceptable |
| Adversarial Evasion | 62% | 55% | High |
| Model Extraction | 41% | 70% | High |
| Data Exfiltration | 29% | 60% | High |
| Denial of Service | 71% | 85% | Limited |
| Supply Chain | 23% | 75% | High |
| Bias/Discrimination | 88% | N/A | Unacceptable |

## Quick Start

```bash
# Clone and install
git clone https://github.com/alpha-one-index/adversary-index.git
cd adversary-index
pip install -r requirements.txt

# Run collection
python -m pipelines.collect

# View exports
cat exports/latest.json | python -m json.tool
```

## Repository Structure

```
adversary-index/
|-- .github/workflows/hourly_collect.yml
|-- pipelines/
|   |-- collect.py
|   |-- enrich.py
|   |-- scrapers/
|       |-- cve_scraper.py
|       |-- mitre_attack.py
|       |-- airisk_db.py
|-- schemas/adversary_v1.json
|-- exports/
|   |-- latest.json
|   |-- latest.csv
|-- docs/methodology.md
|-- requirements.txt
```

## API Access

### Free Tier
Raw threat data updated hourly -- CSV/JSON exports in `exports/`.

### Paid Tiers (via AWS Data Exchange)

| Tier | Price | Includes |
|------|-------|----------|
| **Hobby** | $99/mo or $0.01/1k queries | Live API, hourly updates |
| **Pro** | $299/mo | Full history + compliance mappings |
| **Enterprise** | $799/mo | SLA + private revisions |
| **Bundle (Neutron + Adversary)** | $1,499/mo | 25% discount, both indexes |

All paid tiers include a **14-day free trial**.

## Data Freshness Disclosure

> Hourly automated updates (typically <15 min lag) via public security sources. Minor delays possible due to upstream variability.

## Sources & Methodology

- **NVD**: NIST National Vulnerability Database, filtered for AI/ML keywords
- **MITRE ATLAS**: Adversarial Threat Landscape for AI Systems
- **AIID**: AI Incident Database (Partnership on AI)
- **OWASP**: Top 10 for Large Language Model Applications

See [docs/methodology.md](docs/methodology.md) for full details.

## License

MIT -- free to use, cite, and build upon.

---

Built by [Alpha One Index](https://github.com/alpha-one-index) -- Verified AI infrastructure and security intelligence.
