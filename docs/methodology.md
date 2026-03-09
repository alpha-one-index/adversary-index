# AdversaryIndex Methodology

## Data Collection

AdversaryIndex collects AI/ML threat intelligence from four authoritative public sources, running hourly via GitHub Actions.

### Source 1: NVD/CVE (NIST National Vulnerability Database)
- **Endpoint**: NVD REST API v2.0
- **Filter**: 27 AI/ML keywords including model names, frameworks, and attack patterns
- **Window**: Rolling 72-hour lookback
- **Fields extracted**: CVE ID, CVSS score, severity, CWE classification, description
- **Rate limiting**: Respects NVD 6 req/min public limit; optional API key for 50 req/min

### Source 2: MITRE ATLAS
- **Data**: YAML files from mitre-atlas/atlas-data GitHub repository
- **Content**: AI-specific attack techniques and real-world case studies
- **Mapping**: ATLAS technique IDs mapped to our attack_type taxonomy

### Source 3: AI Incident Database (AIID)
- **API**: GraphQL endpoint at incidentdatabase.ai
- **Content**: Real-world AI system failures and harms
- **Fields**: Incident ID, deployer, developer, harmed parties

### Source 4: OWASP LLM Top 10
- **Content**: Canonical risk taxonomy for LLM applications
- **Version**: 2025 edition
- **Mapping**: Each risk mapped to EU AI Act classification

## Enrichment

Every record is enriched with:

### EU AI Act Risk Classification
Attack types mapped to EU AI Act risk tiers:
- **Unacceptable**: Data poisoning, bias/discrimination, autonomous system failure, surveillance
- **High**: Prompt injection, adversarial evasion, model extraction, data exfiltration, supply chain, RCE
- **Limited**: Denial of service, reconnaissance
- **Minimal**: Unclassified

### Success Rate Estimation
Derived from published research literature on attack effectiveness against undefended models.

### Defense Efficacy Scoring
Based on NIST AI RMF and published defense benchmarks. Includes maturity assessment.

### New Technique Detection
Records are compared against a known technique signature database. Descriptions not matching known patterns are flagged as potential new techniques.

### Threat Score (0-100)
Composite score calculated as:
- CVSS base score (30% weight)
- Attack success rate (30% weight)
- Inverse defense efficacy (20% weight)
- EU AI Act risk tier (20% weight)

## Export Format

- **JSON**: `exports/latest.json` -- full structured data with nested fields
- **CSV**: `exports/latest.csv` -- flattened for spreadsheet/BI tool consumption
- **Schema**: `schemas/adversary_v1.json` -- JSON Schema validation

## Limitations

1. **NVD lag**: CVEs may take 24-72 hours to appear in NVD after disclosure
2. **Keyword matching**: Some non-AI CVEs may be captured (e.g., "inference" in non-ML context)
3. **Success rates**: Based on research literature, not real-time measurement
4. **AIID coverage**: Incident database has editorial lag for recent events

## Update Frequency

Hourly automated updates (typically <15 min lag) via public security sources. Minor delays possible due to upstream variability.
