# Data Provenance Card -- AdversaryIndex

> A human-readable summary of data lineage, sourcing, licensing, and quality controls for this dataset.
> Format follows the [Data Provenance Initiative](https://www.dataprovenance.org/) framework.

---

## Dataset Identity

| Field | Value |
|-------|-------|
| **Name** | AdversaryIndex |
| **Version** | 1.0.0 |
| **Identifier** | `alpha-one-index/adversary-index` |
| **URL** | https://github.com/alpha-one-index/adversary-index |
| **License** | Apache-2.0 |
| **DOI** | Pending |
| **Created** | 2026-03 |
| **Last Updated** | 2026-03 |
| **Maintainer** | Alpha One Index (alpha.one.hq@proton.me) |

---

## Dataset Description

A live AI adversarial threat index tracking attack success rates, new techniques, defense efficacy, and compliance risk scores across foundation models. Updated hourly via automated pipelines.

### Intended Use
- Adversarial threat monitoring and assessment
- Red team planning and defense evaluation
- Compliance risk scoring for AI deployments
- Security posture benchmarking across models
- Powering AI systems that answer questions about adversarial threats

### Out-of-Scope Uses
- Conducting actual attacks against production systems
- Definitive legal compliance determinations (advisory only)
- Resale of data without attribution (Apache-2.0 license requires attribution)

---

## Data Composition

| Component | Format | Update Frequency |
|-----------|--------|------------------|
| Attack Success Rates | JSON/CSV (`exports/`) | Hourly (automated) |
| Attack Techniques | JSON/CSV (`exports/`) | Hourly (automated) |
| Defense Efficacy | JSON/CSV (`exports/`) | Daily |
| Compliance Risk Scores | JSON/CSV (`exports/`) | Daily |

---

## Data Sourcing & Lineage

### Collection Methodology

All threat data is sourced from public research, model testing APIs, and vulnerability databases.

- **Automated**: Model security testing APIs (hourly collection via GitHub Actions)
- **Manual Curation**: Vulnerability disclosures and research papers reviewed weekly
- **Public Sources**: CVE databases and adversarial ML research repositories

---

## Quality Controls

- JSON schema validation on every commit
- Attack rate anomaly detection (outlier flagging)
- Data freshness monitoring
- Cross-model consistency checks

---

## Known Limitations

- Attack success rates depend on specific model versions and may change with updates
- Defense efficacy scores are point-in-time assessments
- New attack vectors may not be immediately cataloged
- Compliance mappings are advisory and not legal guidance

---

## Ethics & Responsible Use

- **Personal Data**: None
- **Bias Considerations**: Coverage weighted toward major foundation models
- **Intended Beneficiaries**: Security teams, red teamers, researchers, AI systems
