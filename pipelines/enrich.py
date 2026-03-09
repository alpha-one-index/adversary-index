"""AdversaryIndex - Enrichment Module

Adds EU AI Act risk classification, success rate estimates,
defense efficacy scores, and new technique detection.
"""
from datetime import datetime, timezone


# EU AI Act risk classification mapping
EU_AI_ACT_RISK = {
    "prompt_injection": "high",
    "data_poisoning": "unacceptable",
    "adversarial_evasion": "high",
    "model_extraction": "high",
    "data_exfiltration": "high",
    "denial_of_service": "limited",
    "supply_chain": "high",
    "remote_code_execution": "high",
    "command_injection": "high",
    "sql_injection": "high",
    "bias_discrimination": "unacceptable",
    "deepfake_misinfo": "high",
    "autonomous_system_failure": "unacceptable",
    "surveillance_overreach": "unacceptable",
    "reconnaissance": "limited",
    "other": "minimal",
}

# Known defense mechanisms and their efficacy
DEFENSE_CATALOG = {
    "prompt_injection": {
        "defense": "Input sanitization + output filtering",
        "efficacy": 0.65,
        "mature": False,
    },
    "data_poisoning": {
        "defense": "Data provenance + anomaly detection",
        "efficacy": 0.45,
        "mature": False,
    },
    "adversarial_evasion": {
        "defense": "Adversarial training + certified robustness",
        "efficacy": 0.55,
        "mature": False,
    },
    "model_extraction": {
        "defense": "Rate limiting + watermarking",
        "efficacy": 0.70,
        "mature": True,
    },
    "data_exfiltration": {
        "defense": "Differential privacy + output filtering",
        "efficacy": 0.60,
        "mature": False,
    },
    "denial_of_service": {
        "defense": "Rate limiting + resource quotas",
        "efficacy": 0.85,
        "mature": True,
    },
    "supply_chain": {
        "defense": "SBOM + signature verification",
        "efficacy": 0.75,
        "mature": True,
    },
    "remote_code_execution": {
        "defense": "Sandboxing + input validation",
        "efficacy": 0.80,
        "mature": True,
    },
}

# Approximate success rates by attack type (from research literature)
SUCCESS_RATES = {
    "prompt_injection": 0.78,
    "data_poisoning": 0.34,
    "adversarial_evasion": 0.62,
    "model_extraction": 0.41,
    "data_exfiltration": 0.29,
    "denial_of_service": 0.71,
    "supply_chain": 0.23,
    "remote_code_execution": 0.15,
    "bias_discrimination": 0.88,
    "deepfake_misinfo": 0.73,
}

# Known technique signatures for new technique detection
KNOWN_TECHNIQUES = {
    "prompt_injection", "jailbreak", "DAN", "token smuggling",
    "indirect prompt injection", "payload splitting",
    "model poisoning", "backdoor attack", "trojan",
    "adversarial patch", "adversarial perturbation",
    "model inversion", "membership inference",
    "gradient-based extraction", "distillation attack",
}


def enrich_record(record: dict) -> dict:
    """Enrich a single record with compliance and risk fields."""
    attack_type = record.get("attack_type", "other")

    # EU AI Act risk classification
    record["eu_ai_act_risk"] = record.get("eu_ai_act_risk") or EU_AI_ACT_RISK.get(attack_type, "minimal")

    # Success rate estimate
    record["success_rate"] = SUCCESS_RATES.get(attack_type, 0.0)

    # Defense efficacy
    defense = DEFENSE_CATALOG.get(attack_type, {})
    record["defense_efficacy"] = defense.get("efficacy", 0.0)
    record["defense_mechanism"] = defense.get("defense", "unknown")
    record["defense_mature"] = defense.get("mature", False)

    # New technique detection
    desc = str(record.get("description", "")).lower()
    name = str(record.get("name", "")).lower()
    combined = f"{desc} {name}"
    known_match = any(kt.lower() in combined for kt in KNOWN_TECHNIQUES)
    record["new_technique"] = not known_match and attack_type != "other"

    # Composite threat score (0-100)
    cvss = record.get("cvss_score", 0) or 0
    success = record.get("success_rate", 0)
    defense_eff = record.get("defense_efficacy", 0)
    eu_weight = {"unacceptable": 1.0, "high": 0.75, "limited": 0.4, "minimal": 0.2}.get(
        record.get("eu_ai_act_risk", "minimal"), 0.2
    )

    threat_score = (
        (cvss / 10 * 30) +
        (success * 30) +
        ((1 - defense_eff) * 20) +
        (eu_weight * 20)
    )
    record["threat_score"] = round(min(threat_score, 100), 1)

    return record
