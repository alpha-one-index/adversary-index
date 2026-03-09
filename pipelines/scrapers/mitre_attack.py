"""AdversaryIndex - MITRE ATLAS Scraper (AI-specific ATT&CK framework)"""
import httpx
from datetime import datetime, timezone


ATLAS_STIX_URL = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/schemas/atlas-attack-enterprise.json"
ATLAS_TECHNIQUES_URL = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/data/techniques.yaml"
ATLAS_CASE_STUDIES_URL = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/data/case-studies.yaml"


async def fetch_mitre_atlas() -> list[dict]:
    """Fetch MITRE ATLAS techniques and case studies for AI attacks."""
    now = datetime.now(timezone.utc).isoformat()
    records = []

    async with httpx.AsyncClient(timeout=30) as client:
        # Fetch ATLAS case studies (real-world AI attack incidents)
        try:
            resp = await client.get(ATLAS_CASE_STUDIES_URL)
            resp.raise_for_status()
            import yaml
            case_studies = yaml.safe_load(resp.text)

            if isinstance(case_studies, list):
                for study in case_studies:
                    records.append({
                        "timestamp": now,
                        "source": "mitre_atlas",
                        "atlas_id": study.get("id", ""),
                        "name": study.get("name", ""),
                        "description": str(study.get("summary", ""))[:500],
                        "model": extract_target_model(study),
                        "attack_type": map_atlas_to_attack_type(study),
                        "techniques_used": [t.get("id", "") for t in study.get("techniques", [])],
                        "severity": assess_severity(study),
                        "record_type": "case_study",
                    })
        except Exception as e:
            print(f"[atlas] Case studies error: {e}")

        # Fetch ATLAS techniques taxonomy
        try:
            resp = await client.get(ATLAS_TECHNIQUES_URL)
            resp.raise_for_status()
            import yaml
            techniques = yaml.safe_load(resp.text)

            if isinstance(techniques, list):
                for tech in techniques:
                    records.append({
                        "timestamp": now,
                        "source": "mitre_atlas",
                        "atlas_id": tech.get("id", ""),
                        "name": tech.get("name", ""),
                        "description": str(tech.get("description", ""))[:500],
                        "model": "generic",
                        "attack_type": map_technique_to_attack_type(tech),
                        "tactic": tech.get("tactic", ""),
                        "severity": "HIGH" if "ML" in tech.get("id", "") else "MEDIUM",
                        "record_type": "technique",
                    })
        except Exception as e:
            print(f"[atlas] Techniques error: {e}")

    return records


def extract_target_model(study: dict) -> str:
    """Extract target model from ATLAS case study."""
    summary = str(study.get("summary", "") or "").lower()
    name = str(study.get("name", "") or "").lower()
    combined = f"{name} {summary}"

    models = {
        "gpt": "GPT", "chatgpt": "ChatGPT", "claude": "Claude",
        "llama": "LLaMA", "bert": "BERT", "resnet": "ResNet",
        "yolo": "YOLO", "tensorflow": "TensorFlow", "pytorch": "PyTorch",
        "stable diffusion": "Stable Diffusion", "dall-e": "DALL-E",
        "whisper": "Whisper", "copilot": "Copilot",
    }
    for key, name in models.items():
        if key in combined:
            return name
    return "generic"


def map_atlas_to_attack_type(study: dict) -> str:
    """Map ATLAS case study to attack type."""
    techniques = [t.get("id", "") for t in study.get("techniques", [])]
    name = str(study.get("name", "")).lower()

    if any("AML.T0043" in t for t in techniques) or "poison" in name:
        return "data_poisoning"
    if any("AML.T0051" in t for t in techniques) or "prompt" in name:
        return "prompt_injection"
    if any("AML.T0024" in t for t in techniques) or "evasion" in name:
        return "adversarial_evasion"
    if any("AML.T0044" in t for t in techniques) or "extract" in name:
        return "model_extraction"
    if any("AML.T0025" in t for t in techniques) or "exfiltrat" in name:
        return "data_exfiltration"
    if "supply chain" in name:
        return "supply_chain"
    return "other"


def map_technique_to_attack_type(tech: dict) -> str:
    """Map ATLAS technique to attack type."""
    tid = tech.get("id", "")
    tactic = str(tech.get("tactic", "")).lower()

    mapping = {
        "reconnaissance": "reconnaissance",
        "initial-access": "prompt_injection",
        "ml-attack-staging": "adversarial_evasion",
        "ml-model-access": "model_extraction",
        "exfiltration": "data_exfiltration",
        "impact": "denial_of_service",
    }
    return mapping.get(tactic, "other")


def assess_severity(study: dict) -> str:
    """Assess severity of a case study."""
    techniques = study.get("techniques", [])
    if len(techniques) >= 4:
        return "CRITICAL"
    if len(techniques) >= 2:
        return "HIGH"
    return "MEDIUM"
