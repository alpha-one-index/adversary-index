"""AdversaryIndex - AI Incident Database + OWASP Top 10 for LLMs Scraper"""
import httpx
from datetime import datetime, timezone


AIID_API = "https://incidentdatabase.ai/api/incidents"
OWASP_LLM_URL = "https://raw.githubusercontent.com/OWASP/www-project-top-10-for-large-language-model-applications/main/data/owasp_llm_top10.json"


async def fetch_ai_incidents() -> list[dict]:
    """Fetch from AI Incident Database (AIID)."""
    now = datetime.now(timezone.utc).isoformat()
    records = []

    async with httpx.AsyncClient(timeout=30) as client:
        try:
            resp = await client.get(
                "https://incidentdatabase.ai/api/graphql",
                params={"query": "{incidents(limit:100,sort:{date:DESC}){incident_id title description date AllegedDeployerOfAISystem AllegedDeveloperOfAISystem AllegedHarmedOrNearlyHarmedParties}}"},
            )
            if resp.status_code == 200:
                data = resp.json()
                incidents = data.get("data", {}).get("incidents", [])
                for inc in incidents:
                    desc = str(inc.get("description", "") or "")[:500]
                    records.append({
                        "timestamp": now,
                        "source": "aiid",
                        "incident_id": inc.get("incident_id"),
                        "title": inc.get("title", ""),
                        "description": desc,
                        "model": extract_model_from_incident(inc),
                        "attack_type": classify_incident(inc),
                        "date": inc.get("date", ""),
                        "deployer": ", ".join(inc.get("AllegedDeployerOfAISystem", []) or []),
                        "developer": ", ".join(inc.get("AllegedDeveloperOfAISystem", []) or []),
                        "harmed_parties": ", ".join(inc.get("AllegedHarmedOrNearlyHarmedParties", []) or []),
                        "record_type": "incident",
                    })
        except Exception as e:
            print(f"[aiid] Error: {e}")

    return records


async def fetch_owasp_llm_top10() -> list[dict]:
    """Fetch OWASP Top 10 for LLMs as reference taxonomy."""
    now = datetime.now(timezone.utc).isoformat()
    records = []

    # Hardcoded OWASP LLM Top 10 2025 taxonomy
    owasp_risks = [
        {"id": "LLM01", "name": "Prompt Injection", "attack_type": "prompt_injection", "eu_risk": "high"},
        {"id": "LLM02", "name": "Insecure Output Handling", "attack_type": "remote_code_execution", "eu_risk": "high"},
        {"id": "LLM03", "name": "Training Data Poisoning", "attack_type": "data_poisoning", "eu_risk": "unacceptable"},
        {"id": "LLM04", "name": "Model Denial of Service", "attack_type": "denial_of_service", "eu_risk": "high"},
        {"id": "LLM05", "name": "Supply Chain Vulnerabilities", "attack_type": "supply_chain", "eu_risk": "high"},
        {"id": "LLM06", "name": "Sensitive Information Disclosure", "attack_type": "data_exfiltration", "eu_risk": "high"},
        {"id": "LLM07", "name": "Insecure Plugin Design", "attack_type": "remote_code_execution", "eu_risk": "high"},
        {"id": "LLM08", "name": "Excessive Agency", "attack_type": "other", "eu_risk": "high"},
        {"id": "LLM09", "name": "Overreliance", "attack_type": "other", "eu_risk": "limited"},
        {"id": "LLM10", "name": "Model Theft", "attack_type": "model_extraction", "eu_risk": "high"},
    ]

    for risk in owasp_risks:
        records.append({
            "timestamp": now,
            "source": "owasp_llm",
            "owasp_id": risk["id"],
            "name": risk["name"],
            "model": "generic",
            "attack_type": risk["attack_type"],
            "eu_ai_act_risk": risk["eu_risk"],
            "record_type": "taxonomy",
        })

    return records


def extract_model_from_incident(inc: dict) -> str:
    """Extract AI model from incident data."""
    text = f"{inc.get('title', '')} {inc.get('description', '')}".lower()
    developers = ", ".join(inc.get("AllegedDeveloperOfAISystem", []) or []).lower()
    combined = f"{text} {developers}"

    models = {
        "openai": "OpenAI", "gpt": "GPT", "chatgpt": "ChatGPT",
        "google": "Google AI", "meta": "Meta AI", "tesla": "Tesla Autopilot",
        "amazon": "Amazon AI", "microsoft": "Microsoft AI",
        "stable diffusion": "Stable Diffusion", "midjourney": "Midjourney",
        "anthropic": "Anthropic", "claude": "Claude",
    }
    for key, name in models.items():
        if key in combined:
            return name
    return "generic"


def classify_incident(inc: dict) -> str:
    """Classify incident attack type."""
    text = f"{inc.get('title', '')} {inc.get('description', '')}".lower()

    if any(t in text for t in ["bias", "discriminat", "fairness"]):
        return "bias_discrimination"
    if any(t in text for t in ["privacy", "data leak", "personal data"]):
        return "data_exfiltration"
    if any(t in text for t in ["deepfake", "misinformation", "fake"]):
        return "deepfake_misinfo"
    if any(t in text for t in ["autonomous", "self-driving", "crash"]):
        return "autonomous_system_failure"
    if any(t in text for t in ["manipulat", "deceiv", "trick"]):
        return "adversarial_evasion"
    if any(t in text for t in ["surveillance", "facial recognition"]):
        return "surveillance_overreach"
    return "other"
