"""AdversaryIndex - CVE/NVD Scraper for AI-related vulnerabilities"""
import httpx
from datetime import datetime, timezone, timedelta


NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

AI_KEYWORDS = [
    "machine learning", "deep learning", "neural network", "LLM",
    "large language model", "GPT", "transformer", "diffusion model",
    "prompt injection", "adversarial", "model poisoning", "data poisoning",
    "jailbreak", "AI", "artificial intelligence", "inference", "training",
    "tensorflow", "pytorch", "huggingface", "langchain", "llamaindex",
    "openai", "anthropic", "ollama", "vllm", "triton inference",
]


async def fetch_nvd_ai_cves(hours_back: int = 72, api_key: str = "") -> list[dict]:
    """Fetch recent CVEs matching AI/ML keywords from NVD."""
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=hours_back)

    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    records = []
    async with httpx.AsyncClient(timeout=60) as client:
        for kw in AI_KEYWORDS:
            params = {
                "keywordSearch": kw,
                "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "resultsPerPage": 50,
            }
            try:
                resp = await client.get(NVD_API, params=params, headers=headers)
                if resp.status_code == 403:
                    print(f"[nvd] Rate limited on keyword: {kw}")
                    continue
                resp.raise_for_status()
                data = resp.json()
            except Exception as e:
                print(f"[nvd] Error for '{kw}': {e}")
                continue

            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "")

                # Skip duplicates
                if any(r["cve_id"] == cve_id for r in records):
                    continue

                descs = cve.get("descriptions", [])
                desc = next((d["value"] for d in descs if d["lang"] == "en"), "")

                metrics = cve.get("metrics", {})
                cvss_score = 0.0
                severity = "UNKNOWN"
                for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if key in metrics and metrics[key]:
                        cvss_data = metrics[key][0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore", 0.0)
                        severity = cvss_data.get("baseSeverity", "UNKNOWN")
                        break

                weaknesses = cve.get("weaknesses", [])
                cwe_ids = []
                for w in weaknesses:
                    for d in w.get("description", []):
                        if d.get("value", "").startswith("CWE-"):
                            cwe_ids.append(d["value"])

                attack_type = classify_attack_type(desc, cwe_ids)

                records.append({
                    "timestamp": now.isoformat(),
                    "source": "nvd",
                    "cve_id": cve_id,
                    "description": desc[:500],
                    "model": extract_model(desc),
                    "attack_type": attack_type,
                    "cvss_score": cvss_score,
                    "severity": severity,
                    "cwe_ids": cwe_ids,
                    "published": cve.get("published", ""),
                    "keyword_match": kw,
                })

    return records


def classify_attack_type(desc: str, cwe_ids: list[str]) -> str:
    """Classify attack type from description and CWE IDs."""
    desc_lower = desc.lower()
    if any(t in desc_lower for t in ["prompt injection", "jailbreak"]):
        return "prompt_injection"
    if any(t in desc_lower for t in ["model poisoning", "data poisoning", "backdoor"]):
        return "data_poisoning"
    if any(t in desc_lower for t in ["adversarial example", "adversarial attack", "evasion"]):
        return "adversarial_evasion"
    if any(t in desc_lower for t in ["model extraction", "model stealing", "model theft"]):
        return "model_extraction"
    if any(t in desc_lower for t in ["membership inference", "data leakage", "exfiltration"]):
        return "data_exfiltration"
    if any(t in desc_lower for t in ["denial of service", "resource exhaustion", "dos"]):
        return "denial_of_service"
    if any(t in desc_lower for t in ["supply chain", "dependency", "package"]):
        return "supply_chain"
    if any(t in desc_lower for t in ["remote code", "rce", "code execution"]):
        return "remote_code_execution"
    if "CWE-77" in cwe_ids or "CWE-78" in cwe_ids:
        return "command_injection"
    if "CWE-89" in cwe_ids:
        return "sql_injection"
    return "other"


def extract_model(desc: str) -> str:
    """Extract AI model name from description."""
    desc_lower = desc.lower()
    models = {
        "gpt-4": "GPT-4", "gpt-3.5": "GPT-3.5", "gpt-3": "GPT-3",
        "claude": "Claude", "llama": "LLaMA", "mistral": "Mistral",
        "gemini": "Gemini", "palm": "PaLM", "dall-e": "DALL-E",
        "stable diffusion": "Stable Diffusion", "midjourney": "Midjourney",
        "tensorflow": "TensorFlow", "pytorch": "PyTorch",
        "huggingface": "HuggingFace", "langchain": "LangChain",
        "llamaindex": "LlamaIndex", "openai": "OpenAI",
        "ollama": "Ollama", "vllm": "vLLM",
    }
    for key, name in models.items():
        if key in desc_lower:
            return name
    return "generic"
