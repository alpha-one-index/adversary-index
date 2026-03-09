"""AdversaryIndex -- Main Collection Pipeline"""
import asyncio
import json
import csv
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from pipelines.scrapers.cve_scraper import fetch_nvd_ai_cves
from pipelines.scrapers.airisk_db import fetch_ai_incidents, fetch_owasp_llm_top10
from pipelines.enrich import enrich_record


async def collect():
    all_records = []

    # Source 1: NVD CVEs (AI-related)
    try:
        records = await fetch_nvd_ai_cves(hours_back=72)
        all_records.extend(records)
        print(f"[nvd] {len(records)} records")
    except Exception as e:
        print(f"[nvd] FAILED: {e}")

    # Source 2: MITRE ATLAS
    try:
        from pipelines.scrapers.mitre_attack import fetch_mitre_atlas
        records = await fetch_mitre_atlas()
        all_records.extend(records)
        print(f"[atlas] {len(records)} records")
    except Exception as e:
        print(f"[atlas] SKIPPED: {e}")

    # Source 3: AI Incident Database
    try:
        records = await fetch_ai_incidents()
        all_records.extend(records)
        print(f"[aiid] {len(records)} records")
    except Exception as e:
        print(f"[aiid] SKIPPED: {e}")

    # Source 4: OWASP LLM Top 10 taxonomy
    try:
        records = await fetch_owasp_llm_top10()
        all_records.extend(records)
        print(f"[owasp] {len(records)} records")
    except Exception as e:
        print(f"[owasp] SKIPPED: {e}")

    if not all_records:
        print("No data collected!")
        sys.exit(1)

    # Enrich all records
    for record in all_records:
        enrich_record(record)

    # Export
    os.makedirs("exports", exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    # JSON export
    with open("exports/latest.json", "w") as f:
        json.dump({"generated": ts, "count": len(all_records), "records": all_records}, f, indent=2, default=str)

    # CSV export with union of all keys
    if all_records:
        all_keys = []
        seen = set()
        for r in all_records:
            for k in r.keys():
                if k not in seen:
                    all_keys.append(k)
                    seen.add(k)
        with open("exports/latest.csv", "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=all_keys, extrasaction="ignore", restval="")
            writer.writeheader()
            for r in all_records:
                # Convert lists to strings for CSV
                row = {}
                for k, v in r.items():
                    row[k] = json.dumps(v) if isinstance(v, (list, dict)) else v
                writer.writerow(row)

    # Parquet export
    try:
        import pyarrow as pa
        import pyarrow.parquet as pq

        # Flatten records for columnar storage
        flat_records = []
        for r in all_records:
            flat = {}
            for k, v in r.items():
                flat[k] = json.dumps(v) if isinstance(v, (list, dict)) else v
            flat_records.append(flat)

        if flat_records:
            # Build table from list of dicts
            table = pa.Table.from_pylist(flat_records)
            pq.write_table(table, "exports/latest.parquet", compression="snappy")
            print(f"[parquet] wrote {len(flat_records)} rows")
    except ImportError:
        print("[parquet] SKIPPED: pyarrow not installed")
    except Exception as e:
        print(f"[parquet] FAILED: {e}")

    # Summary stats
    attack_types = {}
    for r in all_records:
        at = r.get("attack_type", "other")
        attack_types[at] = attack_types.get(at, 0) + 1

    print(f"\n[export] {len(all_records)} records -> exports/ ({ts})")
    print(f"[stats] Attack types: {json.dumps(attack_types, indent=2)}")
    print(f"[stats] Sources: NVD, MITRE ATLAS, AIID, OWASP")


if __name__ == "__main__":
    asyncio.run(collect())
