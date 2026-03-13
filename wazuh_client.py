import os
import requests
from dotenv import load_dotenv

load_dotenv()
requests.packages.urllib3.disable_warnings()

WAZUH_INDEXER_URL = os.getenv("WAZUH_INDEXER_URL")
WAZUH_INDEXER_USERNAME = os.getenv("WAZUH_INDEXER_USERNAME")
WAZUH_INDEXER_PASSWORD = os.getenv("WAZUH_INDEXER_PASSWORD")


def get_latest_100_alerts():
    url = f"{WAZUH_INDEXER_URL}/wazuh-alerts*/_search"

    query = {
        "size": 100,
        "sort": [
            {"@timestamp": {"order": "desc"}}
        ],
        "query": {
            "match_all": {}
        }
    }

    response = requests.post(
        url,
        auth=(WAZUH_INDEXER_USERNAME, WAZUH_INDEXER_PASSWORD),
        headers={"Content-Type": "application/json"},
        json=query,
        verify=False,
        timeout=20
    )
    response.raise_for_status()

    data = response.json()
    hits = data.get("hits", {}).get("hits", [])

    alerts = []

    for hit in hits:
        src = hit.get("_source", {})

        alert = {
            "id": src.get("id", hit.get("_id", "unknown")),
            "timestamp": src.get("@timestamp", "unknown"),
            "rule_description": src.get("rule", {}).get("description", "unknown"),
            "source_ip": src.get("data", {}).get("srcip", "unknown"),
            "agent_name": src.get("agent", {}).get("name", "unknown"),
            "severity": src.get("rule", {}).get("level", 0),
            "full_log": src.get("full_log", "unknown"),
            "groups": src.get("rule", {}).get("groups", []),
            "mitre_ids": src.get("rule", {}).get("mitre", {}).get("id", []),
            "mitre_tactics": src.get("rule", {}).get("mitre", {}).get("tactic", []),
            "raw_alert": src
        }

        alerts.append(alert)

    return alerts