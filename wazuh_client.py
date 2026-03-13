import os
import requests
from dotenv import load_dotenv

load_dotenv()
requests.packages.urllib3.disable_warnings()

WAZUH_INDEXER_URL = os.getenv("WAZUH_INDEXER_URL")
WAZUH_INDEXER_USERNAME = os.getenv("WAZUH_INDEXER_USERNAME")
WAZUH_INDEXER_PASSWORD = os.getenv("WAZUH_INDEXER_PASSWORD")


def get_latest_alert():
    url = f"{WAZUH_INDEXER_URL}/wazuh-alerts*/_search"

    query = {
        "size": 1,
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

    if not hits:
        return {
            "rule_description": "No alert found",
            "source_ip": "unknown",
            "agent_name": "unknown",
            "severity": 0,
            "full_log": "No alerts returned"
        }

    src = hits[0].get("_source", {})

    return {
        "rule_description": src.get("rule", {}).get("description", "unknown"),
        "source_ip": src.get("data", {}).get("srcip", "unknown"),
        "agent_name": src.get("agent", {}).get("name", "unknown"),
        "severity": src.get("rule", {}).get("level", 0),
        "full_log": src.get("full_log", "unknown"),
        "timestamp": src.get("@timestamp", "unknown"),
        "raw_alert": src
    }