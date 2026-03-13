import os
import requests
from dotenv import load_dotenv

load_dotenv()
requests.packages.urllib3.disable_warnings()

WAZUH_INDEXER_URL = os.getenv("WAZUH_INDEXER_URL")
WAZUH_INDEXER_USERNAME = os.getenv("WAZUH_INDEXER_USERNAME")
WAZUH_INDEXER_PASSWORD = os.getenv("WAZUH_INDEXER_PASSWORD")


def fetch_alerts(time_from="now-24h", agent_name=None, size=500):
    url = f"{WAZUH_INDEXER_URL}/wazuh-alerts*/_search"

    filters = [
        {
            "range": {
                "@timestamp": {
                    "gte": time_from
                }
            }
        }
    ]

    if agent_name and agent_name != "All": 
     filters.append({
        "match_phrase": {
            "agent.name": agent_name.strip()
        }
    })

    query = {
        "size": size,
        "sort": [
            {"@timestamp": {"order": "desc"}}
        ],
        "query": {
            "bool": {
                "filter": filters
            }
        }
    }

    response = requests.post(
        url,
        auth=(WAZUH_INDEXER_USERNAME, WAZUH_INDEXER_PASSWORD),
        headers={"Content-Type": "application/json"},
        json=query,
        verify=False,
        timeout=30
    )
    response.raise_for_status()

    data = response.json()
    hits = data.get("hits", {}).get("hits", [])

    alerts = []

    for hit in hits:
        src = hit.get("_source", {})

        alerts.append({
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
        })

    return alerts


def get_available_agents(size=200):
    alerts = fetch_alerts(time_from="now-30d", agent_name=None, size=size)
    agents = sorted(list({a["agent_name"] for a in alerts if a["agent_name"] != "unknown"}))
    return ["All"] + agents