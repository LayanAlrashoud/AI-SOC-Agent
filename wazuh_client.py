import os
import requests
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv

load_dotenv()
requests.packages.urllib3.disable_warnings()

WAZUH_INDEXER_URL = os.getenv("WAZUH_INDEXER_URL")
WAZUH_INDEXER_USERNAME = os.getenv("WAZUH_INDEXER_USERNAME")
WAZUH_INDEXER_PASSWORD = os.getenv("WAZUH_INDEXER_PASSWORD")


def _post_search(query: dict):
    url = f"{WAZUH_INDEXER_URL}/wazuh-alerts*/_search"

    response = requests.post(
        url,
        auth=(WAZUH_INDEXER_USERNAME, WAZUH_INDEXER_PASSWORD),
        headers={"Content-Type": "application/json"},
        json=query,
        verify=False,
        timeout=30
    )
    response.raise_for_status()
    return response.json()


def _normalize_alert(src: dict, fallback_id="unknown"):
    return {
        "id": src.get("id", fallback_id),
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


def fetch_alerts(time_from="now-24h", agent_name=None, size=500):
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

    data = _post_search(query)
    hits = data.get("hits", {}).get("hits", [])

    alerts = []
    for hit in hits:
        src = hit.get("_source", {})
        alerts.append(_normalize_alert(src, fallback_id=hit.get("_id", "unknown")))

    return alerts


def get_available_agents(size=300):
    alerts = fetch_alerts(time_from="now-30d", agent_name=None, size=size)
    agents = sorted(list({a["agent_name"] for a in alerts if a["agent_name"] != "unknown"}))
    return ["All"] + agents


def _parse_timestamp(ts: str):
    # example: 2026-03-09T01:11:21.333Z
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def get_neighbor_alerts(selected_alert: dict, minutes=5, size=100):
    agent_name = selected_alert.get("agent_name", "unknown")
    source_ip = selected_alert.get("source_ip", "unknown")
    selected_time = selected_alert.get("timestamp")

    if not selected_time or selected_time == "unknown":
        return []

    center_dt = _parse_timestamp(selected_time)
    start_dt = center_dt - timedelta(minutes=minutes)
    end_dt = center_dt + timedelta(minutes=minutes)

    filters = [
        {
            "range": {
                "@timestamp": {
                    "gte": start_dt.astimezone(timezone.utc).isoformat(),
                    "lte": end_dt.astimezone(timezone.utc).isoformat()
                }
            }
        },
        {
            "match_phrase": {
                "agent.name": agent_name
            }
        }
    ]

    # إذا فيه source_ip نضيفه
    if source_ip and source_ip != "unknown":
        filters.append({
            "match_phrase": {
                "data.srcip": source_ip
            }
        })

    query = {
        "size": size,
        "sort": [
            {"@timestamp": {"order": "asc"}}
        ],
        "query": {
            "bool": {
                "filter": filters
            }
        }
    }

    data = _post_search(query)
    hits = data.get("hits", {}).get("hits", [])

    alerts = []
    selected_id = selected_alert.get("id")

    for hit in hits:
        src = hit.get("_source", {})
        normalized = _normalize_alert(src, fallback_id=hit.get("_id", "unknown"))

        # نستبعد نفس الـ alert الأساسي من قائمة الجيران
        if normalized["id"] != selected_id:
            alerts.append(normalized)

    return alerts