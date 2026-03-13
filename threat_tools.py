import os
import ipaddress
import requests
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY")


def _is_valid_public_ip(ip: str) -> tuple[bool, str]:
    ip = (ip or "").strip()

    if not ip:
        return False, "IP is empty."

    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False, "IP is invalid."

    if ip_obj.is_private:
        return False, "IP is private."
    if ip_obj.is_loopback:
        return False, "IP is loopback."
    if ip_obj.is_multicast:
        return False, "IP is multicast."
    if ip_obj.is_reserved:
        return False, "IP is reserved."
    if ip_obj.is_unspecified:
        return False, "IP is unspecified."

    return True, "IP is public."


def check_abuseipdb(ip: str) -> dict:
    is_valid, message = _is_valid_public_ip(ip)

    if not is_valid:
        return {
            "tool": "AbuseIPDB",
            "ip": ip,
            "status": "skipped",
            "message": message
        }

    if not ABUSEIPDB_API_KEY:
        return {
            "tool": "AbuseIPDB",
            "ip": ip,
            "status": "not_configured",
            "message": "ABUSEIPDB_API_KEY is missing."
        }

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
        "verbose": True
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=20)
        response.raise_for_status()

        data = response.json().get("data", {})

        return {
            "tool": "AbuseIPDB",
            "ip": ip,
            "status": "ok",
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "country_code": data.get("countryCode"),
            "usage_type": data.get("usageType"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "is_public": data.get("isPublic"),
            "last_reported_at": data.get("lastReportedAt")
        }

    except Exception as e:
        return {
            "tool": "AbuseIPDB",
            "ip": ip,
            "status": "error",
            "error": str(e)
        }


def check_greynoise(ip: str) -> dict:
    is_valid, message = _is_valid_public_ip(ip)

    if not is_valid:
        return {
            "tool": "GreyNoise",
            "ip": ip,
            "status": "skipped",
            "message": message
        }

    if not GREYNOISE_API_KEY:
        return {
            "tool": "GreyNoise",
            "ip": ip,
            "status": "not_configured",
            "message": "GREYNOISE_API_KEY is missing."
        }

    url = f"https://api.greynoise.io/v3/community/{ip}"
    headers = {
        "key": GREYNOISE_API_KEY,
        "accept": "application/json"
    }

    try:
        response = requests.get(url, headers=headers, timeout=20)

        if response.status_code == 404:
            return {
                "tool": "GreyNoise",
                "ip": ip,
                "status": "not_found",
                "noise": False,
                "riot": False,
                "classification": "unknown",
                "name": None
            }

        response.raise_for_status()
        data = response.json()

        return {
            "tool": "GreyNoise",
            "ip": ip,
            "status": "ok",
            "noise": data.get("noise"),
            "riot": data.get("riot"),
            "classification": data.get("classification"),
            "name": data.get("name"),
            "link": data.get("link")
        }

    except Exception as e:
        return {
            "tool": "GreyNoise",
            "ip": ip,
            "status": "error",
            "error": str(e)
        }