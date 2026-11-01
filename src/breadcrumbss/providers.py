"""Provider interface and a no-key RDAP implementation."""

import ipaddress
import json
import os
import re
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from .capture import classify


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class HTTPSOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != "https":
            raise urllib.error.URLError("RDAP redirect was not HTTPS")
        return super().redirect_request(request, fp, code, message, headers, newurl)


_https_opener = urllib.request.build_opener(HTTPSOnlyRedirectHandler)


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None


_virustotal_opener = urllib.request.build_opener(NoRedirectHandler)


def get_json(url: str, timeout: float = 12) -> dict:
    request = urllib.request.Request(url, headers={"Accept": "application/rdap+json, application/json", "User-Agent": "Breadcrumbss/0.1"})
    with _https_opener.open(request, timeout=timeout) as response:
        data = response.read(2_000_001)
    if len(data) > 2_000_000:
        raise ValueError("Response exceeded 2 MB")
    result = json.loads(data)
    if not isinstance(result, dict):
        raise ValueError("Expected a JSON object")
    return result


class Provider:
    name = "base"

    def lookup(self, ip: str) -> dict:
        raise NotImplementedError


class RDAPProvider(Provider):
    name = "rdap"

    def __init__(self, requests_per_second: float = 1.0, fetch=get_json):
        self.fetch = fetch
        self.interval = 1.0 / requests_per_second
        self._rate_lock = threading.Lock()
        self._bootstrap_lock = threading.Lock()
        self._next_request = 0.0
        self._bootstrap = {}

    def _wait(self):
        with self._rate_lock:
            delay = max(0.0, self._next_request - time.monotonic())
            if delay:
                time.sleep(delay)
            self._next_request = time.monotonic() + self.interval

    def _registry(self, version: int):
        with self._bootstrap_lock:
            if version not in self._bootstrap:
                self._wait()
                data = self.fetch(f"https://data.iana.org/rdap/ipv{version}.json")
                entries = []
                for prefixes, urls in data.get("services", []):
                    secure_url = next((url for url in urls if url.startswith("https://")), None)
                    if secure_url:
                        for prefix in prefixes:
                            try:
                                entries.append((ipaddress.ip_network(prefix, strict=False), secure_url))
                            except ValueError:
                                continue
                self._bootstrap[version] = entries
            return self._bootstrap[version]

    def lookup(self, ip: str) -> dict:
        looked_up = utc_now()
        try:
            address = ipaddress.ip_address(ip)
            matches = [(network.prefixlen, url) for network, url in self._registry(address.version)
                       if address in network]
            if not matches:
                return {"status": "no_result", "looked_up_at": looked_up,
                        "source": f"https://data.iana.org/rdap/ipv{address.version}.json", "data": {}}
            _, base = max(matches, key=lambda item: item[0])
            url = base.rstrip("/") + "/ip/" + urllib.parse.quote(ip, safe=":.")
            self._wait()
            data = self.fetch(url)
            summary = {key: data[key] for key in ("handle", "name", "type", "country",
                       "startAddress", "endAddress", "ipVersion") if key in data}
            entities = []
            for entity in data.get("entities", []):
                if isinstance(entity, dict):
                    entities.append({key: entity[key] for key in ("handle", "roles") if key in entity})
            if entities:
                summary["entities"] = entities
            return {"status": "found" if summary else "no_result", "looked_up_at": looked_up,
                    "source": url, "data": summary}
        except urllib.error.HTTPError as exc:
            status = "rate_limited" if exc.code == 429 else "no_result" if exc.code == 404 else "lookup_failed"
            return {"status": status, "looked_up_at": looked_up, "source": None,
                    "error": f"RDAP returned HTTP {exc.code}", "data": {}}
        except (urllib.error.URLError, TimeoutError, OSError, ValueError, KeyError, TypeError) as exc:
            return {"status": "lookup_failed", "looked_up_at": looked_up, "source": None,
                    "error": f"{type(exc).__name__}: RDAP request or response failed", "data": {}}


VT_ENDPOINT = "https://www.virustotal.com/api/v3/ip_addresses/"
DEFAULT_VT_SECRET = Path(__file__).resolve().parents[2] / ".secrets" / "virustotal-api-key.dpapi"


def load_virustotal_key(secret_path: Path = DEFAULT_VT_SECRET) -> str:
    """Load a key from the environment or a Windows user-bound DPAPI file."""
    key = os.environ.get("BREADCRUMBSS_VIRUSTOTAL_API_KEY", "").strip()
    if not key and os.name == "nt" and secret_path.is_file():
        script = (
            "$s = Get-Content -LiteralPath $env:BREADCRUMBSS_VT_SECRET_PATH -Raw "
            "| ConvertTo-SecureString; "
            "[System.Net.NetworkCredential]::new('', $s).Password"
        )
        env = {**os.environ, "BREADCRUMBSS_VT_SECRET_PATH": str(secret_path)}
        # The bundled runtime can put a restricted PowerShell module first.
        env["PSModulePath"] = str(Path(os.environ.get("SystemRoot", r"C:\Windows")) /
                                  "System32" / "WindowsPowerShell" / "v1.0" / "Modules")
        try:
            result = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, timeout=15, env=env, check=True)
            key = result.stdout.strip()
        except (OSError, subprocess.SubprocessError) as exc:
            raise ValueError("Could not unlock the VirusTotal key for this Windows user") from None
    if not re.fullmatch(r"[0-9a-fA-F]{64}", key):
        raise ValueError("VirusTotal key missing or invalid; set BREADCRUMBSS_VIRUSTOTAL_API_KEY "
                         "or unlock the local DPAPI file")
    return key


def get_virustotal_json(ip: str, api_key: str) -> dict:
    url = VT_ENDPOINT + urllib.parse.quote(ip, safe=":.")
    request = urllib.request.Request(url, headers={
        "Accept": "application/json", "x-apikey": api_key,
        "User-Agent": "Breadcrumbss/0.1",
    })
    with _virustotal_opener.open(request, timeout=12) as response:
        body = response.read(2_000_001)
    if len(body) > 2_000_000:
        raise ValueError("Response exceeded 2 MB")
    result = json.loads(body)
    if not isinstance(result, dict):
        raise ValueError("Expected a JSON object")
    return result


class VirusTotalProvider(Provider):
    name = "virustotal"

    def __init__(self, api_key: str, fetch=get_virustotal_json):
        self._api_key = api_key
        self.fetch = fetch

    def lookup(self, ip: str) -> dict:
        looked_up = utc_now()
        try:
            address = ipaddress.ip_address(ip)
            if classify(address) != "public":
                return {"status": "excluded_by_policy", "looked_up_at": None,
                        "source": None, "data": {}}
            payload = self.fetch(ip, self._api_key)
            attributes = payload.get("data", {}).get("attributes", {})
            if not isinstance(attributes, dict):
                raise ValueError("Invalid VirusTotal response")
            fields = ("last_analysis_stats", "last_analysis_date", "reputation",
                      "country", "as_owner", "asn", "tags")
            summary = {field: attributes[field] for field in fields if field in attributes}
            return {"status": "found", "looked_up_at": looked_up,
                    "source": VT_ENDPOINT + urllib.parse.quote(ip, safe=":."),
                    "data": summary}
        except urllib.error.HTTPError as exc:
            status = "rate_limited" if exc.code == 429 else "no_result" if exc.code == 404 else "lookup_failed"
            return {"status": status, "looked_up_at": looked_up, "source": None,
                    "error": f"VirusTotal returned HTTP {exc.code}", "data": {}}
        except (urllib.error.URLError, TimeoutError, OSError, ValueError, KeyError, TypeError, AttributeError):
            return {"status": "lookup_failed", "looked_up_at": looked_up, "source": None,
                    "error": "VirusTotal request or response failed", "data": {}}

