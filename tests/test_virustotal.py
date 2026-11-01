"""Offline checks for the opt-in VirusTotal path."""

import io
import ipaddress
import json
import os
import sys
import tempfile
import unittest
import urllib.error
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from breadcrumbss.capture import classify
from breadcrumbss.cli import main
from breadcrumbss.providers import VirusTotalProvider, load_virustotal_key
from breadcrumbss.state import State
from breadcrumbss.workflow import Processor


def row(ip):
    return {"ip": ip, "ip_version": ipaddress.ip_address(ip).version,
            "classification": classify(ipaddress.ip_address(ip)),
            "directions": ["destination"], "first_seen": "2024-01-01T00:00:00+00:00",
            "last_seen": "2024-01-01T00:00:01+00:00", "first_frame": "1",
            "last_frame": "2", "packet_count": 2, "protocols": ["tcp"], "ports": ["443"]}


class Parser:
    def parse(self, path):
        return 3, [row(ip) for ip in ("8.8.8.8", "1.1.1.1", "10.0.0.1", "239.255.255.250")]


class FakeVirusTotal:
    def __init__(self, status="found"):
        self.calls = []
        self.status = status

    def lookup(self, ip):
        self.calls.append(ip)
        return {"status": self.status, "looked_up_at": "2024-01-01T00:00:00+00:00",
                "source": "https://www.virustotal.com/api/v3/ip_addresses/" + ip,
                "data": {"reputation": 2}}


class VirusTotalTests(unittest.TestCase):
    def test_public_eligibility_and_key_redaction(self):
        key = "a" * 64
        seen = []

        def fetch(ip, supplied_key):
            seen.append((ip, supplied_key))
            return {"data": {"attributes": {"reputation": 2, "secret_extra": key}}}

        provider = VirusTotalProvider(key, fetch=fetch)
        for ip in ("10.0.0.1", "239.255.255.250", "ff02::1", "::1", "0.0.0.0"):
            self.assertEqual(provider.lookup(ip)["status"], "excluded_by_policy")
        result = provider.lookup("8.8.8.8")
        self.assertEqual(seen, [("8.8.8.8", key)])
        self.assertEqual(result["data"], {"reputation": 2})
        self.assertNotIn(key, json.dumps(result))

    def test_quota_response_redacts_key(self):
        key = "b" * 64

        def fetch(ip, supplied_key):
            raise urllib.error.HTTPError("https://example.test/" + key, 429, key, {}, None)

        result = VirusTotalProvider(key, fetch=fetch).lookup("8.8.8.8")
        self.assertEqual(result["status"], "rate_limited")
        self.assertNotIn(key, json.dumps(result))

    def test_environment_key_load(self):
        key = "c" * 64
        with patch.dict(os.environ, {"BREADCRUMBSS_VIRUSTOTAL_API_KEY": key}):
            self.assertEqual(load_virustotal_key(), key)

    def test_durable_minute_and_day_limits(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "state.sqlite3"
            state = State(path)
            try:
                start = datetime(2024, 1, 1, tzinfo=timezone.utc).timestamp()
                for offset in range(4):
                    self.assertEqual(state.vt_reserve_request(start + offset), 0)
                self.assertGreater(state.vt_reserve_request(start + 4), 50)
            finally:
                state.close()
            state = State(path)
            try:
                self.assertGreater(state.vt_reserve_request(start + 4), 50)
                self.assertEqual(state.vt_reserve_request(start + 61), 0)
                for index in range(5, 500):
                    self.assertEqual(state.vt_reserve_request(start + index * 61), 0)
                self.assertIsNone(state.vt_reserve_request(start + 499 * 61 + 1))
            finally:
                state.close()

    def test_cache_expiry(self):
        with tempfile.TemporaryDirectory() as temp:
            state = State(Path(temp) / "state.sqlite3")
            result = {"status": "found", "looked_up_at": "2024-01-01T00:00:00Z", "data": {}}
            try:
                with patch("breadcrumbss.state.time.time", return_value=100):
                    state.vt_save_cache("8.8.8.8", result, hours=1)
                    self.assertEqual(state.vt_cached("8.8.8.8"), result)
                with patch("breadcrumbss.state.time.time", return_value=3701):
                    self.assertIsNone(state.vt_cached("8.8.8.8"))
            finally:
                state.close()

    def test_approval_cache_and_quota_stop(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            capture = base / "a.pcap"
            capture.write_bytes(b"synthetic")
            provider = FakeVirusTotal()
            processor = Processor(base / "out", parser=Parser(),
                                  provider_instances={"virustotal": provider},
                                  approved_ips=["8.8.8.8"], vt_quota_path=base / "quota.sqlite3")
            try:
                report_path, _, _ = processor.process(capture)
                report = json.loads(report_path.read_text())
                statuses = {item["ip"]: item["providers"]["virustotal"]["status"]
                            for item in report["addresses"]}
                self.assertEqual(statuses["8.8.8.8"], "found")
                self.assertEqual(statuses["1.1.1.1"], "not_approved")
                self.assertEqual(statuses["10.0.0.1"], "excluded_by_policy")
                self.assertEqual(statuses["239.255.255.250"], "excluded_by_policy")
                self.assertEqual(provider.calls, ["8.8.8.8"])
                processor.process(capture, force=True)
                self.assertEqual(provider.calls, ["8.8.8.8"])
            finally:
                processor.close()

            limited = FakeVirusTotal(status="rate_limited")
            processor = Processor(base / "other", parser=Parser(),
                                  provider_instances={"virustotal": limited},
                                  approved_ips=["8.8.8.8", "1.1.1.1"],
                                  vt_quota_path=base / "quota.sqlite3")
            try:
                report_path, _, _ = processor.process(capture)
                report = json.loads(report_path.read_text())
                self.assertEqual(len(limited.calls), 1)
                statuses = {item["ip"]: item["providers"]["virustotal"]["status"]
                            for item in report["addresses"]}
                self.assertIn("rate_limited", statuses.values())
                self.assertIn("not_queried", statuses.values())
            finally:
                processor.close()

    def test_explicit_auto_public_mode_only_queries_public_ips(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            capture = base / "a.pcap"
            capture.write_bytes(b"synthetic")
            provider = FakeVirusTotal()
            processor = Processor(base / "out", parser=Parser(),
                                  provider_instances={"virustotal": provider},
                                  approve_all_public=True, vt_quota_path=base / "quota.sqlite3")
            try:
                report_path, _, _ = processor.process(capture)
                report = json.loads(report_path.read_text())
                self.assertTrue(report["settings"]["approve_all_public"])
                self.assertEqual(set(provider.calls), {"8.8.8.8", "1.1.1.1"})
                statuses = {item["ip"]: item["providers"]["virustotal"]["status"]
                            for item in report["addresses"]}
                self.assertEqual(statuses["10.0.0.1"], "excluded_by_policy")
                self.assertEqual(statuses["239.255.255.250"], "excluded_by_policy")
                self.assertEqual(processor.state.quota_db.execute(
                    "SELECT COUNT(*) FROM virustotal_requests").fetchone()[0], 2)
            finally:
                processor.close()

    def test_preview_does_not_load_secret_or_send_request(self):
        with tempfile.TemporaryDirectory() as temp:
            capture = Path(temp) / "a.pcap"
            capture.write_bytes(b"synthetic")
            output = io.StringIO()
            with patch("breadcrumbss.cli.TSharkParser") as parser_type, \
                 patch("breadcrumbss.workflow.load_virustotal_key", side_effect=AssertionError("key loaded")), \
                 redirect_stdout(output):
                parser_type.return_value.parse.return_value = (3, [row("8.8.8.8"), row("10.0.0.1")])
                code = main(["file", str(capture), "--preview", "--provider", "virustotal"])
            self.assertEqual(code, 0)
            self.assertIn("8.8.8.8", output.getvalue())
            self.assertNotIn("10.0.0.1\n", output.getvalue())

    def test_dry_run_and_missing_approval_never_load_secret(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            capture = base / "a.pcap"
            capture.write_bytes(b"synthetic")
            with patch("breadcrumbss.workflow.load_virustotal_key",
                       side_effect=AssertionError("key loaded")):
                with self.assertRaisesRegex(ValueError, "--approve-ip"):
                    Processor(base / "missing", parser=Parser(), providers=["virustotal"])
                processor = Processor(base / "dry", parser=Parser(), providers=["virustotal"],
                                      approved_ips=["8.8.8.8"], dry_run=True,
                                      vt_quota_path=base / "quota.sqlite3")
                try:
                    path, _, _ = processor.process(capture)
                    report = json.loads(path.read_text())
                    result = next(item["providers"]["virustotal"] for item in report["addresses"]
                                  if item["ip"] == "8.8.8.8")
                    self.assertEqual(result["status"], "not_queried")
                    self.assertEqual(processor.state.quota_db.execute(
                        "SELECT COUNT(*) FROM virustotal_requests").fetchone()[0], 0)
                finally:
                    processor.close()


if __name__ == "__main__":
    unittest.main()
