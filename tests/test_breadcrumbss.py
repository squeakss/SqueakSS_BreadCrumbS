import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from breadcrumbss.capture import TSharkParser, classify
from breadcrumbss.providers import RDAPProvider
from breadcrumbss.html_report import render_html
from breadcrumbss.workflow import Processor, atomic_write, watch


class FakePopen:
    def __init__(self, command, **kwargs):
        self.stdout = io.StringIO(
            '1\t1700000000\t8.8.8.8\t10.0.0.1\t\t\t12345\t443\t\t\teth:ip:tcp\n'
            '2\t1700000010\t10.0.0.1\t8.8.8.8\t\t\t443\t12345\t\t\teth:ip:tcp\n'
            '3\t1700000020\t8.8.8.8\t8.8.8.8\t\t\t100\t100\t\t\teth:ip:tcp\n'
        )

    def wait(self):
        return 0


class ParserTests(unittest.TestCase):
    def test_classification(self):
        import ipaddress
        self.assertEqual(classify(ipaddress.ip_address("8.8.8.8")), "public")
        self.assertNotEqual(classify(ipaddress.ip_address("10.0.0.1")), "public")
        self.assertEqual(classify(ipaddress.ip_address("::1")), "loopback")
        self.assertEqual(classify(ipaddress.ip_address("239.255.255.250")), "multicast")
        self.assertEqual(classify(ipaddress.ip_address("ff02::1")), "multicast")

    def test_dedup_timestamps_and_direction(self):
        with patch("breadcrumbss.capture.subprocess.Popen", FakePopen):
            count, rows = TSharkParser().parse(Path("fake.pcap"))
        self.assertEqual(count, 3)
        public = next(row for row in rows if row["ip"] == "8.8.8.8")
        self.assertEqual(public["packet_count"], 3)
        self.assertEqual(public["directions"], ["destination", "source"])
        self.assertEqual(public["first_frame"], "1")
        self.assertEqual(public["last_frame"], "3")
        self.assertLess(public["first_seen"], public["last_seen"])


class FakeParser:
    def parse(self, path):
        return 2, [{
            "ip": "8.8.8.8", "ip_version": 4, "classification": "public",
            "directions": ["destination"], "first_seen": "2024-01-01T00:00:00+00:00",
            "last_seen": "2024-01-01T00:00:01+00:00",
            "first_frame": "1", "last_frame": "2", "packet_count": 2,
            "protocols": ["tcp"], "ports": ["443"],
        }]


class FakeProvider:
    def __init__(self):
        self.calls = 0

    def lookup(self, ip):
        self.calls += 1
        return {"status": "found", "looked_up_at": "2024-01-01T00:00:00+00:00",
                "source": "https://example.test/rdap", "data": {"name": "Example"}}


class WorkflowTests(unittest.TestCase):
    def test_report_cache_and_idempotency(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            capture = base / "a.pcapng"
            capture.write_bytes(b"synthetic")
            provider = FakeProvider()
            p = Processor(base / "out", parser=FakeParser(), provider_instances={"fake": provider})
            try:
                json_path, csv_path, skipped = p.process(capture)
                self.assertFalse(skipped)
                self.assertTrue(csv_path.is_file())
                self.assertTrue(json_path.with_suffix(".html").is_file())
                self.assertEqual(json.loads(json_path.read_text())["totals"]["unique_ips"], 1)
                json_path.with_suffix(".html").unlink()
                self.assertTrue(p.process(capture)[2])
                self.assertTrue(json_path.with_suffix(".html").is_file())
                self.assertEqual(provider.calls, 1)
                self.assertFalse(p.process(capture, force=True)[2])
                self.assertEqual(provider.calls, 1)
            finally:
                p.close()

    def test_html_report_escapes_capture_and_provider_text(self):
        report = {
            "capture": {"filename": '<img src=x onerror=alert(1)>.pcap', "sha256": "abc"},
            "completed_at": "2024-01-01T00:00:00+00:00",
            "settings": {"providers": ["virustotal"]},
            "totals": {"packets": 1, "unique_ips": 1},
            "addresses": [{
                "ip": "8.8.8.8", "classification": "public", "packet_count": 1,
                "first_seen": "2024-01-01T00:00:00+00:00",
                "last_seen": "2024-01-01T00:00:00+00:00",
                "protocols": ["<script>alert(1)</script>"], "ports": ["53"],
                "directions": ["destination"],
                "providers": {"virustotal": {"status": "found", "data": {
                    "last_analysis_stats": {"malicious": 1},
                    "as_owner": '<img src=x onerror=alert(1)>'}}},
            }],
        }
        page = render_html(report)
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertNotIn('<img src=x onerror=alert(1)>', page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", page)
        self.assertIn("Content-Security-Policy", page)

    def test_dry_run_status_and_no_lookup(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            capture = base / "a.pcap"
            capture.write_bytes(b"synthetic")
            provider = FakeProvider()
            p = Processor(base / "out", parser=FakeParser(), provider_instances={"fake": provider}, dry_run=True)
            try:
                result = p.process(capture)
                row = json.loads(result[0].read_text())["addresses"][0]
                self.assertEqual(row["providers"]["fake"]["status"], "not_queried")
                self.assertEqual(provider.calls, 0)
            finally:
                p.close()

    def test_provider_failure_is_reported_without_aborting_capture(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            capture = base / "a.pcap"
            capture.write_bytes(b"synthetic")
            class FailingProvider:
                def lookup(self, ip):
                    raise RuntimeError("simulated provider error")
            p = Processor(base / "out", parser=FakeParser(),
                          provider_instances={"failing": FailingProvider()})
            try:
                json_path, csv_path, skipped = p.process(capture)
                self.assertFalse(skipped)
                self.assertTrue(csv_path.is_file())
                row = json.loads(json_path.read_text())["addresses"][0]
                self.assertEqual(row["providers"]["failing"]["status"], "lookup_failed")
            finally:
                p.close()

    def test_atomic_write_cleans_failed_temp(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "report.json"
            def fail(stream):
                stream.write("partial")
                raise ValueError("failed")
            with self.assertRaises(ValueError):
                atomic_write(target, fail)
            self.assertFalse(target.exists())
            self.assertEqual(list(Path(temp).iterdir()), [])

    def test_watch_waits_for_newer_stable_segment(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            old, current = base / "cap_001_2024.pcap", base / "cap_002_2024.pcap"
            old.write_bytes(b"old")
            current.write_bytes(b"current")
            os.utime(old, (100, 100))
            os.utime(current, (200, 200))
            class Recorder:
                def __init__(self):
                    self.paths = []
                def process(self, path, **kwargs):
                    self.paths.append(path)
                    return base / "report.json", base / "report.csv", False
            recorder = Recorder()
            ticks = iter([0, 1, 2])
            with patch("breadcrumbss.workflow.time.monotonic", side_effect=lambda: next(ticks)), \
                 patch("breadcrumbss.workflow.time.sleep", side_effect=[None, None, KeyboardInterrupt]):
                with self.assertRaises(KeyboardInterrupt):
                    watch(base, recorder, stable_seconds=0.5, poll_seconds=1, log=lambda _: None)
            self.assertEqual(recorder.paths, [old])

    def test_rdap_uses_longest_bootstrap_match(self):
        urls = []
        def fetch(url):
            urls.append(url)
            if url.endswith("ipv4.json"):
                return {"services": [
                    [["8.0.0.0/8"], ["https://broad.example/"]],
                    [["8.8.8.0/24"], ["https://specific.example/"]],
                ]}
            return {"name": "Example", "country": "US"}
        provider = RDAPProvider(requests_per_second=100000, fetch=fetch)
        result = provider.lookup("8.8.8.8")
        self.assertEqual(result["status"], "found")
        self.assertEqual(urls[-1], "https://specific.example/ip/8.8.8.8")


if __name__ == "__main__":
    unittest.main()

