"""File processing, enrichment, reporting, and continuous watch."""

import csv
import hashlib
import json
import os
import re
import tempfile
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
import ipaddress

from . import __version__
from .capture import TSharkParser, classify, file_hash
from .html_report import render_html
from .providers import DEFAULT_VT_SECRET, RDAPProvider, VirusTotalProvider, load_virustotal_key, utc_now
from .state import State

EXTENSIONS = {".pcap", ".pcapng", ".cap"}


def capture_files(folder: Path) -> list[Path]:
    return sorted((p for p in folder.iterdir() if p.is_file() and p.suffix.lower() in EXTENSIONS),
                  key=lambda p: (p.stat().st_mtime_ns, p.name))


def atomic_write(path: Path, writer):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_name = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="",
                                         dir=path.parent, prefix=".breadcrumbss-", suffix=".tmp",
                                         delete=False) as stream:
            temp_name = stream.name
            writer(stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
    finally:
        if temp_name and os.path.exists(temp_name):
            os.unlink(temp_name)


def write_reports(report: dict, folder: Path) -> tuple[Path, Path]:
    stem = re.sub(r"[^A-Za-z0-9_.-]", "_", Path(report["capture"]["filename"]).stem)[:60]
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base = f"{stem}_breadcrumbss_{stamp}_{report['run_id'].replace('-', '')[:12]}"
    folder.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".breadcrumbss-", dir=folder))
    json_name, csv_name, html_name = f"{base}.json", f"{base}.csv", f"{base}.html"
    json_path, csv_path, html_path = staging / json_name, staging / csv_name, staging / html_name

    def json_writer(stream):
        json.dump(report, stream, indent=2, ensure_ascii=False)
        stream.write("\n")

    def csv_writer(stream):
        columns = ["ip", "ip_version", "classification", "directions", "first_seen",
                   "last_seen", "first_frame", "last_frame", "packet_count", "protocols",
                   "ports", "capture_filename", "capture_sha256", "provider_statuses",
                   "provider_results"]
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        for row in report["addresses"]:
            writer.writerow({
                **{key: row[key] for key in ("ip", "ip_version", "classification", "first_seen",
                    "last_seen", "first_frame", "last_frame", "packet_count")},
                "directions": "|".join(row["directions"]),
                "protocols": "|".join(row["protocols"]),
                "ports": "|".join(row["ports"]),
                "capture_filename": report["capture"]["filename"],
                "capture_sha256": report["capture"]["sha256"],
                "provider_statuses": json.dumps({k: v["status"] for k, v in row["providers"].items()}),
                "provider_results": json.dumps(row["providers"], ensure_ascii=False),
            })

    atomic_write(csv_path, csv_writer)
    atomic_write(json_path, json_writer)
    atomic_write(html_path, lambda stream: stream.write(render_html(report)))
    final_dir = folder / base
    os.replace(staging, final_dir)
    return final_dir / json_name, final_dir / csv_name


def ensure_html_report(json_path: Path) -> Path:
    """Add an HTML view to an older completed report without re-enrichment."""
    html_path = json_path.with_suffix(".html")
    if not html_path.is_file():
        report = json.loads(json_path.read_text(encoding="utf-8"))
        atomic_write(html_path, lambda stream: stream.write(render_html(report)))
    return html_path


class Processor:
    def __init__(self, output_dir: Path, *, tshark="tshark", providers=(), dry_run=False,
                 include_nonpublic=False, cache_hours=24.0, concurrency=2,
                 rdap_rate=1.0, parser=None, provider_instances=None, log=None,
                 approved_ips=(), approve_all_public=False, vt_quota_path=None):
        self.log = log or (lambda message: None)
        self.output_dir = output_dir.resolve()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.parser = parser or TSharkParser(tshark)
        self.dry_run = dry_run
        self.include_nonpublic = include_nonpublic
        self.cache_hours = cache_hours
        self.concurrency = concurrency
        self.approved_ips = {str(ipaddress.ip_address(ip)) for ip in approved_ips}
        self.approve_all_public = bool(approve_all_public)
        if self.approve_all_public and self.approved_ips:
            raise ValueError("Use --approve-all-public or --approve-ip, not both")
        if ("virustotal" in providers or provider_instances and "virustotal" in provider_instances) and not (self.approved_ips or self.approve_all_public):
            raise ValueError("VirusTotal requires --approve-ip or --approve-all-public")
        self.providers = provider_instances if provider_instances is not None else {
            name: (RDAPProvider(rdap_rate) if name == "rdap" else
                   VirusTotalProvider("" if dry_run else load_virustotal_key()))
            for name in providers if name in ("rdap", "virustotal")
        }
        quota_path = None
        if "virustotal" in self.providers:
            quota_path = vt_quota_path or DEFAULT_VT_SECRET.parent / "virustotal-usage.sqlite3"
        self.state = State(self.output_dir / "breadcrumbss-state.sqlite3", quota_path)
        self.profile = hashlib.sha256(json.dumps({
            "providers": sorted(self.providers), "dry_run": dry_run,
            "include_nonpublic": include_nonpublic,
            "approved_ips": sorted(self.approved_ips) if "virustotal" in self.providers else [],
            "approve_all_public": self.approve_all_public if "virustotal" in self.providers else False,
        }, sort_keys=True).encode()).hexdigest()

    def close(self):
        self.state.close()

    def process(self, path: Path, *, force=False) -> tuple[Path, Path, bool]:
        path = path.resolve()
        if not path.is_file() or path.suffix.lower() not in EXTENSIONS:
            raise ValueError(f"Expected an existing PCAP or PCAPNG file: {path}")
        started = utc_now()
        before = path.stat()
        sha256 = file_hash(path)
        if not force:
            completed = self.state.completed(sha256, self.profile)
            if completed:
                ensure_html_report(completed[0])
                return *completed, True
        packet_count, addresses = self.parser.parse(path)
        self.log(f"{path.name}: {packet_count} packets, {len(addresses)} unique IPs")
        after = path.stat()
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns) or file_hash(path) != sha256:
            raise RuntimeError(f"Capture changed while being processed: {path.name}. Retry after rotation.")
        for row in addresses:
            row["providers"] = {}
        virustotal = self.providers.get("virustotal")
        if virustotal is not None:
            stopped = False
            for row in addresses:
                ip = row["ip"]
                eligible = classify(ipaddress.ip_address(ip)) == "public"
                if not eligible:
                    status = "excluded_by_policy"
                elif not (self.approve_all_public or ip in self.approved_ips):
                    status = "not_approved"
                elif self.dry_run:
                    status = "not_queried"
                elif (cached := self.state.vt_cached(ip)) is not None:
                    row["providers"]["virustotal"] = {**cached, "cache_hit": True}
                    continue
                elif stopped:
                    status = "not_queried"
                else:
                    while True:
                        delay = self.state.vt_reserve_request()
                        if delay is None:
                            status = "daily_limit_reached"
                            stopped = True
                            break
                        if delay == 0:
                            try:
                                result = virustotal.lookup(ip)
                            except Exception:
                                result = {"status": "lookup_failed", "looked_up_at": utc_now(),
                                          "source": None, "error": "VirusTotal provider failed", "data": {}}
                            row["providers"]["virustotal"] = result
                            self.state.vt_save_cache(ip, result, self.cache_hours)
                            if result["status"] == "rate_limited":
                                stopped = True
                            break
                        time.sleep(delay)
                    if "virustotal" in row["providers"]:
                        continue
                row["providers"]["virustotal"] = {
                    "status": status, "looked_up_at": None, "source": None, "data": {}}
        futures = {}
        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            for row in addresses:
                for name, provider in self.providers.items():
                    if name == "virustotal":
                        continue
                    if row["classification"] != "public" and not self.include_nonpublic:
                        row["providers"][name] = {"status": "excluded_by_policy", "looked_up_at": None,
                                                  "source": None, "data": {}}
                    elif self.dry_run:
                        row["providers"][name] = {"status": "not_queried", "looked_up_at": None,
                                                  "source": None, "data": {}}
                    elif (cached := self.state.cached(name, row["ip"])) is not None:
                        row["providers"][name] = {**cached, "cache_hit": True}
                    else:
                        futures[pool.submit(provider.lookup, row["ip"])] = (row, name)
            for completed_count, future in enumerate(as_completed(futures), 1):
                row, name = futures[future]
                try:
                    result = future.result()
                except Exception as exc:
                    result = {"status": "lookup_failed", "looked_up_at": utc_now(), "source": None,
                              "error": f"{type(exc).__name__}: provider failed", "data": {}}
                row["providers"][name] = result
                self.state.save_cache(name, row["ip"], result, self.cache_hours)
                if completed_count % 10 == 0 or completed_count == len(futures):
                    self.log(f"{path.name}: {completed_count}/{len(futures)} provider lookups finished")
        report = {
            "schema_version": 1, "breadcrumbss_version": __version__, "run_id": str(uuid.uuid4()),
            "started_at": started, "completed_at": utc_now(),
            "capture": {"filename": path.name, "path": str(path), "sha256": sha256,
                        "size_bytes": before.st_size},
            "settings": {"providers": sorted(self.providers), "dry_run": self.dry_run,
                         "include_nonpublic": self.include_nonpublic,
                         "approved_ips": sorted(self.approved_ips) if virustotal else [],
                         "approve_all_public": self.approve_all_public if virustotal else False},
            "totals": {"packets": packet_count, "unique_ips": len(addresses),
                       "public_ips": sum(row["classification"] == "public" for row in addresses)},
            "addresses": addresses,
        }
        reports = write_reports(report, self.output_dir)
        self.state.mark_complete(sha256, self.profile, *reports)
        return *reports, False


def watch(folder: Path, processor: Processor, *, stable_seconds=5.0, poll_seconds=2.0,
          force=False, log=print):
    """Only process a stable segment after a newer segment exists."""
    observations = {}
    done = set()
    last_sequence = None
    errors = set()
    log(f"Watching {folder}. A segment is eligible after a newer segment appears.")
    while True:
        files = capture_files(folder)
        newest = files[-1] if files else None
        now = time.monotonic()
        current = set(files)
        for missing in set(observations) - current:
            observations.pop(missing)
            done.discard(missing)
            log(f"Capture disappeared before processing: {missing.name}")
        for path in files:
            if path == newest:
                continue
            stat = path.stat()
            signature = (stat.st_size, stat.st_mtime_ns)
            prior = observations.get(path)
            if prior is None or prior[0] != signature:
                observations[path] = (signature, now)
                done.discard(path)
                continue
            if path in done or now - prior[1] < stable_seconds:
                continue
            key = (str(path), signature)
            try:
                json_path, _, skipped = processor.process(path, force=force)
                if not skipped:
                    candidates = re.findall(r"_(\d{3,8})(?=_|$)", path.stem)
                    if candidates:
                        sequence = int(candidates[0])
                        if last_sequence is not None and sequence > last_sequence + 1:
                            log(f"Possible capture sequence gap: {last_sequence + 1} through {sequence - 1}")
                        last_sequence = sequence
                log(("Already processed: " if skipped else "Report: ") + str(json_path))
                done.add(path)
            except Exception as exc:
                if key not in errors:
                    log(f"Could not process {path.name}: {exc}")
                    errors.add(key)
        time.sleep(poll_seconds)



