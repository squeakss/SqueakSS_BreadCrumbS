"""Breadcrumbss command line."""

import argparse
import ipaddress
import sys
import tomllib
from pathlib import Path

from . import __version__
from .workflow import Processor, capture_files, watch
from .capture import TSharkParser, classify, file_hash

DEFAULTS = {
    "output_dir": "breadcrumbss-results", "tshark": "tshark", "providers": [],
    "dry_run": False, "include_nonpublic": False, "cache_hours": 24.0,
    "concurrency": 2, "rdap_rate": 1.0, "stable_seconds": 5.0, "poll_seconds": 2.0,
}


def positive(value: str) -> float:
    number = float(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("Must be positive")
    return number


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Enrich IPs from completed Wireshark captures")
    parser.add_argument("--version", action="version", version=f"Breadcrumbss {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("file", "folder", "watch"):
        sub = commands.add_parser(command)
        sub.add_argument("path", type=Path, help="Capture file or capture folder")
        sub.add_argument("--config", type=Path, help="TOML configuration file")
        sub.add_argument("--output-dir", type=Path)
        sub.add_argument("--tshark", help="TShark executable path")
        sub.add_argument("--provider", action="append", choices=["rdap", "virustotal"], dest="providers")
        sub.add_argument("--preview", action="store_true", help="List public IPs locally without external requests")
        sub.add_argument("--approve-ip", action="append", default=[], help="Allow this exact IP to be sent to VirusTotal")
        sub.add_argument("--approve-all-public", action="store_true",
                         help="Automatically send every public IP to VirusTotal")
        sub.add_argument("--dry-run", action="store_true", default=None)
        sub.add_argument("--include-nonpublic", action="store_true", default=None)
        sub.add_argument("--cache-hours", type=positive)
        sub.add_argument("--concurrency", type=int)
        sub.add_argument("--rdap-rate", type=positive, help="Maximum RDAP requests per second")
        sub.add_argument("--force", action="store_true", help="Create a new report even if already processed")
        if command == "watch":
            sub.add_argument("--stable-seconds", type=positive)
            sub.add_argument("--poll-seconds", type=positive)
    args = parser.parse_args(argv)
    try:
        config = {}
        if args.config:
            with args.config.open("rb") as stream:
                config = tomllib.load(stream)
            if not isinstance(config, dict):
                raise ValueError("Configuration must be a TOML table")
        opts = {key: getattr(args, key, None) if getattr(args, key, None) is not None
                else config.get(key, default) for key, default in DEFAULTS.items()}
        unknown = set(opts["providers"]) - {"rdap", "virustotal"}
        if unknown:
            raise ValueError(f"Unknown providers: {', '.join(sorted(unknown))}")
        if int(opts["concurrency"]) < 1:
            raise ValueError("concurrency must be at least 1")
        for name in ("cache_hours", "rdap_rate", "stable_seconds", "poll_seconds"):
            if float(opts[name]) <= 0:
                raise ValueError(f"{name} must be positive")
        path = args.path.resolve()
        if args.command == "file" and not path.is_file():
            raise ValueError(f"Capture file not found: {path}")
        if args.command != "file" and not path.is_dir():
            raise ValueError(f"Capture folder not found: {path}")
        files = [path] if args.command == "file" else capture_files(path)
        if args.preview:
            if args.command == "watch":
                raise ValueError("Use file or folder for a finite lookup preview")
            parser_impl = TSharkParser(str(opts["tshark"]))
            public_ips = set()
            for item in files:
                before = (item.stat().st_size, item.stat().st_mtime_ns, file_hash(item))
                packets, rows = parser_impl.parse(item)
                after = (item.stat().st_size, item.stat().st_mtime_ns, file_hash(item))
                if before != after:
                    raise RuntimeError(f"Capture changed during preview: {item.name}")
                eligible = sorted(row["ip"] for row in rows
                                  if classify(ipaddress.ip_address(row["ip"])) == "public")
                print(f"{item.name}: {packets} packets; {len(eligible)} public IPs; sha256 {before[2]}")
                public_ips.update(eligible)
            print(f"Eligible unique IPs ({len(public_ips)}); no external requests made:")
            for ip in sorted(public_ips, key=lambda value: (ipaddress.ip_address(value).version,
                                                              ipaddress.ip_address(value))):
                print(f"  {ip}")
            return 0
        approved = {str(ipaddress.ip_address(ip)) for ip in args.approve_ip}
        if approved and "virustotal" not in opts["providers"]:
            raise ValueError("--approve-ip requires --provider virustotal")
        if args.approve_all_public and "virustotal" not in opts["providers"]:
            raise ValueError("--approve-all-public requires --provider virustotal")
        if args.approve_all_public and approved:
            raise ValueError("Use --approve-all-public or --approve-ip, not both")
        processor = Processor(
            Path(opts["output_dir"]), tshark=str(opts["tshark"]),
            providers=opts["providers"], dry_run=bool(opts["dry_run"]),
            include_nonpublic=bool(opts["include_nonpublic"]),
            cache_hours=float(opts["cache_hours"]), concurrency=int(opts["concurrency"]),
            rdap_rate=float(opts["rdap_rate"]), log=print, approved_ips=approved,
            approve_all_public=args.approve_all_public,
        )
        try:
            if args.command == "watch":
                watch(path, processor, stable_seconds=float(opts["stable_seconds"]),
                      poll_seconds=float(opts["poll_seconds"]), force=args.force)
            else:
                if not files:
                    print("No capture files found.")
                failures = 0
                for item in files:
                    try:
                        json_path, csv_path, skipped = processor.process(item, force=args.force)
                        print(("Already processed: " if skipped else "Wrote: ") + str(json_path))
                        if not skipped:
                            print(f"Wrote: {csv_path}")
                        print(f"HTML: {json_path.with_suffix('.html')}")
                    except Exception as exc:
                        failures += 1
                        print(f"Failed {item.name}: {exc}", file=sys.stderr)
                return 1 if failures else 0
        finally:
            processor.close()
    except KeyboardInterrupt:
        print("\nStopped.")
        return 130
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

