"""Capture parsing is isolated here so another parser can replace TShark."""

import csv
import hashlib
import ipaddress
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

FIELDS = (
    "frame.number", "frame.time_epoch", "ip.src", "ip.dst", "ipv6.src",
    "ipv6.dst", "tcp.srcport", "tcp.dstport", "udp.srcport",
    "udp.dstport", "frame.protocols",
)


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def classify(address) -> str:
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link_local"
    if address.is_multicast:
        return "multicast"
    if address.is_unspecified or address.is_reserved:
        return "reserved"
    if address.is_global:
        return "public"
    if address.is_private:
        return "private_or_special"
    return "non_public"


def _addresses(value: str):
    for item in value.split(","):
        try:
            yield ipaddress.ip_address(item.strip())
        except ValueError:
            continue


class TSharkParser:
    def __init__(self, executable: str = "tshark"):
        self.executable = executable

    def parse(self, path: Path) -> tuple[int, list[dict]]:
        command = [self.executable, "-r", str(path), "-n", "-T", "fields",
                   "-E", "separator=/t", "-E", "quote=d", "-E", "occurrence=a",
                   "-E", "aggregator=,", *[arg for field in FIELDS for arg in ("-e", field)]]
        rows: dict[str, dict] = {}
        packet_count = 0
        try:
            with tempfile.TemporaryFile(mode="w+t", encoding="utf-8") as errors:
                proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=errors,
                                        text=True, encoding="utf-8", errors="replace")
                assert proc.stdout is not None
                for columns in csv.reader(proc.stdout, delimiter="\t"):
                    packet_count += 1
                    columns += [""] * (len(FIELDS) - len(columns))
                    frame, epoch = columns[:2]
                    try:
                        observed = datetime.fromtimestamp(float(epoch), timezone.utc).isoformat()
                    except (ValueError, OverflowError):
                        continue
                    seen_in_packet: set[str] = set()
                    protocol_stack = columns[10].split(":") if columns[10] else []
                    protocol = next((p for p in ("tcp", "udp", "icmpv6", "icmp")
                                     if p in protocol_stack), protocol_stack[-1] if protocol_stack else "unknown")
                    for direction, positions, port_positions in (
                        ("source", (2, 4), (6, 8)),
                        ("destination", (3, 5), (7, 9)),
                    ):
                        addresses = {addr for position in positions for addr in _addresses(columns[position])}
                        ports = {p.strip() for position in port_positions
                                 for p in columns[position].split(",") if p.strip().isdigit()}
                        for address in addresses:
                            key = str(address)
                            record = rows.setdefault(key, {
                                "ip": key, "ip_version": address.version,
                                "classification": classify(address), "directions": set(),
                                "first_seen": observed, "last_seen": observed,
                                "first_frame": frame, "last_frame": frame,
                                "packet_count": 0, "protocols": set(), "ports": set(),
                            })
                            record["directions"].add(direction)
                            if observed < record["first_seen"]:
                                record["first_seen"], record["first_frame"] = observed, frame
                            if observed > record["last_seen"]:
                                record["last_seen"], record["last_frame"] = observed, frame
                            if key not in seen_in_packet:
                                record["packet_count"] += 1
                                seen_in_packet.add(key)
                            record["protocols"].add(protocol)
                            record["ports"].update(ports)
                proc.stdout.close()
                code = proc.wait()
                if code:
                    errors.seek(0)
                    raise RuntimeError(f"TShark could not parse {path.name}: {errors.read(1200).strip()}")
        except FileNotFoundError as exc:
            raise RuntimeError("TShark was not found. Install Wireshark/TShark and add tshark to PATH, or pass --tshark PATH.") from exc
        for record in rows.values():
            for field in ("directions", "protocols", "ports"):
                record[field] = sorted(record[field])
        return packet_count, sorted(rows.values(), key=lambda row: (row["ip_version"], ipaddress.ip_address(row["ip"])))

