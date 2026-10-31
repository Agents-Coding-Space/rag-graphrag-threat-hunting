"""Header-only inspection of classic Ethernet PCAP; no authentication payloads."""
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import socket
import struct

from .slice_provenance import digest


def inspect_pcap_headers(path: Path) -> dict:
    """Stream all packet headers, retaining only endpoint/count/time metadata."""
    before = digest(path)
    magics = {b"\xd4\xc3\xb2\xa1": ("<", 1_000_000), b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
              b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000), b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000)}
    count = 0
    times = []
    flows: Counter = Counter()
    unsupported: Counter = Counter()
    with path.open("rb") as stream:
        header = stream.read(24)
        if len(header) != 24 or header[:4] not in magics:
            raise ValueError(f"Unsupported or incomplete classic PCAP header: {path.name}")
        endian, scale = magics[header[:4]]
        major, minor, _, _, snaplen, linktype = struct.unpack(endian + "HHIIII", header[4:])
        if (major, minor) != (2, 4) or linktype != 1:
            raise ValueError(f"Unsupported PCAP version/linktype: {path.name}")
        while packet_header := stream.read(16):
            if len(packet_header) != 16:
                raise ValueError(f"Truncated PCAP packet header: {path.name}")
            seconds, fraction, included, original = struct.unpack(endian + "IIII", packet_header)
            if included > snaplen or included > 16_000_000 or included > original:
                raise ValueError(f"Invalid PCAP packet lengths: {path.name}")
            # Consume captured bytes, but never decode or persist application data.
            packet = stream.read(included)
            if len(packet) != included:
                raise ValueError(f"Truncated PCAP packet: {path.name}")
            count += 1
            times.append(seconds + fraction / scale)
            if len(packet) < 34 or packet[12:14] != b"\x08\x00":
                unsupported["non_ipv4_or_short_frame"] += 1
                continue
            ihl = (packet[14] & 15) * 4
            protocol = packet[23]
            if struct.unpack("!H", packet[20:22])[0] & 0x1fff:
                unsupported["noninitial_ip_fragment"] += 1
                continue
            if ihl < 20 or len(packet) < 14 + ihl + 4 or protocol not in {6, 17}:
                unsupported["non_tcp_udp_or_short_ip"] += 1
                continue
            src, dst = socket.inet_ntoa(packet[26:30]), socket.inet_ntoa(packet[30:34])
            sport, dport = struct.unpack("!HH", packet[14 + ihl:18 + ihl])
            flows[(src, sport, dst, dport, "TCP" if protocol == 6 else "UDP")] += 1
    if digest(path) != before:
        raise ValueError(f"PCAP input changed: {path.name}")
    return {"schema_version": "pcap-header-inventory/v1", "path": str(path.resolve()), "sha256": before,
            "size_bytes": path.stat().st_size, "format": "classic_pcap", "encoding": "binary", "linktype": linktype,
            "packet_count": count, "time_window_from_pcap_epoch": {
                "start": datetime.fromtimestamp(min(times), timezone.utc).isoformat() if times else None,
                "end": datetime.fromtimestamp(max(times), timezone.utc).isoformat() if times else None},
            "flow_packet_counts": [{"source_ip": k[0], "source_port": k[1], "destination_ip": k[2],
                                    "destination_port": k[3], "protocol": k[4], "packets": v} for k, v in sorted(flows.items())],
            "unclassified_packet_counts": dict(unsupported), "status": "observed",
            "limitations": ["Header-only survey: no application/authentication payload parsed or exported.",
                            "Packet counts are not session or authentication-attempt counts.",
                            "No PCAP-to-event identity or timezone alignment inferred; absent IP in failed logons remains null."]}
