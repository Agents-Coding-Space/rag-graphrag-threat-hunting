import struct

import pytest

from threat_hunting.evidence.pcap_inventory import inspect_pcap_headers
from threat_hunting.evidence.slice_provenance import digest


def test_pcap_header_counts_and_immutability(tmp_path):
    path = tmp_path / "fixture.cap"
    ethernet = b"\0" * 12 + b"\x08\x00"
    ip = b"\x45\0\0\x18\0\0\0\0\x40\x06\0\0" + bytes([192, 0, 2, 1, 192, 0, 2, 2])
    packet = ethernet + ip + struct.pack("!HH", 1234, 443)
    path.write_bytes(b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
                     + struct.pack("<IIII", 1, 500000, len(packet), len(packet)) + packet)
    before = digest(path)
    result = inspect_pcap_headers(path)
    assert result["packet_count"] == 1
    assert result["flow_packet_counts"][0]["destination_port"] == 443
    assert result["flow_packet_counts"][0]["packets"] == 1
    assert digest(path) == before
    assert "payload" not in result


def test_pcap_truncated_packet_fails(tmp_path):
    path = tmp_path / "truncated.cap"
    path.write_bytes(b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
                     + struct.pack("<IIII", 1, 0, 10, 10) + b"x")
    with pytest.raises(ValueError, match="Truncated PCAP packet"):
        inspect_pcap_headers(path)
