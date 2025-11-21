from scapy.all import *
from siphash import half_siphash_32
import time
import struct

EPIC_NH = 253
TYPE_IPV6 = 0x86DD
ROUTING_HEADER = 43

INGRESS_IF = "veth0"
EGRESS_IF  = "veth1"

# --- EPIC KEY (must match your P4) ---
SIP_KEY_0 = 0x33323130
SIP_KEY_1 = 0x42413938

# Build a 16-byte key for siphash-cffi
KEY = struct.pack("<IIII", SIP_KEY_0, SIP_KEY_1, SIP_KEY_0, SIP_KEY_1)


# --------------------------------------------------------------------
#  HalfSipHash MAC (must match your P4)
# --------------------------------------------------------------------
def epic_mac(src_as_host: int, pkt_ts: int) -> int:
    # split into 32-bit words exactly like P4:
    m0 = (src_as_host >> 32) & 0xFFFFFFFF
    m1 = src_as_host & 0xFFFFFFFF
    m2 = (pkt_ts >> 32) & 0xFFFFFFFF
    m3 = pkt_ts & 0xFFFFFFFF

    data = struct.pack("<IIII", m0, m1, m2, m3)

    mac32 = half_siphash_32(KEY, data)
    return mac32 & 0x00FFFFFF      # 24-bit EPIC MAC


# --------------------------------------------------------------------
#  Build EPIC L1 header (raw structure)
# --------------------------------------------------------------------
def build_epic_header(src_as_host, pkt_ts, path_ts, per_hop_count, next_header, mac24):
    mac_bytes = mac24.to_bytes(3, "big")

    # Format exactly as in your P4 parser:
    return (
        src_as_host.to_bytes(8, "big") +
        pkt_ts.to_bytes(8, "big") +
        path_ts.to_bytes(4, "big") +
        bytes([per_hop_count]) +
        bytes([next_header]) +
        mac_bytes +
        b"\x00\x01"     # segment_id
    )


# --------------------------------------------------------------------
#  Build SRv6 Routing Header according to your parser expectations
# --------------------------------------------------------------------
def build_srh(segment_list):
    # Scapy SRH builder
    return IPv6ExtHdrRouting(
        segleft=len(segment_list)-1,
        lastentry=len(segment_list)-1,
        type=4,  # SRH
        addresses=list(reversed(segment_list))  # RFC 8754: reversed order
    )


# --------------------------------------------------------------------
#  Build complete EPIC + SRH test packet
# --------------------------------------------------------------------
def build_epic_packet(
    dst="2001:db8::1",
    src="2001:db8::2",
    segment_list=None,
    src_as_host=0x1122334455667788,
    pkt_ts=None,
    path_ts=None,
    per_hop_count=1,
    next_header=59,
    mac_override=None
):
    if segment_list is None:
        segment_list = ["2001:db8::100"]   # at least 1 segment

    if pkt_ts is None:
        pkt_ts = int(time.time())
    if path_ts is None:
        path_ts = pkt_ts

    mac24 = mac_override if mac_override is not None else epic_mac(src_as_host, pkt_ts)

    epic_raw = build_epic_header(src_as_host, pkt_ts, path_ts, per_hop_count, next_header, mac24)

    srh = build_srh(segment_list)

    ipv6 = IPv6(src=src, dst=dst, nh=ROUTING_HEADER)

    pkt = (
        Ether(dst="02:00:00:00:00:02",
              src="02:00:00:00:00:01",
              type=TYPE_IPV6)
        / ipv6
        / srh
        / Raw(epic_raw)
    )
    return pkt


# --------------------------------------------------------------------
#  Send and sniff helpers
# --------------------------------------------------------------------
def send_and_sniff(pkt, expect_forward=True, timeout=1):
    sendp(pkt, iface=INGRESS_IF, verbose=False)
    ans = sniff(iface=EGRESS_IF, timeout=timeout, count=1)
    if expect_forward:
        assert len(ans) > 0, "Expected packet to be forwarded, but saw none"
    else:
        assert len(ans) == 0, "Expected packet to be dropped, but saw one"


# --------------------------------------------------------------------
#  TESTS
# --------------------------------------------------------------------
def test_normal_ipv6_forwarding():
    pkt = Ether(type=TYPE_IPV6) / IPv6(src="2001:db8::2", dst="2001:db8::1") / TCP()
    send_and_sniff(pkt, expect_forward=True)


def test_epic_valid_mac_fresh_timestamp():
    pkt = build_epic_packet()
    send_and_sniff(pkt, expect_forward=True)


def test_epic_invalid_mac():
    pkt = build_epic_packet(mac_override=0xabcdef)  # wrong
    send_and_sniff(pkt, expect_forward=False)


def test_epic_expired_timestamp():
    now = int(time.time())
    pkt = build_epic_packet(pkt_ts=now, path_ts=now - 7200 - 50)
    send_and_sniff(pkt, expect_forward=False)


if __name__ == "__main__":
    test_normal_ipv6_forwarding()
    test_epic_valid_mac_fresh_timestamp()
    test_epic_invalid_mac()
    test_epic_expired_timestamp()
    print("All tests passed ✔")