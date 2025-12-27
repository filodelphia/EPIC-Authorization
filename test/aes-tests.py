from scapy.all import *
from Crypto.Cipher import AES
import time
import struct

EPIC_NH = 253
TYPE_IPV6 = 0x86DD
ROUTING_HEADER = 43

INGRESS_IF = "veth0"
EGRESS_IF  = "veth1"

# --- AES KEY (must match your P4) ---
# P4:
#   const bit<64> K0 = 0x33323130_42413938;
#   const bit<64> K1 = 0x00000000_00000000;
#   const bit<128> AES_KEY = { K0, K1 };
#
# We model the same as two 64-bit integers, then pack to 16 bytes big-endian.
K0 = 0x3332313042413938
K1 = 0x0000000000000000
AES_KEY_INT = (K0 << 64) | K1
AES_KEY = AES_KEY_INT.to_bytes(16, "big")     # 128-bit AES key, big-endian


# --------------------------------------------------------------------
#  AES MAC (must match your P4 extern logic)
#
#  P4:
#      ig_md.mac_msg = { hdr.epic.src_as_host, hdr.epic.packet_ts };
#  C extern (conceptually):
#      msg_bytes[16] = big-endian bytes of that 128-bit value
#      ct = AES_128_ECB(key, msg_bytes)
#      mac_out = (ct[0]<<24 | ct[1]<<16 | ct[2]<<8 | ct[3])
#      hop_validation = mac_out[23:0]
#
#  Here we reproduce exactly that in Python.
# --------------------------------------------------------------------
def epic_mac(src_as_host: int, pkt_ts: int) -> int:
    # Build 128-bit message block: {src_as_host, packet_ts} big-endian
    msg_int = ((src_as_host & ((1 << 64) - 1)) << 64) | (pkt_ts & ((1 << 64) - 1))
    msg_bytes = msg_int.to_bytes(16, "big")

    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    ct = cipher.encrypt(msg_bytes)   # 16 bytes

    # mac_out = big-endian 32-bit word from ct[0..3]
    mac32 = (ct[0] << 24) | (ct[1] << 16) | (ct[2] << 8) | ct[3]

    # EPIC hop_validation is 24 bits: P4 uses mac_out[23:0]
    return mac32 & 0x00FFFFFF


# --------------------------------------------------------------------
#  Build EPIC L1 header (raw structure)
#
#  EXACT BYTE LAYOUT (must match your P4):
#    src_as_host   : 8 bytes (bit<64>)
#    packet_ts     : 8 bytes (bit<64>)
#    path_ts       : 4 bytes (bit<32>)
#    per_hop_count : 1 byte (bit<8>)
#    next_header   : 1 byte (bit<8>)
#    hop_validation: 3 bytes (bit<24>)
#    segment_id    : 2 bytes (bit<16>)
#
#  This mirrors exactly what your siphash test does.
# --------------------------------------------------------------------
def build_epic_header(src_as_host, pkt_ts, path_ts, per_hop_count, next_header, mac24):
    mac_bytes = mac24.to_bytes(3, "big")

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
    # Same as your siphash test
    return IPv6ExtHdrRouting(
        segleft=len(segment_list)-1,
        lastentry=len(segment_list)-1,
        type=4,  # SRH
        addresses=list(reversed(segment_list))  # RFC 8754: reversed order
    )


# --------------------------------------------------------------------
#  Build complete EPIC + SRH test packet
#
#  Structure is identical to the HalfSipHash version. Only epic_mac differs.
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

    epic_raw = build_epic_header(src_as_host, pkt_ts, path_ts,
                                 per_hop_count, next_header, mac24)

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
#
#  Identical to your HalfSipHash test: 1 packet in, sniff 1 packet out.
# --------------------------------------------------------------------
def send_and_sniff(pkt, expect_forward=True, timeout=1):
    sendp(pkt, iface=INGRESS_IF, verbose=False)
    ans = sniff(iface=EGRESS_IF, timeout=timeout, count=1)
    if expect_forward:
        assert len(ans) > 0, "Expected packet to be forwarded, but saw none"
    else:
        assert len(ans) == 0, "Expected packet to be dropped, but saw one"


# --------------------------------------------------------------------
#  TESTS (same semantics as for HalfSipHash)
# --------------------------------------------------------------------
def test_normal_ipv6_forwarding():
    pkt = Ether(type=TYPE_IPV6) / IPv6(src="2001:db8::2", dst="2001:db8::1") / TCP()
    send_and_sniff(pkt, expect_forward=True)


def test_epic_valid_mac_fresh_timestamp():
    pkt = build_epic_packet()
    send_and_sniff(pkt, expect_forward=True)


def test_epic_invalid_mac():
    # override MAC with something incorrect
    pkt = build_epic_packet(mac_override=0xabcdef)
    send_and_sniff(pkt, expect_forward=False)


def test_epic_expired_timestamp():
    now = int(time.time())
    # PATH_DELTA in P4 is 7200, so this should fail timestamp check
    pkt = build_epic_packet(pkt_ts=now, path_ts=now - 7200 - 50)
    send_and_sniff(pkt, expect_forward=False)


if __name__ == "__main__":
    test_normal_ipv6_forwarding()
    test_epic_valid_mac_fresh_timestamp()
    test_epic_invalid_mac()
    test_epic_expired_timestamp()
    print("All AES tests passed ✔")
