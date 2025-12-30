#!/usr/bin/env python3
import struct
import time

from scapy.layers.l2 import Ether
from scapy.layers.inet6 import IPv6, IPv6ExtHdrSegmentRouting
from scapy.packet import Raw
from scapy.sendrecv import sendp, AsyncSniffer

# -----------------------------
# CONFIG
# -----------------------------
INGRESS_IF = "veth0"
EGRESS_IF  = "veth1"
SNIFF_TIMEOUT = 1.2

SRC_MAC = "02:00:00:00:00:01"
DST_MAC = "02:00:00:00:00:02"

SRC_AS_HOST = 0x0123456789ABCDEF
PKT_TS      = 0x1111111111111111
PATH_TS     = 0x22222222

PER_HOP_COUNT = 1
EPIC_NEXT_HDR = 59

TSEXP     = 0x01
ING_IF_ID = 0x02
EG_IF_ID  = 0x03
SEG_ID    = 0x1234

SID_LIST = [
    "2001:db8:0:1::1",
    "2001:db8:0:2::1",
]

SRH_NH  = 43
EPIC_NH = 253

# HalfSipHash key words (must match your P4 constants KEY_0 / KEY_1)
SIP_KEY_0 = 0x33323130
SIP_KEY_1 = 0x42413938

# -----------------------------
# HalfSipHash-2-4 (word-exact like your P4)
# -----------------------------
def rotl32(x, b):
    return ((x << b) & 0xFFFFFFFF) | ((x & 0xFFFFFFFF) >> (32 - b))

def sipround(v0, v1, v2, v3):
    v0 = (v0 + v1) & 0xFFFFFFFF
    v2 = (v2 + v3) & 0xFFFFFFFF
    v1 = rotl32(v1, 5)
    v3 = rotl32(v3, 8)
    v1 ^= v0
    v3 ^= v2
    v0 = rotl32(v0, 16)
    v2 = (v2 + v1) & 0xFFFFFFFF
    v0 = (v0 + v3) & 0xFFFFFFFF
    v1 = rotl32(v1, 13)
    v3 = rotl32(v3, 7)
    v1 ^= v2
    v3 ^= v0
    v2 = rotl32(v2, 16)
    return v0, v1, v2, v3

def halfsiphash_2_4_32(k0, k1, m_words):
    const_0 = 0x00000000
    const_1 = 0x00000000
    const_2 = 0x6c796765
    const_3 = 0x74656462

    v0 = (k0 ^ const_0) & 0xFFFFFFFF
    v1 = (k1 ^ const_1) & 0xFFFFFFFF
    v2 = (k0 ^ const_2) & 0xFFFFFFFF
    v3 = (k1 ^ const_3) & 0xFFFFFFFF

    for m in m_words:
        m &= 0xFFFFFFFF
        v3 ^= m
        v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
        v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
        v0 ^= m

    v2 ^= 0xFF
    for _ in range(4):
        v0, v1, v2, v3 = sipround(v0, v1, v2, v3)

    return (v1 ^ v3) & 0xFFFFFFFF

def swap16_halves(x):
    return ((x & 0xFFFF) << 16) | ((x >> 16) & 0xFFFF)

def u24(x):
    return x & 0xFFFFFF

# -----------------------------
# EPIC L1 MAC chain (matches your P4)
# -----------------------------
def compute_hop_mac(path_ts: int, tsexp: int, ing: int, eg: int, segid: int) -> int:
    m0 = path_ts & 0xFFFFFFFF
    m1 = ((ing & 0xFF) << 24) | ((eg & 0xFF) << 16) | (segid & 0xFFFF)
    m2 = ((tsexp & 0xFF) << 24)
    m3 = 0
    return halfsiphash_2_4_32(SIP_KEY_0, SIP_KEY_1, [m0, m1, m2, m3])

def compute_pkt_mac24(src_as_host: int, pkt_ts: int, hop_mac: int) -> int:
    src_hi = (src_as_host >> 32) & 0xFFFFFFFF
    src_lo = src_as_host & 0xFFFFFFFF
    ts_hi  = (pkt_ts >> 32) & 0xFFFFFFFF
    ts_lo  = pkt_ts & 0xFFFFFFFF

    k0 = hop_mac & 0xFFFFFFFF
    k1 = swap16_halves(hop_mac) & 0xFFFFFFFF

    mac32 = halfsiphash_2_4_32(k0, k1, [src_hi, src_lo, ts_hi, ts_lo])
    return u24(mac32)

# -----------------------------
# Pack EPIC payload EXACTLY as your P4 headers
# -----------------------------
def pack_epic_payload(src_as_host: int, pkt_ts: int, path_ts: int,
                      per_hop_count: int, epic_next_hdr: int,
                      tsexp: int, ing: int, eg: int, segid: int,
                      hop_validation24: int) -> bytes:
    epic_h = struct.pack("!QQIBB",
                         src_as_host & 0xFFFFFFFFFFFFFFFF,
                         pkt_ts & 0xFFFFFFFFFFFFFFFF,
                         path_ts & 0xFFFFFFFF,
                         per_hop_count & 0xFF,
                         epic_next_hdr & 0xFF)

    per_hop = struct.pack("!BBBH",
                          tsexp & 0xFF,
                          ing & 0xFF,
                          eg & 0xFF,
                          segid & 0xFFFF)

    per_hop += (hop_validation24 & 0xFFFFFF).to_bytes(3, "big")
    return epic_h + per_hop

# -----------------------------
# Build / send / sniff
# -----------------------------
def sniff_for_marker(marker: bytes) -> bool:
    sniffer = AsyncSniffer(
        iface=EGRESS_IF,
        store=True,
        filter="ip6",
        lfilter=lambda p: marker in bytes(p),
    )
    sniffer.start()
    time.sleep(0.05)
    return sniffer

def send_and_expect_forward(pkt, marker: bytes):
    sniffer = sniff_for_marker(marker)
    sendp(pkt, iface=INGRESS_IF, verbose=False)
    time.sleep(SNIFF_TIMEOUT)
    pkts = sniffer.stop()
    if len(pkts) == 0:
        raise AssertionError("Expected FORWARD, but nothing seen on egress")

def send_and_expect_drop(pkt, marker: bytes):
    sniffer = sniff_for_marker(marker)
    sendp(pkt, iface=INGRESS_IF, verbose=False)
    time.sleep(SNIFF_TIMEOUT)
    pkts = sniffer.stop()
    if len(pkts) > 0:
        raise AssertionError("Expected DROP, but packet was seen on egress")

def build_epic_packet(marker: bytes,
                      src_override=None,
                      segid_override=None,
                      hop_validation_override=None,
                      bad_segleft=False):
    src_as_host = SRC_AS_HOST if src_override is None else src_override
    segid = SEG_ID if segid_override is None else segid_override

    hop_mac = compute_hop_mac(PATH_TS, TSEXP, ING_IF_ID, EG_IF_ID, segid)
    pkt_mac24 = compute_pkt_mac24(src_as_host, PKT_TS, hop_mac)

    if hop_validation_override is not None:
        pkt_mac24 = hop_validation_override & 0xFFFFFF

    epic_bytes = pack_epic_payload(
        src_as_host, PKT_TS, PATH_TS,
        PER_HOP_COUNT, EPIC_NEXT_HDR,
        TSEXP, ING_IF_ID, EG_IF_ID, segid,
        pkt_mac24
    )

    segleft = len(SID_LIST) - 1
    if bad_segleft:
        segleft = len(SID_LIST) + 3  # intentionally invalid

    # dst should be "active" segment = SegmentList[segleft] in normal cases
    dst = SID_LIST[-1] if segleft >= len(SID_LIST) else SID_LIST[segleft]

    ipv6 = IPv6(src="2001:db8::100", dst=dst, nh=SRH_NH)

    srh = IPv6ExtHdrSegmentRouting(nh=EPIC_NH)
    srh.addresses = SID_LIST
    srh.lastentry = len(SID_LIST) - 1
    srh.segleft   = segleft

    pkt = (
        Ether(src=SRC_MAC, dst=DST_MAC, type=0x86DD) /
        ipv6 /
        srh /
        Raw(load=epic_bytes) /
        Raw(load=marker)
    )
    return pkt, hop_mac, pkt_mac24

# -----------------------------
# Tests
# -----------------------------
def run():
    print(f"Sending on {INGRESS_IF}, sniffing on {EGRESS_IF}\n")

    # 1) VALID packet (correct hop_validation)
    m = b"T_VALID_" + struct.pack("!I", int(time.time()) & 0xFFFFFFFF)
    pkt, hop_mac, pkt_mac24 = build_epic_packet(marker=m)
    print(f"hop_mac    = 0x{hop_mac:08x}  (expected from switch logs: 0xadf715be)")
    print(f"swap16(k1) = 0x{swap16_halves(hop_mac):08x}")
    print(f"pkt_mac24  = 0x{pkt_mac24:06x}  (expected from switch logs: 0x916a5a)\n")
    send_and_expect_forward(pkt, m)
    print("[PASS] VALID forwards")

    # 2) Flip 1 bit of hop_validation -> drop
    m = b"T_BAD_HVF_" + struct.pack("!I", (int(time.time()) + 1) & 0xFFFFFFFF)
    bad_hvf = pkt_mac24 ^ 0x1
    pkt2, _, _ = build_epic_packet(marker=m, hop_validation_override=bad_hvf)
    send_and_expect_drop(pkt2, m)
    print("[PASS] BAD_HVF drops")

    # 3) Change SRC but keep old hop_validation -> drop
    m = b"T_BAD_SRC_" + struct.pack("!I", (int(time.time()) + 2) & 0xFFFFFFFF)
    pkt3, _, _ = build_epic_packet(marker=m, src_override=(SRC_AS_HOST ^ 0x1), hop_validation_override=pkt_mac24)
    send_and_expect_drop(pkt3, m)
    print("[PASS] BAD_SRC drops")

    # 4) Change SEG_ID but keep old hop_validation -> drop
    m = b"T_BAD_SEGID_" + struct.pack("!I", (int(time.time()) + 3) & 0xFFFFFFFF)
    pkt4, _, _ = build_epic_packet(marker=m, segid_override=(SEG_ID ^ 0x1), hop_validation_override=pkt_mac24)
    send_and_expect_drop(pkt4, m)
    print("[PASS] BAD_SEGID drops")

    # 5) Bad SRH segleft -> drop (or at least not forward)
    m = b"T_BAD_SEGLEFT_" + struct.pack("!I", (int(time.time()) + 4) & 0xFFFFFFFF)
    pkt5, _, _ = build_epic_packet(marker=m, bad_segleft=True)
    send_and_expect_drop(pkt5, m)
    print("[PASS] BAD_SEGLEFT drops")

    print("\nALL TESTS PASSED ✅")

if __name__ == "__main__":
    run()
