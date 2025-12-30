#!/usr/bin/env python3
import os
import time
import struct
from siphash import half_siphash_32

from scapy.all import Ether, IPv6, IPv6ExtHdrSegmentRouting, Raw, sendp, AsyncSniffer

# -----------------------------
# CONFIG
# -----------------------------
INGRESS_IF = "veth0"
EGRESS_IF  = "veth1"
SNIFF_WINDOW_S = 0.8

SRC_MAC = "02:00:00:00:00:01"
DST_MAC = "02:00:00:00:00:02"

SRC_AS_HOST = 0x0123456789ABCDEF
PKT_TS      = 0x1111111111111111
PATH_TS     = 0x22222222

PER_HOP_COUNT = 1
EPIC_NEXT_HDR = 59   # No Next Header (placeholder)

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

SIP_KEY_0 = 0x33323130
SIP_KEY_1 = 0x42413938

DIGEST_BYTEORDER = "little"

# -----------------------------
# Helpers
# -----------------------------
def halfsip32_int(key: bytes, msg: bytes) -> int:
    out = half_siphash_32(key, msg)
    if isinstance(out, (bytes, bytearray)):
        return int.from_bytes(out, DIGEST_BYTEORDER) & 0xFFFFFFFF
    return int(out) & 0xFFFFFFFF

def key8(k0_32: int, k1_32: int) -> bytes:
    return struct.pack("<II", k0_32 & 0xFFFFFFFF, k1_32 & 0xFFFFFFFF)

def swap16_halves(x: int) -> int:
    return ((x & 0xFFFF) << 16) | ((x >> 16) & 0xFFFF)

def u24(x: int) -> int:
    return x & 0xFFFFFF

def compute_hop_mac(path_ts: int, tsexp: int, ing: int, eg: int, segid: int) -> int:
    m0 = path_ts & 0xFFFFFFFF
    m1 = ((ing & 0xFF) << 24) | ((eg & 0xFF) << 16) | (segid & 0xFFFF)
    m2 = ((tsexp & 0xFF) << 24)
    m3 = 0
    msg = struct.pack("<IIII", m0, m1, m2, m3)
    return halfsip32_int(key8(SIP_KEY_0, SIP_KEY_1), msg)

def compute_pkt_mac24(src_as_host: int, pkt_ts: int, hop_mac: int) -> int:
    src_hi = (src_as_host >> 32) & 0xFFFFFFFF
    src_lo = src_as_host & 0xFFFFFFFF
    ts_hi  = (pkt_ts >> 32) & 0xFFFFFFFF
    ts_lo  = pkt_ts & 0xFFFFFFFF

    k0 = hop_mac & 0xFFFFFFFF
    k1 = swap16_halves(hop_mac) & 0xFFFFFFFF
    msg = struct.pack("<IIII", src_hi, src_lo, ts_hi, ts_lo)
    mac32 = halfsip32_int(key8(k0, k1), msg)
    return u24(mac32)

def pack_epic_payload(hvf24: int) -> bytes:
    # epic_h: !QQIBB
    epic_h = struct.pack("!QQIBB",
                         SRC_AS_HOST & 0xFFFFFFFFFFFFFFFF,
                         PKT_TS & 0xFFFFFFFFFFFFFFFF,
                         PATH_TS & 0xFFFFFFFF,
                         PER_HOP_COUNT & 0xFF,
                         EPIC_NEXT_HDR & 0xFF)

    # epic_per_hop_h: !BBBH + 24-bit hvf big-endian
    per_hop = struct.pack("!BBBH",
                          TSEXP & 0xFF,
                          ING_IF_ID & 0xFF,
                          EG_IF_ID & 0xFF,
                          SEG_ID & 0xFFFF)
    per_hop += u24(hvf24).to_bytes(3, "big")
    return epic_h + per_hop

def build_pkt(marker: bytes, hvf_override: int | None = None):
    hop_mac = compute_hop_mac(PATH_TS, TSEXP, ING_IF_ID, EG_IF_ID, SEG_ID)
    hvf24 = compute_pkt_mac24(SRC_AS_HOST, PKT_TS, hop_mac)
    if hvf_override is not None:
        hvf24 = u24(hvf_override)

    epic_bytes = pack_epic_payload(hvf24)

    segleft = len(SID_LIST) - 1
    ipv6 = IPv6(src="2001:db8::100", dst=SID_LIST[segleft], nh=SRH_NH)
    srh = IPv6ExtHdrSegmentRouting(nh=EPIC_NH)
    srh.addresses = SID_LIST
    srh.lastentry = len(SID_LIST) - 1
    srh.segleft   = segleft

    pkt = Ether(src=SRC_MAC, dst=DST_MAC, type=0x86DD) / ipv6 / srh / Raw(load=epic_bytes) / Raw(load=marker)
    return pkt, hop_mac, hvf24

def is_final_ipv6_frame(p, marker: bytes) -> bool:
    try:
        b = bytes(p)
        if len(b) < 15:
            return False
        ethertype = int.from_bytes(b[12:14], "big")
        if ethertype != 0x86DD:
            return False
        # IPv6 version nibble must be 6 immediately after Ethernet
        if (b[14] >> 4) != 6:
            return False
        return marker in b
    except Exception:
        return False

def send_and_check(marker: bytes, expect_forward: bool, pkt):
    sniffer = AsyncSniffer(
        iface=EGRESS_IF,
        store=True,
        lfilter=lambda p: is_final_ipv6_frame(p, marker),
    )
    sniffer.start()
    time.sleep(0.05)
    sendp(pkt, iface=INGRESS_IF, verbose=False)
    time.sleep(SNIFF_WINDOW_S)
    seen = sniffer.stop()

    if expect_forward and not seen:
        raise AssertionError("Expected FORWARD (final IPv6 frame), but none was captured")
    if (not expect_forward) and seen:
        raise AssertionError("Expected DROP (no final IPv6 frame), but one was captured")

def main():
    print(f"Sending on {INGRESS_IF}, sniffing final IPv6 on {EGRESS_IF}")

    marker_ok = b"OK_" + os.urandom(6)
    pkt_ok, hop_mac, hvf = build_pkt(marker_ok)
    print(f"hop_mac = 0x{hop_mac:08x}, hvf24 = 0x{hvf:06x}")
    send_and_check(marker_ok, True, pkt_ok)
    print("[PASS] VALID forwards (final IPv6 seen)")

    marker_bad = b"BAD_" + os.urandom(6)
    pkt_bad, _, _ = build_pkt(marker_bad, hvf_override=(hvf ^ 0x1))
    send_and_check(marker_bad, False, pkt_bad)
    print("[PASS] BAD_HVF drops (no final IPv6 seen)")

if __name__ == "__main__":
    main()
