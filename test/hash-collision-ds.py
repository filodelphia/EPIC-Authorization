#!/usr/bin/env python3
import struct
import time
import random
from typing import List, Optional

import argparse
from scapy.layers.l2 import Ether
from scapy.layers.inet6 import IPv6, IPv6ExtHdrSegmentRouting
from scapy.packet import Raw
from scapy.sendrecv import sendp, AsyncSniffer

from include.halfsiphash import halfsiphash_2_4_32, swap16_halves, u24
from include.tofinoports import port_to_iface

# -----------------------------
# CONFIG GLOBALS (set by argparse)
# -----------------------------
INGRESS_PORT = 0
EGRESS_PORT  = 1

# IMPORTANT: dual-pipe + multi-pass often needs >0.15s in the model
SNIFF_TIMEOUT = 1.0

SRC_MAC = "02:00:00:00:00:01"
DST_MAC = "02:00:00:00:00:02"

PATH_TS = 0x22222222
PER_HOP_COUNT = 1
EPIC_NEXT_HDR = 59
TSEXP  = 0x01
SEG_ID = 0x1234

SID_LIST = ["2001:db8:0:1::1", "2001:db8:0:2::1"]
SRH_NH  = 43
EPIC_NH = 253

SIP_KEY_0 = 0x33323130
SIP_KEY_1 = 0x42413938

# Derived
INGRESS_IFACE = ""
EGRESS_IFACE  = ""

# Benchmark controls
MAX_TRIALS = 20000
RNG_SEED   = 1

# -----------------------------
# EPIC L1 MAC chain
# -----------------------------
def compute_hop_mac(path_ts: int, tsexp: int, ing_port: int, eg_port: int, segid: int) -> int:
    m0 = path_ts & 0xFFFFFFFF
    m1 = ((ing_port & 0xFF) << 24) | ((eg_port & 0xFF) << 16) | (segid & 0xFFFF)
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

def pack_epic_payload(src_as_host: int, pkt_ts: int, path_ts: int,
                      per_hop_count: int, epic_next_hdr: int,
                      tsexp: int, ing_port: int, eg_port: int, segid: int,
                      hop_validation24: int) -> bytes:
    epic_h = struct.pack("!QQIBB",
                         src_as_host & 0xFFFFFFFFFFFFFFFF,
                         pkt_ts & 0xFFFFFFFFFFFFFFFF,
                         path_ts & 0xFFFFFFFF,
                         per_hop_count & 0xFF,
                         epic_next_hdr & 0xFF)

    per_hop = struct.pack("!BBBH",
                          tsexp & 0xFF,
                          ing_port & 0xFF,
                          eg_port & 0xFF,
                          segid & 0xFFFF)

    per_hop += (hop_validation24 & 0xFFFFFF).to_bytes(3, "big")
    return epic_h + per_hop

def build_epic_packet(marker: bytes, src_as_host: int, pkt_ts: int, segid: int):
    hop_mac = compute_hop_mac(PATH_TS, TSEXP, INGRESS_PORT, EGRESS_PORT, segid)
    hvf24   = compute_pkt_mac24(src_as_host, pkt_ts, hop_mac)

    epic_bytes = pack_epic_payload(
        src_as_host, pkt_ts, PATH_TS,
        PER_HOP_COUNT, EPIC_NEXT_HDR,
        TSEXP, INGRESS_PORT, EGRESS_PORT, segid,
        hvf24
    )

    segleft = len(SID_LIST) - 1
    dst = SID_LIST[segleft]

    ipv6 = IPv6(src="2001:db8::100", dst=dst, nh=SRH_NH)
    srh = IPv6ExtHdrSegmentRouting(nh=EPIC_NH)
    srh.addresses = SID_LIST
    srh.lastentry = len(SID_LIST) - 1
    srh.segleft   = segleft

    return (
        Ether(src=SRC_MAC, dst=DST_MAC, type=0x86DD) /
        ipv6 /
        srh /
        Raw(load=epic_bytes) /
        Raw(load=marker)
    )

# -----------------------------
# Sniffer + wait-for-marker
# -----------------------------
_seen_i = set()

def _on_pkt(pkt):
    b = bytes(pkt)
    # marker format: b"T_COLL_" + u32(i)
    off = b.find(b"T_COLL_")
    if off != -1 and off + 11 <= len(b):
        i = struct.unpack("!I", b[off + 7: off + 11])[0]
        _seen_i.add(i)

def wait_seen(i: int, timeout_s: float) -> bool:
    deadline = time.perf_counter() + timeout_s
    while time.perf_counter() < deadline:
        if i in _seen_i:
            return True
        time.sleep(0.002)
    return False

# -----------------------------
# Benchmark
# -----------------------------
def run():
    print(f"Injecting on port {INGRESS_PORT} ({INGRESS_IFACE}), expecting final forward on {EGRESS_PORT} ({EGRESS_IFACE})")
    print(f"max_trials={MAX_TRIALS}, per_pkt_timeout={SNIFF_TIMEOUT}s\n")
    print(f"Using seed {RNG_SEED}")

    rng = random.Random(RNG_SEED)

    # Use a fixed timestamp across all trials (this is what makes collisions observable as drops).
    # IMPORTANT: if registers are not cleared from previous runs, this can still fail at i=1 legitimately.
    base_ts = (0xF000000000000000 | (int(time.time()) & 0xFFFFFFFFFFFF))

    sn = AsyncSniffer(
        iface=[EGRESS_IFACE],
        store=False,
        filter="ip6",
        prn=_on_pkt
    )
    sn.start()
    time.sleep(0.05)

    try:
        # Pre-flight: ensure at least one packet comes back out of the *final* egress.
        _seen_i.clear()
        pre_i = 0xAAAAAAAA
        pre_marker = b"T_COLL_" + struct.pack("!I", pre_i)
        pre_pkt = build_epic_packet(pre_marker, src_as_host=0x0123456789ABCDEF, pkt_ts=base_ts + 1, segid=SEG_ID)
        sendp(pre_pkt, iface=INGRESS_IFACE, verbose=False)
        if not wait_seen(pre_i, SNIFF_TIMEOUT):
            raise RuntimeError(
                "Pre-test faild, did no see packet in egress. Either caused by\n" \
                "\t1. Timeout too small\n" \
                "\t2. Sniffing on the wrong interface\n" \
                "\t3. Dual pipe chain not completing"
            )

        start = time.perf_counter()
        collided_at: Optional[int] = None

        for i in range(1, MAX_TRIALS + 1):
            src_rand = rng.getrandbits(64)
            seg_rand = (SEG_ID + (i * 0x9E37)) & 0xFFFF
            marker = b"T_COLL_" + struct.pack("!I", i)

            pkt = build_epic_packet(marker, src_as_host=src_rand, pkt_ts=base_ts, segid=seg_rand)
            sendp(pkt, iface=INGRESS_IFACE, verbose=False)

            if not wait_seen(i, SNIFF_TIMEOUT):
                collided_at = i
                break

        elapsed = time.perf_counter() - start

        if collided_at is None:
            print(f"❌ No collision symptom observed in {MAX_TRIALS} packets (elapsed {elapsed:.3f}s)")
            print("Note: this is 'masked-index aliasing' detection; you might need more trials or a smaller register to see it.")
        else:
            print(f"✅ First collision symptom at i={collided_at} (elapsed {elapsed:.3f}s)")
            print("Two different packet origins likely mapped to the same masked CRC32 index")


    finally:
        sn.stop()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Hash/register aliasing benchmark for EPIC duplicate suppression (Tofino model)")

    parser.add_argument("--ingress", type=int, default=0)
    parser.add_argument("--egress", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=1.5)
    parser.add_argument("--max", type=int, default=20000)

    default_seed = random.randrange(0, 2**32)
    parser.add_argument("--seed", type=int, default=default_seed)

    parser.add_argument("--src-mac", type=str, default=SRC_MAC)
    parser.add_argument("--dst-mac", type=str, default=DST_MAC)
    parser.add_argument("--sid-list", type=str, nargs="+", default=SID_LIST)

    parser.add_argument("--key0", type=lambda x: int(x, 0), default=SIP_KEY_0)
    parser.add_argument("--key1", type=lambda x: int(x, 0), default=SIP_KEY_1)

    args = parser.parse_args()

    INGRESS_PORT = args.ingress
    EGRESS_PORT  = args.egress
    SNIFF_TIMEOUT = args.timeout
    MAX_TRIALS = args.max
    RNG_SEED = args.seed

    SRC_MAC = args.src_mac
    DST_MAC = args.dst_mac
    SID_LIST = args.sid_list

    SIP_KEY_0 = args.key0
    SIP_KEY_1 = args.key1

    INGRESS_IFACE = port_to_iface(INGRESS_PORT)
    EGRESS_IFACE  = port_to_iface(EGRESS_PORT)

    run()
