#!/usr/bin/env python3
import struct
import time
import os
from typing import List, Optional

import argparse

from scapy.layers.l2 import Ether
from scapy.layers.inet6 import IPv6, IPv6ExtHdrSegmentRouting
from scapy.packet import Raw
from scapy.sendrecv import sendp, AsyncSniffer
from scapy.utils import wrpcap

# halfsiphash import based on Princeton paper's implementation
from include.halfsiphash import halfsiphash_2_4_32, swap16_halves, u24

# tofino ports
from include.tofinoports import port_to_iface, all_model_port_ifaces

# -----------------------------
# CONFIG GLOBALS (To be set by argparse)
# -----------------------------
INGRESS_PORT = 0
EGRESS_PORT  = 1
SNIFF_TIMEOUT = 1.2
SRC_MAC = "02:00:00:00:00:01"
DST_MAC = "02:00:00:00:00:02"
SRC_AS_HOST = 0x0123456789ABCDEF
PKT_TS      = 0x1111111111111111
PATH_TS     = 0x22222222
PER_HOP_COUNT = 1
EPIC_NEXT_HDR = 59
TSEXP     = 0x01
SEG_ID    = 0x1234
SID_LIST = ["2001:db8:0:1::1", "2001:db8:0:2::1"]
SRH_NH  = 43
EPIC_NH = 253
SIP_KEY_0 = 0x33323130
SIP_KEY_1 = 0x42413938
PCAP_DIR = "../tmp/"
WRITE_PCAPS = True
STRICT_DROP = True
PRINT_ERRORS = False

# Derived at runtime
INGRESS_IFACE = ""
EGRESS_IFACE  = ""


# -----------------------------
# EPIC L1 MAC chain (ports are Tofino port IDs)
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


# -----------------------------
# IO helpers
# -----------------------------
def _start_sniffer(ifaces, marker: bytes) -> AsyncSniffer:
    sn = AsyncSniffer(
        iface=ifaces,
        store=True,
        filter="ip6",
        lfilter=lambda p: marker in bytes(p),
    )
    sn.start()
    time.sleep(0.05)
    return sn


def send_and_expect(pkt, marker: bytes, expect_forward: bool,
                    sniff_ifaces: List[str],
                    label: str,
                    pcap_prefix: Optional[str] = None):
    sn = _start_sniffer(sniff_ifaces, marker)

    # Always inject on INGRESS_PORT (port 0 -> veth0)
    sendp(pkt, iface=INGRESS_IFACE, verbose=False)

    time.sleep(SNIFF_TIMEOUT)
    pkts = sn.stop()

    if WRITE_PCAPS and pcap_prefix:
        os.makedirs(PCAP_DIR, exist_ok=True)
        wrpcap(os.path.join(PCAP_DIR, f"{pcap_prefix}_tx.pcap"), [pkt])
        if pkts:
            wrpcap(os.path.join(PCAP_DIR, f"{pcap_prefix}_rx.pcap"), pkts)

    if expect_forward and len(pkts) == 0:
        raise AssertionError(f"[{label}] Expected FORWARD, but marker not seen on {sniff_ifaces}")
    if (not expect_forward) and len(pkts) > 0:
        raise AssertionError(f"[{label}] Expected DROP, but marker seen on {sniff_ifaces} (count={len(pkts)})")


def build_epic_packet(marker: bytes,
                      src_override: Optional[int] = None,
                      segid_override: Optional[int] = None,
                      hvf_override: Optional[int] = None,
                      bad_segleft: bool = False,
                      ingress_port_override: Optional[int] = None,
                      egress_port_override: Optional[int] = None,
                      pkt_ts_override: Optional[int] = None):
    src_as_host = SRC_AS_HOST if src_override is None else src_override
    segid = SEG_ID if segid_override is None else segid_override

    ing_p = INGRESS_PORT if ingress_port_override is None else ingress_port_override
    eg_p  = EGRESS_PORT  if egress_port_override is None else egress_port_override

    pkt_ts = PKT_TS if pkt_ts_override is None else pkt_ts_override

    hop_mac = compute_hop_mac(PATH_TS, TSEXP, ing_p, eg_p, segid)
    hvf24 = compute_pkt_mac24(src_as_host, pkt_ts, hop_mac)

    if hvf_override is not None:
        hvf24 = hvf_override & 0xFFFFFF

    epic_bytes = pack_epic_payload(
        src_as_host, pkt_ts, PATH_TS,
        PER_HOP_COUNT, EPIC_NEXT_HDR,
        TSEXP, ing_p, eg_p, segid,
        hvf24
    )

    segleft = len(SID_LIST) - 1
    if bad_segleft:
        segleft = len(SID_LIST) + 3

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
    return pkt, hop_mac, hvf24


# -----------------------------
# Tests
# -----------------------------
def run():
    print(f"Injecting on port {INGRESS_PORT} ({INGRESS_IFACE}), expecting forward on port {EGRESS_PORT} ({EGRESS_IFACE})\n")

    good_sniff = [EGRESS_IFACE]

    if STRICT_DROP:
        candidates = all_model_port_ifaces(max_port=16, extra_ports=[64])
        drop_sniff = [i for i in candidates if i != INGRESS_IFACE]
    else:
        drop_sniff = [EGRESS_IFACE]


    total_test = 9
    valid_tests = 0

    # 1) VALID
    m = b"T_VALID_" + struct.pack("!I", int(time.time()) & 0xFFFFFFFF)
    pkt, hop_mac, hvf24 = build_epic_packet(marker=m)

    print(f"hop_mac    = 0x{hop_mac:08x}")
    print(f"swap16(k1) = 0x{swap16_halves(hop_mac):08x}")
    print(f"hvf24      = 0x{hvf24:06x}\n")

    try:
        send_and_expect(pkt, m, True, good_sniff, "VALID", "01_valid")
        print("✅ [PASS] VALID forwards")
        valid_tests += 1
    except AssertionError as e:
        if(PRINT_ERRORS):
            print(f"Error:\n{'`'*10}\n{str(e)}\n{'`'*10}\n")
        print("❌ [FAIL] VALID did not forward as expected")

    # 2) BAD_HVF (flip 1 bit)
    m = b"T_BAD_HVF_" + struct.pack("!I", (int(time.time()) + 1) & 0xFFFFFFFF)
    pkt2, _, _ = build_epic_packet(marker=m, hvf_override=(hvf24 ^ 0x1))

    try:
        send_and_expect(pkt2, m, False, drop_sniff, "BAD_HVF", "02_bad_hvf")
        print("✅ [PASS] BAD_HVF drops")
        valid_tests += 1
    except AssertionError as e:
        if(PRINT_ERRORS):
            print(f"Error:\n{'`'*10}\n{str(e)}\n{'`'*10}\n")
        print("❌ [FAIL] BAD_HVF did not drop as expected")

    # 3) BAD_SRC but keep hvf
    m = b"T_BAD_SRC_" + struct.pack("!I", (int(time.time()) + 2) & 0xFFFFFFFF)
    pkt3, _, _ = build_epic_packet(marker=m, src_override=(SRC_AS_HOST ^ 0x1), hvf_override=hvf24)
    try:
        send_and_expect(pkt3, m, False, drop_sniff, "BAD_SRC", "03_bad_src")
        print("✅ [PASS] BAD_SRC drops")
        valid_tests += 1
    except AssertionError as e:
        if(PRINT_ERRORS):
            print(f"Error:\n{'`'*10}\n{str(e)}\n{'`'*10}\n")
        print("❌ [FAIL] BAD_SRC did not drop as expected")

    # 4) BAD_SEGID but keep hvf
    m = b"T_BAD_SEGID_" + struct.pack("!I", (int(time.time()) + 3) & 0xFFFFFFFF)
    pkt4, _, _ = build_epic_packet(marker=m, segid_override=(SEG_ID ^ 0x1), hvf_override=hvf24)
    try:
        send_and_expect(pkt4, m, False, drop_sniff, "BAD_SEGID", "04_bad_segid")
        print("✅ [PASS] BAD_SEGID drops")
        valid_tests += 1
    except AssertionError as e:
        if(PRINT_ERRORS):
            print(f"Error:\n{'`'*10}\n{str(e)}\n{'`'*10}\n")
        print("❌ [FAIL] BAD_SEGID did not drop as expected")
    
    # 5) BAD_SEGLEFT
    m = b"T_BAD_SEGLEFT_" + struct.pack("!I", (int(time.time()) + 4) & 0xFFFFFFFF)
    pkt5, _, _ = build_epic_packet(marker=m, bad_segleft=True)
    try:
        send_and_expect(pkt5, m, False, drop_sniff, "BAD_SEGLEFT", "05_bad_segleft")
        print("✅ [PASS] BAD_SEGLEFT drops")
        valid_tests += 1
    except AssertionError as e:
        if(PRINT_ERRORS):
            print(f"Error:\n{'`'*10}\n{str(e)}\n{'`'*10}\n")
        print("❌ [FAIL] BAD_SEGLEFT did not drop as expected")

    # 6) BAD_ING_PORT: EPIC says ingress_if=1 but we inject on port 0
    m = b"T_BAD_INGPORT_" + struct.pack("!I", (int(time.time()) + 5) & 0xFFFFFFFF)
    pkt6, _, _ = build_epic_packet(marker=m, ingress_port_override=1, egress_port_override=EGRESS_PORT)
    try:
        send_and_expect(pkt6, m, False, drop_sniff, "BAD_ING_PORT", "06_bad_ing_port")
        print("✅ [PASS] BAD_ING_PORT drops")
        valid_tests += 1
    except AssertionError as e:
        if(PRINT_ERRORS):
            print(f"Error:\n{'`'*10}\n{str(e)}\n{'`'*10}\n")
        print("❌ [FAIL] BAD_ING_PORT did not drop as expected")
    
    #7) GOOD_TS: two packets, strictly increasing ts -> both forward
    try:
        base = (int(time.time()) & 0xFFFFFFFF)

        ts1 = PKT_TS + 0x10
        m7a = b"T_GOOD_TS_A_" + struct.pack("!I", base)
        pkt7a, _, _ = build_epic_packet(marker=m7a, pkt_ts_override=ts1)
        send_and_expect(pkt7a, m7a, True, good_sniff, "GOOD_TS_A", "07_good_ts_a")

        ts2 = PKT_TS + 0x11  # strictly increasing
        m7b = b"T_GOOD_TS_B_" + struct.pack("!I", base + 1)
        pkt7b, _, _ = build_epic_packet(marker=m7b, pkt_ts_override=ts2)
        send_and_expect(pkt7b, m7b, True, good_sniff, "GOOD_TS_B", "07_good_ts_b")

        print("✅ [PASS] GOOD_TS monotonic accepts increasing timestamps (2/2)")
        valid_tests += 1
    except AssertionError as e:
        if PRINT_ERRORS:
            print(f"Error:\n{'`'*10}\n{str(e)}\n{'`'*10}\n")
        print("❌ [FAIL] GOOD_TS monotonic test failed")

    #8) DUP/ORDERING: 5 packets, show both kinds of drop (smaller and equal)
    #    1st: forward (ts=t1)
    #    2nd: drop    (ts<t1)
    #    3rd: forward (ts>t1)
    #    4th: drop    (ts==t3)
    #    5th: drop    (ts<t3)
    try:
        base = (int(time.time()) & 0xFFFFFFFF) + 100

        t1 = PKT_TS + 0x200
        m8_1 = b"T_DUP_1_" + struct.pack("!I", base)
        p8_1, _, _ = build_epic_packet(marker=m8_1, pkt_ts_override=t1)
        send_and_expect(p8_1, m8_1, True, good_sniff, "DUP_1", "08_dup_1")
        print("Packet 1 forwarded ...", end='\r')

        t2 = PKT_TS + 0x100  # smaller than t1 -> drop
        m8_2 = b"T_DUP_2_" + struct.pack("!I", base + 1)
        p8_2, _, _ = build_epic_packet(marker=m8_2, pkt_ts_override=t2)
        send_and_expect(p8_2, m8_2, False, drop_sniff, "DUP_2_SMALLER", "08_dup_2_smaller")
        print("Packet 2 dropped (as expected) ...    ", end='\r')

        t3 = PKT_TS + 0x300  # greater -> forward
        m8_3 = b"T_DUP_3_" + struct.pack("!I", base + 2)
        p8_3, _, _ = build_epic_packet(marker=m8_3, pkt_ts_override=t3)
        send_and_expect(p8_3, m8_3, True, good_sniff, "DUP_3_GREATER", "08_dup_3_greater")
        print("Packet 3 forwarded (as expected) ...  ", end='\r')

        t4 = t3  # equal -> drop
        m8_4 = b"T_DUP_4_" + struct.pack("!I", base + 3)
        p8_4, _, _ = build_epic_packet(marker=m8_4, pkt_ts_override=t4)
        send_and_expect(p8_4, m8_4, False, drop_sniff, "DUP_4_EQUAL", "08_dup_4_equal")
        print("Packet 4 dropped (as expected) ...    ", end='\r')

        t5 = PKT_TS + 0x250  # smaller than latest (t3) -> drop
        m8_5 = b"T_DUP_5_" + struct.pack("!I", base + 4)
        p8_5, _, _ = build_epic_packet(marker=m8_5, pkt_ts_override=t5)
        send_and_expect(p8_5, m8_5, False, drop_sniff, "DUP_5_SMALLER_AFTER_UPDATE", "08_dup_5_smaller_after")
        print("Packet 5 dropped (as expected) ...    ", end='\r')

        print("✅ [PASS] DUP test: smaller+equal timestamps drop, greater passes (5-step)")
        valid_tests += 1
    except AssertionError as e:
        if PRINT_ERRORS:
            print(f"Error:\n{'`'*10}\n{str(e)}\n{'`'*10}\n")
        print("❌ [FAIL] DUP 5-step test failed")



    #9) DIFF_PO: 2 packets, origin2 != origin1
    try:
        base = (int(time.time()) & 0xFFFFFFFF) + 200

        # Origin #1
        t9_1 = PKT_TS + 0x400
        m9_1 = b"T_PO1_" + struct.pack("!I", base)
        p9_1, _, _ = build_epic_packet(marker=m9_1, pkt_ts_override=t9_1)
        send_and_expect(p9_1, m9_1, True, good_sniff, "PO1", "09_po1")

        # Origin #2 (different src and segid) with smaller timestamp
        t9_2 = PKT_TS + 0x010  # smaller than t9_1
        src2 = SRC_AS_HOST ^ 0x0101010101010101
        seg2 = SEG_ID ^ 0xBEEF
        m9_2 = b"T_PO2_" + struct.pack("!I", base + 1)
        p9_2, _, _ = build_epic_packet(
            marker=m9_2,
            pkt_ts_override=t9_2,
            src_override=src2,
            segid_override=seg2
        )
        send_and_expect(p9_2, m9_2, True, good_sniff, "PO2_SMALLER_TS_DIFFERENT_ORIGIN", "09_po2_smaller_ts")

        print("✅ [PASS] Different packet-origin allows smaller timestamp (2-step)")
        valid_tests += 1
    except AssertionError as e:
        if PRINT_ERRORS:
            print(f"Error:\n{'`'*10}\n{str(e)}\n{'`'*10}\n")
        print("❌ [FAIL] Different packet-origin test failed! Retry (hash collision chance)")

    if total_test == valid_tests: print("---- ALL TESTS PASSED ✅ ----")
    else: print(f"{total_test - valid_tests} TESTS FAILED ❌")

    if WRITE_PCAPS:
        print(f"PCAPs written under: {os.path.abspath(PCAP_DIR)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test script for EPIC P4 with Duplicate Detection on Tofino Model")
    
    # Network Configuration
    parser.add_argument("--ingress", type=int, default=0, help="Ingress Tofino port ID (default: 0)")
    parser.add_argument("--egress", type=int, default=1, help="Expected Egress Tofino port ID (default: 1)")
    parser.add_argument("--timeout", type=float, default=1.2, help="Sniff timeout in seconds (default: 1.2)")
    
    # MAC/Header Configuration
    parser.add_argument("--src-mac", type=str, default="02:00:00:00:00:01", help="Source MAC address")
    parser.add_argument("--dst-mac", type=str, default="02:00:00:00:00:02", help="Destination MAC address")
    parser.add_argument("--src-as-host", type=lambda x: int(x, 0), default=0x0123456789ABCDEF, help="Source AS Host ID (64-bit hex)")
    parser.add_argument("--pkt-ts", type=lambda x: int(x, 0), default=0x1111111111111111, help="Packet Timestamp (64-bit hex)")
    parser.add_argument("--path-ts", type=lambda x: int(x, 0), default=0x22222222, help="Path Timestamp (32-bit hex)")
    parser.add_argument("--seg-id", type=lambda x: int(x, 0), default=0x1234, help="Segment ID (16-bit hex)")
    parser.add_argument("--sid-list", type=str, nargs="+", default=["2001:db8:0:1::1", "2001:db8:0:2::1"], help="List of IPv6 SIDs")
    parser.add_argument("--show-errors", action="store_true", dest="show_errors", help="Print error description if any occur")
    
    # HalfSipHash Keys
    parser.add_argument("--key0", type=lambda x: int(x, 0), default=0x33323130, help="SipHash Key 0 (32-bit hex)")
    parser.add_argument("--key1", type=lambda x: int(x, 0), default=0x42413938, help="SipHash Key 1 (32-bit hex)")
    
    # Logic / IO
    parser.add_argument("--pcap-dir", type=str, default="../tmp/", help="Directory to save PCAP files")
    parser.add_argument("--no-pcap", action="store_false", dest="write_pcaps", help="Disable PCAP writing")
    parser.add_argument("--relaxed", action="store_false", dest="strict_drop", help="Disable strict port sniffing for drops")

    args = parser.parse_args()

    # Map args back to global variables used in the script
    INGRESS_PORT = args.ingress
    EGRESS_PORT  = args.egress
    SNIFF_TIMEOUT = args.timeout
    SRC_MAC = args.src_mac
    DST_MAC = args.dst_mac
    SRC_AS_HOST = args.src_as_host
    PKT_TS = args.pkt_ts
    PATH_TS = args.path_ts
    SEG_ID = args.seg_id
    SID_LIST = args.sid_list
    SIP_KEY_0 = args.key0
    SIP_KEY_1 = args.key1
    PCAP_DIR = args.pcap_dir
    WRITE_PCAPS = args.write_pcaps
    STRICT_DROP = args.strict_drop
    PRINT_ERRORS = args.show_errors

    # Initialize Interfaces
    INGRESS_IFACE = port_to_iface(INGRESS_PORT)
    EGRESS_IFACE  = port_to_iface(EGRESS_PORT)

    run()
