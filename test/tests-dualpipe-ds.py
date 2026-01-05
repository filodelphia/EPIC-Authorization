#!/usr/bin/env python3
import struct
import time
import os
from typing import List, Optional

import argparse

# Packet imports
from scapy.layers.l2 import Ether
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw
from scapy.sendrecv import sendp, AsyncSniffer
from scapy.utils import wrpcap

from include.PacketBuilder import EpicBuilder, SRHBuilder

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
SID_LIST = ["2001:db8:0:1::1", "2001:db8:0:2::1"]
IPV6_NEXT_HEADER  = 43
SRH_NEXT_HEADER = 253
SEG_ID    = 0x1234
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


# -----------------------------
# Tests
# -----------------------------
def run_tests():
    print(f"Injecting on port {INGRESS_PORT} ({INGRESS_IFACE}), expecting forward on port {EGRESS_PORT} ({EGRESS_IFACE})\n")

    good_sniff = [EGRESS_IFACE]
    if STRICT_DROP:
        candidates = all_model_port_ifaces(max_port=16, extra_ports=[64])
        drop_sniff = [i for i in candidates if i != INGRESS_IFACE]
    else:
        drop_sniff = [EGRESS_IFACE]


    epic = EpicBuilder(SIP_KEY_0, SIP_KEY_1, SRC_AS_HOST, SEG_ID, PKT_TS, PATH_TS, PER_HOP_COUNT, EPIC_NEXT_HDR, TSEXP, INGRESS_PORT, EGRESS_PORT)
    srh = SRHBuilder(SID_LIST, SRH_NEXT_HEADER)
    ipv6 = IPv6(src="2001:db8::100", dst=srh.sid_list[srh.last_entry], nh=IPV6_NEXT_HEADER)

    total_test = 12
    valid_tests = 0

    # 1) VALID
    marker = b"T_VALID_" + struct.pack("!I", int(time.time()) & 0xFFFFFFFF)
    epic_pkt = epic.build_epic()
    srh_pkt = srh.build_srh()
    pkt = (
        Ether(src=SRC_MAC, dst=DST_MAC, type=0x86DD) /
        ipv6 /
        srh_pkt /
        Raw(load=epic_pkt) /
        Raw(load=marker)
    )

    try:
        send_and_expect(pkt, marker, True, good_sniff, "VALID_1_EPIC", "01_valid")
        print("✅ [PASS] VALID_1_EPIC forwards")
        valid_tests += 1
    except AssertionError as e:
        if(PRINT_ERRORS):
            print(f"Error:\n{'`'*10}\n{str(e)}\n{'`'*10}\n")
        print("❌ [FAIL] VALID_1_EPIC did not forward as expected")
    
    # 2) VALID multiple per_hop
    epic.per_hop_count = 4
    marker2 = b"T_VALID_" + struct.pack("!I", int(time.time()) & 0xFFFFFFFF)
    epic.pkt_ts = epic.pkt_ts + 1; epic_pkt = epic.build_epic()
    srh_pkt = srh.build_srh()
    pkt2 = (
        Ether(src=SRC_MAC, dst=DST_MAC, type=0x86DD) /
        ipv6 /
        srh_pkt /
        Raw(load=epic_pkt) /
        Raw(load=marker2)
    )

    # Restore
    epic.per_hop_count = PER_HOP_COUNT

    try:
        send_and_expect(pkt2, marker2, True, good_sniff, "VALID_4_EPIC", "02_valid")
        print("✅ [PASS] VALID_4_EPIC forwards")
        valid_tests += 1
    except AssertionError as e:
        if(PRINT_ERRORS):
            print(f"Error:\n{'`'*10}\n{str(e)}\n{'`'*10}\n")
        print("❌ [FAIL] VALID_4_EPIC did not forward as expected")


    # 3) BAD_HVF (flip 1 bit)
    marker3 = b"T_BAD_HVF_" + struct.pack("!I", (int(time.time()) + 1) & 0xFFFFFFFF)

    hvf24 = epic.get_pkt_mac()
    epic.pkt_ts = epic.pkt_ts + 1; epic_pkt = epic.build_epic(hvf_override=(hvf24 ^ 0x1))
    srh_pkt = srh.build_srh()
    pkt3 = (
        Ether(src=SRC_MAC, dst=DST_MAC, type=0x86DD) /
        ipv6 /
        srh_pkt /
        Raw(load=epic_pkt) /
        Raw(load=marker3)
    )

    try:
        send_and_expect(pkt3, marker3, False, drop_sniff, "BAD_HVF", "03_bad_hvf")
        print("✅ [PASS] BAD_HVF drops")
        valid_tests += 1
    except AssertionError as e:
        if(PRINT_ERRORS):
            print(f"Error:\n{'`'*10}\n{str(e)}\n{'`'*10}\n")
        print("❌ [FAIL] BAD_HVF did not drop as expected")   

    # 4) BAD_SRC but keep hvf
    marker4 = b"T_BAD_SRC_" + struct.pack("!I", (int(time.time()) + 2) & 0xFFFFFFFF)
    epic.pkt_ts = epic.pkt_ts + 1; epic_pkt = epic.build_epic(src_override=(SRC_AS_HOST ^ 0x1))
    srh_pkt = srh.build_srh()
    pkt4 = (
        Ether(src=SRC_MAC, dst=DST_MAC, type=0x86DD) /
        ipv6 /
        srh_pkt /
        Raw(load=epic_pkt) /
        Raw(load=marker4)
    )

    try:
        send_and_expect(pkt4, marker4, False, drop_sniff, "BAD_SRC", "04_bad_src")
        print("✅ [PASS] BAD_SRC drops")
        valid_tests += 1
    except AssertionError as e:
        if(PRINT_ERRORS):
            print(f"Error:\n{'`'*10}\n{str(e)}\n{'`'*10}\n")
        print("❌ [FAIL] BAD_SRC did not drop as expected")  

    # 5) BAD_SEGID but keep hvf
    marker5 = b"T_BAD_SEGID_" + struct.pack("!I", (int(time.time()) + 3) & 0xFFFFFFFF)
    epic.pkt_ts = epic.pkt_ts + 1; epic_pkt = epic.build_epic(segid_override=(SEG_ID ^ 0x1))
    srh_pkt = srh.build_srh()
    pkt5 = (
        Ether(src=SRC_MAC, dst=DST_MAC, type=0x86DD) /
        ipv6 /
        srh_pkt /
        Raw(load=epic_pkt) /
        Raw(load=marker5)
    )

    try:
        send_and_expect(pkt5, marker5, False, drop_sniff, "BAD_SEGID", "05_bad_segid")
        print("✅ [PASS] BAD_SEGID drops")
        valid_tests += 1
    except AssertionError as e:
        if(PRINT_ERRORS):
            print(f"Error:\n{'`'*10}\n{str(e)}\n{'`'*10}\n")
        print("❌ [FAIL] BAD_SEGID did not drop as expected")
    
    # 6) BAD_SEGLEFT
    marker6 = b"T_BAD_SEGLEFT_" + struct.pack("!I", (int(time.time()) + 4) & 0xFFFFFFFF)
    epic.pkt_ts = epic.pkt_ts + 1; epic_pkt = epic.build_epic()
    srh_pkt = srh.build_srh(segleft_override=True)
    pkt6 = (
        Ether(src=SRC_MAC, dst=DST_MAC, type=0x86DD) /
        ipv6 /
        srh_pkt /
        Raw(load=epic_pkt) /
        Raw(load=marker6)
    )

    try:
        send_and_expect(pkt6, marker6, False, drop_sniff, "BAD_SEGLEFT", "06_bad_segleft")
        print("✅ [PASS] BAD_SEGLEFT drops")
        valid_tests += 1
    except AssertionError as e:
        if(PRINT_ERRORS):
            print(f"Error:\n{'`'*10}\n{str(e)}\n{'`'*10}\n")
        print("❌ [FAIL] BAD_SEGLEFT did not drop as expected")

    # 7) BAD_ING_PORT: EPIC says ingress_if=1 but we inject on port 0
    #    This should be dropped if your P4 enforces:
    #      if(ig_intr_md.ingress_port != hdr.epic_per_hop.ingress_if) drop;
    marker7 = b"T_BAD_INGPORT_" + struct.pack("!I", (int(time.time()) + 5) & 0xFFFFFFFF)
    epic.pkt_ts = epic.pkt_ts + 1; epic_pkt = epic.build_epic(ingress_port_override=1)
    srh_pkt = srh.build_srh()
    pkt7 = (
        Ether(src=SRC_MAC, dst=DST_MAC, type=0x86DD) /
        ipv6 /
        srh_pkt /
        Raw(load=epic_pkt) /
        Raw(load=marker7)
    )

    try:
        send_and_expect(pkt7, marker7, False, drop_sniff, "BAD_ING_PORT", "07_bad_ing_port")
        print("✅ [PASS] BAD_ING_PORT drops")
        valid_tests += 1
    except AssertionError as e:
        if(PRINT_ERRORS):
            print(f"Error:\n{'`'*10}\n{str(e)}\n{'`'*10}\n")
        print("❌ [FAIL] BAD_ING_PORT did not drop as expected")
    
    # 8) BAD_EG_PORT: EPIC says egress_if=4 but the hvf was calculated differently.
    marker8 = b"T_BAD_EGPORT_" + struct.pack("!I", (int(time.time()) + 5) & 0xFFFFFFFF)
    epic.pkt_ts = epic.pkt_ts + 1; epic_pkt = epic.build_epic(egress_port_override=4)
    srh_pkt = srh.build_srh()
    pkt8 = (
        Ether(src=SRC_MAC, dst=DST_MAC, type=0x86DD) /
        ipv6 /
        srh_pkt /
        Raw(load=epic_pkt) /
        Raw(load=marker8)
    )

    try:
        send_and_expect(pkt8, marker8, False, drop_sniff, "BAD_EG_PORT", "08_bad_eg_port")
        print("✅ [PASS] BAD_EG_PORT drops")
        valid_tests += 1
    except AssertionError as e:
        if(PRINT_ERRORS):
            print(f"Error:\n{'`'*10}\n{str(e)}\n{'`'*10}\n")
        print("❌ [FAIL] BAD_EG_PORT did not drop as expected")


    #9) HVF Reuse: 2 packets, same HVF but ts2 > ts1
    base = (int(time.time()) & 0xFFFFFFFF) + 100
    marker9_1 = b"T_HVF_REUSE_1_" + struct.pack("!I", base + 4)
    epic.pkt_ts = epic.pkt_ts + 1; epic_pkt = epic.build_epic()

    pkt9_1_hvf = epic.get_pkt_mac()
    pkt9_1 = (
        Ether(src=SRC_MAC, dst=DST_MAC, type=0x86DD) /
        ipv6 /
        srh_pkt /
        Raw(load=epic_pkt) /
        Raw(load=marker9_1)
    )

    marker9_2 = b"T_HVF_REUSE_2_" + struct.pack("!I", base + 4)
    epic.pkt_ts = epic.pkt_ts + 1; epic_pkt = epic.build_epic(hvf_override=pkt9_1_hvf)
    pkt9_2 = (
        Ether(src=SRC_MAC, dst=DST_MAC, type=0x86DD) /
        ipv6 /
        srh_pkt /
        Raw(load=epic_pkt) /
        Raw(load=marker9_1)
    )

    try:
        send_and_expect(pkt9_1, marker9_1, True, good_sniff, "HVF_REUSE_1", "09_HVF_1_PASS")
        print("Packet 1 forwarded (as expected) ...  ", end='\r')


        send_and_expect(pkt9_2, marker9_2, False, drop_sniff, "HVF_REUSE_2", "09_HVF_1_DROP")
        print("Packet 2 dropped (as expected) ...    ", end='\r')

        print("✅ [PASS] REUSE test: reused HVF with different timestamp dropped")
        valid_tests += 1
    except AssertionError as e:
        if PRINT_ERRORS:
            print(f"Error:\n{'`'*10}\n{str(e)}\n{'`'*10}\n")
        print("❌ [FAIL] REUSE test: reused HVF with different timestamp forwarded")


    #10) INCR_TS: Two packets with increasing timestamp
    base = (int(time.time()) & 0xFFFFFFFF) + 200

    marker10_1 = b"T_INCR_TS_1_" + struct.pack("!I", base)
    epic.pkt_ts = epic.pkt_ts + 20; epic_pkt = epic.build_epic()
    srh_pkt = srh.build_srh()
    pkt10_1 = (
        Ether(src=SRC_MAC, dst=DST_MAC, type=0x86DD) /
        ipv6 /
        srh_pkt /
        Raw(load=epic_pkt) /
        Raw(load=marker10_1)
    )

    marker10_2 = b"T_INCR_TS_2_" + struct.pack("!I", base + 1)
    epic.pkt_ts = epic.pkt_ts + 1; epic_pkt = epic.build_epic()
    pkt10_2 = (
        Ether(src=SRC_MAC, dst=DST_MAC, type=0x86DD) /
        ipv6 /
        srh_pkt /
        Raw(load=epic_pkt) /
        Raw(load=marker10_2)
    )

    try:
        # Origin #1
        send_and_expect(pkt10_1, marker10_1, True, good_sniff, "INCR_TS_1", "10_INCR_TS_1")

        # Origin #2 (different src and segid) with smaller timestamp
        send_and_expect(pkt10_2, marker10_2, True, good_sniff, "INCR_TS_2", "10_INCR_TS_1")

        print("✅ [PASS] Strictly increasing timestamp from the same PO")
        valid_tests += 1
    except AssertionError as e:
        if PRINT_ERRORS:
            print(f"Error:\n{'`'*10}\n{str(e)}\n{'`'*10}\n")
        print("❌ [FAIL] INCR_TS test faild ")
    

    #11) DUP/ORDERING: 5 packets, show both kinds of drop (smaller and equal)
    #    1st: forward (ts=t1)
    #    2nd: drop    (ts<t1)
    #    3rd: forward (ts>t1)
    #    4th: drop    (ts==t3)
    #    5th: drop    (ts<t3)
    base = (int(time.time()) & 0xFFFFFFFF) + 100
    srh_pkt = srh.build_srh()
    
    try:
        marker11_1 = b"T_DUP_1_" + struct.pack("!I", base)
        epic.pkt_ts = epic.pkt_ts + 10; epic_pkt = epic.build_epic()
        pkt11_1 = (
            Ether(src=SRC_MAC, dst=DST_MAC, type=0x86DD) /
            ipv6 /
            srh_pkt /
            Raw(load=epic_pkt) /
            Raw(load=marker11_1)
        )

        send_and_expect(pkt11_1, marker11_1, True, good_sniff, "DUP_1", "10_dup_1")
        print("Packet 1 forwarded ...", end='\r')

        marker11_2 = b"T_DUP_2_" + struct.pack("!I", base + 1)
        epic.pkt_ts = epic.pkt_ts - 5; epic_pkt = epic.build_epic()
        pkt11_2 = (
            Ether(src=SRC_MAC, dst=DST_MAC, type=0x86DD) /
            ipv6 /
            srh_pkt /
            Raw(load=epic_pkt) /
            Raw(load=marker11_2)
        )

        send_and_expect(pkt11_2, marker11_2, False, drop_sniff, "DUP_2_SMALLER", "10_dup_2_smaller")
        print("Packet 2 dropped (as expected) ...    ", end='\r')

        marker11_3 = b"T_DUP_3_" + struct.pack("!I", base + 2)
        epic.pkt_ts = epic.pkt_ts + 50; epic_pkt = epic.build_epic()
        pkt11_3 = (
            Ether(src=SRC_MAC, dst=DST_MAC, type=0x86DD) /
            ipv6 /
            srh_pkt /
            Raw(load=epic_pkt) /
            Raw(load=marker11_3)
        )

        send_and_expect(pkt11_3, marker11_3, True, good_sniff, "DUP_3_GREATER", "10_dup_3_greater")
        print("Packet 3 forwarded (as expected) ...  ", end='\r')

        marker11_4 = b"T_DUP_4_" + struct.pack("!I", base + 3)
        epic_pkt = epic.build_epic() # Unchanged timestamp
        pkt11_4 = (
            Ether(src=SRC_MAC, dst=DST_MAC, type=0x86DD) /
            ipv6 /
            srh_pkt /
            Raw(load=epic_pkt) /
            Raw(load=marker11_4)
        )

        send_and_expect(pkt11_4, marker11_4, False, drop_sniff, "DUP_4_EQUAL", "10_dup_4_equal")
        print("Packet 4 dropped (as expected) ...    ", end='\r')

        marker11_5 = b"T_DUP_5_" + struct.pack("!I", base + 4)
        epic.pkt_ts = epic.pkt_ts - 5; epic_pkt = epic.build_epic()
        pkt11_5 = (
            Ether(src=SRC_MAC, dst=DST_MAC, type=0x86DD) /
            ipv6 /
            srh_pkt /
            Raw(load=epic_pkt) /
            Raw(load=marker11_5)
        )

        send_and_expect(pkt11_5, marker11_5, False, drop_sniff, "DUP_5_SMALLER_AFTER_UPDATE", "10_dup_5_smaller_after")
        print("Packet 5 dropped (as expected) ...    ", end='\r')

        print("✅ [PASS] DUP test: smaller+equal timestamps drop, greater passes (5-step)")
        valid_tests += 1
    except AssertionError as e:
        if PRINT_ERRORS:
            print(f"Error:\n{'`'*10}\n{str(e)}\n{'`'*10}\n")
        print("❌ [FAIL] DUP 5-step test failed")


    #12) DIFF_PO: 2 packets, origin2 != origin1
    base = (int(time.time()) & 0xFFFFFFFF) + 200

    marker12_1 = b"T_PO_1_" + struct.pack("!I", base)
    epic.pkt_ts = epic.pkt_ts + 20; epic_pkt = epic.build_epic()
    srh_pkt = srh.build_srh()
    pkt12_1 = (
        Ether(src=SRC_MAC, dst=DST_MAC, type=0x86DD) /
        ipv6 /
        srh_pkt /
        Raw(load=epic_pkt) /
        Raw(load=marker12_1)
    )

    marker12_2 = b"T_PO_2_" + struct.pack("!I", base + 1)
    epic2 = EpicBuilder(epic.key0, epic.key1,
                        epic.src_as_host ^ 0x1010101010101010,
                        epic.segid ^ 0x1010,
                        epic.pkt_ts, # Same teimstamps
                        epic.path_ts ^ 0x10101010,
                        epic.per_hop_count, epic.epic_next_hdr, epic.ts_expiry, epic.ingress_port, epic.egress_port)

    epic2_pkt = epic2.build_epic()
    pkt12_2 = (
        Ether(src=SRC_MAC, dst=DST_MAC, type=0x86DD) /
        ipv6 /
        srh_pkt /
        Raw(load=epic2_pkt) /
        Raw(load=marker12_2)
    )

    try:
        # Origin #1
        send_and_expect(pkt12_1, marker12_1, True, good_sniff, "PO_1", "12_PO_1")
        print("First packet (PO_1) forwarded", end='\r')

        # Origin #2 (different src and segid) with smaller timestamp
        send_and_expect(pkt12_2, marker12_2, True, good_sniff, "PO_2", "12_PO_2")

        print("✅ [PASS] Different packet-origin allows equal timestamp (2-step)")
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
    parser.add_argument("--pcap-dir", type=str, default="../tmp/dualpipeds", help="Directory to save PCAP files")
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

    run_tests()
