#!/usr/bin/env python3
import struct
import time
import random
import os
from typing import Optional, List

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
PER_HOP_COUNT = 1
TSEXP     = 0x01
SID_LIST = ["2001:db8:0:1::1", "2001:db8:0:2::1"]
IPV6_NEXT_HEADER  = 43
SRH_NEXT_HEADER = 253
EPIC_NEXT_HDR = 59
SIP_KEY_0 = 0x33323130
SIP_KEY_1 = 0x42413938
PKT_TS = 0x1111111100000000
PCAP_DIR = "../tmp/hashcoll"
WRITE_PCAPS = True
PRINT_ERRORS = False

# Derived at runtime
INGRESS_IFACE = ""
EGRESS_IFACE  = ""
CLEAR_ETYPE = 0xEA06  # register-clear ethertype

# Benchmark controls
MAX_TRIALS = 200
RNG_SEED = 1
REG_SIZE = 4096
FINAL_TS32 = int(time.time()) & 0xFFFFFFFF


# -----------------------------
# Register reset packet builder (simple on purpose)
# -----------------------------
class RegisterResetBuilder:
    src_mac: str
    dst_mac: str
    ethertype: int = CLEAR_ETYPE

    def __init__(self, src, dst):
        self.src_mac = src
        self.dst_mac = dst

    def build(self, index: int):
        # 32-bit index in network byte order
        payload = struct.pack("!I", index & 0xFFFFFFFF)
        return Ether(src=self.src_mac, dst=self.dst_mac, type=self.ethertype) / Raw(load=payload)

    def clear_all(self, iface: str, reg_size: int, chunk: int = 256):
        burst = []
        for i in range(reg_size):
            burst.append(self.build(i))
            if len(burst) >= chunk:
                sendp(burst, iface=iface, verbose=False)
                burst.clear()
        if burst:
            sendp(burst, iface=iface, verbose=False)
        time.sleep(0.05)  # let the model drain


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
                    label: str):
    sn = _start_sniffer(sniff_ifaces, marker)

    # Always inject on INGRESS_PORT (port 0 -> veth0)
    sendp(pkt, iface=INGRESS_IFACE, verbose=False)

    time.sleep(SNIFF_TIMEOUT)
    pkts = sn.stop()

    if expect_forward and len(pkts) == 0:
        raise AssertionError(f"[{label}] Expected FORWARD, but marker not seen on {sniff_ifaces}")
    if (not expect_forward) and len(pkts) > 0:
        raise AssertionError(f"[{label}] Expected DROP, but marker seen on {sniff_ifaces} (count={len(pkts)})")
    
    return pkts


# -----------------------------
# Benchmark
# -----------------------------
def run_test():
    print(f"Injecting on port {INGRESS_PORT} ({INGRESS_IFACE}), expecting forward on port {EGRESS_PORT} ({EGRESS_IFACE})\n")
    good_sniff = [EGRESS_IFACE]

    # Replaced every new packet    SRC_AS_HOST, SEG_ID, PATH_TS
    epic = EpicBuilder(SIP_KEY_0, SIP_KEY_1, 0, 0, PKT_TS, 0, PER_HOP_COUNT, EPIC_NEXT_HDR, TSEXP, INGRESS_PORT, EGRESS_PORT)
    srh = SRHBuilder(SID_LIST, SRH_NEXT_HEADER)
    ipv6 = IPv6(src="2001:db8::100", dst=srh.sid_list[srh.last_entry], nh=IPV6_NEXT_HEADER)
    clear_reg = RegisterResetBuilder(SRC_MAC, DST_MAC)

    rng = random.Random(RNG_SEED + 1)

    j = 0
    pkts = list() 
    while j < MAX_TRIALS:
        j += 1

        clear_reg.clear_all(INGRESS_IFACE, REG_SIZE)
        pkts.clear()
    
        i_th = 0
        while True:
            i_th += 1

            base = (int(time.time()) & 0xFFFFFFFF) + 200
            srh_pkt = srh.build_srh()
            marker = b"T_PO_" + struct.pack("!I", i_th) + b"_" + struct.pack("!I", base)

            epic.src_as_host = rng.getrandbits(64)
            epic.segid = rng.getrandbits(16)
            epic.path_ts = rng.getrandbits(32)

            pkt_ts_hi = (PKT_TS >> 32) & 0xFFFFFFFF
            pkt_ts_lo = (FINAL_TS32 - epic.path_ts) & 0xFFFFFFFF
            epic.pkt_ts = (pkt_ts_hi << 32) | pkt_ts_lo
            epic_pkt = epic.build_epic()
            
            pkt = (
                Ether(src=SRC_MAC, dst=DST_MAC, type=0x86DD) /
                ipv6 /
                srh_pkt /
                Raw(load=epic_pkt) /
                Raw(load=marker)
            )

            try:
                packet = send_and_expect(pkt, marker, True, good_sniff, f"PO_{i_th}")
                pkts.extend(packet)
            except AssertionError as e:
                if PRINT_ERRORS:
                    print(f"Error:\n{'`'*10}\n{str(e)}\n{'`'*10}\n")
                print(f"❌ First hash collision on round {j} found at packet {i_th}")
                break
        
        if WRITE_PCAPS:
            os.makedirs(PCAP_DIR, exist_ok=True)
            wrpcap(os.path.join(PCAP_DIR, f"hashcoll_{j}.pcap"), pkts)
    

    if WRITE_PCAPS:
        print(f"PCAPs written under: {os.path.abspath(PCAP_DIR)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test script for EPIC P4 on Tofino Model")
    
    # Network Configuration
    parser.add_argument("--ingress", type=int, default=0, help="Ingress Tofino port ID (default: 0)")
    parser.add_argument("--egress", type=int, default=1, help="Expected Egress Tofino port ID (default: 1)")
    parser.add_argument("--timeout", type=float, default=1.2, help="Sniff timeout in seconds (default: 1.2)")
    parser.add_argument("--sid-list", type=str, nargs="+", default=["2001:db8:0:1::1", "2001:db8:0:2::1"], help="List of IPv6 SIDs")
    
    # MAC/Header Configuration
    parser.add_argument("--src-mac", type=str, default="02:00:00:00:00:01", help="Source MAC address")
    parser.add_argument("--dst-mac", type=str, default="02:00:00:00:00:02", help="Destination MAC address")
    parser.add_argument("--show-errors", action="store_true", dest="show_errors", help="Print error description if any occur")
    
    # HalfSipHash Keys
    parser.add_argument("--key0", type=lambda x: int(x, 0), default=0x33323130, help="SipHash Key 0 (32-bit hex)")
    parser.add_argument("--key1", type=lambda x: int(x, 0), default=0x42413938, help="SipHash Key 1 (32-bit hex)")
    
    # Logic / IO
    parser.add_argument("--pcap-dir", type=str, default="../tmp/hashcoll/", help="Directory to save PCAP files")
    parser.add_argument("--no-pcap", action="store_false", dest="write_pcaps", help="Disable PCAP writing")

    # Random
    default_seed = random.randrange(0, 2**32)
    parser.add_argument("--seed", type=int, default=default_seed)
    parser.add_argument("--max", type=int, default=200)

    # Hash collision
    parser.add_argument("--reg-size", type=int, default=4096, help="Duplicate-suppression register size")


    args = parser.parse_args()

    # Map args back to global variables used in the script
    INGRESS_PORT = args.ingress
    EGRESS_PORT  = args.egress
    SNIFF_TIMEOUT = args.timeout
    SRC_MAC = args.src_mac
    DST_MAC = args.dst_mac
    SID_LIST = args.sid_list
    SIP_KEY_0 = args.key0
    SIP_KEY_1 = args.key1
    PCAP_DIR = args.pcap_dir
    WRITE_PCAPS = args.write_pcaps
    PRINT_ERRORS = args.show_errors

    RNG_SEED = args.seed
    MAX_TRIALS = args.max
    REG_SIZE = args.reg_size

    # Initialize Interfaces
    INGRESS_IFACE = port_to_iface(INGRESS_PORT)
    EGRESS_IFACE  = port_to_iface(EGRESS_PORT)

    run_test()
