#!/usr/bin/env python3
"""
epic-pcr.py


Allows to create, send and recieve IPv6 packets with Segment Routing Header (SRH)
and a custom EPIC L1 header.

Usage examples:
  sudo python3 epic_send_recv.py -I eth0 -S 2001:db8::1 --hops 2001:db8::2,2001:db8::3 --count 5
  sudo python3 epic_send_recv.py --listen -I eth0
"""

import argparse
import time
import random
from scapy.all import (
    Packet, BitField, ShortField, IntField, LongField, ByteField,
    PacketListField, bind_layers, IPv6, IPv6ExtHdrSegmentRouting,
    Raw, send, sniff, conf
)

# ----------------------------
# Custom EPIC L1 per-hop packet
# ----------------------------
class EPICPerHop(Packet):
    name = "EPICPerHop"
    # hop_validation: 24 bits, segment_id: 16 bits
    fields_desc = [
        BitField("hop_validation", 0, 24),  # 3 bytes
        ShortField("segment_id", 0)        # 2 bytes
    ]

    def guess_payload_class(self, payload):
        return Raw

# ----------------------------
# Custom EPIC L1 header packet
# ----------------------------
class EPIC_L1(Packet):
    name = "EPIC_L1"
    # Based on the defined structure:
    # bit<32> path_ts;
    # bit<64> src_as_host;
    # bit<64> packet_ts;
    # bit<8> per_hop_count;
    # bit<8> nextHeader;
    # followed by per-hop entries (epicl1_per_hop_t) list

    fields_desc = [
        IntField("path_ts", 0),
        LongField("src_as_host", 0),
        LongField("packet_ts", 0),
        ByteField("per_hop_count", 0),
        ByteField("nextHeader", 59),  # default No Next Header (59) unless user sets
        # PacketListField will parse the rest as EPICPerHop items based on per_hop_count
        PacketListField("per_hops", [], EPICPerHop,
                        count_from=lambda pkt: pkt.per_hop_count)
    ]

    def extract_padding(self, s):
        # Everything after the per_hops is payload
        return b"", s

# Bindings: we'll let user place EPIC after Segment Routing header (SRH).
# There isn't a "standard" next header number for EPIC, so we'll let the user stack it manually.
# However for scapy parsing convenience we bind EPIC_L1 as payload after SRH when next header == 4's next.
# (No automatic numeric binding here; packet stack will be IPv6 / IPv6ExtHdrSegmentRouting / EPIC_L1 / payload)
# No bind_layers call strictly required for this custom header; scapy will leave it as Raw unless we construct it explicitly.


# ----------------------------
# Helpers
# ----------------------------
def make_per_hop_entries(hops_segment_ids, hop_validations=None):
    """
    Return a list of EPICPerHop objects.

    hops_segment_ids: list of integers (segment IDs) or list of IPv6 addresses (we'll keep numeric IDs)
    hop_validations: optional list of integers (24-bit), same length as hops_segment_ids
    """
    entries = []
    n = len(hops_segment_ids)
    if hop_validations is None:
        hop_validations = [random.getrandbits(24) for _ in range(n)]
    for sid, hv in zip(hops_segment_ids, hop_validations):
        # Accept either integer segment_id or an IPv6 string (unlikely), cast to int if needed
        sid_int = int(sid) if isinstance(sid, (int, str)) and str(sid).isdigit() else int(sid) if isinstance(sid, int) else 0
        entries.append(EPICPerHop(hop_validation=hv & 0xFFFFFF, segment_id=sid_int & 0xFFFF))
    return entries

def build_epic_header(hops_segment_ids, path_ts=None, src_as_host=None, packet_ts=None, nextHeader=59, hop_validations=None):
    """
    Create an EPIC_L1 instance with per-hop entries.

    hops_segment_ids: list of integers (per-hop segment_id)
    """
    path_ts = int(path_ts or int(time.time()) & 0xFFFFFFFF)
    src_as_host = int(src_as_host or random.getrandbits(64))
    packet_ts = int(packet_ts or int(time.time() * 1000) & 0xFFFFFFFFFFFFFFFF)
    per_hop_count = len(hops_segment_ids)
    per_hops = make_per_hop_entries(hops_segment_ids, hop_validations=hop_validations)
    epic = EPIC_L1(path_ts=path_ts, src_as_host=src_as_host, packet_ts=packet_ts,
                   per_hop_count=per_hop_count, nextHeader=nextHeader, per_hops=per_hops)
    return epic

def build_ipv6_srh_packet(src, dst, segment_list, epic_header, payload=b"EPIC_TEST"):
    """
    Build an IPv6 packet with SRH and the custom EPIC header.

    segment_list: list of IPv6 addresses (strings). The SRH `segments` field typically stores the list of
                  segment addresses in reverse order (last element is current dest). For simplicity we will
                  put the list in the order you supply and set IPv6(dst) to the last segment.
    """
    if not segment_list:
        raise ValueError("segment_list must contain at least one IPv6 address")

    # IPv6 destination should be the last hop in the segment list.
    ipv6_dst = segment_list[-1]
    ipv6_pkt = IPv6(src=src, dst=ipv6_dst)

    # Create the SRH extension header (Scapy's IPv6ExtHdrSegmentRouting expects 'segments' list)
    srh = IPv6ExtHdrSegmentRouting(addresses=list(segment_list))

    # Stack: IPv6 / SRH / EPIC_L1 / Raw(payload)
    pkt = ipv6_pkt / srh / epic_header / Raw(load=payload)
    return pkt

# ----------------------------
# Sending and receiving helpers
# ----------------------------
def send_epic_packet(iface, src, hops, epic_segment_ids, count=1, payload=b"EPIC_TEST", verbose=True):
    """
    iface: interface to send from
    src: IPv6 source address
    hops: list of IPv6 addresses for SRH (segments)
    epic_segment_ids: list of integers for per-hop segment_id entries in EPIC header (length matches hops)
    """
    epic = build_epic_header(epic_segment_ids)
    pkt = build_ipv6_srh_packet(src, hops[-1], hops, epic, payload=payload)
    if verbose:
        print("== Packet to send ==")
        pkt.show()
        print("Sending %d packets on iface %s" % (count, iface))
    # send at layer 3 (Scapy's send will use routing and appropriate interface)
    # We force conf.iface for deterministic send on a specific iface.
    old_iface = conf.iface
    conf.iface = iface
    try:
        for _ in range(count):
            send(pkt, verbose=0)
            if verbose:
                print("sent one")
            time.sleep(0.1)
    finally:
        conf.iface = old_iface

def handle_packet(pkt):
    "Simple callback for sniff: print EPIC header if present"
    if EPIC_L1 in pkt:
        print("=== Received EPIC packet ===")
        pkt[EPIC_L1].show()
    else:
        # Try to detect raw bytes that might contain EPIC header after SRH
        # If SRH present and next payload left, try parsing EPIC from raw payload
        if IPv6ExtHdrSegmentRouting in pkt:
            raw = bytes(pkt[IPv6ExtHdrSegmentRouting].payload)
            try:
                # try to parse EPIC_L1 from raw payload
                parsed = EPIC_L1(raw)
                print("=== Heuristically parsed EPIC from SRH payload ===")
                parsed.show()
            except Exception:
                pass

def listen_epic(iface, timeout=None, count=0, filter_exp="ip6"):
    """
    Sniff on the given iface and call handle_packet for matching captures.
    """
    print(f"Listening on {iface} (filter={filter_exp}) timeout={timeout} count={count}")
    sniff(iface=iface, filter=filter_exp, prn=handle_packet, timeout=timeout, count=count)

# ----------------------------
# CLI
# ----------------------------
def parse_args():
    p = argparse.ArgumentParser(description="Send and receive IPv6 SRH + EPIC_L1 packets")
    p.add_argument("-I", "--iface", required=True, help="Interface to send/receive on (must be IPv6-capable)")
    p.add_argument("-S", "--src", help="Source IPv6 address", default=None)
    p.add_argument("--hops", help="Comma-separated list of IPv6 hops for SRH (at least 1)", default="")
    p.add_argument("--epic-ids", help="Comma-separated list of integer segment IDs for EPIC per-hop entries (same length as hops). If omitted will use 1..N", default="")
    p.add_argument("--count", type=int, default=1, help="Packets to send")
    p.add_argument("--payload", default="EPIC_TEST", help="Payload string")
    p.add_argument("--listen", action="store_true", help="Listen for EPIC packets (sniff) instead of sending")
    p.add_argument("--timeout", type=int, help="Sniff timeout seconds (only with --listen)")
    return p.parse_args()

def main():
    args = parse_args()
    if args.listen:
        listen_epic(args.iface, timeout=args.timeout)
        return

    if not args.hops:
        print("You must provide --hops when sending.")
        return

    hops = [h.strip() for h in args.hops.split(",") if h.strip()]
    if len(hops) == 0:
        print("No hops provided")
        return

    if args.epic_ids:
        epic_ids = [int(x) for x in args.epic_ids.split(",")]
        if len(epic_ids) != len(hops):
            print("Length of --epic-ids must match number of hops")
            return
    else:
        epic_ids = list(range(1, len(hops)+1))

    src = args.src or conf.route6.route(hops[-1])[0] if conf.route6 else None
    if not src:
        print("Provide -S or ensure IPv6 route resolution works.")
        return

    send_epic_packet(args.iface, src, hops, epic_ids, count=args.count, payload=args.payload.encode())

if __name__ == "__main__":
    main()
