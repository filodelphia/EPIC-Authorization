import struct
from typing import Optional
from scapy.layers.inet6 import IPv6, IPv6ExtHdrSegmentRouting

from include.halfsiphash import halfsiphash_2_4_32, swap16_halves, u24

def compute_hop_mac(key0, key1, path_ts: int, tsexp: int, ing_port: int, eg_port: int, segid: int) -> int:
    m0 = path_ts & 0xFFFFFFFF
    m1 = ((ing_port & 0xFF) << 24) | ((eg_port & 0xFF) << 16) | (segid & 0xFFFF)
    m2 = ((tsexp & 0xFF) << 24)
    m3 = 0
    return halfsiphash_2_4_32(key0, key1, [m0, m1, m2, m3])


def compute_pkt_mac24(src_as_host: int, pkt_ts: int, hop_mac: int) -> int:
    src_hi = (src_as_host >> 32) & 0xFFFFFFFF
    src_lo = src_as_host & 0xFFFFFFFF
    ts_hi  = (pkt_ts >> 32) & 0xFFFFFFFF
    ts_lo  = pkt_ts & 0xFFFFFFFF

    k0 = hop_mac & 0xFFFFFFFF
    k1 = swap16_halves(hop_mac) & 0xFFFFFFFF

    mac32 = halfsiphash_2_4_32(k0, k1, [src_hi, src_lo, ts_hi, ts_lo])
    return u24(mac32)

class EpicBuilder:
    key0 = None
    key1 = None
    src_as_host = None
    segid = None
    pkt_ts = None
    path_ts = None
    per_hop_count = None
    epic_next_hdr = None
    ts_expiry = None
    ingress_port = None
    egress_port = None

    __hvf24 = None

    def __init__(self,
                 key0, key1, src_as_host,
                 segid, pkt_ts, path_ts, 
                 per_hop_count, epic_next_hdr,
                 ts_expiry, ingress_port, egress_port):

        self.key0 = key0
        self.key1 = key1
        self.src_as_host = src_as_host
        self.segid = segid
        self.pkt_ts = pkt_ts
        self.path_ts = path_ts
        self.per_hop_count = per_hop_count
        self.epic_next_hdr = epic_next_hdr
        self.ts_expiry = ts_expiry
        self.ingress_port = ingress_port
        self.egress_port = egress_port
        
        pass

    def pack_epic_fixed(self):
        epic_h = struct.pack("!QQIBB",
                            self.src_as_host & 0xFFFFFFFFFFFFFFFF,
                            self.pkt_ts & 0xFFFFFFFFFFFFFFFF,
                            self.path_ts & 0xFFFFFFFF,
                            self.per_hop_count & 0xFF,
                            self.epic_next_hdr & 0xFF)
        return epic_h

    def pack_epic_perhop(self):
        per_hop = struct.pack("!BBBH",
                          self.ts_expiry & 0xFF,
                          self.ingress_port & 0xFF,
                          self.egress_port & 0xFF,
                          self.segid & 0xFFFF)
        
        per_hop += (self.__hvf24 & 0xFFFFFF).to_bytes(3, "big")
        return per_hop
    
    def get_pkt_mac(self):
        hop_mac = compute_hop_mac(self.key0, self.key1, self.path_ts,
                                  self.ts_expiry, self.ingress_port,
                                  self.egress_port, self.segid)

        # Update __hvf24
        self.__hvf24 = compute_pkt_mac24(self.src_as_host, self.pkt_ts, hop_mac)
        return self.__hvf24



    def build_epic(self,
                     src_override: Optional[int] = None,
                     segid_override: Optional[int] = None,
                     hvf_override: Optional[int] = None,
                     ingress_port_override: Optional[int] = None,
                     egress_port_override: Optional[int] = None,
                     per_hop_count_override: Optional[int] = None):
        
        
        # ------------------------- BAD values override -------------------------
        if hvf_override is None: self.get_pkt_mac()
        else: self.__hvf24 = hvf_override & 0xFFFFFF
        
        if per_hop_count_override is not None:
            per_hop_count_restore = self.per_hop_count
            self.per_hop_count = per_hop_count_override

        if ingress_port_override is not None:
            ig_port_restore = self.ingress_port
            self.ingress_port = ingress_port_override
        
        if egress_port_override is not None:
            egress_port_restore = self.egress_port
            self.egress_port = egress_port_override

        if src_override is not None:
            src_restore = self.src_as_host
            self.src_as_host = src_override

        if segid_override is not None:
            segid_restore = self.segid
            self.segid = segid_override
        # -----------------------------------------------------------------------
        
        fixed_bytes = self.pack_epic_fixed()
        per_hop = self.pack_epic_perhop()

        # ------------------------- BAD values restore ------------------------
        if per_hop_count_override is not None:
            self.per_hop_count = per_hop_count_restore
        
        if ingress_port_override is not None:
            self.ingress_port = ig_port_restore

        if egress_port_override is not None:
            self.egress_port = egress_port_restore

        if src_override is not None:
            self.src_as_host = src_restore

        if segid_override is not None:
            self.segid = segid_restore
        # -----------------------------------------------------------------------

        epic = fixed_bytes + per_hop

        # I-based next hops
        if(self.per_hop_count != 1):
            ts_expiry_restore = self.ts_expiry
            segid_restore = self.segid
            egress_port_restore = self.egress_port
            ingress_port_restore = self.ingress_port

            for i in range(self.per_hop_count):
                self.ts_expiry = i+1
                self.segid = i+1
                self.egress_port = i+1
                self.ingress_port = i+1

                epic += self.pack_epic_perhop()
            
            # Restoring after mock next-hops
            self.ts_expiry = ts_expiry_restore
            self.segid = segid_restore
            self.egress_port = egress_port_restore
            self.ingress_port = ingress_port_restore

        return epic


    def pack_epic_perhop(self):
        per_hop = struct.pack("!BBBH",
                          self.ts_expiry & 0xFF,
                          self.ingress_port & 0xFF,
                          self.egress_port & 0xFF,
                          self.segid & 0xFFFF)
        
        per_hop += (self.__hvf24 & 0xFFFFFF).to_bytes(3, "big")
        return per_hop

class SRHBuilder:
    sid_list = None
    nextHeader = None
    last_entry = None

    def __init__(self, sid_list, nextHeader):
        self.sid_list = sid_list
        self.last_entry = len(self.sid_list) - 1
        self.nextHeader = nextHeader
        pass

    def build_srh(self, segleft_override: Optional[bool] = None):
        if segleft_override is None: segleft = len(self.sid_list) - 1
        else: segleft = len(self.sid_list) + 5

        srh = IPv6ExtHdrSegmentRouting(nh=self.nextHeader)
        srh.addresses = self.sid_list
        srh.lastentry = self.last_entry
        srh.segleft   = segleft

        return srh


if __name__ == '__main__':
    print("This is a module, not a standalone script.")
    exit(1)