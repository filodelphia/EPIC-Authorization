#include <core.p4>
#include <tna.p4>

// AES-128 MAC extern definition: key (128b), message (128b), output tag (32b)
extern aes128_mac_t {
    aes128_mac_t();

    void apply(in  bit<128> key,
               in  bit<128> msg,
               out bit<32>  mac);
}

const bit<64> K0 = 0x33323130_42413938; // example
const bit<64> K1 = 0x00000000_00000000; // pad or replace with your real key
const bit<128> AES_KEY = { K0, K1 };


// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
// Layer 2 definitions
const bit<16> TYPE_IPV6 = 0x86DD;

// Layer 3 definitions
const bit<8> HOPOPT = 0;
const bit<8> IPV6_ROUTE = 43;
const bit<8> IPV6_FRAG = 44;
const bit<8> ESP = 50;
const bit<8> AH = 51;
const bit<8> IPV6_OPTS = 60;
const bit<8> MOBILITY_HEADER = 135;
const bit<8> HIP = 139;
const bit<8> SHIM6 = 140;
const bit<8> BIT_EMU = 147;
const bit<8> EPIC = 253;

#ifndef MAX_SRV6_SEGMENTS
    #define MAX_SRV6_SEGMENTS 10
#endif

#ifndef IPV6_EXTENSION_HEADER_SIZE
    #define IPV6_EXTENSION_HEADER_SIZE 8
#endif

const bit<32> PATH_DELTA = 32w7200; // 2 hours stored as seconds in 32bit integer


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;

// Layer 2 headers
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

// IPv6 header
header ipv6_t {
    bit<4> version;
    bit<8> traffClass;
    bit<20> flowLabel;
    bit<16> payloadLen;
    bit<8> nextHeader;
    bit<8> hoplim;
    bit<128> srcAddr;
    bit<128> dstAddr;
}

// IPv6 extension header structure
header ipv6_ext_base_t {
    bit<8> nextHeader;
    bit<8> hdrExtLen;
    varbit<16320> data; // Maximum size is 255 octets => 8 * 255 = 2040 bytes = 16'320bits
}

header ipv6_ext_fixed_t {
    bit<8> nextHeader;
    bit<8> hdrExtLen;
}

// Routing extension header
header route_base_t {
    bit<8>  nextHeader;
    bit<8>  headerLength;   // Length in 8-octet units, minus first 8 octets
    bit<8>  routingType;
    bit<8>  segmentsLeft;   // Index (0..N-1) of the next segment to process
    bit<8>   last_entry;
    bit<8>   flags;
    bit<16>  tag;
}

header route_segment_list_entry_t {
    bit<128> address;
}

// EPIC Headers
header epic_t {
    bit<64> src_as_host;
    bit<64> packet_ts;
    bit<32> path_ts;

    bit<8> per_hop_count;       // Used to loop (with recursion) over the hop validations 
    bit<8> nextHeader;          // Added nextHeader to the paper implementation
    // destination validation is unused in l1
}

header epic_per_hop_t {
    bit<24> hop_validation;
    bit<16> segment_id;
}

// Metadata
struct ig_metadata_t {
    bit<4> ext_idx;
    bit<8> segment_list_count;

    // AES-MAC related metadata
    bit<128> mac_key;   // key used by AES extern
    bit<128> mac_msg;   // message block to MAC
    bit<32>  mac_out;   // AES-MAC output
}

struct eg_metadata_t { }

// Headers
struct headers_t {
    // Layer 2 headers
    ethernet_t ethernet;

    // IPv6 headers
    ipv6_t ipv6;

    // IPv6 extensions
    ipv6_ext_base_t[IPV6_EXTENSION_HEADER_SIZE] ipv6_ext_base_before_SR;
    ipv6_ext_base_t[IPV6_EXTENSION_HEADER_SIZE] ipv6_ext_base_after_SR;

    // Route headers
    route_base_t route_header;
    route_segment_list_entry_t[MAX_SRV6_SEGMENTS] segment_list;

    // EPIC headers
    epic_t epic;
    epic_per_hop_t epic_per_hop;
}


/*************************************************************************/
/**************************  P A R S E R  ********************************/
/*************************************************************************/

// Tofino Ingress parser
parser TofinoIngressParser(
    packet_in packet,
    inout ig_metadata_t ig_md,
    out ingress_intrinsic_metadata_t ig_intr_md) {
        state start {
            packet.extract(ig_intr_md);
            transition select(ig_intr_md.resubmit_flag){
                1 : parse_resubmit;
                0 : parse_port_metadata;
            }
        }

        state parse_resubmit {
            // Parse resubmitted packet
            packet.advance(64);
            transition accept;
        }

        state parse_port_metadata {
            packet.advance(64); //tofino 1 port metadata size
            transition accept;
        }
}

// Switch parser
parser IngressParser(
                packet_in packet,
                out headers_t hdr,
                inout ig_metadata_t ig_md,
                out ingress_intrinsic_metadata_t ig_intr_md) {
    
    TofinoIngressParser tof_ingress_parser();

    state start {
        tof_ingress_parser.apply(packet, ig_md, ig_intr_md)    
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition parse_ipv6;
    }

    state parse_ipv6{
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextHeader){
            IPV6_ROUTE: parse_route;
            EPIC: parse_epic;
            default: parse_ipv6_ext_chain_before_SR;
        }
    }

    state parse_route {
        packet.extract(hdr.route_header);
 
        transition select((hdr.route_header.headerLength / 2) > MAX_SRV6_SEGMENTS) {
            true: reject;
            false: parse_route_list;
        }
    }

    state parse_route_list {
        packet.extract(hdr.segment_list, (bit<32>) (hdr.route_header.headerLength / 2));

        ig_md.segment_list_count = hdr.segment_list.lastIndex + 1;
        ig_md.ext_idx = 0;

        transition select(hdr.route_header.nextHeader){
            EPIC: parse_epic;
            default: parse_ipv6_ext_chain_after_SR;
        }
    }

    state parse_ipv6_ext_chain_before_SR {
        ipv6_ext_fixed_t peek;
        packet.lookahead(peek); // does not advance cursor

        bit<32> len_bytes = ((bit<32>)(peek.hdrExtLen + 1)) * 8; // RFC: units of 8 bytes
        // We already account for the fixed first 2 bytes because the varbit header extracts total length
        // Define ipv6_ext_base_t so its varbit 'data' absorbs len_bytes - 2
        
        packet.extract(hdr.ipv6_ext_base_before_SR[ig_md.ext_idx], len_bytes * 8);
        hdr.ipv6_ext_base_before_SR[ig_md.ext_idx].setValid();
        ig_md.ext_idx = ig_md.ext_idx + 1;

        transition select(peek.nextHeader) {
            HOPOPT: parse_ipv6_ext_chain_before_SR;
            IPV6_ROUTE: parse_route;
            IPV6_FRAG: parse_ipv6_ext_chain_before_SR;
            ESP: parse_ipv6_ext_chain_before_SR;
            AH: parse_ipv6_ext_chain_before_SR;
            IPV6_OPTS: parse_ipv6_ext_chain_before_SR;
            MOBILITY_HEADER: parse_ipv6_ext_chain_before_SR;
            HIP: parse_ipv6_ext_chain_before_SR;
            SHIM6: parse_ipv6_ext_chain_before_SR;
            BIT_EMU: parse_ipv6_ext_chain_before_SR;

            // parse epic
            EPIC: parse_epic;

            default: accept;
        }
    }

    state parse_ipv6_ext_chain_after_SR {
        ipv6_ext_fixed_t peek;
        packet.lookahead(peek); // does not advance cursor

        bit<32> len_bytes = ((bit<32>)(peek.hdrExtLen + 1)) * 8; // RFC: units of 8 bytes
        // We already account for the fixed first 2 bytes because the varbit header extracts total length
        // Define ipv6_ext_base_t so its varbit 'data' absorbs len_bytes - 2
        
        packet.extract(hdr.ipv6_ext_base_after_SR[ig_md.ext_idx], len_bytes * 8);
        hdr.ipv6_ext_base_after_SR[ig_md.ext_idx].setValid();
        ig_md.ext_idx = ig_md.ext_idx + 1;

        transition select(peek.nextHeader) {
            HOPOPT: parse_ipv6_ext_chain_after_SR;
            IPV6_FRAG: parse_ipv6_ext_chain_after_SR;
            ESP: parse_ipv6_ext_chain_after_SR;
            AH: parse_ipv6_ext_chain_after_SR;
            IPV6_OPTS: parse_ipv6_ext_chain_after_SR;
            MOBILITY_HEADER: parse_ipv6_ext_chain_after_SR;
            HIP: parse_ipv6_ext_chain_after_SR;
            SHIM6: parse_ipv6_ext_chain_after_SR;
            BIT_EMU: parse_ipv6_ext_chain_after_SR;

            // parse epic
            EPIC: parse_epic;

            default: accept;
        }
    }

    state parse_epic {
        packet.extract(hdr.epic);

        transition select(hdr.epic.per_hop_count){
            0: reject; // Checks the validity of the EPIC header
            default: parse_epic_hop;
        }
    }

    state parse_epic_hop {
        packet.extract(hdr.epic_per_hop);
        transition accept;
    }
}


// Tofino egress parser
parser TofinoEgressParser (
    packet_in packet,
    out egress_intrinsic_metadata_t eg_intr_md){

        state start {
            packet.extract(eg_intr_md);
            transition accept;
        }

}


// Egress parser
parser EgressParser(packet_in packet,
					out headers_t hdr,
					out egress_intrinsic_metadata_t eg_intr_md ){

    TofinoEgressParser tofino_egress;

	bit<4> eg_ext_idx;   // local index for ext headers

    state start {
        tofino_egress.apply(packet, eg_intr_md);
		eg_ext_idx = 0;
        transition parse_ethernet;
    }

	state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition parse_ipv6;
    }

    state parse_ipv6{
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextHeader){
            IPV6_ROUTE: parse_route;
            EPIC: parse_epic;
            default: parse_ipv6_ext_chain_before_SR;
        }
    }

    state parse_route {
        packet.extract(hdr.route_header);
 
        transition select((hdr.route_header.headerLength / 2) > MAX_SRV6_SEGMENTS) {
            true: reject;
            false: parse_route_list;
        }
    }

    state parse_route_list {
        packet.extract(hdr.segment_list, (bit<32>) (hdr.route_header.headerLength / 2));

        transition select(hdr.route_header.nextHeader){
            EPIC: parse_epic;
            default: parse_ipv6_ext_chain_after_SR;
        }
    }

    state parse_ipv6_ext_chain_before_SR {
        ipv6_ext_fixed_t peek;
        packet.lookahead(peek); // does not advance cursor

        bit<32> len_bytes = ((bit<32>)(peek.hdrExtLen + 1)) * 8; // RFC: units of 8 bytes
        // We already account for the fixed first 2 bytes because the varbit header extracts total length
        // Define ipv6_ext_base_t so its varbit 'data' absorbs len_bytes - 2
        
        packet.extract(hdr.ipv6_ext_base_before_SR[eg_ext_idx], len_bytes * 8);
        hdr.ipv6_ext_base_before_SR[eg_ext_idx].setValid();
        eg_ext_idx = eg_ext_idx + 1;

        transition select(peek.nextHeader) {
            HOPOPT: parse_ipv6_ext_chain_before_SR;
            IPV6_ROUTE: parse_route;
            IPV6_FRAG: parse_ipv6_ext_chain_before_SR;
            ESP: parse_ipv6_ext_chain_before_SR;
            AH: parse_ipv6_ext_chain_before_SR;
            IPV6_OPTS: parse_ipv6_ext_chain_before_SR;
            MOBILITY_HEADER: parse_ipv6_ext_chain_before_SR;
            HIP: parse_ipv6_ext_chain_before_SR;
            SHIM6: parse_ipv6_ext_chain_before_SR;
            BIT_EMU: parse_ipv6_ext_chain_before_SR;

            // parse epic
            EPIC: parse_epic;

            default: accept;
        }
    }

    state parse_ipv6_ext_chain_after_SR {
        ipv6_ext_fixed_t peek;
        packet.lookahead(peek); // does not advance cursor

        bit<32> len_bytes = ((bit<32>)(peek.hdrExtLen + 1)) * 8; // RFC: units of 8 bytes
        // We already account for the fixed first 2 bytes because the varbit header extracts total length
        // Define ipv6_ext_base_t so its varbit 'data' absorbs len_bytes - 2
        
        packet.extract(hdr.ipv6_ext_base_after_SR[eg_ext_idx], len_bytes * 8);
        hdr.ipv6_ext_base_after_SR[eg_ext_idx].setValid();
        eg_ext_idx = eg_ext_idx + 1;

        transition select(peek.nextHeader) {
            HOPOPT: parse_ipv6_ext_chain_after_SR;
            IPV6_FRAG: parse_ipv6_ext_chain_after_SR;
            ESP: parse_ipv6_ext_chain_after_SR;
            AH: parse_ipv6_ext_chain_after_SR;
            IPV6_OPTS: parse_ipv6_ext_chain_after_SR;
            MOBILITY_HEADER: parse_ipv6_ext_chain_after_SR;
            HIP: parse_ipv6_ext_chain_after_SR;
            SHIM6: parse_ipv6_ext_chain_after_SR;
            BIT_EMU: parse_ipv6_ext_chain_after_SR;

            // parse epic
            EPIC: parse_epic;

            default: accept;
        }
    }

    state parse_epic {
        packet.extract(hdr.epic);

        transition select(hdr.epic.per_hop_count){
            0: reject; // Checks the validity of the EPIC header
            default: parse_epic_hop;
        }
    }

    state parse_epic_hop {
        packet.extract(hdr.epic_per_hop);
        transition accept;
    }
}

/*************************************************************************/
/*****************  I N G R E S S   P R O C E S S I N G  *****************/
/*************************************************************************/

control Ingress(inout headers_t hdr,
                inout ig_metadata_t ig_md,
                in ingress_intrinsic_metadata_t ig_intr_md,
                in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dpr_md,
                inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    // Extern instance
    aes128_mac_t epic_aes_mac;

    action drop() { ig_dpr_md.drop_ctl = 0x1; }
    action nop() { }

    action epic_mac_compute() {
        // 1. Load key (global for now; can later be table-driven)
        ig_md.mac_key = AES_EPIC_KEY;

        /* 2. 128-bit message block
         *  (symmetric with HalfSipHash):
         *   upper 64 bits = src_as_host
         *   lower 64 bits = packet_ts
        */
        // This can be extended as needed.
        ig_md.mac_msg = { hdr.epic.src_as_host, hdr.epic.packet_ts };

        // 3. Call AES extern
        epic_aes_mac.apply(ig_md.mac_key, ig_md.mac_msg, ig_md.mac_out);
    }

    //******************** IP based forwarding ***************************//
    action ipv6_forward(bit<9> port){
        hdr.ipv6.hoplim = hdr.ipv6.hoplim - 1;
        ig_tm_md.ucast_egress_port = port;
    }

    //******************** Routing header forwarding ***************************//
    action nextDestination() {
        bit<8> index = ig_md.segment_list_count - hdr.route_header.segmentsLeft;
        hdr.ipv6.dstAddr = hdr.segment_list[index].address;
        hdr.route_header.segmentsLeft = hdr.route_header.segmentsLeft - 1;
    }

    // IPv6 table
    table ipv6_forwarding {
        key = {
            hdr.ipv6.dstAddr: lpm;
        }

        actions = {
            ipv6_forward;
            drop;
        }

        size = 2048;
        default_action = drop();
    }

    // Routing table
    table sr_forwarding {
        key = {
            hdr.ipv6.dstAddr: exact;
        }

        actions = {
            nextDestination;
            nop;
        }

        size = 1024;
        default_action = nop();
    }

    apply {
        if(hdr.epic.isValid()){
            // Here calculate MAC withn extern and verify
            epic_mac_compute();
            
            bit<24> expected = ig_md.mac_out[23:0];
            if (expected != hdr.epic_per_hop.hop_validation) {
                ig_dpr_md.drop_ctl = 1;
                return ;
            }


            // Check timestamp
			bit<64> pkt_ts  = hdr.epic.packet_ts;
			bit<64> path_ts = (bit<64>) hdr.epic.path_ts;
			bit<64> delta   = (bit<64>) PATH_DELTA;

			// If the sip_meta is not valid, it's the last recirculation!
		    if(!(pkt_ts >= path_ts && (pkt_ts - path_ts) <= delta)){
		    	ig_dpr_md.drop_ctl = 1; // drop packet
		    	return;
		    }


            // This was the last 
			if(hdr.epic.per_hop_count > 1) {
				hdr.epic.per_hop_count = hdr.epic.per_hop_count - 1;
			} else {
				if(hdr.ipv6.nextHeader == EPIC) {
					hdr.ipv6.nextHeader = hdr.epic.nextHeader;
				} else if(ig_md.ext_idx == 0){
					hdr.route_header.nextHeader = hdr.epic.nextHeader;
				} else {
					hdr.ipv6_ext_base_after_SR[ig_md.ext_idx - 1].nextHeader = hdr.epic.nextHeader;
				}

				hdr.epic.setInvalid();
			}
        }

        // Packet forwarding
		if(hdr.ipv6.isValid()) {
			ipv6_forwarding.apply();
			
			if(hdr.route_header.isValid() && hdr.route_header.segmentsLeft > 0) {
				sr_forwarding.apply();
			}
		}
    }
}

/*************************************************************************/
/****************  E G R E S S   P R O C E S S I N G   *******************/
/*************************************************************************/

control Egress(inout headers_t hdr,
			   inout eg_metadata_t eg_md,
			   in egress_intrinsic_metadata_t eg_intr_md,
			   in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
			   inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
			   inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {

	apply {

	}
}

/*************************************************************************/
/***********************  D E P A R S E R  *******************************/
/*************************************************************************/

control IngressDeparser(
		packet_out packet,
		inout headers_t hdr,
		in ig_metadata_t ig_md,
		in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {
	apply {
		packet.emit(hdr.ethernet);
		packet.emit(hdr.ipv6);

        // IPv6 extension headers
        packet.emit(hdr.ipv6_ext_base_before_SR);

        // Route header
        packet.emit(hdr.route_header);
        packet.emit(hdr.segment_list);

        // IPv6 extension headers
        packet.emit(hdr.ipv6_ext_base_after_SR);

		if(hdr.epic.isValid()) packet.emit(hdr.epic);
		/*
         * The `epic_per_hop` header is never emitted since, once it's used, it will never be used by the subsenquent routers and
         * not emitting it will save space/time, especially for fast connections.
        */
	}
}

control EgressDeparser(
		packet_out packet,
		inout headers_t hdr,
		in eg_metadata_t eg_md,
		in egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr) {
	
    apply {
		packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv6);

        // IPv6 extension headers
        packet.emit(hdr.ipv6_ext_base_before_SR);

        // Route header
        packet.emit(hdr.route_header);
        packet.emit(hdr.segment_list);

        // IPv6 extension headers
        packet.emit(hdr.ipv6_ext_base_after_SR);

		if(hdr.epic.isValid()) packet.emit(hdr.epic);
		/*
         * The `epic_per_hop` header is never emitted since, once it's used, it will never be used by the subsenquent routers and
         * not emitting it will save space/time, especially for fast connections.
        */
	}
}

/*************************************************************************/
/**************************  S W I T C H  ********************************/
/*************************************************************************/

Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;
