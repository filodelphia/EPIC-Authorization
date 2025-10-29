/* Definitions for implementing halfsiphash */
// supported input lengths: 2~8 words.
#ifndef NUM_WORDS
    #define NUM_WORDS 4
    #define NUM_WORDS_IG 2
    #define NUM_WORDS_EG 2
#endif
#if !((NUM_WORDS_IG+NUM_WORDS_EG==NUM_WORDS) && (NUM_WORDS_IG-NUM_WORDS_EG==0 || NUM_WORDS_IG-NUM_WORDS_EG==1 ))
	#error "Please set NUM_WORDS_IG to be floor((NUM_WORDS+1)/2) and NUM_WORDS_EG to be floor((NUM_WORDS)/2)."
#endif

#define SIP_PORT 5555
#define SIP_KEY_0 0x33323130
#define SIP_KEY_1 0x42413938

const bit<32> const_0 = 0;
const bit<32> const_1 = 0;
const bit<32> const_2 = 0x6c796765;
const bit<32> const_3 = 0x74656462;

#define ROUND_TYPE_COMPRESSION 0
#define ROUND_TYPE_FINALIZATION 1
#define ROUND_TYPE_END 2

#include "loops_macro.h"
#include <core.p4>
#include <tna.p4>

// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
// Layer 2 definitions
const bit<16> TYPE_IPV4 = 0x0800;
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

/* Labels for border policy */
#define WITHIN_AS 0
#define CROSSED_AS 1

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
header epicl1_t {
    bit<64> src_as_host;
    bit<64> packet_ts;
    bit<32> path_ts;

    bit<8> per_hop_count;       // Used to loop (with recursion) over the hop validations 
    bit<8> nextHeader;          // Added nextHeader to the paper implementation
    // destination validation is unused in l1
}

header epicl1_per_hop_t {
    bit<24> hop_validation;
    bit<16> segment_id;
}

// Halfsip-hash header
header sip_inout_h {
	#define vardef_m(i) bit<32> m_##i;
	__LOOP(NUM_WORDS, vardef_m)
}

header sip_meta_h {
	bit<32> v_0;
	bit<32> v_1;
	bit<32> v_2;
	bit<32> v_3;
	bit<8> curr_round;
}

header sip_tmp_h {
	bit<32> a_0;
	bit<32> a_1;
	bit<32> a_2;
	bit<32> a_3;
	bit<32> i_0;
	bit<32> i_1;
	bit<32> i_2;
	bit<32> i_3;
	bit<8> round_type;
}

// Metadata
struct ig_md_t {
    bit<64> key;

    bit<1> is_AS_ingress;
    bit<4> ext_idx;
    bit<8> segment_list_count;
    bit<24> calculated_mac;

    // Half-sip hash metadata
	bool recirc;
	bit<9> rnd_port_for_recirc;
	bit<1> rnd_bit;
	sip_tmp_h sip_tmp;
}

struct eg_md_t { sip_tmp_h sip_tmp; } // egress tmp state only

// Headers
struct headers_t {
    // Layer 2 headers
    ethernet_t ethernet;

    //HalfSipHash
    sip_inout_h sip;
	sip_meta_h sip_meta;

    // IPv6 headers
    ipv6_t ipv6;

    // IPv6 extensions
    ipv6_ext_base_t[IPV6_EXTENSION_HEADER_SIZE] ipv6_ext_base_before_SR;
    ipv6_ext_base_t[IPV6_EXTENSION_HEADER_SIZE] ipv6_ext_base_after_SR;

    // Route headers
    route_base_t route_header;
    route_segment_list_entry_t[MAX_SRV6_SEGMENTS] segment_list;

    // EPIC headers
    epicl1_t epic;
    epicl1_per_hop_t epic_per_hop;

    // HalfSip state as headers -- Parsed and emitted only during recirculation
    sip_inout_h sip;
    sip_meta_h  sip_meta;
}


/*************************************************************************/
/**************************  P A R S E R  ********************************/
/*************************************************************************/

// Tofino Ingress parser
parser TofinoIngressParser(
    packet_in packet,
    inout ig_md_t ig_md,
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
                inout ig_md_t ig_md,
                out ingress_intrinsic_metadata_t ig_intr_md) {
    
    TofinoIngressParser tof_ingress_parser();

    state start {
        tof_ingress_parser.apply(packet, ig_md, ig_intr_md)    
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            TYPE_IPV6: parse_ipv6;
            default: accept;
        }
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

        // TODO: Do the math for handling the number of segments in the header 
        transition select((hdr.route_header.headerLength / 128) > MAX_SRV6_SEGMENTS) {
            true: reject;
            false: parse_route_list;
        }
    }

    state parse_route_list {
        packet.extract(hdr.segment_list, (bit<32>) (hdr.route_header.headerLength / 2));

        meta.segment_list_count = hdr.segment_list.lastIndex + 1;
        meta.ext_idx = 0;

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
        
        packet.extract(hdr.ipv6_ext_base_before_SR[meta.ext_idx], len_bytes * 8);
        hdr.ipv6_ext_base_before_SR[meta.ext_idx].setValid();
        meta.ext_idx = meta.ext_idx + 1;

        transition select(temp.nextHeader) {
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
        
        packet.extract(hdr.ipv6_ext_base_after_SR[meta.ext_idx], len_bytes * 8);
        hdr.ipv6_ext_base_after_SR[meta.ext_idx].setValid();
        meta.ext_idx = meta.ext_idx + 1;

        transition select(temp.nextHeader) {
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
parser EgressParser(packet_in packet, out headers hdr, out egress_intrinsic_metadata_t eg_intr_md){
    TofinoEgressParser tofino_egress;

    state start {
        tofino_egress.apply(packet, eg_intr_md);
        transition accept;
    }
}

/*************************************************************************/
/*****************  I N G R E S S   P R O C E S S I N G  *****************/
/*************************************************************************/

control Ingress(inout headers_t hdr,
                inout ig_md_t ig_md,
                in ingress_intrinsic_metadata_t ig_intr_md,
                in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
                inout ingress_intrinsic_metadata_for_deprarser_t ig_dpr_md,
                inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    action drop() { ig_dpr_md.drop_ctl = 1; }

    //******************** IP based forwarding ***************************//
    action ipv6_forward(bit<9> port){
        hdr.ipv6.hoplim = hdr.ipv6.hoplim - 1;
        ig_tm_md.ucast_egress_port = port;
    }

    //******************** Routing header forwarding ***************************//
    action nextDestination() {
        bit<8> index = meta.segment_list_count - hdr.route_header.segmentsLeft;
        hdr.ipv6.dstAddr = hdr.segment_list[index].address;
        hdr.route_header.segmentsLeft = hdr.route_header.segmentsLeft - 1;
    }

    action mark_internal() { ig_md.is_AS_ingress = WITHIN_AS; }
    action mark_external() { ig_md.is_AS_ingress = CROSSED_AS; }

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
            NoAction;
        }

        size = 1024;
        default_action = NoAction();
    }

    // Verify AS ingress
    table AS_ports {
        key = {
            ig_intr_md.ingress_port: exact;
        }

        actions = {
            mark_internal;
            mark_external;
            NoAction;
        }

        size = 256;
        default_action = NoAction();
    }

    // EPIC tables
    table epic_authorization {
        key = {
            ig_md.calculated_mac: exact;
        }

        actions = {
            NoAction;
            drop;
        }

        size = 1024;
        default_action = drop();
    }

    /* -------- Random for recirculation, following Princeton implementation of Halfsip-hash -------- */
    Random<bit<1>>() rng;
    action get_rnd_bit() { ig_md.rnd_bit = rng.get(); }
    action route_to(bit<9> port) { ig_tm_md.ucast_egress_port = port; }
    action do_recirculate() { route_to(ig_md.rnd_port_for_recirc); }

    /* -------- Halfsip actions in INGRESS, Princeton implementation  -------- */
    action sip_init(bit<32> key_0, bit<32> key_1){
        hdr.sip_meta.v_0 = key_0 ^ const_0;
        hdr.sip_meta.v_1 = key_1 ^ const_1;
        hdr.sip_meta.v_2 = key_0 ^ const_2;
        hdr.sip_meta.v_3 = key_1 ^ const_3;
    }

    #define MSG_VAR_IG ig_md.sip_tmp.i_0
    action sip_1_odd() {
        hdr.sip_meta.v_3 = hdr.sip_meta.v_3 ^ MSG_VAR_IG;
    }

    action sip_1_a(){
        // a_0 = i_0 + i_1
        ig_md.sip_tmp.a_0 = hdr.sip_meta.v_0 + hdr.sip_meta.v_1;
        // a_2 = i_2 + i_3
        ig_md.sip_tmp.a_2 = hdr.sip_meta.v_2 + hdr.sip_meta.v_3;
        // a_1 = i_1 << 5
        @in_hash { ig_md.sip_tmp.a_1 = hdr.sip_meta.v_1[26:0] ++ hdr.sip_meta.v_1[31:27]; }
    }

    action sip_1_b(){
        // a_3 = i_3 << 8
        ig_md.sip_tmp.a_3 = hdr.sip_meta.v_3[23:0] ++ hdr.sip_meta.v_3[31:24];
    }

    action sip_2_a(){
        // b_1 = a_1 ^ a_0
        ig_md.sip_tmp.i_1 = hdr.sip_meta.a_1 ^ hdr.sip_meta.a_0;

        // b_3 = a_3 ^ a_2
        ig_md.sip_tmp.i_3 = hdr.sip_meta.a_3 ^ hdr.sip_meta.a_2;

        // b_0 = a_0 << 16
        ig_md.sip_tmp.i_0 = hdr.sip_meta.a_0[15:0] ++ hdr.sip_meta.a_0[31:16];

        // b_2 = a_2
        ig_md.sip_tmp.b_2 = hdr.sip_meta.a_2;
    }

    action sip_3_a(){
        // c_2 = b_2 + b_1
        ig_md.sip_tmp.a_2 = hdr.sip_meta.i_2 + hdr.sip_meta.i_1;

        // c_0 = b_0 + b_3
        ig_md.sip_tmp.a_0 = hdr.sip_meta.i_0 + hdr.sip_meta.i_3;

        // c_1 = b_1 << 13
        @in_hash { ig_md.sip_tmp.a_1 = hdr.sip_meta.i_1[18:0] ++ hdr.sip_meta.i_1[31:19]; }
    }

    action sip_3_b(){
        // c_3 = b_3 << 7
        @in_hash { ig_md.sip_tmp.a_3 = ig_md.sip_tmp.i_3[24:0] ++ ig_md.sip_tmp.I-3[31:25]; }
    }

    action sip_4_a(){
        // d_1 = c_1 ^ c_2
		hdr.sip_meta.v_1 = ig_md.sip_tmp.a_1 ^ ig_md.sip_tmp.a_2;
		// d_3 = c_3 ^ c_0 i
		hdr.sip_meta.v_3 = ig_md.sip_tmp.a_3 ^ ig_md.sip_tmp.a_0;
		// d_2 = c_2 << 16
		hdr.sip_meta.v_2 = ig_md.sip_tmp.a_2[15:0] ++ ig_md.sip_tmp.a_2[31:16];
    }

    action sip_4_b_odd(){
		// d_0 = c_0
		hdr.sip_meta.v_0 = ig_md.sip_tmp.a_0;
	}
	action sip_4_b_even(){
		// d_0 = c_0 ^ message
		hdr.sip_meta.v_0 = ig_md.sip_tmp.a_0 ^ MSG_VAR_IG;
	}

	// compression rounds
	// round 0~(2*NUM_WORDS-1)
	#define ig_def_start_m(i) action start_m_## i ##_compression(){\
		ig_md.sip_tmp.round_type = ROUND_TYPE_COMPRESSION;		\
		MSG_VAR_IG = hdr.sip.m_## i;								\
	}
	__LOOP(NUM_WORDS,ig_def_start_m)

	// round 2*NUM_WORDS (first 2 finalization rounds)
	action start_finalization_a(){
		ig_md.sip_tmp.round_type = ROUND_TYPE_FINALIZATION;
		MSG_VAR_IG = 0;
		// also xor v2 with FF at beginning of first finalization pass
		hdr.sip_meta.v_2 = hdr.sip_meta.v_2 ^ 32w0xff;
	}
	// round 2*NUM_WORDS+2 (last 2 finalization rounds)
	action start_finalization_b(){
		ig_md.sip_tmp.round_type = ROUND_TYPE_END;
		MSG_VAR_IG = 0;
	}

    table tb_start_round {
		key = {
			hdr.sip_meta.curr_round: exact;
		}
		size = 32;
		actions = {
			#define ig_actname_start_m_mul2(ix2) start_m_## ix2 ##_compression;
			#define ig_actname_start_m(i) __MUL(2,i, ig_actname_start_m_mul2)
			#if NUM_WORDS%2==0
				__LOOP(NUM_WORDS_IG, ig_actname_start_m)
				start_finalization_a;
			#else
				__LOOP(NUM_WORDS_IG, ig_actname_start_m)
				start_finalization_b;
			#endif
		}
		const entries = {
			#define ig_match_start_m_mul2(ix2) (ix2*2): start_m_## ix2 ##_compression();
			#define ig_match_start_m(i)  __MUL(2,i, ig_match_start_m_mul2)
			#if NUM_WORDS%2==0
				__LOOP(NUM_WORDS_IG, ig_match_start_m)
				(NUM_WORDS*2): start_finalization_a();
			#else
				__LOOP(NUM_WORDS_IG, ig_match_start_m)
				(NUM_WORDS*2+2): start_finalization_b();
			#endif
		}
	}

	#define ig_def_pre_end_m(i) action pre_end_m_## i ##_compression(){\
		MSG_VAR_IG = hdr.sip.m_## i;									\
	}
	__LOOP(NUM_WORDS,ig_def_pre_end_m)
	action pre_end_finalization_a(){
		MSG_VAR_IG = 0;
	}
	action pre_end_finalization_b(){
		MSG_VAR_IG = 0;
	}

	table tb_pre_end{
		key = {
			hdr.sip_meta.curr_round: exact;
		}
		size = 32;
		actions = {
			#define ig_actname_pre_end_m_mul2(ix2) pre_end_m_## ix2 ##_compression;
			#define ig_actname_pre_end_m(i) __MUL(2,i, ig_actname_pre_end_m_mul2)
			#if NUM_WORDS%2==0
				__LOOP(NUM_WORDS_IG, ig_actname_pre_end_m)
				pre_end_finalization_a;
			#else
				__LOOP(NUM_WORDS_IG, ig_actname_pre_end_m)
				pre_end_finalization_b;
			#endif
		}
		const entries = {
			#define ig_match_pre_end_m_mul2(ix2) (ix2*2): pre_end_m_## ix2 ##_compression();
			#define ig_match_pre_end_m(i) __MUL(2,i, ig_match_pre_end_m_mul2)
			#if NUM_WORDS%2==0
				__LOOP(NUM_WORDS_IG, ig_match_pre_end_m)
				(NUM_WORDS*2): pre_end_finalization_a();
			#else
				__LOOP(NUM_WORDS_IG, ig_match_pre_end_m)
				(NUM_WORDS*2+2): pre_end_finalization_b();
			#endif
		}
	}

	action start_first_pass(){
		// first pass init
		hdr.sip_meta.setValid();
		hdr.sip_meta.curr_round=0;

		sip_init(SIP_KEY_0, SIP_KEY_1);
		start_m_0_compression();

		routing_decision();
	}

    apply {
        // Packet forwarding
        if(hdr.ipv6.isValid()) {
            ipv6_forwarding.apply();

            if(hdr.route_header.isValid() && hdr.route_header.segmentsLeft > 0) {
                sr_forwarding.apply();
            }
        }

        //      EPIC only on AS ingress
        if(meta.is_AS_ingress == CROSSED_AS && hdr.epic.isValid()) {
            // Load key
            key_load.apply();

            bit<24> mac = ameta.sipm.out32[31:8];
            meta.calculated_mac = mac;

            epic_authorization.apply();

            /*
             * Modifying the epic header to save on space
             */

            // Once it's been authorized, the first per-hop header can be removed
            hdr.epic_per_hop.setInvalid();

            // This was the last 
            if(hdr.epic.per_hop_count > 1) {
                hdr.epic.per_hop_count = hdr.epic.per_hop_count - 1;
            } else {
                if(hdr.ipv6.nextHeader == EPIC) {
                    hdr.ipv6.nextHeader = hdr.epic.nextHeader;
                } else if(meta.ext_idx == 0){
                    hdr.route_header.nextHeader = hdr.epic.nextHeader;
                } else {
                    hdr.ipv6_ext_base_after_SR[meta.ext_idx].nextHeader = hdr.epic.nextHeader;
                }

                hdr.epic.setInvalid();
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
    
    
    action nop() {
	}

	action final_round_xor(){
		hdr.udp.dst_port=SIP_PORT;
		#define eg_writeout_m(i) hdr.sip.m_##i = 0;
		__LOOP(NUM_WORDS,eg_writeout_m)
		@in_hash { hdr.sip.m_0 = hdr.sip_meta.v_1 ^ hdr.sip_meta.v_3; }
		hdr.sip_meta.setInvalid();
	}

	action sip_init(bit<32> key_0, bit<32> key_1){
		hdr.sip_meta.v_0 = key_0 ^ const_0;
		hdr.sip_meta.v_1 = key_1 ^ const_1;
		hdr.sip_meta.v_2 = key_0 ^ const_2;
		hdr.sip_meta.v_3 = key_1 ^ const_3;
	}

	#define MSG_VAR_EG eg_md.sip_tmp.i_0
	action sip_1_odd(){
		// for first SipRound in set of <c> SipRounds
		// i_3 = i_3 ^ message
		hdr.sip_meta.v_3 = hdr.sip_meta.v_3 ^ MSG_VAR_EG;
	}
	action sip_1_a(){
		// a_0 = i_0 + i_1
		eg_md.sip_tmp.a_0 = hdr.sip_meta.v_0 + hdr.sip_meta.v_1;
		// a_2 = i_2 + i_3
		eg_md.sip_tmp.a_2 = hdr.sip_meta.v_2 + hdr.sip_meta.v_3;
		// a_1 = i_1 << 5
		@in_hash { eg_md.sip_tmp.a_1 = hdr.sip_meta.v_1[26:0] ++ hdr.sip_meta.v_1[31:27]; }
	}
	action sip_1_b(){
		// a_3 = i_3 << 8
		eg_md.sip_tmp.a_3 = hdr.sip_meta.v_3[23:0] ++ hdr.sip_meta.v_3[31:24];

	}
	action sip_2_a(){
		// b_1 = a_1 ^ a_0
		eg_md.sip_tmp.i_1 = eg_md.sip_tmp.a_1 ^ eg_md.sip_tmp.a_0;
		// b_3 = a_3 ^ a_2
		eg_md.sip_tmp.i_3 = eg_md.sip_tmp.a_3 ^ eg_md.sip_tmp.a_2;
		// b_0 = a_0 << 16
		eg_md.sip_tmp.i_0 = eg_md.sip_tmp.a_0[15:0] ++ eg_md.sip_tmp.a_0[31:16];
		// b_2 = a_2
		eg_md.sip_tmp.i_2 = eg_md.sip_tmp.a_2;
	}

	action sip_3_a(){
		// c_2 = b_2 + b_1
		eg_md.sip_tmp.a_2 = eg_md.sip_tmp.i_2 + eg_md.sip_tmp.i_1;
		// c_0 = b_0 + b_3
		eg_md.sip_tmp.a_0 = eg_md.sip_tmp.i_0 + eg_md.sip_tmp.i_3;
		// c_1 = b_1 << 13
		@in_hash { eg_md.sip_tmp.a_1 = eg_md.sip_tmp.i_1[18:0] ++ eg_md.sip_tmp.i_1[31:19]; }
	}
	action sip_3_b(){
		//c_3 = b_3 << 7
		@in_hash { eg_md.sip_tmp.a_3 = eg_md.sip_tmp.i_3[24:0] ++ eg_md.sip_tmp.i_3[31:25]; }
	}

	action sip_4_a(){
		// d_1 = c_1 ^ c_2
		hdr.sip_meta.v_1 = eg_md.sip_tmp.a_1 ^ eg_md.sip_tmp.a_2;
		// d_3 = c_3 ^ c_0 i
		hdr.sip_meta.v_3 = eg_md.sip_tmp.a_3 ^ eg_md.sip_tmp.a_0;
		// d_2 = c_2 << 16
		hdr.sip_meta.v_2 = eg_md.sip_tmp.a_2[15:0] ++ eg_md.sip_tmp.a_2[31:16];

	}
	action sip_4_b_odd(){
		// d_0 = c_0
		hdr.sip_meta.v_0 = eg_md.sip_tmp.a_0;
	}
	action sip_4_b_even(){
		// d_0 = c_0 ^ message
		hdr.sip_meta.v_0 = eg_md.sip_tmp.a_0 ^ MSG_VAR_EG;
	}

	//compression rounds
	// round 0~(2*NUM_WORDS-1)
	#define eg_def_start_m(i) action start_m_## i ##_compression(){\
		eg_md.sip_tmp.round_type = ROUND_TYPE_COMPRESSION;		\
		MSG_VAR_EG = hdr.sip.m_## i;								\
	}
	__LOOP(NUM_WORDS,eg_def_start_m)

	// round 2*NUM_WORDS (first 2 finalization rounds)
	action start_finalization_a(){
		eg_md.sip_tmp.round_type = ROUND_TYPE_FINALIZATION;
		MSG_VAR_EG = 0;
		// also xor v2 with FF at beginning of first finalization pass
		hdr.sip_meta.v_2 = hdr.sip_meta.v_2 ^ 32w0xff;
	}
	// round 2*NUM_WORDS+2 (last 2 finalization rounds)
	action start_finalization_b(){
		eg_md.sip_tmp.round_type = ROUND_TYPE_END;
		MSG_VAR_EG = 0;
	}

	table tb_start_round {
		key = {
			hdr.sip_meta.curr_round: exact;
		}
		size = 32;
		actions = {
			#define eg_actname_start_m_mul2plus1(ix2p1) start_m_## ix2p1 ##_compression;
			#define eg_actname_start_m_mul2(ix2) __ADD(1,ix2,eg_actname_start_m_mul2plus1)
			#define eg_actname_start_m(i) __MUL(2,i, eg_actname_start_m_mul2)
			#if NUM_WORDS%2==0
				__LOOP(NUM_WORDS_EG, eg_actname_start_m)
				start_finalization_b;
			#else
				__LOOP(NUM_WORDS_EG, eg_actname_start_m)
				start_finalization_a;
			#endif
		}
		const entries = {
			#define eg_match_start_m_mul2plus1(ix2p1) (ix2p1*2): start_m_## ix2p1 ##_compression();
			#define eg_match_start_m_mul2(ix2) __ADD(1,ix2,eg_match_start_m_mul2plus1)
			#define eg_match_start_m(i) __MUL(2,i, eg_match_start_m_mul2)
			#if NUM_WORDS%2==0
				__LOOP(NUM_WORDS_EG, eg_match_start_m)
				(2*NUM_WORDS+2): start_finalization_b;
			#else
				__LOOP(NUM_WORDS_EG, eg_match_start_m)
				(2*NUM_WORDS): start_finalization_a;
			#endif
		}
	}

	#define eg_def_pre_end_m(i) action pre_end_m_## i ##_compression(){\
		MSG_VAR_EG = hdr.sip.m_## i;									\
	}
	__LOOP(NUM_WORDS,eg_def_pre_end_m)
	action pre_end_finalization_a(){
		MSG_VAR_EG = 0;
	}
	action pre_end_finalization_b(){
		MSG_VAR_EG = 0;
	}

	table tb_pre_end{
		key = {
			hdr.sip_meta.curr_round: exact;
		}
		size = 32;
		actions = {
			#define eg_actname_pre_end_m_mul2plus1(ix2p1) pre_end_m_## ix2p1 ##_compression;
			#define eg_actname_pre_end_m_mul2(ix2) __ADD(1,ix2,eg_actname_pre_end_m_mul2plus1)
			#define eg_actname_pre_end_m(i) __MUL(2,i, eg_actname_pre_end_m_mul2)
			#if NUM_WORDS%2==0
				__LOOP(NUM_WORDS_EG, eg_actname_pre_end_m)
				start_finalization_b;
			#else
				__LOOP(NUM_WORDS_EG, eg_actname_pre_end_m)
				start_finalization_a;
			#endif
		}
		const entries = {
			#define eg_match_pre_end_m_mul2plus1(ix2p1) (ix2p1*2): pre_end_m_## ix2p1 ##_compression();
			#define eg_match_pre_end_m_mul2(ix2) __ADD(1,ix2,eg_match_pre_end_m_mul2plus1)
			#define eg_match_pre_end_m(i) __MUL(2,i, eg_match_pre_end_m_mul2)
			#if NUM_WORDS%2==0
				__LOOP(NUM_WORDS_EG, eg_match_pre_end_m)
				(2*NUM_WORDS+2): start_finalization_b;
			#else
				__LOOP(NUM_WORDS_EG, eg_match_pre_end_m)
				(2*NUM_WORDS): start_finalization_a;
			#endif
		}
	}

	apply {
		if(!hdr.sip_meta.isValid()){
			exit;
		}
		else
			tb_start_round.apply();

		// compression round: xor msg
		// note: for finalization rounds msg is zero, no effect//v3^=m
		sip_1_odd();
		// first SipRound
		sip_1_a();
		sip_1_b();
		sip_2_a();
		sip_3_a();
		sip_3_b();
		sip_4_a();
		sip_4_b_odd();
		// second SipRound
		sip_1_a();
		sip_1_b();
		sip_2_a();
		sip_3_a();
		sip_3_b();
		tb_pre_end.apply();
		sip_4_a();
		// v0^=m
		sip_4_b_even();

		if(hdr.sip_meta.curr_round < (NUM_WORDS*2+2)){
			// need more rounds in ingress pipeline, packet should be during recirculation right now
			hdr.sip_meta.curr_round = hdr.sip_meta.curr_round + 2;
		}else{
			final_round_xor();
		}
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

        /*
         * The `epic_per_hop` header is never emitted since, once it's used, it will never be used by the subsenquent routers and
         * not emitting it will save space/time, especially for fast connections.
        */
        packet.emit(hdr.epic);

        // Emit sip and sip_meta only during recirculation
        if(eg_md.recirc){
		    packet.emit(hdr.sip);
		    packet.emit(hdr.sip_meta);
        }
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

        /*
         * The `epic_per_hop` header is never emitted since, once it's used, it will never be used by the subsenquent routers and
         * not emitting it will save space/time, especially for fast connections.
        */
        packet.emit(hdr.epic);

        // Emit sip and sip_meta only during recirculation
        if(eg_md.recirc){
		    packet.emit(hdr.sip);
		    packet.emit(hdr.sip_meta);
        }
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
