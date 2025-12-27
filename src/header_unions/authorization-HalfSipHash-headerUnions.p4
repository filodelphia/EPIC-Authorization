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

#define KEY_0 0x33323130
#define KEY_1 0x42413938
 
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
const bit<16> TYPE_IPV6 = 0x86DD;
const bit<16> SIP_AUTHENTICATOR = 0xEA01;
const bit<16> SIP_VALIDATION = 0xEA02;
const bit<16> LOAD_KEY_1 = 0xEA03;
const bit<16> LOAD_KEY_2 = 0xEA04;
const bit<16> MAC_1 = 0xEA05;
const bit<16> MAC_2 = 0xEA06;


// Layer 3 definitions
const bit<8> EPIC = 252;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

// Layer 2 headers
header ethernet_h {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

// IPv6 header
header ipv6_h {
    bit<4> version;
    bit<8> traffClass;
    bit<20> flowLabel;
    bit<16> payloadLen;
    bit<8> nextHeader;
    bit<8> hoplim;
    bit<128> srcAddr;
    bit<128> dstAddr;
}

header mac_loader_h {
	bit<32> key_0;
	bit<32> key_1;

	bit<32> m_0;
	bit<32> m_1;
	bit<32> m_2;
	bit<32> m_3;
}

header mac_result_h {
	bit<32> calculated_mac;
	bit<16> etherType;
}

header sip_inout_h {
	#define vardef_m(i) bit<32> m_##i;
	__LOOP(NUM_WORDS, vardef_m)

	bit<16> etherType;
}

header sip_meta_h {
	bit<32> v_0;
	bit<32> v_1;
	bit<32> v_2;
	bit<32> v_3;

	bit<8> curr_round;
}

// EPIC Headers
header epic_h {
    bit<64> src_as_host;
    bit<64> packet_ts;
    bit<32> path_ts;

    bit<8> per_hop_count;
    bit<8> nextHeader;
}


header epic_per_hop_h {
	bit<8> tsexp;
    bit<8> ingress_if;
    bit<8> egress_if;

	bit<16> segment_identifier;
    bit<24> hop_validation;
}

/*************************************************************************
*********************** S T R U C T S  ***********************************
*************************************************************************/
struct sip_tmp_t {
    bit<32> t0;
    bit<32> t1;
    bit<32> t2;
    bit<32> t3;
    bit<32> msg;

	bit<8> round_type;
}


/*************************************************************************
*********************** Header Unions  ***********************************
*************************************************************************/
header_union exclusives_u {
	epic_h epic;
	sip_inout_h sip;
}

header_union exclusives_ext_u {
	epic_per_hop_h epic_per_hop;
	sip_meta_h sip_meta;
}

// Headers
struct headers_t {
	// Layer 2 headers
    ethernet_h ethernet;

	mac_loader_h mac_loader;
	mac_result_h mac_res;

    // IPv6 headers
    ipv6_h ipv6;

	// Mutually exclusives headers
	exclusives_u me_headers;
	exclusives_ext_u me_ext_headers; 
}

// Metadata
struct ig_metadata_t {
	// Halfsiphash temp
	sip_tmp_t sip_tmp;

	// Key rotation
	bit<32> rotated_k1;

    // Half-sip hash metadata
	bit<1> rnd_bit;
	bit<9> rnd_port_for_recirc;
	bool early_exit;
}

struct eg_metadata_t {
	sip_tmp_t sip_tmp;
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
                out ig_metadata_t ig_md,
                out ingress_intrinsic_metadata_t ig_intr_md) {
    
    TofinoIngressParser() tof_ingress_parser;

    state start {
        tof_ingress_parser.apply(packet, ig_md, ig_intr_md);

        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);

		transition select(hdr.ethernet.etherType){
			TYPE_IPV6: parse_ipv6;
			LOAD_KEY_1: parse_keys;
			LOAD_KEY_2: parse_keys;
			MAC_1: parse_mac_partial;
			MAC_2: parse_mac_full;
			SIP_AUTHENTICATOR:  parse_sip;
			SIP_VALIDATION: parse_sip;

			default: accept;
		}
    }

	state parse_keys {
		packet.extract(hdr.mac_loader);
		packet.extract(hdr.me_ext_headers.sip_meta);
		transition accept;
	}

	state parse_sip {
		packet.extract(hdr.me_ext_headers.sip);
		packet.extract(hdr.me_ext_headers.sip_meta);
		transition accept;
	}

	state parse_ipv6{
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextHeader){
            EPIC: parse_epic;
			default: accept;
        }
    }

	state parse_mac_partial {
		packet.extract(hdr.mac_res);
		packet.extract(hdr.ipv6);
		packet.extract(hdr.me_headers.epic);
		transition accept;
	}

	state parse_mac_full {
		packet.extract(hdr.mac_res);
		packet.extract(hdr.ipv6);
		packet.extract(hdr.me_headers.epic);
		packet.extract(hdr.me_ext_headers.epic_per_hop);
		transition accept;
	}
   
    state parse_epic {
        packet.extract(hdr.me_headers.epic);
		packet.extract(hdr.me_ext_headers.epic_per_hop);
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
					out eg_metadata_t eg_md,
					out egress_intrinsic_metadata_t eg_intr_md ){

    TofinoEgressParser() tofino_egress;

    state start {
        tofino_egress.apply(packet, eg_intr_md);
        transition parse_ethernet;
    }

	state parse_ethernet {
        packet.extract(hdr.ethernet);

		transition select(hdr.ethernet.etherType){
			SIP_AUTHENTICATOR:  parse_sip;
			SIP_VALIDATION: parse_sip;
			default: accept;
		}
    }

	state parse_sip {
		packet.extract(hdr.me_ext_headers.sip);
		packet.extract(hdr.me_ext_headers.sip_meta);
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

    action drop() { ig_dpr_md.drop_ctl = 0x1; }
    action nop() { }

	/*
	 *
	 *  Halfisip-hash implementation
	 *
	 *
	 */


    /* -------- Random for recirculation, following Princeton implementation of Halfsip-hash -------- */
    Random<bit<1>>() rng;
    action get_rnd_bit() { ig_md.rnd_bit = rng.get(); }
    action route_to(bit<9> port) { ig_tm_md.ucast_egress_port = port; }
    action do_recirculate() { route_to(ig_md.rnd_port_for_recirc); }

    action incr_and_recirc(bit<8> next_round){
		hdr.me_ext_headers.sip_meta.curr_round = next_round;
		do_recirculate();
    }

	action do_not_recirc_end_in_ig(){
		#define ig_writeout_m(i) hdr.me_headers.sip.m_##i = 0;
		__LOOP(NUM_WORDS,ig_writeout_m)
		@in_hash { hdr.me_headers.sip.m_0 = hdr.me_ext_headers.sip_meta.v_1 ^ hdr.me_ext_headers.sip_meta.v_3; }
		hdr.me_ext_headers.sip_meta.setInvalid(); //TODO!!!!!! Check egress ifs
	}

	action do_not_recirc_end_in_eg(bit<8> next_round){
		hdr.me_ext_headers.sip_meta.curr_round = next_round;
	}

	table tb_recirc_decision {
		key = {
			hdr.me_ext_headers.sip_meta.curr_round: exact;
		}
		actions = {
			incr_and_recirc;
			do_not_recirc_end_in_eg;
			do_not_recirc_end_in_ig;
			nop;
		}
		size = 32;
		default_action = nop();
		const entries = {
			// ingress performs round 0,4,8,...
			// even NUM_WORDS last round ends in egress, odd ends in ingress
			#define ig_rule_incr_m(i) (i*4): incr_and_recirc(i*4+2);
			#if (NUM_WORDS%2==0)
				__LOOP(NUM_WORDS_IG, ig_rule_incr_m)
				(NUM_WORDS*2): do_not_recirc_end_in_eg(NUM_WORDS*2+2);
			#else
				__LOOP(NUM_WORDS_IG, ig_rule_incr_m)
				(NUM_WORDS*2+2): do_not_recirc_end_in_ig();
			#endif
		}

	}

    /* -------- Halfsip actions in INGRESS, Princeton implementation  -------- */
    action sip_init(bit<32> key_0, bit<32> key_1){
		hdr.me_ext_headers.sip_meta.setValid();
		hdr.me_ext_headers.sip_meta.curr_round = 0;

        hdr.me_ext_headers.sip_meta.v_0 = key_0 ^ const_0;
        hdr.me_ext_headers.sip_meta.v_1 = key_1 ^ const_1;
        hdr.me_ext_headers.sip_meta.v_2 = key_0 ^ const_2;
        hdr.me_ext_headers.sip_meta.v_3 = key_1 ^ const_3;
    }

    #define MSG_VAR_IG ig_md.sip_tmp.msg
    	action sip_1_odd() {
    	hdr.me_ext_headers.sip_meta.v_3 = hdr.me_ext_headers.sip_meta.v_3 ^ MSG_VAR_IG;
	}

	action sip_1_a(){
		ig_md.sip_tmp.t0 = hdr.me_ext_headers.sip_meta.v_0 + hdr.me_ext_headers.sip_meta.v_1;
		ig_md.sip_tmp.t2 = hdr.me_ext_headers.sip_meta.v_2 + hdr.me_ext_headers.sip_meta.v_3;
		@in_hash { ig_md.sip_tmp.t1 = hdr.me_ext_headers.sip_meta.v_1[26:0] ++ hdr.me_ext_headers.sip_meta.v_1[31:27]; } // rotl5
	}

	action sip_1_b(){
		ig_md.sip_tmp.t3 = hdr.me_ext_headers.sip_meta.v_3[23:0] ++ hdr.me_ext_headers.sip_meta.v_3[31:24]; // rotl8
	}

	action sip_2_a(){
		hdr.me_ext_headers.sip_meta.v_1 = ig_md.sip_tmp.t1 ^ ig_md.sip_tmp.t0;
		hdr.me_ext_headers.sip_meta.v_3 = ig_md.sip_tmp.t3 ^ ig_md.sip_tmp.t2;
		hdr.me_ext_headers.sip_meta.v_0 = ig_md.sip_tmp.t0[15:0] ++ ig_md.sip_tmp.t0[31:16]; // rotl16
		hdr.me_ext_headers.sip_meta.v_2 = ig_md.sip_tmp.t2;
	}

	action sip_3_a(){
		ig_md.sip_tmp.t2 = hdr.me_ext_headers.sip_meta.v_2 + hdr.me_ext_headers.sip_meta.v_1;
		ig_md.sip_tmp.t0 = hdr.me_ext_headers.sip_meta.v_0 + hdr.me_ext_headers.sip_meta.v_3;
		@in_hash { ig_md.sip_tmp.t1 = hdr.me_ext_headers.sip_meta.v_1[18:0] ++ hdr.me_ext_headers.sip_meta.v_1[31:19]; } // rotl13
	}
	action sip_3_b(){
		@in_hash { ig_md.sip_tmp.t3 = hdr.me_ext_headers.sip_meta.v_3[24:0] ++ hdr.me_ext_headers.sip_meta.v_3[31:25]; } // rotl7
	}

	action sip_4_a(){
		hdr.me_ext_headers.sip_meta.v_1 = ig_md.sip_tmp.t1 ^ ig_md.sip_tmp.t2;
		hdr.me_ext_headers.sip_meta.v_3 = ig_md.sip_tmp.t3 ^ ig_md.sip_tmp.t0;
		hdr.me_ext_headers.sip_meta.v_2 = ig_md.sip_tmp.t2[15:0] ++ ig_md.sip_tmp.t2[31:16]; // rotl16
	}

	action sip_4_b_odd(){
		hdr.me_ext_headers.sip_meta.v_0 = ig_md.sip_tmp.t0;
	}
	action sip_4_b_even(){
		hdr.me_ext_headers.sip_meta.v_0 = ig_md.sip_tmp.t0 ^ MSG_VAR_IG;
	}

	// compression rounds
	// round 0~(2*NUM_WORDS-1)
	#define ig_def_start_m(i) action start_m_## i ##_compression(){\
		ig_md.sip_tmp.round_type = ROUND_TYPE_COMPRESSION;		\
		MSG_VAR_IG = hdr.me_headers.sip.m_## i;								\
	}
	__LOOP(NUM_WORDS,ig_def_start_m)

	// round 2*NUM_WORDS (first 2 finalization rounds)
	action start_finalization_a(){
		ig_md.sip_tmp.round_type = ROUND_TYPE_FINALIZATION;
		MSG_VAR_IG = 0;
		// also xor v2 with FF at beginning of first finalization pass
		hdr.me_ext_headers.sip_meta.v_2 = hdr.me_ext_headers.sip_meta.v_2 ^ 32w0xff;
	}
	// round 2*NUM_WORDS+2 (last 2 finalization rounds)
	action start_finalization_b(){
		ig_md.sip_tmp.round_type = ROUND_TYPE_END;
		MSG_VAR_IG = 0;
	}

    table tb_start_round {
		key = {
			hdr.me_ext_headers.sip_meta.curr_round: exact;
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
		MSG_VAR_IG = hdr.me_headers.sip.m_## i;									\
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
			hdr.me_ext_headers.sip_meta.curr_round: exact;
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


	/*
	 *
	 *   EPIC actions
	 *
	 */

	action create_hop_authenticator(){
		hdr.mac_loader.setValid();
		hdr.mac_loader.key_0 = KEY_0;
		hdr.mac_loader.key_1 = KEY_1;
		
		hdr.me_ext_headers.sip_meta.setValid();
		hdr.me_headers.sip.etherType = hdr.ethernet.etherType;
		hdr.ethernet.etherType = LOAD_KEY_1;

		hdr.me_headers.sip.m_0 = hdr.me_headers.epic.path_ts;
		hdr.me_headers.sip.m_1 = hdr.me_ext_headers.epic_per_hop.ingress_if
					++ hdr.me_ext_headers.epic_per_hop.egress_if
					++ hdr.me_ext_headers.epic_per_hop.segment_identifier;

		hdr.me_headers.sip.m_2 = hdr.me_ext_headers.epic_per_hop.tsexp ++ (bit<24>) 0;
		hdr.me_headers.sip.m_3 = 0;

		ig_tm_md.ucast_egress_port = ig_md.rnd_port_for_recirc;
		ig_md.early_exit = true;
	}

	action create_packet_authorization(){
		hdr.mac_loader.setValid();
		ig_md.rotated_k1 = hdr.mac.calculated_mac[15:0]
						 ++ hdr.mac.calculated_mac[31:16];
		
		hdr.mac_loader.key_0 = hdr.mac.calculated_mac;
		hdr.mac_loader.key_1 = ig_md.rotated_k1;

		hdr.mac_loader.m_0 = (bit<32>)(hdr.me_headers.epic.src_as_host[63:32]);
		hdr.mac_loader.m_1 = (bit<32>)(hdr.me_headers.epic.src_as_host[31:0]);
		hdr.mac_loader.m_2 = (bit<32>)(hdr.me_headers.epic.packet_ts[63:32]);
		hdr.mac_loader.m_3 = (bit<32>)(hdr.me_headers.epic.packet_ts[31:0]);
		
		hdr.me_ext_headers.sip_meta.setValid();
		hdr.me_headers.sip.etherType = hdr.mac.etherType;
		hdr.ethernet.etherType = LOAD_KEY_2;

		hdr.mac.setInvalid();
		ig_tm_md.ucast_egress_port = ig_md.rnd_port_for_recirc;
		ig_md.early_exit = true;
	}

	action load_hop_authenticator(){
		hdr.me_headers.sip.setValid();
		hdr.me_ext_headers.sip_meta.setValid();

		hdr.me_headers.sip.m_0 = hdr.mac_loader.m_0;
		hdr.me_headers.sip.m_1 = hdr.mac_loader.m_1;
		hdr.me_headers.sip.m_2 = hdr.mac_loader.m_2;
		hdr.me_headers.sip.m_3 = hdr.mac_loader.m_3;


		hdr.mac_loader.setInvalid();
		hdr.ethernet.etherType = SIP_AUTHENTICATOR;
		sip_init(hdr.mac_loader.key_0, hdr.mac_loader.key_1);
	}

	action load_packet_authorization(){
		hdr.me_headers.sip.setValid();
		hdr.me_ext_headers.sip_meta.setValid();

		hdr.me_headers.sip.m_0 = hdr.mac_loader.m_0;
		hdr.me_headers.sip.m_1 = hdr.mac_loader.m_1;
		hdr.me_headers.sip.m_2 = hdr.mac_loader.m_2;
		hdr.me_headers.sip.m_3 = hdr.mac_loader.m_3;

		hdr.mac_loader.setInvalid();
		hdr.ethernet.etherType = SIP_VALIDATION;
		sip_init(hdr.mac_loader.key_0, hdr.mac_loader.key_1);
	}

	action epic_forward(){
		hdr.ethernet.etherType = TYPE_IPV6;
	}

	table epic_stage {
		key = {
			hdr.ethernet.etherType: exact;
		}

		size = 32;
		actions = {
			create_hop_authenticator;
			load_hop_authenticator;
			create_packet_authorization;
			load_packet_authorization;
			epic_forward;
			nop;
		}

		default_action = nop();
	}

    apply {
		ig_md.early_exit = false;
		
		// Get random bit for recirculation
		get_rnd_bit();

		if (ig_md.rnd_bit == 0){
			ig_md.rnd_port_for_recirc = 68;
		} else{
			ig_md.rnd_port_for_recirc = 68 + 128;
		}

		epic_stage.apply();

		if(hdr.mac_res.isValid() && hdr.ethernet.etherType == MAC_2){
			if((bit <24>) (hdr.mac.calculated_mac[23:0]) != hdr.me_ext_headers.epic_per_hop.hop_validation){
				drop();
				ig_md.early_exit = true;
			}

			hdr.ethernet.etherType = hdr.mac_res.etherType;
			hdr.mac_res.setInvalid();

			if(hdr.me_headers.epic.per_hop_count > 1) {
				hdr.me_headers.epic.per_hop_count = hdr.me_headers.epic.per_hop_count - 1;
			} else {
				hdr.ipv6.nextHeader = hdr.me_headers.epic.nextHeader;
				hdr.me_headers.epic.setInvalid();
			}

			hdr.me_ext_headers.epic_per_hop.setInvalid();
		}

		if(ig_md.early_exit || !hdr.me_ext_headers.sip_meta.isValid()) { exit; }

		// Halfsip hash calculations
    	tb_start_round.apply();

		//compression round: xor msg
		//note: for finalization rounds msg is zero, no effect
		//v3^=m
		sip_1_odd();
		//first SipRound
		sip_1_a();
		sip_1_b();
		sip_2_a();
		sip_3_a();
		sip_3_b();
		sip_4_a();
		sip_4_b_odd();
		//second SipRound
		sip_1_a();
		sip_1_b();
		sip_2_a();
		sip_3_a();
		sip_3_b();
		tb_pre_end.apply();
		sip_4_a();
		//v0^=m
		sip_4_b_even();

		tb_recirc_decision.apply();

		if((NUM_WORDS%2==0 && hdr.me_ext_headers.sip_meta.curr_round == (NUM_WORDS*2+2)) ||
		   (NUM_WORDS%2==1 && hdr.me_ext_headers.sip_meta.curr_round == (NUM_WORDS*2))) {
			ig_tm_md.ucast_egress_port = ig_md.rnd_port_for_recirc;
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
		#define eg_writeout_m(i) hdr.me_headers.sip.m_##i = 0;
		__LOOP(NUM_WORDS,eg_writeout_m)
		@in_hash { hdr.me_headers.sip.m_0 = hdr.me_ext_headers.sip_meta.v_1 ^ hdr.me_ext_headers.sip_meta.v_3; }
	}

	action sip_init(bit<32> key_0, bit<32> key_1){
		hdr.me_ext_headers.sip_meta.v_0 = key_0 ^ const_0;
		hdr.me_ext_headers.sip_meta.v_1 = key_1 ^ const_1;
		hdr.me_ext_headers.sip_meta.v_2 = key_0 ^ const_2;
		hdr.me_ext_headers.sip_meta.v_3 = key_1 ^ const_3;
	}

	#define MSG_VAR_EG eg_md.sip_tmp.msg
	action sip_1_odd() {
    	hdr.me_ext_headers.sip_meta.v_3 = hdr.me_ext_headers.sip_meta.v_3 ^ MSG_VAR_EG;
	}

	action sip_1_a(){
		eg_md.sip_tmp.t0 = hdr.me_ext_headers.sip_meta.v_0 + hdr.me_ext_headers.sip_meta.v_1;
		eg_md.sip_tmp.t2 = hdr.me_ext_headers.sip_meta.v_2 + hdr.me_ext_headers.sip_meta.v_3;
		@in_hash { eg_md.sip_tmp.t1 = hdr.me_ext_headers.sip_meta.v_1[26:0] ++ hdr.me_ext_headers.sip_meta.v_1[31:27]; } // rotl5
	}

	action sip_1_b(){
		eg_md.sip_tmp.t3 = hdr.me_ext_headers.sip_meta.v_3[23:0] ++ hdr.me_ext_headers.sip_meta.v_3[31:24]; // rotl8
	}

	action sip_2_a(){
		hdr.me_ext_headers.sip_meta.v_1 = eg_md.sip_tmp.t1 ^ eg_md.sip_tmp.t0;
		hdr.me_ext_headers.sip_meta.v_3 = eg_md.sip_tmp.t3 ^ eg_md.sip_tmp.t2;
		hdr.me_ext_headers.sip_meta.v_0 = eg_md.sip_tmp.t0[15:0] ++ eg_md.sip_tmp.t0[31:16]; // rotl16
		hdr.me_ext_headers.sip_meta.v_2 = eg_md.sip_tmp.t2;
	}

	action sip_3_a(){
		eg_md.sip_tmp.t2 = hdr.me_ext_headers.sip_meta.v_2 + hdr.me_ext_headers.sip_meta.v_1;
		eg_md.sip_tmp.t0 = hdr.me_ext_headers.sip_meta.v_0 + hdr.me_ext_headers.sip_meta.v_3;
		@in_hash { eg_md.sip_tmp.t1 = hdr.me_ext_headers.sip_meta.v_1[18:0] ++ hdr.me_ext_headers.sip_meta.v_1[31:19]; } // rotl13
	}
	action sip_3_b(){
		@in_hash { eg_md.sip_tmp.t3 = hdr.me_ext_headers.sip_meta.v_3[24:0] ++ hdr.me_ext_headers.sip_meta.v_3[31:25]; } // rotl7
	}

	action sip_4_a(){
		hdr.me_ext_headers.sip_meta.v_1 = eg_md.sip_tmp.t1 ^ eg_md.sip_tmp.t2;
		hdr.me_ext_headers.sip_meta.v_3 = eg_md.sip_tmp.t3 ^ eg_md.sip_tmp.t0;
		hdr.me_ext_headers.sip_meta.v_2 = eg_md.sip_tmp.t2[15:0] ++ eg_md.sip_tmp.t2[31:16]; // rotl16
	}

	action sip_4_b_odd(){
		hdr.me_ext_headers.sip_meta.v_0 = eg_md.sip_tmp.t0;
	}
	action sip_4_b_even(){
		hdr.me_ext_headers.sip_meta.v_0 = eg_md.sip_tmp.t0 ^ MSG_VAR_EG;
	}

	//compression rounds
	// round 0~(2*NUM_WORDS-1)
	#define eg_def_start_m(i) action start_m_## i ##_compression(){\
		eg_md.sip_tmp.round_type = ROUND_TYPE_COMPRESSION;		\
		MSG_VAR_EG = hdr.me_headers.sip.m_## i;								\
	}
	__LOOP(NUM_WORDS,eg_def_start_m)

	// round 2*NUM_WORDS (first 2 finalization rounds)
	action start_finalization_a(){
		eg_md.sip_tmp.round_type = ROUND_TYPE_FINALIZATION;
		MSG_VAR_EG = 0;
		// also xor v2 with FF at beginning of first finalization pass
		hdr.me_ext_headers.sip_meta.v_2 = hdr.me_ext_headers.sip_meta.v_2 ^ 32w0xff;
	}
	// round 2*NUM_WORDS+2 (last 2 finalization rounds)
	action start_finalization_b(){
		eg_md.sip_tmp.round_type = ROUND_TYPE_END;
		MSG_VAR_EG = 0;
	}

	table tb_start_round {
		key = {
			hdr.me_ext_headers.sip_meta.curr_round: exact;
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
				(2*NUM_WORDS+2): start_finalization_b();
			#else
				__LOOP(NUM_WORDS_EG, eg_match_start_m)
				(2*NUM_WORDS): start_finalization_a();
			#endif
		}
	}

	#define eg_def_pre_end_m(i) action pre_end_m_## i ##_compression(){\
		MSG_VAR_EG = hdr.me_headers.sip.m_## i;									\
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
			hdr.me_ext_headers.sip_meta.curr_round: exact;
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
				(2*NUM_WORDS+2): start_finalization_b();
			#else
				__LOOP(NUM_WORDS_EG, eg_match_pre_end_m)
				(2*NUM_WORDS): start_finalization_a();
			#endif
		}
	}

	apply {
		if(!(hdr.me_ext_headers.sip_meta.isValid() || hdr.me_ext_headers.sip_meta.isValid())) { exit; }
		else tb_start_round.apply();

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

		if(hdr.me_ext_headers.sip_meta.curr_round < (NUM_WORDS*2+2)){
			// need more rounds in ingress pipeline, packet should be during recirculation right now
			hdr.me_ext_headers.sip_meta.curr_round = hdr.me_ext_headers.sip_meta.curr_round + 2;
		} else {
			final_round_xor();

			hdr.mac.setValid();
			hdr.mac.calculated_mac = hdr.me_headers.sip.m_0;
			hdr.mac.etherType = hdr.me_headers.sip.etherType;
			if(hdr.ethernet.etherType == SIP_AUTHENTICATOR) hdr.ethernet.etherType = MAC_1;
			else if(hdr.ethernet.etherType == SIP_VALIDATION) hdr.ethernet.etherType = MAC_2;

			hdr.me_ext_headers.sip_meta.setInvalid();
			hdr.me_ext_headers.sip_meta.setInvalid();
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

		packet.emit(hdr.mac_loader);
		packet.emit(hdr.mac); // TODO? Should the MAC be deparsed in the ingress? When? Why?

		// Emit sip and sip_meta only during recirculation
        packet.emit(hdr.me_ext_headers.sip_meta);
        packet.emit(hdr.me_ext_headers.sip_meta);

		packet.emit(hdr.ipv6);
		packet.emit(hdr.me_headers.epic);
		packet.emit(hdr.me_ext_headers.epic_per_hop);
	}
}

control EgressDeparser(
		packet_out packet,
		inout headers_t hdr,
		in eg_metadata_t eg_md,
		in egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr) {
	
    apply {
		packet.emit(hdr.ethernet);
		packet.emit(hdr.mac);
        packet.emit(hdr.me_ext_headers.sip_meta);
        packet.emit(hdr.me_ext_headers.sip_meta);
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

Switch(pipe) main;