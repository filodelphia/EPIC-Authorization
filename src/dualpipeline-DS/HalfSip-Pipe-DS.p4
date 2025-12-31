/* Definitions for implementing halfsiphash */
#ifndef NUM_WORDS
    #define NUM_WORDS 4
    #define NUM_WORDS_IG 2
    #define NUM_WORDS_EG 2
#endif
#if !((NUM_WORDS_IG+NUM_WORDS_EG==NUM_WORDS) && (NUM_WORDS_IG-NUM_WORDS_EG==0 || NUM_WORDS_IG-NUM_WORDS_EG==1 ))
	#error "Please set NUM_WORDS_IG to be floor((NUM_WORDS+1)/2) and NUM_WORDS_EG to be floor((NUM_WORDS)/2)."
#endif

const bit<32> const_0 = 0;
const bit<32> const_1 = 0;
const bit<32> const_2 = 0x6c796765;
const bit<32> const_3 = 0x74656462;

#define ROUND_TYPE_COMPRESSION 0
#define ROUND_TYPE_FINALIZATION 1
#define ROUND_TYPE_END 2

#include "../../include/loops_macro.h"
#include "../../include/cross_def.h"
#include "../../include/cross_headers.p4"

#ifndef EPIC_PIPE_PORT
	#define EPIC_PIPE_PORT 68
#endif
#ifndef MAC_PIPE_PORT
	#define MAC_PIPE_PORT 196
#endif

/*************************************************************************
************************** H E A D E R S *********************************
*************************************************************************/

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
	bit<16> nextJob;
}

/*************************************************************************
************************** S T R U C T S *********************************
*************************************************************************/

struct sip_tmp_t {
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

struct hsh_headers_t {
	ethernet_h ethernet;
	sip_inout_h sip;
	sip_meta_h sip_meta;

	mac_loader_h mac_load;
	mac_result_h mac_res;
}

struct hsh_ig_metadata_t {
	sip_tmp_t sip_tmp;

	bool recirc;
}

struct hsh_eg_metadata_t {
	sip_tmp_t sip_tmp;
}

/*************************************************************************/
/**************************  P A R S E R  ********************************/
/*************************************************************************/
parser HalfSipHashTofinoIngressParser(
    packet_in packet,
    inout hsh_ig_metadata_t ig_md,
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

parser HalfSipHashIngressParser(
    packet_in packet,
    out hsh_headers_t hdr,
    out hsh_ig_metadata_t ig_md,
    out ingress_intrinsic_metadata_t ig_intr_md) {

	HalfSipHashTofinoIngressParser() tofino_parser;

	state start {
		tofino_parser.apply(packet, ig_md, ig_intr_md);
		transition parse_ethernet;
	}

	state parse_ethernet {
		packet.extract(hdr.ethernet);
		transition select(hdr.ethernet.etherType) {
			HOP_MAC_LOAD_ETHERTYPE: parse_mac_loader;
			AUTH_MAC_LOAD_ETHERTYPE: parse_mac_loader;
			
			HOP_MAC_RESULT_ETHERTYPE: accept;
			AUTH_MAC_RESULT_ETHERTYPE: accept;

			SIP_META_ETHERTYPE: parse_sip_and_meta;

			default : reject;
		}
	}

	state parse_mac_loader {
		packet.extract(hdr.mac_load);
		transition accept;
	}

	state parse_sip_and_meta {
		packet.extract(hdr.sip);
		packet.extract(hdr.sip_meta);
		transition accept;
	}
}

parser HalfSipHashTofinoEgressParser(
		packet_in packet,
		out egress_intrinsic_metadata_t eg_intr_md) {

	state start {
		packet.extract(eg_intr_md);
		transition accept;
	}
}

parser HalfSipHashEgressParser(
		packet_in packet,
		out hsh_headers_t hdr,
		out hsh_eg_metadata_t eg_md,
		out egress_intrinsic_metadata_t eg_intr_md) {

	HalfSipHashTofinoEgressParser() tofino_parser;

	state start {
		tofino_parser.apply(packet, eg_intr_md);
		transition parse_ethernet;
	}

	state parse_ethernet {
		packet.extract(hdr.ethernet);
		transition select(hdr.ethernet.etherType) {
			SIP_META_ETHERTYPE: parse_sip_and_meta;
			default: accept;
		}
	}

	state parse_sip_and_meta {
		packet.extract(hdr.sip);
		packet.extract(hdr.sip_meta);
		transition accept;
	}
}

/*************************************************************************/
/***********************  D E P A R S E R  *******************************/
/*************************************************************************/
control HalfSipHashIngressDeparser(
		packet_out packet,
		inout hsh_headers_t hdr,
		in hsh_ig_metadata_t ig_md,
		in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {
	apply {
		packet.emit(hdr.ethernet);
		packet.emit(hdr.mac_res);
		packet.emit(hdr.sip);
		packet.emit(hdr.sip_meta);
	}
}

control HalfSipHashEgressDeparser(
		packet_out packet,
		inout hsh_headers_t hdr,
		in hsh_eg_metadata_t eg_md,
		in egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr) {
	apply {
		packet.emit(hdr.ethernet);
		packet.emit(hdr.mac_res);
		packet.emit(hdr.sip);
		packet.emit(hdr.sip_meta);
	}
}

/*************************************************************************/
/*****************  I N G R E S S   P R O C E S S I N G  *****************/
/*************************************************************************/
control HalfSipHashIngress(
		inout hsh_headers_t hdr,
		inout hsh_ig_metadata_t ig_md,
		in ingress_intrinsic_metadata_t ig_intr_md,
		in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
		inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
		inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

	action drop(){
		ig_intr_dprsr_md.drop_ctl = 0x1; // Drop packet.
	}

	action nop() {
	}
	
	action route_to(bit<9> port){ ig_intr_tm_md.ucast_egress_port=port; }
	action to_mac_pipe() { route_to(MAC_PIPE_PORT); }
	action to_epic_pipe() { route_to(EPIC_PIPE_PORT); }
    action do_recirculate() { to_mac_pipe(); }

	action incr_and_recirc(bit<8> next_round){
		hdr.sip_meta.curr_round = next_round;
		do_recirculate();

		hdr.ethernet.etherType = SIP_META_ETHERTYPE;
	}

	action do_not_recirc_end_in_ig(){
		to_epic_pipe();
		#define ig_writeout_m(i) hdr.sip.m_##i = 0;
		__LOOP(NUM_WORDS,ig_writeout_m)

		hdr.ethernet.etherType = hdr.sip_meta.nextJob;
		hdr.mac_res.setValid();

		@in_hash { hdr.mac_res.calculated_mac = hdr.sip_meta.v_1 ^ hdr.sip_meta.v_3; }
		
		hdr.sip_meta.setInvalid();
		hdr.sip.setInvalid();
	}

	action final_recirc_end_in_eg(bit<8> next_round){
		to_mac_pipe();
		hdr.sip_meta.curr_round = next_round;
	}

	table tb_recirc_decision {
		key = {
			hdr.sip_meta.curr_round: exact;
		}
		actions = {
			incr_and_recirc;
			final_recirc_end_in_eg;
			do_not_recirc_end_in_ig;
			nop;
		}

		size = 32;
		default_action = nop;
		const entries = {
			// ingress performs round 0,4,8,...
			// even NUM_WORDS last round ends in egress, odd ends in ingress
			#define ig_rule_incr_m(i) (i*4): incr_and_recirc(i*4+2);
			#if (NUM_WORDS%2==0)
				__LOOP(NUM_WORDS_IG, ig_rule_incr_m)
				(NUM_WORDS*2): final_recirc_end_in_eg(NUM_WORDS*2+2);
			#else
				__LOOP(NUM_WORDS_IG, ig_rule_incr_m)
				(NUM_WORDS*2+2): do_not_recirc_end_in_ig();
			#endif
		}

	}
	
	action sip_init(bit<32> key_0, bit<32> key_1){
		hdr.sip_meta.v_0 = key_0 ^ const_0;
		hdr.sip_meta.v_1 = key_1 ^ const_1;
		hdr.sip_meta.v_2 = key_0 ^ const_2;
		hdr.sip_meta.v_3 = key_1 ^ const_3;
    }

    #define MSG_VAR_IG ig_md.sip_tmp.i_0
	action sip_1_odd(){
		//for first SipRound in set of <c> SipRounds
		//i_3 = i_3 ^ message
		hdr.sip_meta.v_3 = hdr.sip_meta.v_3 ^ MSG_VAR_IG;
	}

	action sip_1_a(){
		//a_0 = i_0 + i_1
		ig_md.sip_tmp.a_0 = hdr.sip_meta.v_0 + hdr.sip_meta.v_1;
		//a_2 = i_2 + i_3
		ig_md.sip_tmp.a_2 = hdr.sip_meta.v_2 + hdr.sip_meta.v_3;
		//a_1 = i_1 << 5
		@in_hash { ig_md.sip_tmp.a_1 = hdr.sip_meta.v_1[26:0] ++ hdr.sip_meta.v_1[31:27]; }
	}

	action sip_1_b(){
		//a_3 = i_3 << 8
		ig_md.sip_tmp.a_3 = hdr.sip_meta.v_3[23:0] ++ hdr.sip_meta.v_3[31:24];
	}

	action sip_2_a(){
		//b_1 = a_1 ^ a_0
		ig_md.sip_tmp.i_1 = ig_md.sip_tmp.a_1 ^ ig_md.sip_tmp.a_0;
		//b_3 = a_3 ^ a_2
		ig_md.sip_tmp.i_3 = ig_md.sip_tmp.a_3 ^ ig_md.sip_tmp.a_2;
		// b_0 = a_0 << 16
		ig_md.sip_tmp.i_0 = ig_md.sip_tmp.a_0[15:0] ++ ig_md.sip_tmp.a_0[31:16];
		//b_2 = a_2
		ig_md.sip_tmp.i_2 = ig_md.sip_tmp.a_2;
	}

	action sip_3_a(){
		//c_2 = b_2 + b_1
		ig_md.sip_tmp.a_2 = ig_md.sip_tmp.i_2 + ig_md.sip_tmp.i_1;
		//c_0 = b_0 + b_3
		ig_md.sip_tmp.a_0 = ig_md.sip_tmp.i_0 + ig_md.sip_tmp.i_3;
		//c_1 = b_1 << 13
		@in_hash { ig_md.sip_tmp.a_1 = ig_md.sip_tmp.i_1[18:0] ++ ig_md.sip_tmp.i_1[31:19]; }
	}
	
	action sip_3_b(){
		//c_3 = b_3 << 7
		@in_hash { ig_md.sip_tmp.a_3 = ig_md.sip_tmp.i_3[24:0] ++ ig_md.sip_tmp.i_3[31:25]; }
	}

	action sip_4_a(){
		//d_1 = c_1 ^ c_2
		hdr.sip_meta.v_1 = ig_md.sip_tmp.a_1 ^ ig_md.sip_tmp.a_2;
		//d_3 = c_3 ^ c_0 i
		hdr.sip_meta.v_3 = ig_md.sip_tmp.a_3 ^ ig_md.sip_tmp.a_0;
		//d_2 = c_2 << 16
		hdr.sip_meta.v_2 = ig_md.sip_tmp.a_2[15:0] ++ ig_md.sip_tmp.a_2[31:16];

	}
	action sip_4_b_odd(){
		//d_0 = c_0
		hdr.sip_meta.v_0 = ig_md.sip_tmp.a_0;
	}
	action sip_4_b_even(){
		//d_0 = c_0 ^ message
		hdr.sip_meta.v_0 = ig_md.sip_tmp.a_0 ^ MSG_VAR_IG;
	}

	//compression rounds
	// round 0~(2*NUM_WORDS-1)
	#define ig_def_start_m(i) action start_m_## i ##_compression(){\
		ig_md.sip_tmp.round_type = ROUND_TYPE_COMPRESSION;		\
		MSG_VAR_IG = hdr.sip.m_## i;								\
	}
	__LOOP(NUM_WORDS,ig_def_start_m)

	//round 2*NUM_WORDS (first 2 finalization rounds)
	action start_finalization_a(){
		ig_md.sip_tmp.round_type = ROUND_TYPE_FINALIZATION;
		MSG_VAR_IG = 0;
		// also xor v2 with FF at beginning of first finalization pass
		hdr.sip_meta.v_2 = hdr.sip_meta.v_2 ^ 32w0xff;
	}
	//round 2*NUM_WORDS+2 (last 2 finalization rounds)
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

	action initialize_mac() {
		hdr.sip.setValid();
		hdr.sip.m_0 = hdr.mac_load.m_0;
		hdr.sip.m_1 = hdr.mac_load.m_1;
		hdr.sip.m_2 = hdr.mac_load.m_2;
		hdr.sip.m_3 = hdr.mac_load.m_3;
		hdr.ethernet.etherType = SIP_META_ETHERTYPE;
		
		hdr.sip_meta.setValid();
		hdr.sip_meta.curr_round=0;
		hdr.sip_meta.nextJob = hdr.mac_load.nextJob;

		sip_init(hdr.mac_load.key_0, hdr.mac_load.key_1);
		
		hdr.mac_load.setInvalid();

		start_m_0_compression();
	}

	apply {
		if(hdr.ethernet.etherType == HOP_MAC_RESULT_ETHERTYPE || hdr.ethernet.etherType == AUTH_MAC_RESULT_ETHERTYPE){
			to_epic_pipe();
			exit;
		}

		if (!hdr.sip.isValid() && !hdr.mac_load.isValid()) { drop(); exit; }

		// First pass
		if(hdr.mac_load.isValid()) initialize_mac();
		else tb_start_round.apply();

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
	}
}

/*************************************************************************/
/****************  E G R E S S   P R O C E S S I N G   *******************/
/*************************************************************************/
control HalfSipHashEgress(
		inout hsh_headers_t hdr,
		inout hsh_eg_metadata_t eg_md,
		in egress_intrinsic_metadata_t eg_intr_md,
		in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
		inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
		inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {

	action nop() {
	}

	action final_round_xor(){
		#define eg_writeout_m(i) hdr.sip.m_##i = 0;
		__LOOP(NUM_WORDS,eg_writeout_m)
		
		hdr.mac_res.setValid();
		hdr.ethernet.etherType = hdr.sip_meta.nextJob;

		@in_hash { hdr.mac_res.calculated_mac = hdr.sip_meta.v_1 ^ hdr.sip_meta.v_3; }
		
		hdr.sip_meta.setInvalid();
		hdr.sip.setInvalid();
	}

	action sip_init(bit<32> key_0, bit<32> key_1){
		hdr.sip_meta.v_0 = key_0 ^ const_0;
		hdr.sip_meta.v_1 = key_1 ^ const_1;
		hdr.sip_meta.v_2 = key_0 ^ const_2;
		hdr.sip_meta.v_3 = key_1 ^ const_3;
	}

	#define MSG_VAR_EG eg_md.sip_tmp.i_0
	action sip_1_odd(){
		//for first SipRound in set of <c> SipRounds
		//i_3 = i_3 ^ message
		hdr.sip_meta.v_3 = hdr.sip_meta.v_3 ^ MSG_VAR_EG;
	}
	action sip_1_a(){
		//a_0 = i_0 + i_1
		eg_md.sip_tmp.a_0 = hdr.sip_meta.v_0 + hdr.sip_meta.v_1;
		//a_2 = i_2 + i_3
		eg_md.sip_tmp.a_2 = hdr.sip_meta.v_2 + hdr.sip_meta.v_3;
		//a_1 = i_1 << 5
		@in_hash { eg_md.sip_tmp.a_1 = hdr.sip_meta.v_1[26:0] ++ hdr.sip_meta.v_1[31:27]; }
	}
	action sip_1_b(){
		//a_3 = i_3 << 8
		eg_md.sip_tmp.a_3 = hdr.sip_meta.v_3[23:0] ++ hdr.sip_meta.v_3[31:24];

	}
	action sip_2_a(){
		//b_1 = a_1 ^ a_0
		eg_md.sip_tmp.i_1 = eg_md.sip_tmp.a_1 ^ eg_md.sip_tmp.a_0;
		//b_3 = a_3 ^ a_2
		eg_md.sip_tmp.i_3 = eg_md.sip_tmp.a_3 ^ eg_md.sip_tmp.a_2;
		// b_0 = a_0 << 16
		eg_md.sip_tmp.i_0 = eg_md.sip_tmp.a_0[15:0] ++ eg_md.sip_tmp.a_0[31:16];
		//b_2 = a_2
		eg_md.sip_tmp.i_2 = eg_md.sip_tmp.a_2;
	}

	action sip_3_a(){
		//c_2 = b_2 + b_1
		eg_md.sip_tmp.a_2 = eg_md.sip_tmp.i_2 + eg_md.sip_tmp.i_1;
		//c_0 = b_0 + b_3
		eg_md.sip_tmp.a_0 = eg_md.sip_tmp.i_0 + eg_md.sip_tmp.i_3;
		//c_1 = b_1 << 13
		@in_hash { eg_md.sip_tmp.a_1 = eg_md.sip_tmp.i_1[18:0] ++ eg_md.sip_tmp.i_1[31:19]; }
	}
	action sip_3_b(){
		//c_3 = b_3 << 7
		@in_hash { eg_md.sip_tmp.a_3 = eg_md.sip_tmp.i_3[24:0] ++ eg_md.sip_tmp.i_3[31:25]; }
	}

	action sip_4_a(){
		//d_1 = c_1 ^ c_2
		hdr.sip_meta.v_1 = eg_md.sip_tmp.a_1 ^ eg_md.sip_tmp.a_2;
		//d_3 = c_3 ^ c_0 i
		hdr.sip_meta.v_3 = eg_md.sip_tmp.a_3 ^ eg_md.sip_tmp.a_0;
		//d_2 = c_2 << 16
		hdr.sip_meta.v_2 = eg_md.sip_tmp.a_2[15:0] ++ eg_md.sip_tmp.a_2[31:16];

	}
	action sip_4_b_odd(){
		//d_0 = c_0
		hdr.sip_meta.v_0 = eg_md.sip_tmp.a_0;
	}
	action sip_4_b_even(){
		//d_0 = c_0 ^ message
		hdr.sip_meta.v_0 = eg_md.sip_tmp.a_0 ^ MSG_VAR_EG;
	}

	//compression rounds
	// round 0~(2*NUM_WORDS-1)
	#define eg_def_start_m(i) action start_m_## i ##_compression(){\
		eg_md.sip_tmp.round_type = ROUND_TYPE_COMPRESSION;		\
		MSG_VAR_EG = hdr.sip.m_## i;								\
	}
	__LOOP(NUM_WORDS,eg_def_start_m)

	//round 2*NUM_WORDS (first 2 finalization rounds)
	action start_finalization_a(){
		eg_md.sip_tmp.round_type = ROUND_TYPE_FINALIZATION;
		MSG_VAR_EG = 0;
		// also xor v2 with FF at beginning of first finalization pass
		hdr.sip_meta.v_2 = hdr.sip_meta.v_2 ^ 32w0xff;
	}
	//round 2*NUM_WORDS+2 (last 2 finalization rounds)
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
		if(!hdr.sip_meta.isValid()) exit;
		else tb_start_round.apply();

		//compression round: xor msg
		//note: for finalization rounds msg is zero, no effect//v3^=m
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

		if(hdr.sip_meta.curr_round < (NUM_WORDS*2+2)){
			//need more rounds in ingress pipeline, packet should be during recirculation right now
			hdr.sip_meta.curr_round = hdr.sip_meta.curr_round + 2;
		} else {
			final_round_xor();
		}
	}
}

/*************************************************************************/
/**************************  S W I T C H  ********************************/
/*************************************************************************/
Pipeline(
    HalfSipHashIngressParser(),
    HalfSipHashIngress(),
    HalfSipHashIngressDeparser(),
    HalfSipHashEgressParser(),
    HalfSipHashEgress(),
    HalfSipHashEgressDeparser()
) HalfSipHashPipeDS;