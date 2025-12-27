#include <core.p4>
#include <tna.p4>

#define KEY_0 0x33323130
#define KEY_1 0x42413938

#include "../../include/loops_macro.h"
#include "../../include/cross_def.h"
#include "../../include/cross_headers.p4"

// Low maximum for testing only
#ifndef MAX_SRH
#define MAX_SRH 4
#endif

// Layer 3 definitions
const bit<8> IPV6_ROUTE = 43;
const bit<8> EPIC = 252;

/*************************************************************************
************************** H E A D E R S *********************************
*************************************************************************/
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

header srh_fixed_h {
	bit<8>  nextHeader;
    bit<8>  headerLength;   // Length in 8-octet units, minus first 8 octets
    bit<8>  routingType;
    bit<8>  segmentsLeft;   // Index (0..N-1) of the next segment to process
    bit<8>  last_entry;
    bit<8>  flags;
    bit<16> tag;
}

header srh_seg_h {
	bit<128> segment_address;
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
************************** S T R U C T S *********************************
*************************************************************************/

struct headers_t {
	// Layer 2 headers
    ethernet_h ethernet;

	mac_loader_h mac_load;
	mac_result_h mac_res;

    // IPv6 headers
    ipv6_h ipv6;
	srh_fixed_h srh_fixed;
	srh_seg_h[MAX_SRH] srh_seg;

    // EPIC headers
    epic_h epic;
	epic_per_hop_h epic_per_hop;
}

// Metadata
struct ig_metadata_t {
	// Key rotation
	bit<32> rotated_k1;

    // Half-sip hash metadata
	bit<1> rnd_bit;
	bit<9> rnd_port_for_recirc;
	bool early_exit;

	// EPIC freshness
    bit<64> now_unix_s;
}

struct eg_metadata_t {
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

	ParserCounter() pc;

    state start {
        tof_ingress_parser.apply(packet, ig_md, ig_intr_md);

        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);

		transition select(hdr.ethernet.etherType){
			TYPE_IPV6: parse_ipv6;
			HOP_MAC_RESULT_ETHERTYPE: parse_mac_res;
			AUTH_MAC_RESULT_ETHERTYPE: parse_mac_res;

			default: accept;
		}
    }

	state parse_mac_res {
		packet.extract(hdr.mac_res);
		transition parse_ipv6;
	}

	state parse_ipv6{
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextHeader){
			IPV6_ROUTE: parse_srh;
            EPIC: parse_epic;
			default: reject;
        }
    }

	state parse_srh {
		packet.extract(hdr.srh_fixed);

		pc.set(hdr.srh_fixed.last_entry, /*max*/ 3, /*rotate*/ 0, /*mask*/ 1, /*add*/ 1);
		transition parse_seg0;
	}

	state parse_seg0 {
		packet.extract(hdr.srh_seg[0]);
		pc.decrement(1);
		transition select(pc.is_zero()){
			true: parse_epic;
			false: parse_seg1;
		}
	}

	state parse_seg1 {
		packet.extract(hdr.srh_seg[1]);
		pc.decrement(1);
		transition select(pc.is_zero()){
			true: parse_epic;
			false: parse_seg2;
		}
	}

	state parse_seg2 {
		packet.extract(hdr.srh_seg[2]);
		pc.decrement(1);
		transition select(pc.is_zero()){
			true: parse_epic;
			false: parse_seg3;
		}
	}

	state parse_seg3 {
		packet.extract(hdr.srh_seg[3]);
		pc.decrement(1);
		transition select(pc.is_zero()){
			true: parse_epic;
			false: reject;
		}
	}


   
    state parse_epic {
        packet.extract(hdr.epic);
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
					out eg_metadata_t eg_md,
					out egress_intrinsic_metadata_t eg_intr_md ){

    TofinoEgressParser() tofino_egress;

    state start {
        tofino_egress.apply(packet, eg_intr_md);
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

    /* -------- Random for recirculation -------- */
    Random<bit<1>>() rng;
    action get_rnd_bit() { ig_md.rnd_bit = rng.get(); }
    action route_to(bit<9> port) { ig_tm_md.ucast_egress_port = port; }
    action do_recirculate() { route_to(ig_md.rnd_port_for_recirc); }


	/*
	 *
	 *   EPIC actions
	 *
	 */
	action create_hop_authenticator(){
		hdr.mac_load.setValid();

		hdr.mac_load.key_0 = KEY_0;
		hdr.mac_load.key_1 = KEY_1;

		hdr.mac_load.m_0 = hdr.epic.path_ts;
		hdr.mac_load.m_1 = hdr.epic_per_hop.ingress_if
					++ hdr.epic_per_hop.egress_if
					++ hdr.epic_per_hop.segment_identifier;
		hdr.mac_load.m_2 = hdr.epic_per_hop.tsexp ++ (bit<24>) 0;
		hdr.mac_load.m_3 = 0;

		hdr.ethernet.etherType = HOP_MAC_LOAD_ETHERTYPE;
		hdr.mac_load.nextJob = HOP_MAC_RESULT_ETHERTYPE;

		// TODO: Route to HalfSip PIPE
		ig_tm_md.ucast_egress_port = ig_md.rnd_port_for_recirc;
		ig_md.early_exit = true;
	}

	action create_packet_authorization(){
		hdr.mac_load.setValid();

		ig_md.rotated_k1 = hdr.mac_res.calculated_mac[15:0]
						 ++ hdr.mac_res.calculated_mac[31:16];
		hdr.mac_load.key_0 = hdr.mac_res.calculated_mac;
		hdr.mac_load.key_1 = ig_md.rotated_k1;


		hdr.mac_load.m_0 = (bit<32>)(hdr.epic.src_as_host[63:32]);
		hdr.mac_load.m_1 = (bit<32>)(hdr.epic.src_as_host[31:0]);
		hdr.mac_load.m_2 = (bit<32>)(hdr.epic.packet_ts[63:32]);
		hdr.mac_load.m_3 = (bit<32>)(hdr.epic.packet_ts[31:0]);

		hdr.ethernet.etherType = AUTH_MAC_LOAD_ETHERTYPE;
		hdr.mac_load.nextJob = AUTH_MAC_RESULT_ETHERTYPE;

		hdr.mac_res.setInvalid();
		// TODO: Route to HalfSip PIPE
		ig_tm_md.ucast_egress_port = ig_md.rnd_port_for_recirc;
		ig_md.early_exit = true;
	}

	table epic_stage {
		key = {
			hdr.ethernet.etherType: exact;
		}

		size = 32;
		actions = {
			create_hop_authenticator;
			create_packet_authorization;
			nop;
		}

		default_action = nop();
	}

	/*
	 *
	 *   SRv6 actions
	 *
	 */
	#define def_srv6_next(i) action srv6_next_##i(){			\
		hdr.ipv6.dstAddr = hdr.srh_seg[i].segment_address;  \
		hdr.srh_fixed.segmentsLeft = hdr.srh_fixed.segmentsLeft - 1; \
	}

	__LOOP(MAX_SRH, def_srv6_next)


	#define srv6_actname(i) srv6_next_##i;
	table srv6 {
		key = {
			hdr.ipv6.dstAddr: exact;
			hdr.srh_fixed.segmentsLeft: exact;
		}

		size = 32;
		actions = {
			__LOOP(MAX_SRH, srv6_actname)
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
		if(ig_md.early_exit) { exit; }
		srv6.apply();

		if(hdr.ethernet.etherType == AUTH_MAC_RESULT_ETHERTYPE){
			if((bit <24>)(hdr.mac_res.calculated_mac[23:0]) != hdr.epic_per_hop.hop_validation){
				drop();
			}

			hdr.ethernet.etherType = TYPE_IPV6;
			hdr.mac_res.setInvalid();

			if(hdr.epic.per_hop_count > 1) hdr.epic.per_hop_count = hdr.epic.per_hop_count - 1;
			else {
				hdr.ipv6.nextHeader = hdr.epic.nextHeader;
				hdr.epic.setInvalid();
			}

			hdr.epic_per_hop.setInvalid();
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
    
    action nop() {}

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
		packet.emit(hdr.mac_load);
		packet.emit(hdr.ipv6);
		packet.emit(hdr.srh_fixed);
		packet.emit(hdr.srh_seg);
		packet.emit(hdr.epic);
		packet.emit(hdr.epic_per_hop);
	}
}

control EgressDeparser(
		packet_out packet,
		inout headers_t hdr,
		in eg_metadata_t eg_md,
		in egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr) {
	
    apply {

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