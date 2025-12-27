#ifndef _CROSS_HEADERS_
#define _CROSS_HEADERS_

header ethernet_h {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header mac_loader_h {
	bit<32> key_0;
	bit<32> key_1;

	bit<32> m_0;
	bit<32> m_1;
	bit<32> m_2;
	bit<32> m_3;

	bit<16> nextJob;
}

header mac_result_h {
	bit<32> calculated_mac;
}

#endif