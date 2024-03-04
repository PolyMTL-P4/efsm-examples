/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>


################################################## FLOWBLAZE PARAMETERS #############################################

#define FLOW_SCOPE {  hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }
#define CUSTOM_ACTIONS_DEFINITION @name(".FlowBlaze.forward") \
                                  action forward() { \
                                    \
                                  } \
                                  @name(".FlowBlaze.drop") \
                                  action drop() { \
                                    mark_to_drop(standard_metadata); \
                                    exit; \
                                  }
#define CUSTOM_ACTIONS_DECLARATION forward; drop;
// Configuration parameter left black because not needed
//    #define METADATA_OPERATION_COND
    #define EFSM_MATCH_FIELDS hdr.ipv4.srcAddr: lpm;
//    #define CONTEXT_TABLE_SIZE
####################################################################################################################

#include "flowblaze_lib/flowblaze_metadata.p4"
#include "include/headers.p4"
#include "flowblaze_lib/flowblaze.p4"

const bit<16> ETH_TYPE_IPV4 = 0x800;
const bit<16> ETH_TYPE_ARP  = 0x806;
const bit<8>  IP_TYPE_TCP   = 0x06;
const bit<8>  IP_TYPE_UDP   = 0x11;


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
         transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETH_TYPE_IPV4: parse_ipv4;
            ETH_TYPE_ARP:  accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        meta.tcpLength = hdr.ipv4.totalLen - 16w20;
        if (hdr.ipv4.srcAddr < hdr.ipv4.dstAddr) {
            meta.srcAddrHash = hdr.ipv4.srcAddr;
            meta.dstAddrHash = hdr.ipv4.dstAddr;
        } else {
            meta.srcAddrHash = hdr.ipv4.dstAddr;
            meta.dstAddrHash = hdr.ipv4.srcAddr;
        }
        transition select(hdr.ipv4.protocol) {
            IP_TYPE_TCP:    parse_tcp;
            IP_TYPE_UDP:    parse_udp;
            default:        accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        meta.applLength = hdr.ipv4.totalLen - 16w40;
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        meta.applLength = meta.tcpLength - 16w28;
        transition accept;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {


    efsm stateful_firewall(inout headers hdr) {
        state start {
            drop();
            transition closed;
        }

        state closed {
            drop();
            t_lim = now + 5000000;
            transition select (hdr.ipv4.srcAddr & 0xFFFFFF00) {
                0x0a000100: allowed;
                default: closed;
            }
        }

        state allowed {
            forward();
            t_lim = now + 5000000;
            transition select (now > t_lim) {
                true: start;
                false: allowed;
            }
        }
    }

    action main_drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {

        //set the src mac address as the previous dst, this is not correct right?
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;

       //set the destination mac address that we got from the match in the table
        hdr.ethernet.dstAddr = dstAddr;

        //set the output port that we also get from the table
        standard_metadata.egress_spec = port;

        //decrease ttl by 1
        hdr.ipv4.ttl = hdr.ipv4.ttl -1;

    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            main_drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        if (hdr.ipv4.isValid()){
            FlowBlaze.apply(hdr, meta, standard_metadata);
            ipv4_lpm.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {

        //parsed headers have to be added again into the packet.
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);

    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;