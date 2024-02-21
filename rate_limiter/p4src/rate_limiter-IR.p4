#include <core.p4>
#define V1MODEL_VERSION 20180101
#include <v1model.p4>

struct flowblaze_t {
    bit<32> lookup_state_index;
    bit<32> update_state_index;
    bit<16> state;
    bit<32> R0;
    bit<32> R1;
    bit<32> R2;
    bit<32> R3;
    bit<32> G0;
    bit<32> G1;
    bit<32> G2;
    bit<32> G3;
    bit<32> pkt_data;
}

typedef bit<9> egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
    udp_t      udp;
}

struct metadata_t {
    bit<16>     l4Length;
    flowblaze_t flowblaze_metadata;
}

register<bit<32>>(4) reg_G;
register<bit<32>>(2014) reg_R0;
register<bit<32>>(2014) reg_R1;
register<bit<32>>(2014) reg_R2;
register<bit<32>>(2014) reg_R3;
register<bit<16>>(2014) reg_state;
control UpdateLogic(inout headers hdr, inout flowblaze_t flowblaze_metadata, in standard_metadata_t standard_metadata) {
    apply {
        hash(flowblaze_metadata.update_state_index, HashAlgorithm.crc32, (bit<32>)0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, (bit<32>)2014);
        bit<32> t_result = 0;
        if (flowblaze_metadata.state == 0) {
            t_result = flowblaze_metadata.pkt_data;
            reg_R0.write(flowblaze_metadata.update_state_index, t_result);
            t_result = (bit<32>)standard_metadata.ingress_global_timestamp + 1000000;
            reg_R1.write(flowblaze_metadata.update_state_index, t_result);
        }
        if (flowblaze_metadata.state == 0) {
            reg_state.write(flowblaze_metadata.update_state_index, (bit<16>)1);
        }
        if (flowblaze_metadata.state == 1) {
            t_result = flowblaze_metadata.R0 + flowblaze_metadata.pkt_data;
            reg_R0.write(flowblaze_metadata.update_state_index, t_result);
        }
        if (flowblaze_metadata.state == 1) {
            if (flowblaze_metadata.R0 > 131072) {
                if (flowblaze_metadata.R1 >= (bit<32>)standard_metadata.ingress_global_timestamp) {
                    reg_state.write(flowblaze_metadata.update_state_index, (bit<16>)2);
                }
            }
            if (flowblaze_metadata.R1 < (bit<32>)standard_metadata.ingress_global_timestamp) {
                reg_state.write(flowblaze_metadata.update_state_index, (bit<16>)0);
            }
        }
        if (flowblaze_metadata.state == 2) {
            if (flowblaze_metadata.R1 < (bit<32>)standard_metadata.ingress_global_timestamp) {
                reg_state.write(flowblaze_metadata.update_state_index, (bit<16>)0);
            }
        }
    }
}

control FlowBlaze(inout headers hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {
    @name(".FlowBlaze.forward") action forward() {
    }
    @name(".FlowBlaze.drop") action drop() {
        mark_to_drop(standard_metadata);
        exit;
    }
    @name(".FlowBlaze.EFSM_table_counter") direct_counter(CounterType.packets_and_bytes) EFSM_table_counter;
    @name(".FlowBlaze.EFSM_table") table EFSM_table {
        actions = {
            forward;
            drop;
            NoAction;
        }
        key = {
            meta.flowblaze_metadata.state: ternary @name("FlowBlaze.state");
        }
        default_action = NoAction;
        counters = EFSM_table_counter;
    }
    @name(".FlowBlaze.lookup_context_table") action lookup_context_table() {
        hash(meta.flowblaze_metadata.lookup_state_index, HashAlgorithm.crc32, (bit<32>)0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, (bit<32>)2014);
        reg_state.read(meta.flowblaze_metadata.state, meta.flowblaze_metadata.lookup_state_index);
        reg_R0.read(meta.flowblaze_metadata.R0, meta.flowblaze_metadata.lookup_state_index);
        reg_R1.read(meta.flowblaze_metadata.R1, meta.flowblaze_metadata.lookup_state_index);
        reg_R2.read(meta.flowblaze_metadata.R2, meta.flowblaze_metadata.lookup_state_index);
        reg_R3.read(meta.flowblaze_metadata.R3, meta.flowblaze_metadata.lookup_state_index);
        reg_G.read(meta.flowblaze_metadata.G0, 0);
        reg_G.read(meta.flowblaze_metadata.G1, 1);
        reg_G.read(meta.flowblaze_metadata.G2, 2);
        reg_G.read(meta.flowblaze_metadata.G3, 3);
    }
    @name(".FlowBlaze.context_lookup_counter") direct_counter(CounterType.packets_and_bytes) context_lookup_counter;
    @name(".FlowBlaze.context_lookup") table context_lookup {
        actions = {
            lookup_context_table;
            NoAction;
        }
        default_action = lookup_context_table();
        counters = context_lookup_counter;
    }
    UpdateLogic() update_logic;
    apply {
        meta.flowblaze_metadata.pkt_data = (bit<32>)((bit<32>)meta.l4Length & 0xffffffff);
        context_lookup.apply();
        update_logic.apply(hdr, meta.flowblaze_metadata, standard_metadata);
        EFSM_table.apply();
    }
}

const bit<16> ETH_TYPE_IPV4 = 0x800;
const bit<16> ETH_TYPE_ARP = 0x806;
const bit<8> IP_TYPE_TCP = 0x6;
const bit<8> IP_TYPE_UDP = 0x11;
parser ParserImpl(packet_in packet, out headers hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETH_TYPE_IPV4: parse_ipv4;
            ETH_TYPE_ARP: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        meta.l4Length = hdr.ipv4.totalLen - 16w20;
        transition select(hdr.ipv4.protocol) {
            IP_TYPE_TCP: parse_tcp;
            IP_TYPE_UDP: parse_udp;
            default: accept;
        }
    }
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}

control ingress(inout headers hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {
    action main_forward(bit<9> port) {
        standard_metadata.egress_spec = port;
    }
    action main_drop() {
        mark_to_drop(standard_metadata);
        exit;
    }
    direct_counter(CounterType.packets_and_bytes) l2_fwd_counter;
    table t_l2_fwd {
        key = {
            standard_metadata.ingress_port: ternary;
            hdr.ethernet.dstAddr          : ternary;
            hdr.ethernet.srcAddr          : ternary;
            hdr.ethernet.etherType        : ternary;
        }
        actions = {
            main_forward;
            main_drop;
            NoAction;
        }
        default_action = NoAction();
        counters = l2_fwd_counter;
    }
    apply {
        if (hdr.ethernet.isValid()) {
            FlowBlaze.apply(hdr, meta, standard_metadata);
            t_l2_fwd.apply();
        }
    }
}

control egress(inout headers hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {
    apply {
    }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

control verifyChecksum(inout headers hdr, inout metadata_t meta) {
    apply {
        verify_checksum(hdr.ipv4.isValid(), { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

control computeChecksum(inout headers hdr, inout metadata_t meta) {
    apply {
        update_checksum(hdr.ipv4.isValid(), { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
        update_checksum_with_payload(hdr.tcp.isValid(), { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, 8w0, hdr.ipv4.protocol, meta.l4Length, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.tcp.seqNo, hdr.tcp.ackNo, hdr.tcp.dataOffset, hdr.tcp.res, hdr.tcp.ecn, hdr.tcp.ctrl, hdr.tcp.window, hdr.tcp.urgentPtr }, hdr.tcp.checksum, HashAlgorithm.csum16);
    }
}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;
