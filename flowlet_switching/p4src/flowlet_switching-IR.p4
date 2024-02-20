#include <core.p4>
#define V1MODEL_VERSION 20180101
#include <v1model.p4>

struct flowblaze_single_update_t {
    bit<8>  operation;
    bit<8>  result;
    bit<8>  op1;
    bit<8>  op2;
    bit<32> operand1;
    bit<32> operand2;
}

struct flowblaze_update_block_t {
    flowblaze_single_update_t u_block_0;
    flowblaze_single_update_t u_block_1;
    flowblaze_single_update_t u_block_2;
}

struct flowblaze_t {
    bit<32>                  lookup_state_index;
    bit<32>                  update_state_index;
    bit<16>                  state;
    bit<32>                  R0;
    bit<32>                  R1;
    bit<32>                  R2;
    bit<32>                  R3;
    bit<32>                  G0;
    bit<32>                  G1;
    bit<32>                  G2;
    bit<32>                  G3;
    bit<8>                   pkt_action;
    bit<32>                  pkt_data;
    flowblaze_update_block_t update_block;
}

const bit<16> TYPE_IPV4 = 0x800;
typedef bit<9> egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<6>    dscp;
    bit<2>    ecn;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct metadata {
    bit<14>     ecmp_hash;
    bit<14>     ecmp_group_id;
    bit<48>     flowlet_last_stamp;
    bit<48>     flowlet_time_diff;
    bit<13>     flowlet_register_index;
    bit<16>     flowlet_id;
    bit<16>     l4Length;
    flowblaze_t flowblaze_metadata;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
}

parser MyParser(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            default: accept;
        }
    }
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

register<bit<32>>(4) reg_G;
register<bit<32>>(2014) reg_R0;
register<bit<32>>(2014) reg_R1;
register<bit<32>>(2014) reg_R2;
register<bit<32>>(2014) reg_R3;
register<bit<16>>(2014) reg_state;
control UpdateLogic(inout headers hdr, inout flowblaze_t flowblaze_metadata, inout flowblaze_single_update_t update_block, in standard_metadata_t standard_metadata) {
    apply {
        hash(flowblaze_metadata.update_state_index, HashAlgorithm.crc32, (bit<32>)0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.ipv4.protocol }, (bit<32>)2014);
        if (update_block.operation != 0x0) {
            if (update_block.op1 == 0x0) {
                update_block.operand1 = flowblaze_metadata.R0;
            }
            if (update_block.op1 == 0x1) {
                update_block.operand1 = flowblaze_metadata.R1;
            }
            if (update_block.op1 == 0x2) {
                update_block.operand1 = flowblaze_metadata.R2;
            }
            if (update_block.op1 == 0x3) {
                update_block.operand1 = flowblaze_metadata.R3;
            }
            if (update_block.op1 == 0xf) {
                update_block.operand1 = flowblaze_metadata.G0;
            }
            if (update_block.op1 == 0x1f) {
                update_block.operand1 = flowblaze_metadata.G1;
            }
            if (update_block.op1 == 0x2f) {
                update_block.operand1 = flowblaze_metadata.G2;
            }
            if (update_block.op1 == 0x3f) {
                update_block.operand1 = flowblaze_metadata.G3;
            }
            if (update_block.op1 == 0xf1) {
                update_block.operand1 = flowblaze_metadata.pkt_data;
            }
            if (update_block.op1 == 0xf2) {
                update_block.operand1 = (bit<32>)standard_metadata.ingress_global_timestamp;
            }
            if (update_block.op2 == 0x0) {
                update_block.operand2 = flowblaze_metadata.R0;
            }
            if (update_block.op2 == 0x1) {
                update_block.operand2 = flowblaze_metadata.R1;
            }
            if (update_block.op2 == 0x2) {
                update_block.operand2 = flowblaze_metadata.R2;
            }
            if (update_block.op2 == 0x3) {
                update_block.operand2 = flowblaze_metadata.R3;
            }
            if (update_block.op2 == 0xf) {
                update_block.operand2 = flowblaze_metadata.G0;
            }
            if (update_block.op2 == 0x1f) {
                update_block.operand2 = flowblaze_metadata.G1;
            }
            if (update_block.op2 == 0x2f) {
                update_block.operand2 = flowblaze_metadata.G2;
            }
            if (update_block.op2 == 0x3f) {
                update_block.operand2 = flowblaze_metadata.G3;
            }
            if (update_block.op2 == 0xf1) {
                update_block.operand2 = flowblaze_metadata.pkt_data;
            }
            if (update_block.op2 == 0xf2) {
                update_block.operand2 = (bit<32>)standard_metadata.ingress_global_timestamp;
            }
            bit<32> t_result = 0;
            bit<1> op_done = 0b0;
            if (update_block.operation == 0x1) {
                t_result = update_block.operand1 + update_block.operand2;
                op_done = 0b1;
            }
            if (update_block.operation == 0x2) {
                t_result = update_block.operand1 - update_block.operand2;
                op_done = 0b1;
            }
            if (update_block.operation == 0x3) {
                t_result = update_block.operand1 >> (bit<8>)update_block.operand2;
                op_done = 0b1;
            }
            if (update_block.operation == 0x4) {
                t_result = update_block.operand1 << (bit<8>)update_block.operand2;
                op_done = 0b1;
            }
            if (update_block.operation == 0x5) {
                t_result = update_block.operand1 * update_block.operand2;
                op_done = 0b1;
            }
            if (op_done == 0b1) {
                if (update_block.result == 0x0) {
                    reg_R0.write(flowblaze_metadata.update_state_index, t_result);
                }
                if (update_block.result == 0x1) {
                    reg_R1.write(flowblaze_metadata.update_state_index, t_result);
                }
                if (update_block.result == 0x2) {
                    reg_R2.write(flowblaze_metadata.update_state_index, t_result);
                }
                if (update_block.result == 0x3) {
                    reg_R3.write(flowblaze_metadata.update_state_index, t_result);
                }
                if (update_block.result == 0xf) {
                    reg_G.write(0, t_result);
                }
                if (update_block.result == 0x1f) {
                    reg_G.write(1, t_result);
                }
                if (update_block.result == 0x2f) {
                    reg_G.write(2, t_result);
                }
                if (update_block.result == 0x3f) {
                    reg_G.write(3, t_result);
                }
            }
        }
    }
}

control UpdateState(inout headers hdr, inout flowblaze_t flowblaze_metadata, in standard_metadata_t standard_metadata) {
    apply {
        hash(flowblaze_metadata.update_state_index, HashAlgorithm.crc32, (bit<32>)0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.ipv4.protocol }, (bit<32>)2014);
        if (flowblaze_metadata.state == 0) {
            reg_state.write(flowblaze_metadata.update_state_index, (bit<16>)1);
        }
        if (flowblaze_metadata.state == 1) {
            if (flowblaze_metadata.R1 < (bit<32>)standard_metadata.ingress_global_timestamp) {
                reg_state.write(flowblaze_metadata.update_state_index, (bit<16>)1);
            }
        }
        if (flowblaze_metadata.state == 1) {
            if (flowblaze_metadata.R1 >= (bit<32>)standard_metadata.ingress_global_timestamp) {
                reg_state.write(flowblaze_metadata.update_state_index, (bit<16>)2);
            }
        }
        if (flowblaze_metadata.state == 2) {
            if (flowblaze_metadata.R1 < (bit<32>)standard_metadata.ingress_global_timestamp) {
                reg_state.write(flowblaze_metadata.update_state_index, (bit<16>)1);
            }
        }
        if (flowblaze_metadata.state == 2) {
            if (flowblaze_metadata.R1 >= (bit<32>)standard_metadata.ingress_global_timestamp) {
                reg_state.write(flowblaze_metadata.update_state_index, (bit<16>)2);
            }
        }
    }
}

control FlowBlaze(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".FlowBlaze.define_operation_update_state") action define_operation_update_state(bit<8> operation_0, bit<8> result_0, bit<8> op1_0, bit<8> op2_0, bit<32> operand1_0, bit<32> operand2_0, bit<8> operation_1, bit<8> result_1, bit<8> op1_1, bit<8> op2_1, bit<32> operand1_1, bit<32> operand2_1, bit<8> operation_2, bit<8> result_2, bit<8> op1_2, bit<8> op2_2, bit<32> operand1_2, bit<32> operand2_2, bit<8> pkt_action) {
        meta.flowblaze_metadata.pkt_action = pkt_action;
        meta.flowblaze_metadata.update_block.u_block_0.operation = operation_0;
        meta.flowblaze_metadata.update_block.u_block_0.result = result_0;
        meta.flowblaze_metadata.update_block.u_block_0.op1 = op1_0;
        meta.flowblaze_metadata.update_block.u_block_0.op2 = op2_0;
        meta.flowblaze_metadata.update_block.u_block_0.operand1 = operand1_0;
        meta.flowblaze_metadata.update_block.u_block_0.operand2 = operand2_0;
        meta.flowblaze_metadata.update_block.u_block_1.operation = operation_1;
        meta.flowblaze_metadata.update_block.u_block_1.result = result_1;
        meta.flowblaze_metadata.update_block.u_block_1.op1 = op1_1;
        meta.flowblaze_metadata.update_block.u_block_1.op2 = op2_1;
        meta.flowblaze_metadata.update_block.u_block_1.operand1 = operand1_1;
        meta.flowblaze_metadata.update_block.u_block_1.operand2 = operand2_1;
        meta.flowblaze_metadata.update_block.u_block_2.operation = operation_2;
        meta.flowblaze_metadata.update_block.u_block_2.result = result_2;
        meta.flowblaze_metadata.update_block.u_block_2.op1 = op1_2;
        meta.flowblaze_metadata.update_block.u_block_2.op2 = op2_2;
        meta.flowblaze_metadata.update_block.u_block_2.operand1 = operand1_2;
        meta.flowblaze_metadata.update_block.u_block_2.operand2 = operand2_2;
    }
    @name(".FlowBlaze.EFSM_table_counter") direct_counter(CounterType.packets_and_bytes) EFSM_table_counter;
    @name(".FlowBlaze.EFSM_table") table EFSM_table {
        actions = {
            define_operation_update_state;
            NoAction;
        }
        key = {
            meta.flowblaze_metadata.state: ternary @name("FlowBlaze.state");
        }
        default_action = NoAction;
        counters = EFSM_table_counter;
    }
    @name(".FlowBlaze.lookup_context_table") action lookup_context_table() {
        hash(meta.flowblaze_metadata.lookup_state_index, HashAlgorithm.crc32, (bit<32>)0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.ipv4.protocol }, (bit<32>)2014);
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
    @name(".FlowBlaze.forward") action forward() {
    }
    @name(".FlowBlaze.fill_meta_flowlet_id") action fill_meta_flowlet_id() {
        meta.flowlet_id = (bit<16>)meta.flowblaze_metadata.R0;
    }
    @name(".FlowBlaze.pkt_action_counter") direct_counter(CounterType.packets_and_bytes) pkt_action_counter;
    @name(".FlowBlaze.pkt_action") table pkt_action {
        key = {
            meta.flowblaze_metadata.pkt_action: ternary @name("FlowBlaze.pkt_action");
        }
        actions = {
            forward;
            fill_meta_flowlet_id;
            NoAction;
        }
        default_action = NoAction();
        counters = pkt_action_counter;
    }
    UpdateLogic() update_logic;
    UpdateState() update_state;
    apply {
        context_lookup.apply();
        EFSM_table.apply();
        update_logic.apply(hdr, meta.flowblaze_metadata, meta.flowblaze_metadata.update_block.u_block_0, standard_metadata);
        update_logic.apply(hdr, meta.flowblaze_metadata, meta.flowblaze_metadata.update_block.u_block_1, standard_metadata);
        update_logic.apply(hdr, meta.flowblaze_metadata, meta.flowblaze_metadata.update_block.u_block_2, standard_metadata);
        pkt_action.apply();
        update_state.apply(hdr, meta.flowblaze_metadata, standard_metadata);
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }
    action ecmp_group(bit<14> ecmp_group_id, bit<16> num_nhops) {
        hash(meta.ecmp_hash, HashAlgorithm.crc16, (bit<1>)0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.ipv4.protocol, meta.flowlet_id }, num_nhops);
        meta.ecmp_group_id = ecmp_group_id;
    }
    action set_nhop(macAddr_t dstAddr, egressSpec_t port) {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    table ecmp_group_to_nhop {
        key = {
            meta.ecmp_group_id: exact;
            meta.ecmp_hash    : exact;
        }
        actions = {
            drop;
            set_nhop;
        }
        size = 1024;
    }
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            set_nhop;
            ecmp_group;
            drop;
        }
        size = 1024;
        default_action = drop;
    }
    apply {
        if (hdr.ipv4.isValid()) {
            @atomic {
                FlowBlaze.apply(hdr, meta, standard_metadata);
            }
            switch (ipv4_lpm.apply().action_run) {
                ecmp_group: {
                    ecmp_group_to_nhop.apply();
                }
            }
        }
    }
}

control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
    }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(hdr.ipv4.isValid(), { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.dscp, hdr.ipv4.ecn, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

V1Switch(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(), MyComputeChecksum(), MyDeparser()) main;
