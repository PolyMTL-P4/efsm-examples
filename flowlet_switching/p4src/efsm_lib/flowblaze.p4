/*
* Copyright 2020 Daniele Moro <daniele.moro@polimi.it>
*                Davide Sanvito <davide.sanvito@neclab.eu>
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#ifndef _FLOWBLAZE_LIB_
#define _FLOWBLAZE_LIB_

// Useful for using flowblaze.p4 with fabric.p4
#ifndef FABRIC
#define METADATA_NAME metadata
#define HEADER_NAME headers
#endif

#define _NO_OP 0x00
#define _PLUS 0x01
#define _MINUS 0x02
#define _R_SHIFT 0x03
#define _L_SHIFT 0x04
#define _MUL 0x05

#define _R0 0x00
#define _R1 0x01
#define _R2 0x02
#define _R3 0x03

#define _G0 0x0F
#define _G1 0x1F
#define _G2 0x2F
#define _G3 0x3F

#define _META 0xF1
#define _TIME_NOW 0xF2
#define _EXPL 0xFF

#define NO_CONDITION    0b000
#define CONDITION_EQ    0b001
#define CONDITION_GT    0b010
#define CONDITION_GTE   0b011
#define CONDITION_LT    0b100
#define CONDITION_LTE   0b101

#ifndef CONTEXT_TABLE_SIZE
    #define CONTEXT_TABLE_SIZE 2014
#endif


// Global Data Variable: 4
register<bit<32>>(4) reg_G;

// 4 Flow Registers
register<bit<32>>(CONTEXT_TABLE_SIZE) reg_R0;
register<bit<32>>(CONTEXT_TABLE_SIZE) reg_R1;
register<bit<32>>(CONTEXT_TABLE_SIZE) reg_R2;
register<bit<32>>(CONTEXT_TABLE_SIZE) reg_R3;

// Register that stores the state of the flows
register<bit<16>>(CONTEXT_TABLE_SIZE) reg_state;


// ----------------------- UPDATE LOGIC BLOCK ----------------------------------
control UpdateLogic(inout HEADER_NAME hdr,
                    inout flowblaze_t flowblaze_metadata,
                    in standard_metadata_t standard_metadata) {

    apply{
        // Calculate update lookup index
        // TODO: (improvement) save hash in metadata when calculated for reading registers
        hash(flowblaze_metadata.update_state_index,
             HashAlgorithm.crc32,
             (bit<32>) 0,
             FLOW_SCOPE,
             (bit<32>) CONTEXT_TABLE_SIZE);

        bit<32> t_result = 0;
        if (flowblaze_metadata.state == 0) {
            t_result = 0 + 0;
            reg_R0.write(flowblaze_metadata.update_state_index, t_result);
            t_result = (bit<32>)standard_metadata.ingress_global_timestamp + 100000;
            reg_R1.write(flowblaze_metadata.update_state_index, t_result);
        }
        if (flowblaze_metadata.state == 1) {
            t_result = flowblaze_metadata.R0 + 99;
            reg_R0.write(flowblaze_metadata.update_state_index, t_result);
            t_result = (bit<32>)standard_metadata.ingress_global_timestamp + 100000;
            reg_R1.write(flowblaze_metadata.update_state_index, t_result);
        }
        if (flowblaze_metadata.state == 2) {
            t_result = (bit<32>)standard_metadata.ingress_global_timestamp + 100000;
            reg_R1.write(flowblaze_metadata.update_state_index, t_result);
        }

    }
}


// ----------------------- UPDATE STATE BLOCK ----------------------------------
control UpdateState(inout HEADER_NAME hdr,
                    inout flowblaze_t flowblaze_metadata,
                    in standard_metadata_t standard_metadata) {

    apply{
        // Calculate update lookup index
        // TODO: (improvement) save hash in metadata when calculated for reading registers
        hash(flowblaze_metadata.update_state_index,
             HashAlgorithm.crc32,
             (bit<32>) 0,
             FLOW_SCOPE,
             (bit<32>) CONTEXT_TABLE_SIZE);
        if (flowblaze_metadata.state == 0) {
        reg_state.write(flowblaze_metadata.update_state_index, (bit<16>)1);
        }
        if (flowblaze_metadata.state == 1) {
        if (flowblaze_metadata.R1<(bit<32>)standard_metadata.ingress_global_timestamp) {
                reg_state.write(flowblaze_metadata.update_state_index, (bit<16>)1);
            }
        }
        if (flowblaze_metadata.state == 1) {
        if (flowblaze_metadata.R1>=(bit<32>)standard_metadata.ingress_global_timestamp) {
                reg_state.write(flowblaze_metadata.update_state_index, (bit<16>)2);
            }
        }
        if (flowblaze_metadata.state == 2) {
        if (flowblaze_metadata.R1<(bit<32>)standard_metadata.ingress_global_timestamp) {
                reg_state.write(flowblaze_metadata.update_state_index, (bit<16>)1);
            }
        }
        if (flowblaze_metadata.state == 2) {
        if (flowblaze_metadata.R1>=(bit<32>)standard_metadata.ingress_global_timestamp) {
                reg_state.write(flowblaze_metadata.update_state_index, (bit<16>)2);
            }
        }
    }
}









// ------------------------------------------------------------------------------------

control FlowBlaze (inout HEADER_NAME hdr,
                 inout METADATA_NAME meta,
                 inout standard_metadata_t standard_metadata){
    // ------------------------ EFSM TABLE -----------------------------

    #ifdef CUSTOM_ACTIONS_DEFINITION
        CUSTOM_ACTIONS_DEFINITION
    #endif

    @name(".FlowBlaze.EFSM_table_counter")
    direct_counter(CounterType.packets_and_bytes) EFSM_table_counter;
    @name(".FlowBlaze.EFSM_table")
    table EFSM_table {
        actions = {
            #ifdef CUSTOM_ACTIONS_DECLARATION
                CUSTOM_ACTIONS_DECLARATION
            #endif
            NoAction;
        }
        key = {
            meta.flowblaze_metadata.state                : ternary @name("FlowBlaze.state");
        }
        default_action = NoAction;
        counters = EFSM_table_counter;
    }


    // ------------------------------------------------------------------------

    // ----------------------------- CONTEXT LOOKUP ---------------------------
    @name(".FlowBlaze.lookup_context_table")
    action lookup_context_table() {
        // Calculate lookup index
        hash(meta.flowblaze_metadata.lookup_state_index,
             HashAlgorithm.crc32,
             (bit<32>) 0,
             FLOW_SCOPE,
             (bit<32>)CONTEXT_TABLE_SIZE);

        // Extract the state and all the registers related to the current lookup
        reg_state.read(meta.flowblaze_metadata.state, meta.flowblaze_metadata.lookup_state_index);
        reg_R0.read(meta.flowblaze_metadata.R0, meta.flowblaze_metadata.lookup_state_index);
        reg_R1.read(meta.flowblaze_metadata.R1, meta.flowblaze_metadata.lookup_state_index);
        reg_R2.read(meta.flowblaze_metadata.R2, meta.flowblaze_metadata.lookup_state_index);
        reg_R3.read(meta.flowblaze_metadata.R3, meta.flowblaze_metadata.lookup_state_index);

        // Extract also the global register
        reg_G.read(meta.flowblaze_metadata.G0, 0);
        reg_G.read(meta.flowblaze_metadata.G1, 1);
        reg_G.read(meta.flowblaze_metadata.G2, 2);
        reg_G.read(meta.flowblaze_metadata.G3, 3);
    }

    @name(".FlowBlaze.context_lookup_counter")
    direct_counter(CounterType.packets_and_bytes) context_lookup_counter;
    @name(".FlowBlaze.context_lookup")
    table context_lookup {
        actions = {
            lookup_context_table;
            NoAction;
        }
        default_action = lookup_context_table();
        counters = context_lookup_counter;
    }
    // --------------------------------------------------------------------------

    UpdateLogic() update_logic;
    UpdateState() update_state;
    apply {
        #ifdef METADATA_OPERATION_COND
            // FIXME: is cast really necessary?
            meta.flowblaze_metadata.pkt_data = (bit<32>) (METADATA_OPERATION_COND & 0xFFFFFFFF);
        #endif

        context_lookup.apply();
        update_logic.apply(hdr, meta.flowblaze_metadata, standard_metadata);
        EFSM_table.apply();
        update_state.apply(hdr, meta.flowblaze_metadata, standard_metadata);
    }
}
#endif
