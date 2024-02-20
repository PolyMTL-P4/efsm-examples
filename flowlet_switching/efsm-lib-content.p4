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

