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
            if (hdr.tcp.dstPort == 1234) {
                reg_state.write(flowblaze_metadata.update_state_index, (bit<16>)1);
            }
        }
        if (flowblaze_metadata.state == 1) {
            if (hdr.tcp.dstPort == 2345) {
                reg_state.write(flowblaze_metadata.update_state_index, (bit<16>)2);
            } else {
                reg_state.write(flowblaze_metadata.update_state_index, (bit<16>)0);
            }
        }
        if (flowblaze_metadata.state == 2) {
            if (hdr.tcp.dstPort == 3456) {
                reg_state.write(flowblaze_metadata.update_state_index, (bit<16>)3);
            } else {
                reg_state.write(flowblaze_metadata.update_state_index, (bit<16>)0);
            }
        }
        if (flowblaze_metadata.state == 3) {
            if (hdr.tcp.dstPort == 4567) {
                reg_state.write(flowblaze_metadata.update_state_index, (bit<16>)4);
            } else {
                reg_state.write(flowblaze_metadata.update_state_index, (bit<16>)0);
            }
        }
        if (flowblaze_metadata.state == 4) {
        }
    }
}

