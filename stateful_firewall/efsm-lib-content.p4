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
            reg_state.write(flowblaze_metadata.update_state_index, (bit<16>)1);
        }
        if (flowblaze_metadata.state == 1) {
            t_result = (bit<32>)standard_metadata.ingress_global_timestamp + 5000000;
            reg_R0.write(flowblaze_metadata.update_state_index, t_result);
        }
        if (flowblaze_metadata.state == 1) {
            if (hdr.ipv4.srcAddr&0xffffff00 == 0xa000100) {
                reg_state.write(flowblaze_metadata.update_state_index, (bit<16>)2);
            }
        }
        if (flowblaze_metadata.state == 2) {
            t_result = (bit<32>)standard_metadata.ingress_global_timestamp + 5000000;
            reg_R0.write(flowblaze_metadata.update_state_index, t_result);
        }
        if (flowblaze_metadata.state == 2) {
            if ((bit<32>)standard_metadata.ingress_global_timestamp>flowblaze_metadata.R0) {
                reg_state.write(flowblaze_metadata.update_state_index, (bit<16>)1);
            }
        }
    }
}
