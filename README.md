# efsm-examples

Specific instructions can be found in examples' READMEs.

This is a guide which explains how to use the proposed P4 extensions.

### Compiling modified p4c

```bash
cd
git clone https://github.com/PolyMTL-P4/efsm-examples.git
git clone --recursive https://github.com/PolyMTL-P4/p4c-f4.git
cd p4c-f4
git switch flowblaze-efsm

mkdir build
cd build
cmake ..
make -j4
```

### Compiling an extended P4 program

To compile a program containing the proposed extensions, the command used is:

```bash
cd efsm-examples/flowlet_switching/p4src
../../../p4c-f4/build/p4test --std f4 flowlet_switching.p4
```

The parameter `--std f4` tells the compiler to use the compiler passes found in the p4c-f4/frontends/p4/fromF4/converters.cpp file and thus apply the conversion of the new structures.

This command generates a new P4 program `*-IR.p4` and table fill commands in the case of FlowBlaze.p4 backend.

In the future it would be interesting to directly compile the program directly for the BMv2 if the backend is compatible using the `p4c` command and not `p4test`.

The output of the compiler can be used for example in the p4-utils VM environment to test that the program is functional.

We should provide examples with all the configuration to test properly the output of the compiler.

### Testing

To test the compiler output, the VM from [p4-utils](https://github.com/nsg-ethz/p4-utils) can be used. We have to provide the *-IR.p4 file and table fill commands to make it work properly.

#### Disabling Debugging in the bmv2 Switch (taken from https://github.com/nsg-ethz/p4-utils)
As you have already seen in the previous exercises, if you do an `iperf`
between two directly connected hosts you get roughly a bandwidth of `~5mbps`.
In order to be able to send packets fast to the switch we can clone the
repository again with a different name and compile it with different flags.
Since this process can take up to 10 minutes you can just leave it running in
the background.
```bash
cd ~/p4-tools/
git clone https://github.com/p4lang/behavioral-model.git bmv2-opt
cd bmv2-opt
git checkout 62a013a15ed2c42b1063c26331d73c2560d1e4d0
./autogen.sh
./configure --without-nanomsg --disable-elogger --disable-logging-macros 'CFLAGS=-g -O2' 'CXXFLAGS=-g -O2'
make -j 2
sudo make install
sudo ldconfig
```
**IMPORTANT:** It is recommended that you do not run the `sudo make install`
command until you have a working solution. When using this optimized compilation
the switch will not generate log files, and thus it will be hard for you to
properly debug your program. Since we keep the two compiled versions of `bmv2`
in different folders, you can enable the one with the `debugging` enabled by
just running the `make install` command again:
```bash
cd ~/p4-tools/bmv2
sudo make install
sudo ldconfig
```
Thus by running `sudo make install` in `~/p4-tools/bmv2` or `~/p4-tools/bmv2-opt` you can easily enable each compiled version.

---

There are two functional extensions in our modified p4c compiler: p4class and FlowBlaze.p4 EFSM.

### p4class

The p4class is a system of code templating. You create a p4class which depends on several arguments.

Then the constructor of the p4class can be called with parameters, and it generates specific code.

The goal of the p4class is to factorize code in a P4 program, because a P4 program is often made of very repetitive parts.

That was more of an exercise to start tinkering with the p4c compiler, so it is not very very useful and mature, and we focus on the second part:


### efsm

The Extended Finite State Machine (EFSM) is a common model in network applications.

The [FlowBlaze.p4](https://github.com/ANTLab-polimi/flowblaze.p4) project proposed an implementation of EFSM in P4.

We propose a P4 syntax for this implementation of EFSM.

The syntax is inspired by the P4 packet header parser.

Example

```
efsm MyEFSM(in headers hdr,
            in metadata meta,
            in standard_metadata_t
                 standard_metadata) {

  state start {                               
    pkt = 1;                                 
    forward();                              
    transition select(hdr.tcp.dstPort) {     
      22: block;
      default: count;
    };
  }

  state count {
    pkt = pkt + 1;                        
    forward();
    transition select(pkt<10, hdr.tcp.dstPort){ 
      (_, 22): block;
      (true, _): count;
      (false, _): block;
  }

  state block {
    drop();
    transition block;                          
  }
}
```


This example can be included in a control block in a P4 program, and then it should be called (not yet implemented). Instead for now, the FlowBlaze main block is called.


#### Using the efsm


The code pieces that should be added to a P4 program using a FlowBlaze.p4 EFSM are:

The beginning of the program usually looks like this:

```
/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

################################################## FLOWBLAZE PARAMETERS #############################################

#define FLOW_SCOPE {  }
#define METADATA_OPERATION_COND (bit<32>)
#define EFSM_MATCH_FIELDS
#define CONTEXT_TABLE_SIZE
#define CUSTOM_ACTIONS_DEFINITION
#define CUSTOM_ACTIONS_DECLARATION
####################################################################################################################

#include "../flowblaze_lib/flowblaze_metadata.p4"

// HERE  here the definition of your header and metadata
#include "metadata_header.p4"

#include "../flowblaze_lib/flowblaze.p4"
```

The includes should be automatically integrated in the code in future versions.

Then in the ingress block the EFSM should be invoked:

```
control MyIngress(inout headers hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

    efsm MyEFSM(in headers hdr,
            in metadata meta,
            in standard_metadata_t
                 standard_metadata) {
        //Define the states and transitions
    }

   // Define your ingress processing

    apply {
        // Invoke EFSM
        FlowBlaze.apply(hdr, meta, standard_metadata);
    }
}
```
# Notes

This has been removed in the commit https://github.com/PolyMTL-P4/p4c-f4/commit/ed0361298e88a907e2be305c59ccb8902c1e32d6 but it may be useful in the future:
The parameter `--efsm fb` specifies the backend used to convert the `efsm` structure. Indeed, the modular design of the compiler allows the creation of other backends than FlowBlaze.p4, for example for other targets than the BMv2. 