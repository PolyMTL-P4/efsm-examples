# Packet Limiter

```
                   +--+
                   |h4|
                   ++-+
                    |
                    |
+--+      +--+     ++-+     +--+
|h1+------+s1+-----+s3+-----+h3|
+--+      +-++     +--+     +--+
            |
            |
          +-++
          |s2|
          +-++
            |
            |
          +-++
          |h2|
          +--+
```

## Introduction

Blocks flows after a certain amount of packets.


## How to run

Compile first using the modified p4test.

```bash
../../p4c-f4/build/p4test --std f4 --efsm fb p4src/packet_limiter.p4
```

Then copy table fill commands from `flowblaze-table-commands.txt` in s*-commands.txt

Run the topology:

```bash
sudo p4run
```

or
```bash
sudo python network.py
```
And test the bandwidth in mininet CLI with:

```bash
iperf h1 h2
```

