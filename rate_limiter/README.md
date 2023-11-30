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

Run the receiver and the sending scripts in `h2` and `h1` respectively:

```bash
mx h2
python receive.py
```

Send 15 packets from `h1` to `h2`. Only the first 10 will be received.

```bash
mx h1
python send.py 10.0.2.2 15
```


