# Port Knocking Firewall

```bash
+--+      +--+     +--+
|h1+------+s1+-----+h2|
+--+      +--+     +--+
```

## Introduction

This application assumes that a client wants to connect
to a server protected by a firewall. In this scheme, the
client sends a sequence of packets with specific port numbers
acting as an identifier for a legitimate client.

## How to run

Compile first using the modified p4test.

```bash
../../p4c-f4/build/p4test --std f4 --efsm fb p4src/port_knocking_firewall.p4
```

Then copy table fill commands from `flowblaze-table-commands.txt` in s1-commands.txt

Run the topology:

```bash
sudo p4run
```

or
```bash
sudo python network.py
```

Run the receiver script in `h2`:

```bash
mx h2
python receive.py
```

Send traffic with specific port numbers using the `send.py` script.

```bash
mx h1
python send.py 10.0.1.2
```

