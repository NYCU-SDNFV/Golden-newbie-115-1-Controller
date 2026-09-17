# Lab 1 Report — SDN: OVS + your own OpenFlow controller

**Student ID:** TODO  **Name:** TODO

> Keep the table layouts exactly as they are (the autograder parses the row
> labels). Replace every TODO. Numbers must come from *your* `results/*.json`;
> the grader cross-checks them. Write in English.

## Part A — the five runs, measured

Fill in from `results/<mode>.json` (`make a0` … `make a4` print the same numbers).

| Mode       | OpenFlow flows | FDB entries | leak to h3 (ICMP pkts) | first-RTT ratio | packet-ins |
|------------|----------------|-------------|------------------------|-----------------|------------|
| flood      | TODO           | TODO        | TODO                   | TODO            | TODO       |
| normal     | TODO           | TODO        | TODO                   | TODO            | TODO       |
| reference  | TODO           | TODO        | TODO                   | TODO            | TODO       |
| controller | TODO           | TODO        | TODO                   | TODO            | TODO       |
| proactive  | TODO           | TODO        | TODO                   | TODO            | TODO       |

**A.0 The wire.** Open `captures/reference.pcap` in Wireshark (it decodes OpenFlow) and list the message sequence of the handshake up to and including the first `FLOW_MOD`, with direction and `xid`. Then answer: (a) which messages are request/reply pairs and how do you know; (b) the reference sends `FLOW_MOD`s of two different lengths — decode both `ofp_match` structures byte by byte and explain the difference; (c) what is the `xid` of `PACKET_IN` and why.

TODO

**A.1 Where does the forwarding state live in each mode?** (switch FDB / OpenFlow table / controller memory / nowhere) — one line per mode, and say *who* wrote it there.

TODO

**A.2 The first packet.** Explain the *first-RTT ratio* column: what exactly happens to the first ICMP request in each mode, and why do `reference`/`controller` differ from `proactive`? Then compare `reference` with `controller`: they exchange the *same* messages (check the captures) — if their first-RTT ratios differ by an order of magnitude, find out why. Wireshark's time column on `captures/controller.pcap` and the number of TCP segments per PACKET_IN are the clues; name the mechanism and the one-line fix.

TODO

**A.3 Why is A3 "SDN" while A2 (NORMAL) is not?** Both learn MACs and both reach 0 leak. Point at the specific difference in *where the decision is made* and *what you can change*.

TODO

## Part B — Design Problem: 9-Switch Ring Shortest-Path Controller

> Fill this in after completing `harness/sp_controller.py`.

**B.1 Design overview.** Describe how your controller satisfies each requirement. In particular: how do you avoid broadcast storm on a ring? How do you ensure unicast stays on the data plane after setup?

TODO

**B.2 Scalability.** A new host h10 is plugged into s3 (on a new port). Without implementing it, describe what your controller would need to do to handle this. Which flows change? Which don't?

TODO

---

## Part C — design judgement and failure modes

**C.1 Which mode for which network?** For each of: (a) a fixed 3-node lab bench, (b) a campus access network where laptops move, (c) a datacenter pod with a policy requirement ("host X may only talk to Y") — pick a mode and defend it with numbers from your table (flows, leak, first-packet cost, state location). A wrong pick with good reasoning scores better than a right pick with none.

TODO

**C.2 Failure modes.** Predict the behaviour of each mode. You are strongly encouraged to *test* at least one cell with `make hold MODE=<mode>` and describe what you saw — the checkpoint will ask you to do exactly this live.

| Scenario         | flood | normal (NORMAL) | controller (yours) / proactive |
|------------------|-------|-----------------|--------------------------------|
| MAC move         | TODO  | TODO            | TODO                           |
| MAC flooding     | TODO  | TODO            | TODO                           |
| controller down  | TODO  | TODO            | TODO                           |

*MAC move* = a host is re-plugged into another switch port. *MAC flooding* = an attacker sends frames from thousands of random source MACs. *Controller down* = the controller process dies while hosts keep talking (think about `fail_mode` `secure` vs `standalone`).

**C.3 What would you change in your controller** so that MAC move does *not* leave a stale flow behind? Describe the mechanism (you do not have to implement it — yet).

TODO
