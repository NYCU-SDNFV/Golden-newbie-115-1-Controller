# Lab 1 — SDN: Open vSwitch + Your Own OpenFlow Controller

**SDNFV (CSIC30127), 115-1 — NYCU Institute of Network Engineering**

> **Grading.** 100 autograded points (the take-home part, 50 % of the lab grade
> — AI tools allowed) plus an **in-person checkpoint and viva** (50 % — proctored,
> no personal AI). Every autograded point is visible: after `make up`, `make test`
> checks release freshness and runs the same rubric checks. Official grading
> uses the current published canonical bundle, not your local copies.
>
> **You may use AI tools for the take-home part.** Record how in `ai-usage.md`.
> You are still responsible for being able to explain every line you submit —
> the viva runs on *your* controller, byte by byte.

---

## 1. What this lab is about

OpenFlow is the protocol between an SDN controller and a switch. Frameworks
(Ryu, os-ken, ONOS, …) hide it behind objects; in this lab **you speak it
yourself**: a Python program with nothing but `socket` and `struct` that
accepts the switch's TCP connection, completes the handshake, keeps the
connection alive, decodes the packets the switch sends up, and encodes the
flow entries and packets it sends down. In Part A, the application on top is a learning switch, so you can focus on
the protocol bytes. Part B extends the lab to a multi-switch shortest-path
controller, where you design how the network discovers and forwards traffic.
Part C asks you to analyse your measurements and failure modes.

### Part A — Single-switch forwarding

To see what your controller changes, the same traffic is forwarded five ways:

| Mode | Who decides | Where the state lives | You write |
|---|---|---|---|
| **A0 reference** | a *given* controller built on a framework | controller memory + flows | nothing — you record what it says on the wire |
| **A1 flood** (hub) | nobody | nowhere | one OpenFlow rule |
| **A2 normal** (learning inside the switch) | OVS's built-in L2 pipeline | the switch FDB | one OpenFlow rule |
| **A3 controller** — *the lab* | **your program, on every packet-in** | controller memory + the flows you install | an OpenFlow 1.3 speaker, from the header up |
| **A4 proactive** | you, before the first packet | the OpenFlow table | one rule per host |

Topology (`topo/lab1_topo.py`, given):

```
        ┌────────────────── container "lab1" ─────────────────────┐
        │                                                         │
        │   h1 ─── port 1 ┐                                       │
        │   h2 ─── port 2 ┼─ s1  (OVS, userspace datapath,        │
        │   h3 ─── port 3 ┘       OpenFlow 1.3, fail_mode secure, │
        │                         EMPTY table)                    │
        │                          │ tcp 127.0.0.1:6653           │
        │                          ▼                              │
        │            harness/controller.py   (A3: yours)          │
        │            reference/refctl.py     (A0: given)          │
        └─────────────────────────────────────────────────────────┘
```

**h3 is the eavesdropper.** It never sends anything. Every h1↔h2 ICMP packet
that shows up on h3 is *leaked* unicast — the number that separates a hub
from a switch. The switch starts with **no controller and an empty table**; an
OpenFlow 1.3 switch drops what matches nothing, so nothing works until your
code says how.

### Part B — Multi-switch shortest-path controller

Your Part A controller manages **one** switch. Part B is a **design problem**:
nine switches in a ring, and your controller must figure everything out from
scratch. It is worth 20 of the 100 autograded points (B1 and B2, 10 each) and
it is the main preparation for the checkpoint.

#### Requirements

1. **The controller knows nothing at boot** — it does not know which switches are connected to each other, which ports connect to hosts or other switches, where the hosts are, or what the topology looks like.
2. **Unicast packets must take the shortest path** — no detours. s1→s5 must be 4 hops, not 5.
3. **There must be no chance of a broadcast storm** — on a ring topology a naive flood loops forever. Your design must not allow a storm at any stage.
4. **Any host must be able to ping any other host** — including ARP.
5. **Once a path is established, every packet must stay on the data plane** — the controller no longer takes part in forwarding. Each unicast packet follows a flow installed on the switch and never reaches the controller.
6. **The design must scale to hosts being added arbitrarily** — you do not have to implement this, but your report must explain how your design handles a previously unseen host appearing on some switch.

#### Topology

```
    9 switches in a ring, 9 hosts (h1..h9)

               h1                 Port layout (all switches):
               |                    port 1 = host
              s1                    port 2 = clockwise neighbour
             /    \                 port 3 = counter-clockwise
      h9---s9      s2---h2
           |        |             Max shortest path = 4 hops (floor(9/2))
      h8---s8      s3---h3
           |        |             s1→s5: clockwise  s1→s2→s3→s4→s5 = 4 hops ✓
      h7---s7      s4---h4        s1→s5: counter-CW s1→s9→s8→s7→s6→s5 = 5 hops ✗
             \    /
              s6--s5
              |   |
              h6  h5
```

Your controller must discover the topology itself — do not assume N=9. You may
assume **N < 20**; the ring is never larger than that.

#### Design questions

There are **no TODO markers** in `sp_controller.py`. You get two empty methods
and six requirements. How you satisfy them is up to you. Some things to think
about:

- How do you discover which switches are connected to each other?
- How do you discover where hosts are?
- How do you compute shortest paths on a ring?
- How do you avoid broadcast storm when flooding on a ring?
- When do you install flows? How do you ensure unicast stays on the data plane?
- The 11-switch test uses random MACs. What does that break if you hardcode?


## 2. What you have to change

| File | What to do |
|---|---|
| `harness/modes.py` | Four small functions: `capture_filter()` (A0), `flood()`, `normal()`, `proactive()`. |
| `harness/controller.py` | **The lab.** Ten `TODO`s, `T1`–`T9`: HELLO reply, ECHO reply, FEATURES request/reply, PACKET_IN decoding (fixed fields, OXM match TLVs, Ethernet header), FLOW_MOD and PACKET_OUT encoding, and the learning logic that ties them together. The TCP server loop, message framing, constants and an ERROR decoder are given. |
| `harness/sp_controller.py` | Implement `on_switch_ready()` and `on_packet_in()`. The select() loop, handshake, and OpenFlow encoding/decoding helpers are given — they are the same code from Part A3. Everything else (topology discovery, host learning, path computation, flow installation, broadcast handling) is your design. You may also rewrite the whole file from scratch if you prefer — the given structure is a convenience, not a requirement. |
| `REPORT.md` | Tables from your own `results/*.json`, the wire analysis (A.0), your Part B explanation of how to handle new hosts, and Part C. Keep the table row labels — the grader parses them. |
| `ai-usage.md` | How you used AI tools (or that you did not). |

Everything else — `Dockerfile`, `docker-compose.yml`, `Makefile`, `topo/`,
`reference/`, `harness/run_mode.py`, `tests/`, `.github/` — is given and
**must not be modified**. Official grading downloads a fresh canonical bundle
of checks and policy files; changing your local tests cannot change it.
Files listed in `.github/policy/manifest.sha256` are integrity-checked against
the canonical manifest. `.github/` is also restored by `gh student submit`.
Editing a test to make it pass is an academic integrity violation and gains nothing.
An outdated starter or changed protected file fails the whole take-home
integrity gate (0/100), not just the 5-point policy item. Update the starter
through the supported flow below; do not edit the manifest.

`harness/controller.py` **must use the standard library only.** The grader
checks its imports. os-ken is in the container for the reference controller;
importing it (or Ryu, or Scapy) in your controller fails A3a.

## 3. How to work

```bash
make up                       # build + start the container (as in Lab 0)
make a0                       # run the reference controller, record captures/reference.pcap
make a1 a2 a4                 # the one-rule modes
make a3                       # run YOUR controller: A3a handshake -> A3b decode -> A3c encode -> A3d behaviour
make b                        # run both Part B ring checks
make c                        # run the Part C report check (same as make report)
make report                   # cross-check REPORT.md against your results
make test                     # everything, in autograder order
make hold MODE=controller     # bring a mode up and stay in the Mininet CLI
make shell                    # a shell inside the container
make clean                    # tear down, delete results/ and captures/
```

Each `make aN` runs `harness/run_mode.py <mode>` **inside the container**: it
builds the topology, applies the mode, has h3 sniff, pings h1→h2 six times
and writes `results/<mode>.json`. For the reference and controller modes it
also records the switch↔controller TCP conversation to
`captures/<mode>.pcap`. Then `.github/grade/lab1_grade.py` grades the JSON
**and the capture** and prints `PASS`/`FAIL` lines **with hints**. Read the
hints; they were written for the exact mistake you are about to make.

> **On Windows, work inside WSL 2** — not Git Bash and not PowerShell (see the
> Lab 0 README for why). Docker Desktop with the WSL 2 backend is fine.

The supplied Compose file caps `nofile` at 65536. Keep that setting:
`mnexec` closes descriptors one by one when creating a Mininet host. Some
Docker installations inherit a limit above one billion, turning each host
startup into minutes of CPU work rather than a networking failure.

### The recommended order

1. `make a0`. Open `captures/reference.pcap` in Wireshark (`Analyze →
   Decode As…` is not needed; port 6653 is recognised as OpenFlow). You now
   have a byte-exact recording of a conversation that works.
2. `make a1`, `a2`, `a4` — quick, and they teach you `ovs-ofctl` flow syntax.
3. `harness/controller.py`, in TODO order. After every one or two TODOs run
   `make a3`; the four sub-checks tell you how far the conversation got. When
   the switch answers with `OFPT_ERROR`, the given `decode_error()` prints
   what it objected to, and `captures/controller.pcap` sits right next to the
   reference capture for a byte-by-byte comparison.
4. `harness/sp_controller.py` for Part B. Use the ring workflow below to
   develop and inspect your design; `make test` includes both B1 and B2.
5. `REPORT.md` and `ai-usage.md`, then `make test`.

### Running the Part A controller by hand

```bash
make shell
python3 harness/controller.py -v                    # terminal 1: every message in/out is logged
python3 harness/run_mode.py controller --hold       # terminal 2: reuses the running controller
```

Inside the Mininet CLI: `h1 ping -c 3 h2`, `sh ovs-ofctl -O OpenFlow13
dump-flows s1`, `sh ovs-appctl fdb/show s1`, `h3 tcpdump -nn -c 5 icmp`,
`sh tcpdump -i lo -nn port 6653`.

### Running the Part B controller by hand

```bash
# Terminal 1: start your shortest-path controller
make shell
python3 harness/sp_controller.py -v

# Terminal 2: start the 9-switch ring (reuses the running controller)
make shell
python3 topo/ring_topo.py pingall           # 0% dropped = success
python3 topo/ring_topo.py cli               # interactive: try pingall, dump-flows
```

Inside the Mininet CLI: `pingall`, `sh ovs-ofctl -O OpenFlow13 dump-flows s1`,
`h1 traceroute -n 10.0.0.3`.

### Reading

- **OpenFlow Switch Specification 1.3.5** (ONF TS-023) — the only document
  you really need. §7.1 header, §7.2.3 OXM match, §7.2.4/§7.2.5 instructions
  and actions, §7.3.1 features, §7.3.4.1 flow-mod, §7.3.7 packet-out,
  §7.4.1 packet-in, §7.4.4 error, §7.5 handshake / echo. The docstrings in
  `controller.py` quote the relevant structs.
- Python `struct` — <https://docs.python.org/3/library/struct.html>
  (`!` = network byte order; `x` = pad byte).
- Wireshark's OpenFlow dissector shows every field name and offset when you
  click a byte in the hex pane. Use it on both captures.
- `ovs-ofctl` flow syntax — `man ovs-ofctl`, *Flow Syntax*, for A1/A2/A4.

#### Reference: LLDP TLV format

```
Ethernet header (14 bytes):
    dst:  01:80:c2:00:00:0e  (LLDP multicast)
    src:  <6 bytes, e.g. low bytes of dpid>
    type: 0x88cc

Each TLV:
    header: 2 bytes = uint16 where top 7 bits = type, low 9 bits = length
    value:  `length` bytes

TLV type 1 — Chassis ID:
    subtype byte (use 7 = "locally assigned") + dpid as 8 big-endian bytes
    → total value length = 1 + 8 = 9

TLV type 2 — Port ID:
    subtype byte (use 7) + port_no as 4 big-endian bytes
    → total value length = 1 + 4 = 5

TLV type 0 — End of LLDPDU:
    length = 0 → the header is just 0x0000 (2 zero bytes)
```

## 4. The checks (100 points)

| # | Check | Points | What it really tests |
|---|---|---|---|
| — | policy: repo layout / protected files unchanged | 5 + 5 | Base rules, as in Lab 0 |
| — | environment builds and starts | 10 | `make up` |
| 0 | `tests/00_env.sh` | 0 | container up, tools present, repo mounted |
| A0 | `tests/05_a0_reference.sh` | 5 | `capture_filter()` points tcpdump at the control channel: the capture holds HELLO both ways, PACKET_IN and FLOW_MOD |
| A1 | `tests/10_a1_flood.sh` | 5 | ping works **and** h3 sees the traffic; a flood action is installed |
| A2 | `tests/20_a2_normal.sh` | 5 | `NORMAL` in use, FDB learned h1/h2, 0 leak, no hand-written `dl_dst` flows |
| A3a | `tests/30_a3a_handshake.sh` | 5 | stdlib-only imports; HELLO answered; FEATURES_REQUEST/REPLY with matching `xid`; every ECHO_REQUEST answered with the same `xid` and payload; still connected at the end; no ERROR about handshake messages |
| A3b | `tests/31_a3b_packet_in.sh` | 5 | PACKET_INs arrive and (almost) every one gets a PACKET_OUT; no ERROR about your PACKET_OUTs; ping works |
| A3c | `tests/32_a3c_flow_mod.sh` | 5 | FLOW_MODs sent and none rejected; table-miss flow present; `dl_dst` flows with the right ports |
| A3d | `tests/33_a3d_learning.sh` | 15 | 0 leak; no `NORMAL`; no flow that floods; learned flows installed *after* the first PACKET_IN (reactive, not pre-programmed) |
| A4 | `tests/40_a4_proactive.sh` | 5 | ping works (yes, ARP!), one flow per host, no controller, no `NORMAL`, 0 leak *including the first packet* |
| B1 | `tests/50_b_ring.sh` | 10 | 9-switch ring: pingall passes, unicast flows follow the shortest path, no leak, no storm |
| B2 | `tests/51_b_ring11.sh` | 10 | 11-switch ring with random host MACs: same checks — nothing hardcoded |
| — | `tests/60_git.sh` | 0 | ≥ 3 commits of your own, `.gitignore` tracked, no litter — not scored, but still run |
| C | `tests/70_report.sh` | 10 | `REPORT.md` tables complete, numbers match **your** results, all failure-mode cells filled, `ai-usage.md` filled |

The A3 checks read the **capture**, not your log: what counts is what the
switch actually received and accepted. Absolute latencies are never graded —
they differ between laptops and the CI runner — but they are recorded, and
`REPORT.md` asks about them.

### Part B test topologies

Your controller is tested on **two** topologies:

| Test | Topology | Switches | Host MACs | What it checks |
|---|---|---|---|---|
| B1 | `ring_topo.py` | 9 | sequential (`00:...:01`–`09`) | pingall, shortest-path flows, no unicast leak |
| B2 | `ring11_topo.py` | 11 | **random (different every run)** | same — your controller must not hardcode switch count or MAC patterns |

Both rings use the userspace datapath, just like Part A. The checks verify
zero loss in both directions, a destination flow on every switch, and bounded
broadcast propagation. They then disconnect every control channel and repeat
the pings: a controller that forwards every packet with `PACKET_OUT` is not a
data-plane solution. Results and controller logs are saved under `results/`.

Stop a manually started Part B controller before `make b`; the tests start
and clean up their own controller process.

## 5. Things that will bite you

1. **An empty OpenFlow 1.3 table drops everything.** 100 % loss with no error
   is the symptom. Look at the flow table the test prints.
2. **Length fields must be right, everywhere.** The header length covers the
   whole message; `ofp_match.length` covers the OXM TLVs *but not* the padding
   that follows; the instruction length covers the instruction *and* its
   actions; the OUTPUT action is always 16 bytes. OVS answers a wrong length
   with `OFPT_ERROR BAD_LEN` — and then usually drops the connection.
3. **Padding to 8 bytes** after the match is not optional. An empty match is
   4 bytes long and occupies 8.
4. **ECHO.** OVS sends `ECHO_REQUEST` every two seconds in this lab
   (`inactivity_probe=2000`). Ignore one and the switch disconnects; your
   log will say "connection lost" a few seconds into every run.
5. **`actions=FLOOD` makes OVS learn nothing.** After A1, `fdb/show` is empty.
   Learning happens only under `NORMAL`, or in *your* controller.
6. **ARP.** Before h1 can ping h2 it broadcasts an ARP request. In A4 no
   `dl_dst=<host>` rule matches it. In A3 it is your first PACKET_IN.
7. **Never install a flow whose action is FLOOD** for an unknown destination.
   Flood the *packet* (PACKET_OUT), not the *flow*. The grader checks.
8. **The packet that caused the PACKET_IN is in your process, not in the
   switch.** The flow you install applies to the *next* packet; this one needs
   a PACKET_OUT or it is lost.
9. **Match on `eth_dst` only and MAC move will leave a stale flow.** The
   skeleton does exactly that on purpose. `REPORT.md` C.3 asks how you would
   fix it; the checkpoint asks you to do it — which means encoding two more
   OXM fields and a `FLOW_MOD` with `command=DELETE`.
10. **Your first packet is slow. Slower than the reference's.** Same messages,
    very different latency. `REPORT.md` A.2 asks why; the answer is one line
    of code and a classic TCP mechanism.

## 6. The in-person checkpoint and viva (50 % of the lab grade)

You will sit at a course VM with **your** repository at its state at the
deadline, no internet, no AI. Expect to:

- **predict** (on paper) how each mode reacts to a scenario the TA injects —
  a host re-plugged to another port, a new host appearing, a forwarding loop;
- **demonstrate** the actual behaviour with `make hold MODE=...` and
  `ovs-ofctl` / `fdb/show` / `tcpdump`;
- **modify your controller live** so it copes — this touches the match
  encoding and a `FLOW_MOD` you have not sent before;
- **read bytes**: the TA will point at an offset in one of your captured
  messages and ask what it is and what happens if it changes;
- **defend your report** — where the state lives in each mode, what
  `fail_mode` changes when the controller dies, why the first packet costs
  what it costs.

If you wrote `harness/controller.py` yourself and can explain every line,
nothing at the checkpoint will surprise you. If you cannot, the take-home
part will be re-examined.

## 7. Submission

Push to your Classroom repository; every push is autograded and the result
appears as a Release on your repo. Use the deadline announced by your instructor;
this guide does not set a deadline.
Upload `REPORT.md` (as PDF, including your Wireshark screenshots for A.0) to
E3 as well — the repo copy is for the autograder's cross-check, the E3 copy
is what the TA reads and grades.

### Starter updates

Run `make help` for the update and resubmission sequence. The JSON files under
`results/` are not ignored: commit or stash those measurements as well as your
answers before updating. Captures and logs remain ignored; do not force-add
them merely to make the working tree clean.

Prefer committing and pushing your Classroom default branch from your Linux
or WSL checkout. `gh student submit` creates a remote snapshot; verify that
your local work commits were pushed and fetch/merge any new remote commit
before continuing locally. The tested Windows v1.52.1 CLI can lose executable
bits while snapshotting files. Do not reset away your history to resolve this;
use a normal merge and retain the supplied file modes.

```sh
make check-update
make update
```

`make test` checks the public template's release metadata before running any
lab checks. A required update or an unreachable/invalid metadata endpoint
stops it with an explicit error. The official grader also requires the
current published contract; a local offline pass cannot bypass that gate.

Updates are **manual**; no automatic update PR is created. Commit or stash
your work first, including untracked files. `make update` fetches only the
old and new immutable tags from your public **NYCU-SDNFV Controller** channel
template and makes a three-way merge on `instructor/update-<tag>`. It keeps
your exercise changes, `.classroom50.yaml`, and the injected
`.github/workflows/autograde.yaml`. It never pushes or replaces your original
branch. Do not switch channels or point the updater at a private instructor repo.
The update commit honors your normal Git identity, hooks and signing policy.
If a hook or signing fails, changes remain staged on the update branch;
fix the cause and commit normally before merging. The updater does not retry
with verification or signing disabled.

On success, review `git show`, then follow the printed `git switch` and
`git merge --ff-only instructor/update-<tag>` commands. Merge into your
Classroom **default branch**, run `make up` and `make test`, then push that
default branch to resubmit. Pushing only the update branch does not submit
the updated work. If the default branch has advanced, resolve a normal merge
instead of resetting either branch.

On a conflict, the update branch has **not been committed**: `HEAD` still
points to your original commit. Run `git status`, resolve the files while
preserving your answers, `git add` the resolved files and `git commit`.
Review and merge that branch, test, and push your default branch. Do not
rerun `make update` over a pending update. A repeated update on a current
release is a no-op; an existing pending update branch is never overwritten.

For a deliberately offline checkpoint/local verification, use
`make test-offline` after `make up`. It runs policy and all local checks,
but **does not establish release freshness or submit work**. Reconnect and
run `make check-update` before resubmitting. A repository without
`.lab-release.json` needs an instructor migration: do not fabricate a marker.
