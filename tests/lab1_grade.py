#!/usr/bin/env python3
"""Lab 1 checker. Official grading runs this file from the canonical bundle.
The protected tests/ copy supports local checks in the public student tree.

    python3 tests/lab1_grade.py <flood|normal|proactive|reference|a3a|a3b|a3c|a3d|controller|report>

Reads results/<mode>.json (and, for the controller parts, captures/<mode>.pcap)
written by harness/run_mode.py and applies the checks below. `controller`
runs a3a..a3d together (that is what `make a3` does). Exit 0 = all checks for that part passed. Every FAIL comes with
a hint; read it before changing code.

Grading checks forwarding behaviour and the OpenFlow conversation. RTTs are
recorded for the report, not graded against absolute latency thresholds,
because latency differs between laptops and the CI runner.
"""
import ast
import json
import os
import re
import struct
import sys

RESULTS = "results"
MODES = ("flood", "normal", "reference", "controller", "proactive")
CLI_MODES = ("flood", "normal", "proactive")          # ARP-only first packet, no controller

_pass = 0
_fail = 0


def ok(msg):
    global _pass
    _pass += 1
    print("PASS  " + msg)


def fail(msg, hint=None):
    global _fail
    _fail += 1
    print("FAIL  " + msg)
    if hint:
        print("      hint: " + hint)


def check(cond, msg, hint=None):
    if cond:
        ok(msg)
    else:
        fail(msg, hint)
    return bool(cond)


def load(mode, required=True):
    path = os.path.join(RESULTS, "%s.json" % mode)
    if not os.path.exists(path):
        if required:
            fail("%s is missing" % path,
                 "run `make %s` (or `python3 harness/run_mode.py %s` inside the container); "
                 "if it crashed, the traceback is the real error" % (MODE_TARGET[mode], mode))
        return None
    with open(path) as f:
        return json.load(f)


MODE_TARGET = {"flood": "a1", "normal": "a2", "reference": "a0", "controller": "a3", "proactive": "a4"}


def has_action(r, token, with_dst=None):
    """Is there a flow whose actions contain `token`? with_dst=True/False
    restricts to flows that do / do not match on dl_dst."""
    for l in r["flows_dump"]:
        acts = l.split("actions=", 1)[1] if "actions=" in l else ""
        if token not in acts:
            continue
        if with_dst is None or (("dl_dst=" in l) == with_dst):
            return True
    return False


# ----------------------------------------------------------------------------
def grade_flood():
    r = load("flood")
    if not r:
        return
    n = r["ping_count"]
    check(r["ping_loss_pct"] == 0, "A1: h1 can ping h2 (loss=%d%%)" % r["ping_loss_pct"],
          "an OpenFlow 1.3 switch with an empty table drops everything -- did flood() install a rule? "
          "check the flow table printed above")
    check(r["leak_to_h3"] >= n, "A1: h3 (the eavesdropper) saw the h1<->h2 traffic (%d ICMP packets)" % r["leak_to_h3"],
          "in hub mode EVERY frame must be copied to every other port; h3 should see both requests and replies")
    check(has_action(r, "FLOOD") or has_action(r, "ALL"),
          "A1: a flow with a flood action is installed (%d flow(s))" % r["openflow_flows"],
          "use actions=FLOOD (or ALL); NORMAL is A2, not A1")
    if r["fdb_entries"] == 0:
        ok("A1: OVS learned nothing (fdb=0) -- flooding is stateless")
    else:
        print("INFO  A1: fdb has %d entries while flooding -- interesting, explain it in the report" % r["fdb_entries"])


def grade_normal():
    r = load("normal")
    if not r:
        return
    check(r["ping_loss_pct"] == 0, "A2: h1 can ping h2 (loss=%d%%)" % r["ping_loss_pct"],
          "did normal() install a rule with actions=NORMAL?")
    check(has_action(r, "NORMAL"), "A2: the NORMAL action is in use",
          "A2 is about OVS's built-in learning switch: one rule, actions=NORMAL")
    check(not r["dst_mapping"], "A2: no explicit dl_dst flows (learning happens inside OVS, not in the OpenFlow table)",
          "you programmed the table by hand -- that is A4 (proactive), not A2")
    check(r["fdb_entries"] >= 2, "A2: OVS learned the talking hosts (fdb=%d)" % r["fdb_entries"],
          "with actions=NORMAL, `ovs-appctl fdb/show s1` must list h1 and h2 after the ping. "
          "If it is empty you are probably still flooding")
    check(r["leak_to_h3"] == 0, "A2: nothing leaked to h3 (%d)" % r["leak_to_h3"],
          "once a MAC is learned, unicast to it must not reach h3")


# ----------------------------------------------------------------------------
# OpenFlow-over-pcap reader (stdlib only). Reassembles the TCP payload per
# direction and cuts it into OpenFlow messages by the length field.
# ----------------------------------------------------------------------------
OF_NAMES = {0: "HELLO", 1: "ERROR", 2: "ECHO_REQUEST", 3: "ECHO_REPLY", 5: "FEATURES_REQUEST",
            6: "FEATURES_REPLY", 10: "PACKET_IN", 13: "PACKET_OUT", 14: "FLOW_MOD",
            18: "MULTIPART_REQUEST", 19: "MULTIPART_REPLY"}
CTL_PORT = 6653
ERR_TYPES = {0: "HELLO_FAILED", 1: "BAD_REQUEST", 2: "BAD_ACTION", 3: "BAD_INSTRUCTION", 4: "BAD_MATCH",
             5: "FLOW_MOD_FAILED", 6: "GROUP_MOD_FAILED", 7: "PORT_MOD_FAILED", 8: "TABLE_MOD_FAILED"}
ERR_CODES = {1: {0: "BAD_VERSION", 1: "BAD_TYPE", 2: "BAD_MULTIPART", 5: "EPERM", 6: "BAD_LEN", 7: "BUFFER_EMPTY",
                 8: "BUFFER_UNKNOWN", 9: "BAD_TABLE_ID", 11: "BAD_PORT", 12: "BAD_PACKET"},
             2: {0: "BAD_TYPE", 1: "BAD_LEN", 4: "BAD_OUT_PORT", 5: "BAD_ARGUMENT", 7: "TOO_MANY", 10: "MATCH_INCONSISTENT"},
             3: {0: "UNKNOWN_INST", 1: "UNSUP_INST", 2: "BAD_TABLE_ID", 3: "UNSUP_METADATA", 6: "BAD_EXPERIMENTER", 7: "BAD_LEN"},
             4: {0: "BAD_TYPE", 1: "BAD_LEN", 2: "BAD_TAG", 5: "BAD_WILDCARDS", 6: "BAD_FIELD", 7: "BAD_VALUE",
                 8: "BAD_MASK", 9: "BAD_PREREQ", 10: "DUP_FIELD"},
             5: {0: "UNKNOWN", 1: "TABLE_FULL", 2: "BAD_TABLE_ID", 3: "OVERLAP", 4: "EPERM", 5: "BAD_TIMEOUT", 6: "BAD_COMMAND", 7: "BAD_FLAGS"}}


def read_pcap_of(path):
    """Return a time-ordered list of dicts: {t, dir, type, xid, len, body}
    where dir is 'c2s' (controller -> switch) or 's2c'. None if unreadable."""
    try:
        d = open(path, "rb").read()
    except OSError:
        return None
    if len(d) < 24:
        return None
    magic = struct.unpack("<I", d[:4])[0]
    if magic in (0xa1b2c3d4, 0xa1b23c4d):
        end = "<"
    elif magic in (0xd4c3b2a1, 0x4d3cb2a1):
        end = ">"
    else:
        return None
    linktype = struct.unpack(end + "I", d[20:24])[0]
    off, bufs, msgs = 24, {"c2s": b"", "s2c": b""}, []
    while off + 16 <= len(d):
        ts, tus, incl, _ = struct.unpack(end + "IIII", d[off:off + 16])
        off += 16
        pkt = d[off:off + incl]
        off += incl
        if linktype == 1:
            et, l3 = struct.unpack("!H", pkt[12:14])[0], pkt[14:]
        elif linktype == 113:
            et, l3 = struct.unpack("!H", pkt[14:16])[0], pkt[16:]
        elif linktype == 276:
            et, l3 = struct.unpack("!H", pkt[0:2])[0], pkt[20:]
        else:
            return None
        if et != 0x0800 or len(l3) < 20 or l3[9] != 6:
            continue
        ihl, tot = (l3[0] & 0xf) * 4, struct.unpack("!H", l3[2:4])[0]
        tcp = l3[ihl:tot]
        if len(tcp) < 20:
            continue
        sport, dport = struct.unpack("!HH", tcp[:4])
        payload = tcp[(tcp[12] >> 4) * 4:]
        if not payload:
            continue
        direction = "c2s" if sport == CTL_PORT else ("s2c" if dport == CTL_PORT else None)
        if direction is None:
            continue
        buf = bufs[direction] + payload
        while len(buf) >= 8:
            v, t, l, x = struct.unpack("!BBHI", buf[:8])
            if v != 4 or l < 8:
                buf = buf[1:]                       # resync -- should never happen
                continue
            if len(buf) < l:
                break
            msgs.append({"t": ts + tus / 1e6, "dir": direction, "type": t, "xid": x, "len": l, "body": buf[8:l]})
            buf = buf[l:]
        bufs[direction] = buf
    return msgs


def of_summary(msgs):
    return " ".join("%s%s(%d)" % ("<" if m["dir"] == "s2c" else ">", OF_NAMES.get(m["type"], m["type"]), m["len"]) for m in msgs)


def errors_by_offender(msgs):
    """{offending_type: [error_text, ...]} from every ERROR the switch sent."""
    out = {}
    for m in msgs:
        if m["dir"] != "s2c" or m["type"] != 1 or len(m["body"]) < 4:
            continue
        etype, code = struct.unpack("!HH", m["body"][:4])
        data = m["body"][4:]
        offender = struct.unpack("!BBHI", data[:8])[1] if len(data) >= 8 else None
        out.setdefault(offender, []).append("%s/%s (offending %s, %d bytes)" % (
            ERR_TYPES.get(etype, etype), ERR_CODES.get(etype, {}).get(code, code), OF_NAMES.get(offender, offender),
            struct.unpack("!BBHI", data[:8])[2] if len(data) >= 8 else 0))
    return out


def controller_imports_ok():
    """harness/controller.py must be written from the bytes up: standard library only."""
    allowed = {"socket", "struct", "sys", "os", "argparse", "logging", "time", "collections",
               "typing", "dataclasses", "select", "selectors", "threading", "json", "re",
               "binascii", "enum", "functools", "itertools", "signal", "errno", "math", "io"}
    try:
        tree = ast.parse(open("harness/controller.py", encoding="utf-8").read())
    except (OSError, SyntaxError) as e:
        return False, "cannot parse harness/controller.py: %s" % e
    bad = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            bad |= {a.name.split(".")[0] for a in node.names if a.name.split(".")[0] not in allowed}
        elif isinstance(node, ast.ImportFrom) and node.module:
            top = node.module.split(".")[0]
            if top not in allowed:
                bad.add(top)
    return (not bad), ("non-stdlib imports: %s" % ", ".join(sorted(bad)) if bad else "ok")


def load_capture(mode):
    r = load(mode)
    if not r:
        return None, None
    path = r.get("pcap") or os.path.join("captures", "%s.pcap" % mode)
    msgs = read_pcap_of(path)
    if msgs is None:
        fail("%s: no readable capture at %s" % (mode, path),
             "harness/run_mode.py records the control channel with tcpdump using capture_filter() from "
             "harness/modes.py (A0) -- is that TODO done, and does the filter really capture TCP port 6653?")
        return r, None
    return r, msgs


# ----------------------------------------------------------------------------
def grade_reference():
    """A0 -- the reference controller was run and its conversation captured."""
    r, msgs = load_capture("reference")
    if not r or msgs is None:
        return
    s2c = [m for m in msgs if m["dir"] == "s2c"]
    c2s = [m for m in msgs if m["dir"] == "c2s"]
    print("      capture: " + of_summary(msgs)[:400])
    check(any(m["type"] == 0 for m in s2c) and any(m["type"] == 0 for m in c2s),
          "A0: the capture contains the HELLO exchange in both directions",
          "the filter must catch traffic in BOTH directions on the interface the switch and controller share")
    check(any(m["type"] == 10 for m in s2c) and any(m["type"] == 14 for m in c2s),
          "A0: the capture contains PACKET_IN (switch->controller) and FLOW_MOD (controller->switch)",
          "captures/reference.pcap should hold the whole experiment; did tcpdump start before the switch connected?")
    check(r["ping_loss_pct"] == 0 and r["leak_to_h3"] == 0,
          "A0: the reference controller forwards correctly (loss=%d%%, leak=%d) -- this is the behaviour you must reproduce" % (r["ping_loss_pct"], r["leak_to_h3"]))


def grade_a3a():
    """A3a -- handshake and keepalive, from the wire."""
    ok_imp, why = controller_imports_ok()
    check(ok_imp, "A3a: harness/controller.py uses the standard library only (%s)" % why,
          "no os_ken / ryu / scapy / third-party OpenFlow libraries -- this lab is about producing the bytes yourself")
    r, msgs = load_capture("controller")
    if not r or msgs is None:
        return
    print("      capture: " + of_summary(msgs)[:400])
    s2c = [m for m in msgs if m["dir"] == "s2c"]
    c2s = [m for m in msgs if m["dir"] == "c2s"]
    errs = errors_by_offender(msgs)
    check(any(m["type"] == 0 for m in c2s), "A3a: you answered the switch's HELLO with a HELLO",
          "T1: OVS opens with OFPT_HELLO; reply with an 8-byte header of type 0")
    freq = [m for m in c2s if m["type"] == 5]
    frep = [m for m in s2c if m["type"] == 6]
    check(freq and frep and any(q["xid"] == p["xid"] for q in freq for p in frep),
          "A3a: FEATURES_REQUEST sent and FEATURES_REPLY received with the same xid",
          "T3: send OFPT_FEATURES_REQUEST after HELLO; the reply carries your xid back")
    ereq = [m for m in s2c if m["type"] == 2]
    erep = [m for m in c2s if m["type"] == 3]
    check(ereq, "A3a: the switch sent at least one ECHO_REQUEST during the run (%d)" % len(ereq),
          "run_mode sets inactivity_probe=2s and waits; if no ECHO_REQUEST appears the capture stopped early")
    check(ereq and any(q["xid"] == p["xid"] and q["body"] == p["body"] for q in ereq for p in erep),
          "A3a: every ECHO_REQUEST got an ECHO_REPLY with the same xid and payload",
          "T2: reply OFPT_ECHO_REPLY, same xid, same body -- or OVS drops the connection after the probe")
    check(r["controller_connected"], "A3a: s1 still reports is_connected=true at the end of the run",
          "the switch gave up on you: usually a missing ECHO_REPLY or a malformed message (see the ERRORs below)")
    hs_errs = [e for k, v in errs.items() if k not in (13, 14) for e in v]
    check(not hs_errs, "A3a: no OFPT_ERROR about handshake messages",
          "the switch rejected: %s -- decode_error() in your controller prints the same thing" % "; ".join(hs_errs))


def grade_a3b():
    """A3b -- PACKET_IN decoded, PACKET_OUT encoded."""
    r, msgs = load_capture("controller")
    if not r or msgs is None:
        return
    pin = [m for m in msgs if m["dir"] == "s2c" and m["type"] == 10]
    pout = [m for m in msgs if m["dir"] == "c2s" and m["type"] == 13]
    errs = errors_by_offender(msgs)
    check(r["packet_ins"] >= 1 and pin, "A3b: the switch sent PACKET_INs to you (%d on the wire)" % len(pin),
          "no table-miss flow, or it does not output to CONTROLLER -- see A3c")
    check(pout, "A3b: you sent PACKET_OUTs back (%d)" % len(pout),
          "T4-T6, T8: decode the PACKET_IN (fixed fields, OXM match, Ethernet), then forward the frame with a PACKET_OUT")
    check(not errs.get(13), "A3b: no OFPT_ERROR about your PACKET_OUTs",
          "the switch rejected: %s -- compare your bytes with captures/reference.pcap in Wireshark" % "; ".join(errs.get(13, [])))
    check(r["ping_loss_pct"] == 0, "A3b: h1 can ping h2 (loss=%d%%)" % r["ping_loss_pct"],
          "packets reach you but never come out: check in_port (T5) and the out_port decision (T9)")
    check(len(pout) >= len(pin) // 2, "A3b: (almost) every PACKET_IN produced a PACKET_OUT (%d in / %d out)" % (len(pin), len(pout)),
          "a PACKET_IN you do not answer is a dropped packet -- the flow you install applies only to the next one")


def grade_a3c():
    """A3c -- FLOW_MOD encoded and accepted."""
    r, msgs = load_capture("controller")
    if not r or msgs is None:
        return
    fmods = [m for m in msgs if m["dir"] == "c2s" and m["type"] == 14]
    errs = errors_by_offender(msgs)
    check(fmods, "A3c: you sent FLOW_MODs (%d)" % len(fmods), "T7: build_match() + build_flow_mod()")
    check(not errs.get(14), "A3c: no OFPT_ERROR about your FLOW_MODs",
          "the switch rejected: %s -- BAD_MATCH/BAD_LEN usually means the OXM length or the padding is off; "
          "BAD_INSTRUCTION/BAD_ACTION means the instruction len or the 16-byte output action" % "; ".join(errs.get(14, [])))
    check(has_action(r, "CONTROLLER", with_dst=False), "A3c: a table-miss flow (priority 0, match-all, output CONTROLLER) is in the table",
          "install it right after FEATURES_REPLY: an empty match is a 4-byte ofp_match padded to 8")
    check(len(r["dst_mapping"]) >= 2 and r["dst_mapping_correct"],
          "A3c: explicit dl_dst flows with the right output ports are in the table (%s)" % r["dst_mapping"],
          "if an ERROR is reported above, fix that first; otherwise the switch accepted your FLOW_MODs but they do not "
          "say what you think -- dump-flows shows what OVS decoded (wrong OXM field number? wrong port encoding?)")


def grade_a3d():
    """A3d -- the learning switch behaves, and is reactive."""
    r, msgs = load_capture("controller")
    if not r or msgs is None:
        return
    check(r["leak_to_h3"] == 0, "A3d: nothing leaked to h3 (%d)" % r["leak_to_h3"],
          "after learning, h1<->h2 unicast must go out one port only")
    check(not has_action(r, "NORMAL"), "A3d: the controller does not delegate to NORMAL",
          "installing actions=NORMAL from the controller is A2 with extra steps -- the learning must be yours")
    check(not has_action(r, "FLOOD", with_dst=True), "A3d: no flow floods a known destination",
          "never install a flow whose action is FLOOD -- flood the *packet* (PACKET_OUT), not the *flow*")
    pin_t = [m["t"] for m in msgs if m["dir"] == "s2c" and m["type"] == 10]
    learned = [m for m in msgs if m["dir"] == "c2s" and m["type"] == 14 and len(m["body"]) >= 24
               and struct.unpack_from("!H", m["body"], 22)[0] > 0]
    check(pin_t and learned and min(m["t"] for m in learned) > min(pin_t),
          "A3d: learned flows (priority > 0) were installed *after* the first PACKET_IN -- reactive, not pre-programmed",
          "a flow for a destination must be a reaction to seeing that MAC; pre-installing the table is A4")
    if r.get("first_rtt_ratio"):
        ref = load("reference", required=False)
        print("INFO  A3d: first-packet RTT ratio %.1fx (reference controller: %s) -- explain the difference in REPORT.md A.2"
              % (r["first_rtt_ratio"], ("%.1fx" % ref["first_rtt_ratio"]) if ref and ref.get("first_rtt_ratio") else "n/a"))


def grade_controller():
    for g in (grade_a3a, grade_a3b, grade_a3c, grade_a3d):
        g()


def grade_proactive():
    r = load("proactive")
    if not r:
        return
    check(r["ping_loss_pct"] == 0, "A4: h1 can ping h2 (loss=%d%%)" % r["ping_loss_pct"],
          "100% loss with correct dl_dst flows = the ARP request (broadcast, dst ff:ff:ff:ff:ff:ff) "
          "matches none of them and is dropped. Add a rule for it")
    check(len(r["dst_mapping"]) >= len(r["dst_mapping_truth"]) and r["dst_mapping_correct"],
          "A4: one dl_dst flow per host, all pointing at the right port (%s)" % r["dst_mapping"],
          "install one flow per (mac, port) in `hosts` -- all of them, including h3")
    check(not has_action(r, "CONTROLLER") and r["packet_ins"] == 0, "A4: no controller involved",
          "proactive means the table is complete before the first packet; nothing should go to a controller")
    check(not has_action(r, "NORMAL"), "A4: no NORMAL action (no learning)",
          "proactive = no learning at all; the table is programmed from known topology")
    check(r["leak_to_h3"] == 0 and not r["first_packet_leaked"],
          "A4: nothing leaked to h3, not even the first packet (%d)" % r["leak_to_h3"],
          "with a complete table there is no unknown-unicast flood at all")
    if r["fdb_entries"] == 0:
        ok("A4: fdb is empty -- the switch learned nothing, everything came from the control plane")


# ----------------------------------------------------------------------------
def parse_table_rows(text, labels):
    """Return {label: [cells...]} for markdown table rows whose first cell is a label."""
    rows = {}
    for line in text.splitlines():
        if not line.strip().startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if cells and cells[0].lower() in labels:
            rows[cells[0].lower()] = cells[1:]
    return rows


def num(cell):
    m = re.search(r"-?\d+(\.\d+)?", cell or "")
    return float(m.group(0)) if m else None


def grade_report():
    if not check(os.path.exists("REPORT.md"), "report: REPORT.md exists", "keep the file name; the template is REPORT.md"):
        return
    text = open("REPORT.md", encoding="utf-8", errors="replace").read()
    todo = [l for l in text.splitlines() if "TODO" in l and not l.lstrip().startswith(">")]
    check(not todo, "report: no TODO markers left (%d line(s) still have one)" % len(todo),
          "fill in every TODO in REPORT.md")

    # Part A table: rows labelled by mode; columns: flows | fdb | leak | first-RTT ratio | packet-ins
    rows = parse_table_rows(text, set(MODES))
    check(len(rows) == 5, "report: Part A table has all five mode rows (%d found)" % len(rows),
          "keep the five rows labelled flood / normal / reference / controller / proactive")
    for mode in MODES:
        r = load(mode)
        cells = rows.get(mode)
        complete = cells is not None and len(cells) == 5 and all(num(cell) is not None for cell in cells)
        if not check(complete, "report: %s row has all five numeric measurements" % mode,
                     "keep flows / FDB / leak / first-RTT ratio / packet-ins; do not remove columns"):
            continue
        if not r:
            continue
        flows, leak = num(cells[0]), num(cells[2])
        if mode == "flood":
            good = leak is not None and leak >= r["ping_count"] and abs(leak - r["leak_to_h3"]) <= 2
            hint = "the number must come from YOUR run (results/flood.json), not from a classmate or a sample"
        else:
            good = leak is not None and leak == 0 == r["leak_to_h3"]
            hint = "your own measurement shows %d leaked packets" % r["leak_to_h3"]
        check(good, "report: %s row leak matches your measurement (%s vs %d)" % (mode, cells[2], r["leak_to_h3"]), hint)
        check(flows is not None and flows == r["openflow_flows"],
              "report: %s row flow count matches your measurement (%s vs %d)" % (mode, cells[0], r["openflow_flows"]),
              "copy the flow count from results/%s.json" % mode)
        for column, field in ((1, "fdb_entries"), (4, "packet_ins")):
            check(num(cells[column]) == r[field],
                  "report: %s row %s matches your measurement" % (mode, field),
                  "copy %s from results/%s.json" % (field, mode))

    for section in (1, 2):
        heading = re.search(r"(?m)^\*\*B\.%d\b[^\n]*" % section, text)
        answer = (re.split(r"(?m)^(?:\*\*[A-Z]\.\d|##|---)", text[heading.end():],
                           maxsplit=1)[0].strip() if heading else "")
        check(bool(answer),
              "report: Part B.%d has a design response" % section,
              "keep and answer both the ring design and new-host scalability questions")

    # Part C failure-mode table: 3 scenarios x 3 modes, no empty cells
    frows = parse_table_rows(text, {"mac move", "mac flooding", "controller down"})
    check(len(frows) == 3, "report: Part C failure-mode table has the three scenario rows (%d found)" % len(frows),
          "rows must be labelled 'MAC move', 'MAC flooding', 'controller down'")
    empty = sum(1 for cells in frows.values() for c in cells[:3] if len(c) < 8)
    complete = len(frows) == 3 and all(len(cells) == 3 for cells in frows.values())
    check(complete and empty == 0, "report: every failure-mode cell has content",
          "keep all three mode columns; %d cell(s) are empty or too short" % empty)

    if check(os.path.exists("ai-usage.md"), "report: ai-usage.md exists", "the template ships it; do not delete it"):
        ai = open("ai-usage.md", encoding="utf-8", errors="replace").read()
        check(len(ai.strip()) > 80 and "TODO" not in ai, "report: ai-usage.md is filled in",
              "a few honest sentences: which tools, for what, what you had to fix yourself. 'None' is a valid answer if true")


def main():
    table = {"flood": grade_flood, "normal": grade_normal, "proactive": grade_proactive,
             "reference": grade_reference, "a3a": grade_a3a, "a3b": grade_a3b, "a3c": grade_a3c,
             "a3d": grade_a3d, "controller": grade_controller, "report": grade_report}
    if len(sys.argv) != 2 or sys.argv[1] not in table:
        sys.exit("usage: lab1_grade.py <%s>" % "|".join(table))
    table[sys.argv[1]]()
    print("--- %d passed, %d failed ---" % (_pass, _fail))
    sys.exit(1 if _fail else 0)


if __name__ == "__main__":
    main()
