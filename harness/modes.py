"""Lab 1, Part A -- the three "no controller" modes.

Each function receives the Mininet switch object `s1` (and, for proactive, the
list of hosts) and must leave s1's OpenFlow table in the requested state. The
table is empty when you are called. Talk to the switch with ofctl(s1, cmd, ...),
which runs `ovs-ofctl -O OpenFlow13 <cmd> s1 <args>` and returns its output.

Useful reading: `man ovs-ofctl` ("Flow Syntax"), and `ovs-ofctl dump-flows s1`
after each change to see what you actually installed.
"""


def ofctl(s1, cmd, *args):
    """Run `ovs-ofctl -O OpenFlow13 <cmd> s1 <args...>` and return the output.

    e.g. ofctl(s1, "add-flow", "priority=5,dl_type=0x0800,actions=drop")
         ofctl(s1, "dump-flows")
    """
    return s1.cmd("ovs-ofctl -O OpenFlow13 %s %s %s" % (cmd, s1.name, " ".join(args)))


def capture_filter():
    """A0 -- where does the switch talk to the controller?

    harness/run_mode.py records the switch<->controller conversation with
    tcpdump so you can open it in Wireshark. Tell it where to listen: return
    (interface_name, bpf_filter). The switch is s1 inside this container, the
    controller is a process in the same container listening on TCP port 6653.
    The filter must capture that conversation and nothing else (no ICMP from
    the hosts, no ARP). `man pcap-filter` has the syntax.
    """
    raise NotImplementedError("TODO A0 -- read the docstring above capture_filter()")


def flood(s1):
    """A1 -- hub mode: every frame goes out every port except the one it came in on.

    Install a single rule that matches everything and floods.
    """
    raise NotImplementedError("TODO A1 -- read the docstring above flood()")


def normal(s1):
    """A2 -- reactive learning *inside* the switch (the "NORMAL" action).

    Install a single rule that hands every frame to OVS's built-in MAC-learning
    L2 pipeline. Afterwards look at `ovs-appctl fdb/show s1`: that table is
    where the learned state lives -- not in the OpenFlow table.
    """
    raise NotImplementedError("TODO A2 -- read the docstring above normal()")


def proactive(s1, hosts):
    """A4 -- proactive: program the whole forwarding table up front, no learning.

    `hosts` is a list of (mac, port) tuples for every host on s1, e.g.
    [("00:00:00:00:00:01", 1), ...]. For every host install one flow that sends
    frames *destined to* that MAC out of that port. Then think about what the
    table still cannot handle -- the very first thing a host does before it can
    send an IP packet is not addressed to any of those MACs. Add a rule for it.
    """
    raise NotImplementedError("TODO A4 -- read the docstring above proactive()")
