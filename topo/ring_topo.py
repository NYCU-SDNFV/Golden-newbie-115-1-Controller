#!/usr/bin/env python3
"""Lab 1, Part B -- 9-switch ring topology: 9 switches, 9 hosts.

              h1
              |
             s1
           /    \
         s9      s2
         |        |
    h9--s9      s2--h2
         |        |
         s8      s3
         |        |
    h8--s8      s3--h3
          \    /
           s7  s4
           |    |
      h7--s7  s4--h4
            \  /
         s6--s5
         |    |
         h6  h5

9 switches in a ring, each with one host.
Link cost = 1 everywhere.  Port layout (consistent across all switches):

    port 1 = host
    port 2 = clockwise neighbour    (s1→s2, s2→s3, ..., s9→s1)
    port 3 = counter-clockwise      (s1→s9, s2→s1, ..., s9→s8)

Shortest path from s1 to s5 = s1→s2→s3→s4→s5 (4 hops, clockwise)
                             = s1→s9→s8→s7→s6→s5 (5 hops, counter-clockwise -- NOT optimal)
Max shortest path on a 9-ring = 4 hops (floor(9/2)).

The controller must discover the topology (via LLDP), compute shortest
paths, and install per-destination flows on every switch along each path.
Do not modify this file.
"""
import sys
from functools import partial

from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.cli import CLI

NUM_SWITCHES = 9

# Fixed MAC addresses for all hosts (h1..h9).
HOST_MACS = {
    1: "00:00:00:00:00:01",
    2: "00:00:00:00:00:02",
    3: "00:00:00:00:00:03",
    4: "00:00:00:00:00:04",
    5: "00:00:00:00:00:05",
    6: "00:00:00:00:00:06",
    7: "00:00:00:00:00:07",
    8: "00:00:00:00:00:08",
    9: "00:00:00:00:00:09",
}


class RingTopo(Topo):
    """Nine switches in a ring, each with one host."""

    def build(self):
        switches = []
        for i in range(1, NUM_SWITCHES + 1):
            s = self.addSwitch("s%d" % i)
            h = self.addHost("h%d" % i,
                             ip="10.0.0.%d/24" % i,
                             mac=HOST_MACS[i])
            self.addLink(s, h)   # port 1 on each switch = its host
            switches.append(s)

        # Ring: s1-s2, s2-s3, ..., s8-s9, s9-s1
        # port 2 = clockwise, port 3 = counter-clockwise
        for i in range(NUM_SWITCHES):
            nxt = (i + 1) % NUM_SWITCHES
            self.addLink(switches[i], switches[nxt], port1=2, port2=3)


def build_net():
    switch = partial(OVSSwitch, datapath="user", failMode="secure", protocols="OpenFlow13")
    net = Mininet(topo=RingTopo(), switch=switch,
                  controller=lambda name: RemoteController(name, ip="127.0.0.1", port=6653),
                  link=TCLink, autoSetMacs=False, waitConnected=False)
    return net


def run_cli():
    net = build_net()
    try:
        net.start()
        info("*** Ring topology started. %d switches, %d hosts\n"
             % (NUM_SWITCHES, NUM_SWITCHES))
        info("*** Port layout per switch: 1=host, 2=clockwise, 3=counter-clockwise\n")
        info("*** Max shortest path = %d hops (floor(%d/2))\n"
             % (NUM_SWITCHES // 2, NUM_SWITCHES))
        for s in net.switches:
            info("    %s: %s\n" % (s.name,
                 " ".join("%s(%s)" % (i, i.name) for i in s.intfList() if str(i) != "lo")))
        CLI(net)
    finally:
        net.stop()


def run_pingall():
    net = build_net()
    try:
        net.start()
        import time
        time.sleep(8)           # give the controller time to discover and install
        dropped = net.pingAll(timeout="2")
        print("dropped: %.1f%% over %d hosts" % (dropped, len(net.hosts)))
        return 0 if dropped == 0.0 else 1
    finally:
        net.stop()


MODES = {"cli": run_cli, "pingall": run_pingall}

if __name__ == "__main__":
    setLogLevel("info")
    mode = sys.argv[1] if len(sys.argv) > 1 else "cli"
    if mode not in MODES:
        print("usage: %s [%s]" % (sys.argv[0], "|".join(MODES)))
        sys.exit(2)
    sys.exit(MODES[mode]())
