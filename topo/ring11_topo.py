#!/usr/bin/env python3
"""Part B test -- 11-switch ring with random MACs.

Same structure as ring_topo.py but with 11 switches and random MACs generated
at startup. Tests that the controller does not hardcode the number of switches
or assume MAC addresses follow any pattern. Do not modify this file.
"""
import os
import sys
from functools import partial

from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.cli import CLI

NUM_SWITCHES = 11


def _random_mac():
    """Generate a random locally-administered unicast MAC."""
    b = os.urandom(6)
    # Set locally-administered bit (bit 1 of first byte), clear multicast bit (bit 0)
    first = (b[0] | 0x02) & 0xfe
    return "%02x:%02x:%02x:%02x:%02x:%02x" % (first, b[1], b[2], b[3], b[4], b[5])


# Generated fresh every time this module is loaded.
HOST_MACS = {i: _random_mac() for i in range(1, NUM_SWITCHES + 1)}


class Ring11Topo(Topo):
    def build(self):
        switches = []
        for i in range(1, NUM_SWITCHES + 1):
            s = self.addSwitch("s%d" % i)
            h = self.addHost("h%d" % i, ip="10.0.0.%d/24" % i, mac=HOST_MACS[i])
            self.addLink(s, h)
            switches.append(s)
        # port 2 = clockwise, port 3 = counter-clockwise
        for i in range(NUM_SWITCHES):
            nxt = (i + 1) % NUM_SWITCHES
            self.addLink(switches[i], switches[nxt], port1=2, port2=3)


def build_net():
    switch = partial(OVSSwitch, datapath="user", failMode="secure", protocols="OpenFlow13")
    return Mininet(topo=Ring11Topo(), switch=switch,
                   controller=lambda name: RemoteController(name, ip="127.0.0.1", port=6653),
                   link=TCLink, autoSetMacs=False, waitConnected=False)


def run_pingall():
    net = build_net()
    try:
        net.start()
        import time
        time.sleep(10)
        dropped = net.pingAll(timeout="2")
        print("dropped: %.1f%% over %d hosts" % (dropped, len(net.hosts)))
        return 0 if dropped == 0.0 else 1
    finally:
        net.stop()


def run_cli():
    net = build_net()
    try:
        net.start()
        info("*** 11-switch ring, random MACs. Port layout: 1=host, 2=CW, 3=CCW\n")
        info("*** MACs this run:\n")
        for i in range(1, NUM_SWITCHES + 1):
            info("    h%d = %s\n" % (i, HOST_MACS[i]))
        CLI(net)
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
