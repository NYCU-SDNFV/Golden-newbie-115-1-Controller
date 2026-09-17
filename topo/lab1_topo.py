#!/usr/bin/env python3
"""Lab 1 topology. Do not modify.

    h1 (10.0.0.1, port 1) --+
    h2 (10.0.0.2, port 2) --+-- s1 (Open vSwitch, userspace datapath, OpenFlow 1.3)
    h3 (10.0.0.3, port 3) --+

h3 is the *eavesdropper*: it never talks. If h3 receives an ICMP packet that
was sent between h1 and h2, the switch leaked unicast traffic.

The switch starts with NO controller and an EMPTY flow table
(fail_mode=secure), so nothing is forwarded until *you* say how. That is the
point of this lab: every mode in harness/modes.py and harness/controller.py
decides forwarding explicitly.

We use the userspace (netdev) datapath on purpose: this lab is about
correctness, not throughput, and the userspace datapath behaves identically
on every laptop and on the autograder.
"""
from functools import partial

from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.topo import Topo

HOSTS = ("h1", "h2", "h3")
SWITCH = "s1"


class Lab1Topo(Topo):
    def build(self):
        s1 = self.addSwitch(SWITCH)
        for i, h in enumerate(HOSTS, start=1):
            host = self.addHost(h, ip="10.0.0.%d/8" % i, mac="00:00:00:00:00:0%d" % i)
            self.addLink(host, s1, port2=i)   # h<i> is on s1 port <i>


UserspaceOVS = partial(OVSSwitch, datapath="user", protocols="OpenFlow13",
                       failMode="secure")


def build_net():
    """Create and start the network. Returns the Mininet object."""
    net = Mininet(topo=Lab1Topo(), switch=UserspaceOVS, controller=None,
                  waitConnected=False)
    net.start()
    # IPv6 off on the hosts: otherwise neighbour discovery / MLD chatter shows
    # up as extra PACKET_INs and keeps the control channel busy, so the
    # experiment would look different on every machine.
    for h in HOSTS:
        net.get(h).cmd("sysctl -q -w net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1")
    return net


if __name__ == "__main__":
    from mininet.cli import CLI
    from mininet.log import setLogLevel
    setLogLevel("info")
    net = build_net()
    CLI(net)
    net.stop()
