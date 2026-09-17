"""A0 -- the reference controller. Given; do not modify.

This is the same learning switch you will write in harness/controller.py, but
built on os-ken (a maintained fork of the Ryu framework), which hides every
byte of OpenFlow behind Python objects. It exists for one reason: so that you
can record what a *working* controller says on the wire (`make a0` writes
captures/reference.pcap) before you produce those bytes yourself.

Read it to see the *logic* (learn, decide, install, forward). It will not tell
you how the bytes look -- that is what the capture and the spec are for.
"""
from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.lib.packet import ethernet, ether_types, packet
from os_ken.ofproto import ofproto_v1_3


class ReferenceSwitch(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def on_features(self, ev):
        dp = ev.msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        self.add_flow(dp, 0, parser.OFPMatch(),
                      [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)])
        self.logger.info("switch dpid=%016x connected; table-miss installed", dp.id)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def on_packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        in_port = msg.match["in_port"]
        eth = packet.Packet(msg.data).get_protocol(ethernet.ethernet)
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        self.mac_to_port[eth.src] = in_port                       # learn
        out_port = self.mac_to_port.get(eth.dst, ofp.OFPP_FLOOD)  # decide
        actions = [parser.OFPActionOutput(out_port)]
        if out_port != ofp.OFPP_FLOOD:                            # install
            self.add_flow(dp, 10, parser.OFPMatch(eth_dst=eth.dst), actions, idle_timeout=60)
        dp.send_msg(parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,   # forward
                                        in_port=in_port, actions=actions, data=msg.data))
        self.logger.info("packet_in in_port=%s src=%s dst=%s -> out=%s", in_port, eth.src, eth.dst, out_port)

    def add_flow(self, dp, priority, match, actions, idle_timeout=0):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=priority, match=match,
                                      instructions=inst, idle_timeout=idle_timeout))
