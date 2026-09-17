#!/usr/bin/env python3
"""Lab 1, Part B -- shortest-path controller for the 9-switch ring.

No framework. Only `socket`, `struct` and `select`.

    python3 harness/sp_controller.py -v
    python3 topo/ring_topo.py pingall             # in another terminal

Given:
  - OpenFlow 1.3 constants, framing, encoding/decoding helpers
  - Switch class, select() loop, handshake (HELLO/ECHO/FEATURES)
  - LLDP constants

NOT given:
  - What to do when a PACKET_IN arrives
  - How/when to send LLDP
  - How to discover hosts
  - How to build a graph or compute paths
  - How to install flows
  - How to avoid broadcast storm on a ring

Standard-library only. No os-ken, no Scapy.
"""
import argparse
import collections
import logging
import select
import socket
import struct
import sys
import time

log = logging.getLogger("spctl")

# ---------------------------------------------------------------------------
# OpenFlow 1.3 constants (identical to controller.py)
# ---------------------------------------------------------------------------
OFP_VERSION = 0x04

OFPT_HELLO, OFPT_ERROR, OFPT_ECHO_REQUEST, OFPT_ECHO_REPLY = 0, 1, 2, 3
OFPT_FEATURES_REQUEST, OFPT_FEATURES_REPLY = 5, 6
OFPT_PACKET_IN, OFPT_FLOW_REMOVED, OFPT_PORT_STATUS = 10, 11, 12
OFPT_PACKET_OUT, OFPT_FLOW_MOD = 13, 14
TYPE_NAMES = {0: "HELLO", 1: "ERROR", 2: "ECHO_REQUEST", 3: "ECHO_REPLY",
              5: "FEATURES_REQUEST", 6: "FEATURES_REPLY",
              10: "PACKET_IN", 13: "PACKET_OUT", 14: "FLOW_MOD"}

OFPP_FLOOD, OFPP_CONTROLLER, OFPP_ANY = 0xfffffffb, 0xfffffffd, 0xffffffff
OFPG_ANY = 0xffffffff
OFP_NO_BUFFER = 0xffffffff
OFPCML_NO_BUFFER = 0xffff

OFPFC_ADD = 0
OFPIT_APPLY_ACTIONS = 4
OFPAT_OUTPUT = 0
OFPMT_OXM = 1
OFPXMC_OPENFLOW_BASIC = 0x8000
OXM_OF_IN_PORT, OXM_OF_ETH_DST, OXM_OF_ETH_SRC, OXM_OF_ETH_TYPE = 0, 3, 4, 5

ETH_TYPE_LLDP = 0x88cc
LLDP_DST_MAC = bytes([0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e])

HEADER = struct.Struct("!BBHI")

# ---------------------------------------------------------------------------
# Given: framing + OpenFlow encoding (same as your Part A3 controller)
# ---------------------------------------------------------------------------

def pack_msg(msg_type, xid, body=b""):
    return HEADER.pack(OFP_VERSION, msg_type, HEADER.size + len(body), xid) + body

def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("switch closed the connection")
        buf += chunk
    return buf

def read_msg(sock):
    version, msg_type, length, xid = HEADER.unpack(recv_exact(sock, HEADER.size))
    body = recv_exact(sock, length - HEADER.size) if length > HEADER.size else b""
    return msg_type, xid, body

def mac_str(b):
    return ":".join("%02x" % x for x in b)

def mac_bytes(s):
    return bytes(int(x, 16) for x in s.split(":"))

def decode_error(body):
    etype, code = struct.unpack_from("!HH", body, 0)
    return "ERROR type=%d code=%d" % (etype, code)

def build_match(fields):
    """Encode an OXM match from {field: value}."""
    tlvs = b""
    for field, value in fields.items():
        if isinstance(value, int):
            value = struct.pack("!I", value)
        elif isinstance(value, str):
            value = mac_bytes(value)
        tlvs += struct.pack("!HBB", OFPXMC_OPENFLOW_BASIC, field << 1, len(value)) + value
    match_length = 4 + len(tlvs)
    match = struct.pack("!HH", OFPMT_OXM, match_length) + tlvs
    pad_len = ((match_length + 7) // 8) * 8 - match_length
    return match + b"\x00" * pad_len

def build_flow_mod(priority, match_fields, out_port, max_len=0, idle_timeout=0):
    """Build a FLOW_MOD body with one OUTPUT action."""
    match = build_match(match_fields)
    action = struct.pack("!HHIHxxxxxx", OFPAT_OUTPUT, 16, out_port, max_len)
    instruction = struct.pack("!HHxxxx", OFPIT_APPLY_ACTIONS, 8 + len(action)) + action
    fixed = struct.pack("!QQBBHHHIIIHxx",
                        0, 0, 0, OFPFC_ADD,
                        idle_timeout, 0, priority,
                        OFP_NO_BUFFER, OFPP_ANY, OFPG_ANY, 0)
    return fixed + match + instruction

def build_packet_out(in_port, out_port, frame):
    """Build a PACKET_OUT body."""
    action = struct.pack("!HHIHxxxxxx", OFPAT_OUTPUT, 16, out_port, 0)
    fixed = struct.pack("!IIHxxxxxx", OFP_NO_BUFFER, in_port, len(action))
    return fixed + action + frame

def parse_match(buf, off):
    """Parse an OXM match, return ({field: value}, end_after_padding)."""
    match_type, match_length = struct.unpack_from("!HH", buf, off)
    fields = {}
    pos = off + 4
    tlv_end = off + match_length
    while pos < tlv_end:
        oxm_class, oxm_field_mask, oxm_length = struct.unpack_from("!HBB", buf, pos)
        oxm_field = oxm_field_mask >> 1
        pos += 4
        value = buf[pos:pos + oxm_length]
        if oxm_field == OXM_OF_IN_PORT:
            fields[oxm_field] = struct.unpack("!I", value)[0]
        else:
            fields[oxm_field] = value
        pos += oxm_length
    padded_end = off + ((match_length + 7) // 8) * 8
    return fields, padded_end

def parse_ethernet(frame):
    """Parse the 14-byte Ethernet header -> (dst_mac_str, src_mac_str, ethertype)."""
    return mac_str(frame[0:6]), mac_str(frame[6:12]), struct.unpack("!H", frame[12:14])[0]

def parse_packet_in(body):
    """Parse PACKET_IN body -> (buffer_id, in_port, frame_bytes)."""
    buffer_id, total_len, reason, table_id, cookie = struct.unpack_from("!IHBBq", body, 0)
    fields, end = parse_match(body, 16)
    in_port = fields.get(OXM_OF_IN_PORT, 0)
    frame = body[end + 2:]
    return buffer_id, in_port, frame


# ---------------------------------------------------------------------------
# Per-switch state
# ---------------------------------------------------------------------------
class Switch:
    def __init__(self, sock):
        self.sock = sock
        self.dpid = None
        self.xid = 100

    def next_xid(self):
        self.xid += 1
        return self.xid

    def send(self, msg_type, body=b"", xid=None):
        xid = self.next_xid() if xid is None else xid
        self.sock.sendall(pack_msg(msg_type, xid, body))

    def dpid_hex(self):
        return "%016x" % self.dpid if self.dpid else "?"


# ---------------------------------------------------------------------------
# YOUR controller — implement everything below
# ---------------------------------------------------------------------------
class SPController:
    """Shortest-path controller for a ring of switches.

    The select() loop and OpenFlow handshake are given. You must implement
    on_packet_in() and any helper methods you need to satisfy the requirements
    in the README.

    Useful state you may want (or not — your design, your choice):
        self.switches      {sock_fd: Switch}
        self.dpid_to_sw    {dpid: Switch}
    """

    def __init__(self, num_switches=9):
        self.num_switches = num_switches
        self.switches = {}            # {sock_fd: Switch}
        self.dpid_to_sw = {}          # {dpid: Switch}

    # ---- select() loop + handshake (given) --------------------------------

    def serve(self, port):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", port))
        srv.listen(self.num_switches)
        log.info("listening on tcp:%d, waiting for %d switches", port, self.num_switches)

        read_socks = [srv]
        while True:
            readable, _, _ = select.select(read_socks, [], [], 1.0)
            for sock in readable:
                if sock is srv:
                    conn, peer = srv.accept()
                    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    sw = Switch(conn)
                    self.switches[conn.fileno()] = sw
                    read_socks.append(conn)
                    log.info("switch connected from %s:%d", *peer)
                else:
                    sw = self.switches.get(sock.fileno())
                    if not sw:
                        continue
                    try:
                        msg_type, xid, body = read_msg(sock)
                        self._dispatch(sw, msg_type, xid, body)
                    except (ConnectionError, OSError, ValueError) as e:
                        log.warning("switch %s lost: %s", sw.dpid_hex(), e)
                        read_socks.remove(sock)
                        self.switches.pop(sock.fileno(), None)
                        if self.dpid_to_sw.get(sw.dpid) is sw:
                            del self.dpid_to_sw[sw.dpid]
                        sock.close()

    def _dispatch(self, sw, msg_type, xid, body):
        if msg_type == OFPT_HELLO:
            sw.send(OFPT_HELLO)
            sw.send(OFPT_FEATURES_REQUEST)
        elif msg_type == OFPT_ECHO_REQUEST:
            sw.send(OFPT_ECHO_REPLY, body=body, xid=xid)
        elif msg_type == OFPT_FEATURES_REPLY:
            sw.dpid = struct.unpack_from("!Q", body, 0)[0]
            self.dpid_to_sw[sw.dpid] = sw
            log.info("switch dpid=%s", sw.dpid_hex())
            self.on_switch_ready(sw)
        elif msg_type == OFPT_PACKET_IN:
            self.on_packet_in(sw, xid, body)
        elif msg_type == OFPT_ERROR:
            log.error("switch %s: %s", sw.dpid_hex(), decode_error(body))

    # ---- YOUR CODE BELOW --------------------------------------------------

    def on_switch_ready(self, sw):
        """Called when a switch completes the handshake (FEATURES_REPLY received).

        You decide what to do here.
        """
        pass

    def on_packet_in(self, sw, xid, body):
        """Called when a switch sends a PACKET_IN.

        You decide what to do here.
        """
        pass



# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Lab 1 Part B: shortest-path controller")
    ap.add_argument("--port", type=int, default=6653)
    ap.add_argument("-n", "--num-switches", type=int, default=9)
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s", stream=sys.stdout)
    SPController(num_switches=args.num_switches).serve(args.port)


if __name__ == "__main__":
    main()
