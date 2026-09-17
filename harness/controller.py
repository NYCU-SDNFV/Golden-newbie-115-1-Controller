#!/usr/bin/env python3
"""Lab 1, Part A3 -- your own OpenFlow 1.3 controller, from the bytes up.

No framework. Only `socket` and `struct`. The switch (s1) connects to us on
tcp:6653 and speaks OpenFlow 1.3; every byte it sends and every byte we reply
is built or taken apart here.

    python3 harness/controller.py                 # listen on 6653, log to stdout
    python3 harness/run_mode.py controller        # ...or let the harness run it

What you implement (search for TODO):

    T1  HELLO reply                      T5  walk the OXM match, find in_port
    T2  ECHO reply (or OVS drops us)     T6  Ethernet header -> src / dst / type
    T3  FEATURES_REQUEST + parse dpid    T7  build a match + FLOW_MOD
    T4  PACKET_IN fixed fields           T8  build a PACKET_OUT
    T9  the learning switch itself (learn / decide / install / forward)

Byte layouts quoted in the docstrings are from the OpenFlow Switch
Specification 1.3.5 (ONF TS-023); section numbers are given so you can check.
Everything is big-endian ("network byte order"): use "!" in struct formats.

Debugging: run `make a0` once -- it records what a *working* controller says
on the wire (captures/reference.pcap). Your own run is recorded next to it
(captures/controller.pcap). Wireshark decodes both as OpenFlow.
"""
import argparse
import logging
import socket
import struct
import sys

log = logging.getLogger("ctl")

# --------------------------------------------------------------------------
# Constants (OF 1.3.5 -- A.1 header/types, A.2 common structures)
# --------------------------------------------------------------------------
OFP_VERSION = 0x04

# message types (§7.1.1, enum ofp_type)
OFPT_HELLO, OFPT_ERROR, OFPT_ECHO_REQUEST, OFPT_ECHO_REPLY = 0, 1, 2, 3
OFPT_FEATURES_REQUEST, OFPT_FEATURES_REPLY = 5, 6
OFPT_PACKET_IN, OFPT_FLOW_REMOVED, OFPT_PORT_STATUS = 10, 11, 12
OFPT_PACKET_OUT, OFPT_FLOW_MOD = 13, 14
OFPT_MULTIPART_REQUEST, OFPT_MULTIPART_REPLY = 18, 19
TYPE_NAMES = {0: "HELLO", 1: "ERROR", 2: "ECHO_REQUEST", 3: "ECHO_REPLY", 5: "FEATURES_REQUEST",
              6: "FEATURES_REPLY", 10: "PACKET_IN", 11: "FLOW_REMOVED", 12: "PORT_STATUS",
              13: "PACKET_OUT", 14: "FLOW_MOD", 18: "MULTIPART_REQUEST", 19: "MULTIPART_REPLY"}

# reserved port numbers (§7.2.1, enum ofp_port_no)
OFPP_FLOOD, OFPP_CONTROLLER, OFPP_ANY = 0xfffffffb, 0xfffffffd, 0xffffffff
OFPG_ANY = 0xffffffff
OFP_NO_BUFFER = 0xffffffff          # buffer_id: "the packet is in the message"
OFPCML_NO_BUFFER = 0xffff           # max_len for output-to-controller: send the whole packet

# flow-mod commands (§7.3.4.1, enum ofp_flow_mod_command)
OFPFC_ADD, OFPFC_MODIFY, OFPFC_DELETE = 0, 1, 3
# instruction / action types (§7.2.4, §7.2.5)
OFPIT_APPLY_ACTIONS = 4
OFPAT_OUTPUT = 0
# match (§7.2.3): ofp_match.type, OXM class and the fields we need
OFPMT_OXM = 1
OFPXMC_OPENFLOW_BASIC = 0x8000
OXM_OF_IN_PORT, OXM_OF_ETH_DST, OXM_OF_ETH_SRC, OXM_OF_ETH_TYPE = 0, 3, 4, 5

ETH_TYPE_LLDP = 0x88cc

# error types (§7.4.4, enum ofp_error_type) -- so the switch can tell you what you got wrong
ERROR_TYPES = {0: "HELLO_FAILED", 1: "BAD_REQUEST", 2: "BAD_ACTION", 3: "BAD_INSTRUCTION",
               4: "BAD_MATCH", 5: "FLOW_MOD_FAILED", 6: "GROUP_MOD_FAILED", 7: "PORT_MOD_FAILED",
               8: "TABLE_MOD_FAILED", 9: "QUEUE_OP_FAILED", 10: "SWITCH_CONFIG_FAILED",
               11: "ROLE_REQUEST_FAILED", 12: "METER_MOD_FAILED", 13: "TABLE_FEATURES_FAILED"}
BAD_REQUEST_CODES = {0: "BAD_VERSION", 1: "BAD_TYPE", 2: "BAD_MULTIPART", 3: "BAD_EXPERIMENTER",
                     4: "BAD_EXP_TYPE", 5: "EPERM", 6: "BAD_LEN", 7: "BUFFER_EMPTY", 8: "BUFFER_UNKNOWN",
                     9: "BAD_TABLE_ID", 10: "IS_SLAVE", 11: "BAD_PORT", 12: "BAD_PACKET", 13: "MULTIPART_BUFFER_OVERFLOW"}
BAD_MATCH_CODES = {0: "BAD_TYPE", 1: "BAD_LEN", 2: "BAD_TAG", 3: "BAD_DL_ADDR_MASK", 4: "BAD_NW_ADDR_MASK",
                   5: "BAD_WILDCARDS", 6: "BAD_FIELD", 7: "BAD_VALUE", 8: "BAD_MASK", 9: "BAD_PREREQ",
                   10: "DUP_FIELD", 11: "EPERM"}
BAD_ACTION_CODES = {0: "BAD_TYPE", 1: "BAD_LEN", 2: "BAD_EXPERIMENTER", 3: "BAD_EXP_TYPE", 4: "BAD_OUT_PORT",
                    5: "BAD_ARGUMENT", 6: "EPERM", 7: "TOO_MANY", 8: "BAD_QUEUE", 9: "BAD_OUT_GROUP",
                    10: "MATCH_INCONSISTENT", 11: "UNSUPPORTED_ORDER", 12: "BAD_TAG", 13: "BAD_SET_TYPE",
                    14: "BAD_SET_LEN", 15: "BAD_SET_ARGUMENT"}

# --------------------------------------------------------------------------
# Given: framing. Every OpenFlow message starts with the same 8-byte header
# (§7.1.1, struct ofp_header):
#     uint8  version;   /* 0x04 for 1.3 */
#     uint8  type;      /* one of OFPT_* */
#     uint16 length;    /* whole message, header included */
#     uint32 xid;       /* transaction id: a reply carries the request's xid */
# --------------------------------------------------------------------------
HEADER = struct.Struct("!BBHI")


def pack_msg(msg_type, xid, body=b""):
    """Header + body -> bytes. length is computed for you."""
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
    """Read exactly one OpenFlow message. Returns (type, xid, body_bytes)."""
    version, msg_type, length, xid = HEADER.unpack(recv_exact(sock, HEADER.size))
    if version != OFP_VERSION:
        raise ValueError("switch speaks OpenFlow version 0x%02x, we only do 0x04" % version)
    body = recv_exact(sock, length - HEADER.size) if length > HEADER.size else b""
    return msg_type, xid, body


def decode_error(body):
    """Given: turn an OFPT_ERROR body (§7.4.4: uint16 type, uint16 code, data[]) into text."""
    etype, code = struct.unpack_from("!HH", body, 0)
    codes = {1: BAD_REQUEST_CODES, 2: BAD_ACTION_CODES, 4: BAD_MATCH_CODES}.get(etype, {})
    data = body[4:]
    # data holds the first bytes of the offending message: show its header
    offending = ""
    if len(data) >= HEADER.size:
        v, t, l, x = HEADER.unpack_from(data, 0)
        offending = " -- offending message: type=%s len=%d xid=%d" % (TYPE_NAMES.get(t, t), l, x)
    return "OFPT_ERROR %s / %s%s" % (ERROR_TYPES.get(etype, etype), codes.get(code, code), offending)


def mac_str(b):
    return ":".join("%02x" % x for x in b)


def mac_bytes(s):
    return bytes(int(x, 16) for x in s.split(":"))


# --------------------------------------------------------------------------
# The controller
# --------------------------------------------------------------------------
class Controller:
    def __init__(self):
        self.sock = None
        self.xid = 100                      # our own transaction ids
        self.dpid = None
        self.mac_to_port = {}               # the control-plane FDB: {mac: port}

    def next_xid(self):
        self.xid += 1
        return self.xid

    def send(self, msg_type, body=b"", xid=None):
        xid = self.next_xid() if xid is None else xid
        self.sock.sendall(pack_msg(msg_type, xid, body))
        log.debug("-> %s xid=%d len=%d", TYPE_NAMES.get(msg_type, msg_type), xid, HEADER.size + len(body))

    # ---- connection loop -------------------------------------------------
    def serve(self, port):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", port))
        srv.listen(1)
        log.info("listening on tcp:%d, waiting for the switch", port)
        while True:
            self.sock, peer = srv.accept()
            log.info("switch connected from %s:%d", *peer)
            self.mac_to_port = {}
            try:
                while True:
                    msg_type, xid, body = read_msg(self.sock)
                    log.debug("<- %s xid=%d len=%d", TYPE_NAMES.get(msg_type, msg_type), xid, HEADER.size + len(body))
                    try:
                        self.dispatch(msg_type, xid, body)
                    except NotImplementedError as e:
                        log.error("unfinished: %s", e)
            except (ConnectionError, OSError, ValueError) as e:
                log.warning("connection lost: %s", e)
            finally:
                self.sock.close()

    def dispatch(self, msg_type, xid, body):
        if msg_type == OFPT_HELLO:
            self.on_hello(xid, body)
        elif msg_type == OFPT_ECHO_REQUEST:
            self.on_echo_request(xid, body)
        elif msg_type == OFPT_FEATURES_REPLY:
            self.on_features_reply(xid, body)
        elif msg_type == OFPT_PACKET_IN:
            self.on_packet_in(xid, body)
        elif msg_type == OFPT_ERROR:
            log.error("switch says: %s", decode_error(body))
        else:
            log.debug("ignoring %s", TYPE_NAMES.get(msg_type, msg_type))

    # ---- handshake -------------------------------------------------------
    def on_hello(self, xid, body):
        """The switch opens with HELLO (§7.5.1). Reply with our own HELLO, then
        ask who we are talking to.

        T1  A HELLO is just the 8-byte header with type OFPT_HELLO. The
            "hello elements" that may follow are optional in 1.3 -- send none.
            Use a fresh xid (this is not a reply to theirs).
        T3a Immediately after, send OFPT_FEATURES_REQUEST: also header-only.
        """
        raise NotImplementedError("T1 -- reply HELLO, then send FEATURES_REQUEST (T3a)")

    def on_echo_request(self, xid, body):
        """Keepalive (§7.5.4). OVS sends one every `inactivity_probe` ms and
        DROPS THE CONNECTION if we do not answer.

        T2  Reply OFPT_ECHO_REPLY with the SAME xid and the SAME body.
        """
        raise NotImplementedError("T2 -- reply ECHO_REPLY with the same xid and body")

    def on_features_reply(self, xid, body):
        """FEATURES_REPLY body (§7.3.1, struct ofp_switch_features, 24 bytes
        after the header):
            uint64 datapath_id;  uint32 n_buffers;  uint8 n_tables;
            uint8 auxiliary_id;  uint8 pad[2];      uint32 capabilities;
            uint32 reserved;
        T3b Unpack it and remember self.dpid (log it as hex: OVS shows the same
            value in `ovs-ofctl show s1`).
        """
        raise NotImplementedError("T3b -- unpack FEATURES_REPLY and set self.dpid")
        # Now that we know the switch, make sure unknown traffic reaches us:
        # a table-miss entry (priority 0, match everything, output CONTROLLER).
        self.send(OFPT_FLOW_MOD, self.build_flow_mod(
            priority=0, match_fields={}, out_port=OFPP_CONTROLLER, max_len=OFPCML_NO_BUFFER))
        log.info("table-miss flow installed")

    # ---- decoding --------------------------------------------------------
    def parse_packet_in(self, body):
        """PACKET_IN body (§7.4.1, struct ofp_packet_in):
            uint32 buffer_id;   uint16 total_len;   uint8 reason;   uint8 table_id;
            uint64 cookie;      struct ofp_match match;   uint8 pad[2];   uint8 data[0];
        The match is variable-length (see parse_match). After it come 2 bytes
        of padding, then the raw Ethernet frame.

        T4  Unpack the 16 fixed bytes, call parse_match() on what follows, skip
            the 2 pad bytes, and return (buffer_id, in_port, frame_bytes).
        """
        raise NotImplementedError("T4 -- unpack the PACKET_IN fixed fields, then the match, then the frame")

    def parse_match(self, buf, off):
        """OXM match (§7.2.3.1-7.2.3.3). struct ofp_match:
            uint16 type;      /* OFPMT_OXM = 1 */
            uint16 length;    /* header (4) + all TLVs, EXCLUDING the padding */
            oxm_fields...     /* TLVs, see below */
            pad to a multiple of 8 bytes
        Each TLV has a 4-byte OXM header followed by `oxm_length` bytes of value:
            oxm_class : 16 bits   (OFPXMC_OPENFLOW_BASIC = 0x8000)
            oxm_field :  7 bits   (OXM_OF_IN_PORT = 0, OXM_OF_ETH_DST = 3, ...)
            oxm_hasmask: 1 bit
            oxm_length:  8 bits   (of the value; doubled if hasmask)
        i.e. the second 16-bit word is (field << 9) | (hasmask << 8) | length.

        T5  Walk the TLVs from off+4 to off+length. Return
            ({field: value_bytes, ...}, offset_just_after_the_padding).
            in_port is a 4-byte big-endian integer -- convert it.
        """
        raise NotImplementedError("T5 -- walk the OXM TLVs and return ({field: value}, end_after_padding)")

    @staticmethod
    def parse_ethernet(frame):
        """Ethernet II header, 14 bytes: dst MAC (6), src MAC (6), EtherType (2).
        T6  Return (dst_mac_str, src_mac_str, ethertype_int). Use mac_str().
        """
        raise NotImplementedError("T6 -- split the 14-byte Ethernet header")

    # ---- encoding --------------------------------------------------------
    @staticmethod
    def build_match(fields):
        """Encode an OXM match (§7.2.3) from {oxm_field: value_bytes_or_int}.
        Values: OXM_OF_IN_PORT -> 4 bytes, OXM_OF_ETH_DST/SRC -> 6 bytes.

        T7a For each field emit  oxm_header (4 bytes) + value.  Then prepend
            ofp_match {type=OFPMT_OXM, length=4+len(tlvs)} and pad the whole
            thing with zero bytes to a multiple of 8. An empty dict is a
            "match everything" (length 4, padded to 8).
        """
        raise NotImplementedError("T7a -- encode ofp_match with OXM TLVs, padded to 8 bytes")

    def build_flow_mod(self, priority, match_fields, out_port, max_len=0, idle_timeout=0,
                       command=OFPFC_ADD, delete_out_port=OFPP_ANY):
        """FLOW_MOD body (§7.3.4.1, struct ofp_flow_mod), 40 bytes then match then instructions:
            uint64 cookie;  uint64 cookie_mask;  uint8 table_id;  uint8 command;
            uint16 idle_timeout;  uint16 hard_timeout;  uint16 priority;  uint32 buffer_id;
            uint32 out_port;  uint32 out_group;  uint16 flags;  uint8 pad[2];
            struct ofp_match match;            /* variable, padded */
            struct ofp_instruction instructions[];
        One instruction (§7.2.4, struct ofp_instruction_actions):
            uint16 type = OFPIT_APPLY_ACTIONS;  uint16 len;  uint8 pad[4];  actions[]
        One action (§7.2.5, struct ofp_action_output, 16 bytes):
            uint16 type = OFPAT_OUTPUT;  uint16 len = 16;  uint32 port;  uint16 max_len;  uint8 pad[6]

        T7b Build it. buffer_id = OFP_NO_BUFFER. out_port/out_group in the
            fixed part are only used by DELETE (set OFPP_ANY / OFPG_ANY for ADD).
            The instruction's len covers itself plus its actions.
        """
        raise NotImplementedError("T7b -- 40 fixed bytes + match + APPLY_ACTIONS instruction with one OUTPUT action")

    @staticmethod
    def build_packet_out(in_port, out_port, frame):
        """PACKET_OUT body (§7.3.7, struct ofp_packet_out):
            uint32 buffer_id;  uint32 in_port;  uint16 actions_len;  uint8 pad[6];
            struct ofp_action_header actions[];   uint8 data[0];
        T8  buffer_id = OFP_NO_BUFFER (the frame travels inside this message),
            one OFPAT_OUTPUT action (16 bytes, max_len 0), then the frame.
        """
        raise NotImplementedError("T8 -- 16 fixed bytes + one OUTPUT action + the frame")

    # ---- the learning switch --------------------------------------------
    def on_packet_in(self, xid, body):
        """T9 -- the algorithm. Everything above exists so these ten lines can run:
            1. decode: buffer_id, in_port, frame = parse_packet_in(body);
               dst, src, ethertype = parse_ethernet(frame). Ignore LLDP.
            2. learn:  mac_to_port[src] = in_port
            3. decide: out_port = mac_to_port.get(dst, OFPP_FLOOD)
            4. install: if out_port is a real port, FLOW_MOD priority 10,
               match {OXM_OF_ETH_DST: dst}, output out_port, idle_timeout 60.
               (Never install a flow whose action is FLOOD.)
            5. forward THIS frame with a PACKET_OUT -- the flow you just
               installed applies only to the next one.
        """
        raise NotImplementedError("T9 -- decode, learn, decide, install, forward")


def main():
    ap = argparse.ArgumentParser(description="Lab 1 OpenFlow 1.3 learning-switch controller")
    ap.add_argument("--port", type=int, default=6653)
    ap.add_argument("-v", "--verbose", action="store_true", help="log every message in and out")
    args = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s", stream=sys.stdout)
    Controller().serve(args.port)


if __name__ == "__main__":
    main()
