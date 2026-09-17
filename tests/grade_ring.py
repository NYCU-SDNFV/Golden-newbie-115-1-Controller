#!/usr/bin/env python3
"""Part B grader: ring shortest-path verification.

Runs inside the container. Parameterised by --num and --macs so the same
grader works for the 9-switch and 11-switch (random MAC) rings.

    python3 tests/grade_ring.py --num 9
    python3 tests/grade_ring.py --num 11 --topo topo/ring11_topo.py

Checks:
  1. All host pairs can ping (0% loss)
  2. Flows use shortest paths (output port per destination verified)
  3. No unicast leak to uninvolved hosts (no broadcast storm)
"""
import argparse
import importlib.util
import json
import os
import re
import signal
import socket
import struct
import subprocess
import sys
import time

from mininet.log import setLogLevel

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


def optimal_hops(src, dst, n):
    if src == dst:
        return 0
    return min((dst - src) % n, (src - dst) % n)


def optimal_port(src, dst, n):
    """Return expected output port: 1=host, 2=clockwise, 3=counter-clockwise."""
    if src == dst:
        return 1
    cw = (dst - src) % n
    ccw = (src - dst) % n
    return 2 if cw <= ccw else 3


def load_topo_module(path):
    """Dynamically load a topology module and return its build_net()."""
    spec = importlib.util.spec_from_file_location("topo_mod", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def get_flows(switch):
    out = switch.cmd("ovs-ofctl -O OpenFlow13 dump-flows %s" % switch.name)
    return [l.strip() for l in out.splitlines() if "actions=" in l]


def parse_dst_flows(flows):
    """Extract {dst_mac: output_port_number} from flow entries."""
    result = {}
    for f in flows:
        m_dst = re.search(r'dl_dst=([0-9a-f:]+)', f)
        m_out = re.search(r'output:"?([^",\s]+)"?', f)
        if not (m_dst and m_out):
            continue
        port_str = m_out.group(1)
        if port_str.isdigit():
            result[m_dst.group(1)] = int(port_str)
        else:
            pm = re.search(r'eth(\d+)$', port_str)
            if pm:
                result[m_dst.group(1)] = int(pm.group(1))
    return result


def ping_failures(net, hosts, n):
    failures = []
    for i in range(1, n + 1):
        for j in range(1, n + 1):
            if i == j:
                continue
            out = hosts[i].cmd("ping -n -c 2 -W 1 -i 0.1 10.0.0.%d" % j)
            sent, received = net._parsePing(out)
            if sent != 2 or received != 2:
                failures.append("h%d->h%d (%d/%d)" % (i, j, received, sent))
    return failures


def stop_process(proc, sig=signal.SIGTERM):
    if proc.poll() is None:
        proc.send_signal(sig)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def broadcast_probe(host, switch, n):
    mac = bytes.fromhex(host.MAC().replace(":", ""))
    frame = (b"\xff" * 6 + mac + b"\x08\x06"
             + struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
             + mac + socket.inet_aton(host.IP())
             + b"\0" * 6 + socket.inet_aton("10.0.0.254"))
    path = "/tmp/lab1-ring%d-broadcast.txt" % n
    with open(path, "w") as output:
        capture = subprocess.Popen(
            ["tcpdump", "-i", "%s-eth2" % switch.name, "-nn", "-l",
             "arp and arp[24:4] = 0x0a0000fe"],
            stdout=output, stderr=subprocess.PIPE)
        try:
            time.sleep(0.5)
            if capture.poll() is not None:
                raise RuntimeError("ARP capture failed: " + capture.stderr.read().decode())
            sender = host.popen([
                sys.executable, "-c",
                "import socket,sys; s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW); "
                "s.bind((sys.argv[1],0)); s.send(bytes.fromhex(sys.argv[2])); s.close()",
                str(host.defaultIntf()), frame.hex()])
            try:
                if sender.wait(timeout=5) != 0:
                    raise RuntimeError("could not send the ARP broadcast probe")
            finally:
                stop_process(sender)
            time.sleep(2)
        finally:
            stop_process(capture, signal.SIGINT)
    with open(path) as captured:
        return sum("who-has 10.0.0.254" in line for line in captured)


def run(num_switches, topo_mod):
    setLogLevel("warning")
    subprocess.run(["mn", "-c"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    net = topo_mod.build_net()
    result = {"num_switches": num_switches, "completed": False}

    try:
        net.start()
        hosts = {int(h.name[1:]): h for h in net.hosts}
        switches = {int(s.name[1:]): s for s in net.switches}
        N = num_switches
        for host in hosts.values():
            host.cmd("sysctl -q -w net.ipv6.conf.all.disable_ipv6=1 "
                     "net.ipv6.conf.default.disable_ipv6=1")

        datapaths = {
            i: switches[i].cmd("ovs-vsctl get bridge %s datapath_type"
                               % switches[i].name).strip().strip('"')
            for i in switches
        }
        result["datapaths"] = datapaths
        check(all(dp == "netdev" for dp in datapaths.values()),
              "B: all switches use the userspace datapath")

        # Read actual MACs from the running hosts — no dependency on topology module's dict
        host_macs = {}
        for i, h in hosts.items():
            host_macs[i] = h.MAC(h.defaultIntf())
        print("      host MACs (from running network):")
        for i in sorted(host_macs):
            print("        h%d = %s" % (i, host_macs[i]))

        # Wait for controller to discover and install
        wait = max(8, N)
        print("      waiting for controller to converge (%ds)..." % wait)
        time.sleep(wait)
        if not check(all(get_flows(sw) for sw in switches.values()),
                     "B: every switch has initial discovery/forwarding flows",
                     "implement on_switch_ready(); an empty secure table drops everything"):
            return 1

        observed = broadcast_probe(hosts[1], switches[1], N)
        result["broadcast_probe_packets"] = observed
        if not check(observed <= 2 * N,
                     "B: one ARP broadcast does not circulate indefinitely (%d link copies)"
                     % observed,
                     "broadcast handling must be loop-free before the first host learns"):
            return 1

        # Phase 1: initial ping to trigger ARP + host learning
        print("      phase 1: initial ping (all %d pairs)..." % (N * (N - 1) // 2))
        for i in range(1, N + 1):
            for j in range(i + 1, N + 1):
                hosts[i].cmd("ping -c 1 -W 2 10.0.0.%d" % j)
        time.sleep(3)

        # Phase 2: verification ping
        print("      phase 2: verification ping...")
        failures = ping_failures(net, hosts, N)
        total_pairs = N * (N - 1)
        result["host_macs"] = host_macs
        result["directed_pairs"] = total_pairs
        result["online_failures"] = failures
        check(not failures,
              "B: all directed host pairs have 0%% loss (%d/%d)"
              % (total_pairs - len(failures), total_pairs),
              "failed: %s" % ", ".join(failures[:10]))

        # Phase 3: verify shortest-path flows
        print("      phase 3: verifying shortest-path flows...")
        path_errors = []
        flows_checked = 0

        for sw_id in range(1, N + 1):
            flows = get_flows(switches[sw_id])
            dst_flows = parse_dst_flows(flows)

            for dst_id in range(1, N + 1):
                if dst_id == sw_id:
                    continue
                dst_mac = host_macs[dst_id]
                if dst_mac not in dst_flows:
                    path_errors.append("s%d: no destination flow for h%d(%s)"
                                       % (sw_id, dst_id, dst_mac))
                    continue

                out_port = dst_flows[dst_mac]
                expected = optimal_port(sw_id, dst_id, N)
                flows_checked += 1

                if out_port != expected:
                    direction = "CW(port2)" if expected == 2 else "CCW(port3)"
                    path_errors.append(
                        "s%d: dst=h%d(%s) -> port %d (expected %d=%s, optimal %d hops)"
                        % (sw_id, dst_id, dst_mac, out_port, expected, direction,
                           optimal_hops(sw_id, dst_id, N)))

        check(not path_errors,
              "B: all %d verified flows use shortest paths" % flows_checked,
              "suboptimal:\n      " + "\n      ".join(path_errors[:15]))

        check(flows_checked == N * (N - 1),
              "B: all destination paths have flows (%d checked, expected %d)"
              % (flows_checked, N * (N - 1)),
              "not all switches have per-destination flows installed")
        result["flows_checked"] = flows_checked
        result["path_errors"] = path_errors

        # Phase 4: no broadcast storm / unicast leak
        print("      phase 4: checking for unicast leak...")
        # Pick a host in the middle of the ring to sniff
        sniffer_id = (N // 2) + 1
        src_id = 1
        dst_id = 2
        sniffer = hosts[sniffer_id]
        src = hosts[src_id]

        sniff_path = "/tmp/lab1-ring%d-sniff.txt" % N
        with open(sniff_path, "w") as capture:
            sniffer_proc = sniffer.popen(
                ["tcpdump", "-i", "h%d-eth0" % sniffer_id, "-nn", "-l", "icmp"],
                stdout=capture, stderr=subprocess.PIPE)
            try:
                time.sleep(0.5)
                if sniffer_proc.poll() is not None:
                    raise RuntimeError("tcpdump failed: " + sniffer_proc.stderr.read().decode())
                src.cmd("ping -n -c 3 -W 1 -i 0.3 10.0.0.%d" % dst_id)
                time.sleep(0.5)
            finally:
                stop_process(sniffer_proc, signal.SIGINT)
        with open(sniff_path) as capture:
            sniff = capture.read()
        leaked = sum("ICMP echo" in line for line in sniff.splitlines())
        result["leaked_packets"] = leaked
        check(leaked == 0,
              "B: no unicast leak (h%d saw %d h%d<->h%d packets)" % (sniffer_id, leaked, src_id, dst_id),
              "unicast h%d<->h%d should not reach h%d — flooding or broadcast storm?"
              % (src_id, dst_id, sniffer_id))

        # Summary: print a couple of flow tables
        print("      --- flow table samples ---")
        for sw_id in [1, N // 2 + 1]:
            flows = get_flows(switches[sw_id])
            print("      s%d: %d flows" % (sw_id, len(flows)))
            for f in flows[:12]:
                print("        %s" % f)
            if len(flows) > 12:
                print("        ... (%d more)" % (len(flows) - 12))

        print("      phase 5: verifying forwarding with all control channels disconnected...")
        # Removing the last configured controller makes OVS flush the table.
        # Retarget to an inert listener instead: no controller can program
        # packets, but the primary-controller configuration remains nonempty.
        before = {i: parse_dst_flows(get_flows(sw)) for i, sw in switches.items()}
        with socket.socket() as disconnected:
            disconnected.bind(("127.0.0.1", 0))
            disconnected.listen(128)
            target = "tcp:127.0.0.1:%d" % disconnected.getsockname()[1]
            command = ["ovs-vsctl"]
            for sw in switches.values():
                command += ["--", "set-controller", sw.name, target]
            subprocess.run(command, check=True)
            preserved = all(parse_dst_flows(get_flows(sw)) == before[i]
                            for i, sw in switches.items())
            result["offline_flows_preserved"] = preserved
            check(preserved, "B: cutting control channels preserves installed destination flows")
            failures = ping_failures(net, hosts, N)
        result["offline_failures"] = failures
        check(not failures,
              "B: data plane alone forwards every directed pair (%d/%d)"
              % (total_pairs - len(failures), total_pairs),
              "PACKET_OUT is not a replacement for installed paths: %s"
              % ", ".join(failures[:10]))
        result["completed"] = True
    finally:
        net.stop()
        result.update(passed=_pass, failed=_fail)
        os.makedirs("results", exist_ok=True)
        with open("results/ring%d.json" % num_switches, "w") as output:
            json.dump(result, output, indent=2)

    print("\n--- %d passed, %d failed ---" % (_pass, _fail))
    return 1 if _fail else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--num", type=int, default=9, help="number of switches in the ring")
    ap.add_argument("--topo", default=None, help="path to topology module (default: auto)")
    ap.add_argument("--start-controller", action="store_true",
                    help="start and clean up a dedicated student controller")
    args = ap.parse_args()

    # Resolve topology path
    if args.topo:
        topo_path = args.topo
    elif args.num == 11:
        topo_path = os.path.join(os.path.dirname(__file__), "..", "topo", "ring11_topo.py")
    else:
        topo_path = os.path.join(os.path.dirname(__file__), "..", "topo", "ring_topo.py")

    topo_mod = load_topo_module(topo_path)
    if not args.start_controller:
        return run(args.num, topo_mod)

    with socket.socket() as probe:
        if probe.connect_ex(("127.0.0.1", 6653)) == 0:
            fail("tcp:6653 is already in use",
                 "stop your manually started controller before running make b")
            return 1
    log_path = "results/ring%d-controller.log" % args.num
    os.makedirs("results", exist_ok=True)
    with open(log_path, "w") as log:
        controller = subprocess.Popen(
            [sys.executable, "harness/sp_controller.py", "-n", str(args.num)],
            stdout=log, stderr=subprocess.STDOUT)
    rc = 1
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if controller.poll() is not None:
                fail("sp_controller.py exited before listening", "see " + log_path)
                return 1
            with socket.socket() as probe:
                if probe.connect_ex(("127.0.0.1", 6653)) == 0:
                    break
            time.sleep(0.1)
        else:
            fail("sp_controller.py did not listen within 10s", "see " + log_path)
            return 1
        rc = run(args.num, topo_mod)
        return rc
    finally:
        stop_process(controller)
        if rc:
            print("      --- controller log (last 30 lines) ---")
            with open(log_path) as log:
                for line in log.readlines()[-30:]:
                    print("      " + line.rstrip())


if __name__ == "__main__":
    sys.exit(main())
