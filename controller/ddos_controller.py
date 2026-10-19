"""OpenFlow 1.3 controller: L2 forwarding + temporary, model-driven drop rules.

Run (os-ken, the maintained Ryu fork, in its own Python 3.12 venv):
    .venv-osken/bin/osken-manager controller/ddos_controller.py

Forwarding (priority 10)
  * table-miss (priority 0) sends packets to the controller; switches run fail-mode=secure,
    so nothing is forwarded without it
  * MAC learning per switch; a known destination gets an exact (in_port, eth_src, eth_dst)
    rule with an idle timeout, so a flood is forwarded by the switch, not via packet-in
  * packet-ins are rate limited per (switch, port) to protect the controller
  * flooding is only safe on loop-free topologies (testbed/topology.py is a tree)
  * optional static routes (DDOS_STATIC_ROUTES): forward by destination IP and rewrite both
    MACs, for switch ports that only accept their own MAC (SR-IOV on a cloud testbed)

Mitigation (priority 100), REST API on 127.0.0.1:8080 (localhost only by default)
  POST /block      {"ip": "10.0.0.11", "duration": 30, "reason": "...", "score": 0.97}
  POST /unblock    {"ip": "10.0.0.11"}
  POST /mitigation {"enabled": false}   detect-only: block requests are logged, not installed
  GET  /status     switches, mitigation flag, active blocks with their drop counters
  A block is a drop rule (match ipv4_src) added to every switch with hard_timeout=duration,
  so it expires on its own. Whitelisted addresses (the server) are never blocked and the
  number of active blocks is capped. A block request with no switch connected returns 503.

Renewal: once a source is blocked, its packets die at the switch, so the monitor can no
longer tell if the attack continues. Only the switch can. The controller polls the drop
rules' packet counters every second; a rule still dropping packets within
DDOS_RENEW_LEAD_S of expiry is re-installed for another full duration ("block_renewed"); a
rule whose counter stopped moving expires. The counters are logged each poll ("block_stats")
and are the only measure of the traffic a block actually drops.

Environment variables
  DDOS_API_PORT (8080)  DDOS_API_HOST (127.0.0.1)  DDOS_API_TOKEN (unset = no auth; set it
  when the API listens off loopback, then requests need "Authorization: Bearer <token>")
  DDOS_WHITELIST ("10.0.0.100")  DDOS_MAX_BLOCK_S (300)  DDOS_MITIGATION (1 = enforce)
  DDOS_MAX_BLOCKS (64)  DDOS_CTRL_LOG (results/controller_events.jsonl)
  DDOS_PACKET_IN_RATE (200 packet-ins/s per port)
  DDOS_RENEW (1 = renew active blocks, 0 = never)  DDOS_RENEW_LEAD_S (3)
  DDOS_STATIC_ROUTES  path to a JSON list of
      {"ip": "10.0.0.100", "port": 1, "eth_dst": "<host MAC>", "eth_src": "<switch port MAC>"}
"""

import hmac
import ipaddress
import json
import os
import time

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, DEAD_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.lib import hub
from os_ken.lib.packet import ether_types, ethernet, packet
from os_ken.ofproto import ofproto_v1_3

FORWARD_PRIORITY = 10
BLOCK_PRIORITY = 100
FORWARD_IDLE_TIMEOUT = 60
BLOCK_COOKIE = 0xDD05
COOKIE_MASK = 0xFFFFFFFFFFFFFFFF
STATS_POLL_S = 1.0


def load_static_routes(path):
    """Read and check DDOS_STATIC_ROUTES. A bad file stops the controller at start-up
    instead of leaving the network half-forwarding."""
    if not path:
        return []
    with open(path) as fh:
        routes = json.load(fh)
    for r in routes:
        ipaddress.IPv4Address(r["ip"])
        r["port"] = int(r["port"])
        for key in ("eth_dst", "eth_src"):
            if len(r[key].split(":")) != 6:
                raise ValueError(f"static route {r['ip']}: {key} is not a MAC address: {r[key]!r}")
    return routes


class DDoSController(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.api_port = int(os.environ.get("DDOS_API_PORT", "8080"))
        self.api_host = os.environ.get("DDOS_API_HOST", "127.0.0.1")
        self.api_token = os.environ.get("DDOS_API_TOKEN", "")
        self.mitigation = os.environ.get("DDOS_MITIGATION", "1") != "0"
        self.started = time.time()
        self.whitelist = {ip.strip() for ip in os.environ.get("DDOS_WHITELIST", "10.0.0.100").split(",") if ip.strip()}
        self.max_block_s = int(os.environ.get("DDOS_MAX_BLOCK_S", "300"))
        self.max_blocks = int(os.environ.get("DDOS_MAX_BLOCKS", "64"))
        self.packet_in_rate = float(os.environ.get("DDOS_PACKET_IN_RATE", "200"))
        self.renew = os.environ.get("DDOS_RENEW", "1") != "0"
        self.renew_lead_s = float(os.environ.get("DDOS_RENEW_LEAD_S", "3"))
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.log_path = os.environ.get("DDOS_CTRL_LOG", os.path.join(root, "results", "controller_events.jsonl"))
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        self.datapaths = {}
        self.mac_to_port = {}
        self.static_routes = load_static_routes(os.environ.get("DDOS_STATIC_ROUTES", ""))
        self.blocks = {}  # ip -> {"expires": t, "requested": t, "xids": {dpid: xid}, ...}
        self.totals = {"blocks": 0, "renewals": 0, "dropped_packets": 0, "dropped_bytes": 0}
        self.pending_barriers = {}  # (dpid, xid) -> ip
        self.buckets = {}  # (dpid, port) -> [tokens, last_ts]

    # ------------------------------------------------------------------ helpers
    def log_event(self, event, quiet=False, **fields):
        rec = {"ts": time.time(), "event": event, **fields}
        with open(self.log_path, "a") as fh:
            fh.write(json.dumps(rec) + "\n")
        if not quiet:  # per-second counters would flood the console
            self.logger.info("%s %s", event, fields)

    def add_flow(self, dp, priority, match, actions, idle=0, hard=0, cookie=0, flags=0):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)] if actions else []
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, priority=priority, match=match, instructions=inst,
            idle_timeout=idle, hard_timeout=hard, cookie=cookie, flags=flags,
        ))

    def allow_packet_in(self, dpid, port):
        now = time.time()
        tokens, last = self.buckets.get((dpid, port), (self.packet_in_rate, now))
        tokens = min(self.packet_in_rate, tokens + (now - last) * self.packet_in_rate)
        if tokens < 1:
            self.buckets[(dpid, port)] = (tokens, now)
            return False
        self.buckets[(dpid, port)] = (tokens - 1, now)
        return True

    # --------------------------------------------------------------- OpenFlow
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features(self, ev):
        dp = ev.msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        self.datapaths[dp.id] = dp
        # Clear the table so old rules from a past run cannot linger.
        dp.send_msg(parser.OFPFlowMod(datapath=dp, command=ofp.OFPFC_DELETE, table_id=ofp.OFPTT_ALL,
                                      out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY, match=parser.OFPMatch()))
        self.add_flow(dp, 0, parser.OFPMatch(), [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)])
        for route in self.static_routes:
            self.add_flow(dp, FORWARD_PRIORITY,
                          parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=route["ip"]),
                          [parser.OFPActionSetField(eth_src=route["eth_src"]),
                           parser.OFPActionSetField(eth_dst=route["eth_dst"]),
                           parser.OFPActionOutput(route["port"])])
        # Re-apply active blocks to a switch that just (re)connected.
        now = time.time()
        for ip, blk in self.blocks.items():
            remaining = int(blk["expires"] - now)
            if remaining > 0:
                self._install_block(dp, ip, remaining)
        self.log_event("switch_connected", dpid=dp.id, static_routes=len(self.static_routes))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        in_port = msg.match["in_port"]
        if not self.allow_packet_in(dp.id, in_port):
            return
        eth = packet.Packet(msg.data).get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        table = self.mac_to_port.setdefault(dp.id, {})
        table[eth.src] = in_port
        out_port = table.get(eth.dst, ofp.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]
        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_src=eth.src, eth_dst=eth.dst)
            self.add_flow(dp, FORWARD_PRIORITY, match, actions, idle=FORWARD_IDLE_TIMEOUT)
        dp.send_msg(parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
                                        in_port=in_port, actions=actions, data=msg.data))

    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def barrier_reply(self, ev):
        key = (ev.msg.datapath.id, ev.msg.xid)
        ip = self.pending_barriers.pop(key, None)
        if ip is None or ip not in self.blocks:
            return
        blk = self.blocks[ip]
        blk["confirmed"][str(key[0])] = time.time()
        if len(blk["confirmed"]) == len(blk["xids"]):
            now = time.time()
            self.log_event("block_confirmed", ip=ip, latency_ms=round((now - blk["requested"]) * 1000, 2),
                           switches=sorted(blk["confirmed"]))

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed(self, ev):
        msg = ev.msg
        if msg.cookie != BLOCK_COOKIE:
            return
        ip = msg.match.get("ipv4_src")
        reason = {0: "idle_timeout", 1: "hard_timeout", 2: "delete"}.get(msg.reason, msg.reason)
        self.log_event("block_removed", ip=ip, dpid=msg.datapath.id, reason=reason,
                       dropped_packets=msg.packet_count, dropped_bytes=msg.byte_count)
        blk = self.blocks.get(ip)
        if blk and time.time() >= blk["expires"] - 1:
            self.blocks.pop(ip, None)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change(self, ev):
        dp = ev.datapath
        if ev.state == DEAD_DISPATCHER and self.datapaths.pop(dp.id, None) is not None:
            self.mac_to_port.pop(dp.id, None)
            self.log_event("switch_disconnected", dpid=dp.id)

    # -------------------------------------------------------------- mitigation
    def _install_block(self, dp, ip, duration):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip)
        self.add_flow(dp, BLOCK_PRIORITY, match, [], hard=duration, cookie=BLOCK_COOKIE,
                      flags=ofp.OFPFF_SEND_FLOW_REM)
        barrier = parser.OFPBarrierRequest(dp)
        dp.set_xid(barrier)
        dp.send_msg(barrier)
        self.pending_barriers[(dp.id, barrier.xid)] = ip
        return barrier.xid

    def block(self, ip, duration, reason="", score=None):
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            return 400, {"error": f"invalid IPv4 address: {ip!r}"}
        if ip in self.whitelist:
            self.log_event("block_refused", ip=ip, why="whitelisted")
            return 403, {"error": f"{ip} is whitelisted"}
        if not self.mitigation:
            self.log_event("block_suppressed", ip=ip, reason=reason, score=score)
            return 200, {"ip": ip, "dry_run": True, "suppressed": True}
        if not self.datapaths:
            self.log_event("block_refused", ip=ip, why="no_switch")
            return 503, {"error": "no switch connected; nothing installed"}
        now = time.time()
        self.blocks = {k: v for k, v in self.blocks.items() if v["expires"] > now}
        if ip not in self.blocks and len(self.blocks) >= self.max_blocks:
            self.log_event("block_refused", ip=ip, why="max_blocks")
            return 429, {"error": "too many active blocks"}
        duration = max(1, min(int(duration), self.max_block_s))
        blk = {"requested": now, "expires": now + duration, "duration": duration, "reason": reason,
               "score": score, "xids": {}, "confirmed": {}, "counts": {}, "renewals": 0,
               "dropped": {}, "drop_pps": 0.0}
        self.blocks[ip] = blk
        self.totals["blocks"] += 1
        for dpid, dp in self.datapaths.items():
            blk["xids"][str(dpid)] = self._install_block(dp, ip, duration)
        self.log_event("block_installed", ip=ip, duration=duration, reason=reason, score=score,
                       switches=sorted(blk["xids"]))
        return 200, {"ip": ip, "duration": duration, "installed_at": now, "switches": len(blk["xids"])}

    def _renew_block(self, ip, blk, drop_pps):
        """Re-install an active block: an identical ADD replaces the rule and restarts its
        hard timeout (OpenFlow 1.3, 6.4), so no packets slip through in between."""
        now = time.time()
        for dp in self.datapaths.values():
            ofp, parser = dp.ofproto, dp.ofproto_parser
            self.add_flow(dp, BLOCK_PRIORITY, parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip),
                          [], hard=blk["duration"], cookie=BLOCK_COOKIE, flags=ofp.OFPFF_SEND_FLOW_REM)
        blk["expires"] = now + blk["duration"]
        blk["renewals"] += 1
        self.totals["renewals"] += 1
        self.log_event("block_renewed", ip=ip, duration=blk["duration"], drop_pps=round(drop_pps, 1),
                       renewals=blk["renewals"])

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply(self, ev):
        dpid, now = ev.msg.datapath.id, time.time()
        for st in ev.msg.body:
            if st.cookie != BLOCK_COOKIE:
                continue
            ip = st.match.get("ipv4_src")
            blk = self.blocks.get(ip)
            if blk is None:
                continue
            prev = blk["counts"].get(dpid)
            blk["counts"][dpid] = (st.packet_count, st.byte_count, now)
            if prev is None:
                continue  # need two samples to tell if packets still arrive
            # A counter below the last sample means the rule was re-created and restarted.
            d_pkts = st.packet_count - prev[0] if st.packet_count >= prev[0] else st.packet_count
            d_bytes = st.byte_count - prev[1] if st.byte_count >= prev[1] else st.byte_count
            pps = d_pkts / max(now - prev[2], 1e-3)
            seen = blk["dropped"].setdefault(dpid, [0, 0, 0.0])
            seen[0] += d_pkts
            seen[1] += d_bytes
            seen[2] = pps
            self.totals["dropped_packets"] += d_pkts
            self.totals["dropped_bytes"] += d_bytes
            blk["drop_pps"] = sum(v[2] for v in blk["dropped"].values())
            self.log_event("block_stats", quiet=True, ip=ip, dpid=dpid, drop_pps=round(pps, 1),
                           dropped_packets=sum(v[0] for v in blk["dropped"].values()),
                           dropped_bytes=sum(v[1] for v in blk["dropped"].values()),
                           remaining_s=round(blk["expires"] - now, 1))
            if self.renew and d_pkts > 0 and blk["expires"] - now <= self.renew_lead_s:
                self._renew_block(ip, blk, pps)

    def _poll_block_stats(self):
        while True:
            hub.sleep(STATS_POLL_S)
            if not self.blocks:
                continue
            for dp in list(self.datapaths.values()):
                ofp, parser = dp.ofproto, dp.ofproto_parser
                dp.send_msg(parser.OFPFlowStatsRequest(
                    dp, table_id=ofp.OFPTT_ALL, out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                    cookie=BLOCK_COOKIE, cookie_mask=COOKIE_MASK, match=parser.OFPMatch()))

    def unblock(self, ip):
        for dp in self.datapaths.values():
            ofp, parser = dp.ofproto, dp.ofproto_parser
            dp.send_msg(parser.OFPFlowMod(
                datapath=dp, command=ofp.OFPFC_DELETE_STRICT, priority=BLOCK_PRIORITY, table_id=0,
                out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                match=parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip)))
        existed = self.blocks.pop(ip, None) is not None
        self.log_event("unblock", ip=ip, existed=existed)
        return 200, {"ip": ip, "removed": existed}

    def set_mitigation(self, enabled):
        self.mitigation = bool(enabled)
        self.log_event("mitigation_changed", enabled=self.mitigation)
        return 200, {"mitigation": self.mitigation}

    def status(self):
        now = time.time()
        return 200, {
            "switches": sorted(self.datapaths),
            "whitelist": sorted(self.whitelist),
            "mitigation": self.mitigation,
            "uptime_s": round(now - self.started, 1),
            "totals": self.totals,
            "blocks": {ip: {"remaining_s": round(b["expires"] - now, 1), "duration_s": b["duration"],
                            "reason": b["reason"], "score": b["score"], "renewals": b["renewals"],
                            "installed_at": b["requested"], "drop_pps": round(b["drop_pps"], 1),
                            "dropped_packets": sum(v[0] for v in b["dropped"].values()),
                            "dropped_bytes": sum(v[1] for v in b["dropped"].values())}
                       for ip, b in self.blocks.items() if b["expires"] > now},
        }

    # --------------------------------------------------------------------- REST
    def start(self):
        super().start()
        self.threads.append(hub.spawn(self._serve_api))
        self.threads.append(hub.spawn(self._poll_block_stats))

    def _serve_api(self):
        self.logger.info("mitigation API on %s:%d%s", self.api_host, self.api_port,
                         " (token required)" if self.api_token else "")
        hub.WSGIServer((self.api_host, self.api_port), self._wsgi).serve_forever()

    def _route(self, method, path, body):
        if method == "GET" and path == "/status":
            return self.status()
        if method != "POST":
            return 404, {"error": "not found"}
        if not isinstance(body, dict):
            return 400, {"error": "body must be a JSON object"}
        if path == "/block":
            return self.block(str(body.get("ip", "")), body.get("duration", 30),
                              str(body.get("reason", "")), body.get("score"))
        if path == "/unblock":
            return self.unblock(str(body.get("ip", "")))
        if path == "/mitigation":
            return self.set_mitigation(body.get("enabled", True))
        return 404, {"error": "not found"}

    def _wsgi(self, environ, start_response):
        method, path = environ["REQUEST_METHOD"], environ.get("PATH_INFO", "")
        try:
            if self.api_token and not hmac.compare_digest(
                    environ.get("HTTP_AUTHORIZATION", ""), f"Bearer {self.api_token}"):
                code, resp = 401, {"error": "missing or wrong bearer token"}
            else:
                body = {}
                if method == "POST":
                    size = int(environ.get("CONTENT_LENGTH") or 0)
                    body = json.loads(environ["wsgi.input"].read(size) or b"{}")
                code, resp = self._route(method, path, body)
        except (ValueError, KeyError, TypeError) as exc:
            code, resp = 400, {"error": str(exc)}
        reason = {200: "OK", 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
                  429: "Too Many Requests", 503: "Service Unavailable"}[code]
        start_response(f"{code} {reason}", [("Content-Type", "application/json")])
        return [json.dumps(resp).encode()]
