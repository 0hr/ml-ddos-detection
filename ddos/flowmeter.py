"""Two-way flow meter that reproduces CICFlowMeter-V3 features (ddos.features.FEATURES).

Rules checked against the CIC-DDoS2019 CSVs (see README, "Why 43 features"):
  * flow key is the 5-tuple; forward = whoever sent the first packet
  * a flow ends on FIN (that packet is counted) or after 120 s
  * only flows with >= 2 packets are emitted
  * packet length = payload bytes; times are in microseconds
  * std/variance are sample stats (ddof=1), 0 with fewer than 2 values
  * the overall packet-length list counts the first packet twice (a CICFlowMeter bug):
    Packet Length Mean/Std/Variance use n+1 values, Average Packet Size = sum / n
  * rates use max(duration, 1 us) (ddos.features.MIN_DURATION_US)
"""

import math
from dataclasses import dataclass, field

from ddos.features import FEATURES, MIN_DURATION_US
from ddos.pcapio import TCP_FIN, Packet

FLOW_TIMEOUT_S = 120.0
MIN_PACKETS = 2


class Stat:
    """Online count/sum/min/max/sample-variance (Welford)."""

    __slots__ = ("n", "total", "mean", "m2", "min", "max")

    def __init__(self) -> None:
        self.n = 0
        self.total = 0.0
        self.mean = 0.0
        self.m2 = 0.0
        self.min = 0.0
        self.max = 0.0

    def add(self, x: float) -> None:
        self.n += 1
        self.total += x
        if self.n == 1:
            self.min = self.max = x
        else:
            self.min = min(self.min, x)
            self.max = max(self.max, x)
        delta = x - self.mean
        self.mean += delta / self.n
        self.m2 += delta * (x - self.mean)

    @property
    def var(self) -> float:
        return self.m2 / (self.n - 1) if self.n > 1 else 0.0

    @property
    def std(self) -> float:
        return math.sqrt(self.var)

    def as_tuple(self) -> tuple[float, float, float, float]:
        """(max, min, mean, std), all 0 when empty."""
        if self.n == 0:
            return 0.0, 0.0, 0.0, 0.0
        return self.max, self.min, self.mean, self.std


@dataclass
class Flow:
    src: str
    dst: str
    sport: int
    dport: int
    proto: int
    start: float
    last: float = 0.0
    last_fwd: float | None = None
    last_bwd: float | None = None
    init_win_fwd: int = -1
    init_win_bwd: int = -1
    fwd_len: Stat = field(default_factory=Stat)
    bwd_len: Stat = field(default_factory=Stat)
    all_len: Stat = field(default_factory=Stat)
    flow_iat: Stat = field(default_factory=Stat)
    fwd_iat: Stat = field(default_factory=Stat)
    bwd_iat: Stat = field(default_factory=Stat)
    closed: bool = False

    @property
    def packets(self) -> int:
        return self.fwd_len.n + self.bwd_len.n

    def add(self, pkt: Packet) -> None:
        us = pkt.ts * 1e6
        if self.packets == 0:
            self.all_len.add(pkt.payload_len)  # CICFlowMeter counts the first packet twice
        else:
            self.flow_iat.add(us - self.last * 1e6)
        self.all_len.add(pkt.payload_len)
        if pkt.src == self.src and pkt.sport == self.sport:
            if self.last_fwd is not None:
                self.fwd_iat.add(us - self.last_fwd * 1e6)
            else:
                self.init_win_fwd = pkt.window
            self.last_fwd = pkt.ts
            self.fwd_len.add(pkt.payload_len)
        else:
            if self.last_bwd is not None:
                self.bwd_iat.add(us - self.last_bwd * 1e6)
            else:
                self.init_win_bwd = pkt.window
            self.last_bwd = pkt.ts
            self.bwd_len.add(pkt.payload_len)
        self.last = pkt.ts

    def features(self) -> dict[str, float]:
        fwd, bwd = self.fwd_len, self.bwd_len
        n = fwd.n + bwd.n
        duration = (self.last - self.start) * 1e6
        dur_s = max(duration, MIN_DURATION_US) / 1e6
        f_max, f_min, f_mean, f_std = fwd.as_tuple()
        b_max, b_min, b_mean, b_std = bwd.as_tuple()
        fi_max, fi_min, fi_mean, fi_std = self.flow_iat.as_tuple()
        wi_max, wi_min, wi_mean, wi_std = self.fwd_iat.as_tuple()
        bi_max, bi_min, bi_mean, bi_std = self.bwd_iat.as_tuple()
        allv = self.all_len
        values = {
            "Protocol": self.proto,
            "Flow Duration": round(duration),
            "Total Fwd Packets": fwd.n,
            "Total Backward Packets": bwd.n,
            "Total Length of Fwd Packets": fwd.total,
            "Total Length of Bwd Packets": bwd.total,
            "Fwd Packet Length Max": f_max,
            "Fwd Packet Length Min": f_min,
            "Fwd Packet Length Mean": f_mean,
            "Fwd Packet Length Std": f_std,
            "Bwd Packet Length Max": b_max,
            "Bwd Packet Length Min": b_min,
            "Bwd Packet Length Mean": b_mean,
            "Bwd Packet Length Std": b_std,
            "Flow Bytes/s": (fwd.total + bwd.total) / dur_s,
            "Flow Packets/s": n / dur_s,
            "Flow IAT Mean": fi_mean,
            "Flow IAT Std": fi_std,
            "Flow IAT Max": fi_max,
            "Flow IAT Min": fi_min,
            "Fwd IAT Total": self.fwd_iat.total,
            "Fwd IAT Mean": wi_mean,
            "Fwd IAT Std": wi_std,
            "Fwd IAT Max": wi_max,
            "Fwd IAT Min": wi_min,
            "Bwd IAT Total": self.bwd_iat.total,
            "Bwd IAT Mean": bi_mean,
            "Bwd IAT Std": bi_std,
            "Bwd IAT Max": bi_max,
            "Bwd IAT Min": bi_min,
            "Fwd Packets/s": fwd.n / dur_s,
            "Bwd Packets/s": bwd.n / dur_s,
            "Min Packet Length": allv.min,
            "Max Packet Length": allv.max,
            "Packet Length Mean": allv.mean,
            "Packet Length Std": allv.std,
            "Packet Length Variance": allv.var,
            "Down/Up Ratio": bwd.n // fwd.n if fwd.n else 0,
            "Average Packet Size": allv.total / n if n else 0.0,
            "Avg Fwd Segment Size": f_mean,
            "Avg Bwd Segment Size": b_mean,
            "Init_Win_bytes_forward": self.init_win_fwd,
            "Init_Win_bytes_backward": self.init_win_bwd,
        }
        assert len(values) == len(FEATURES)
        return values

    def record(self) -> dict:
        """Features plus identifying metadata (not model inputs)."""
        return {
            "Source IP": self.src,
            "Source Port": self.sport,
            "Destination IP": self.dst,
            "Destination Port": self.dport,
            "start_ts": self.start,
            "last_ts": self.last,
            **self.features(),
        }


class FlowMeter:
    """Assigns packets to flows. ``add`` returns flows that just finished."""

    def __init__(self, flow_timeout: float = FLOW_TIMEOUT_S, min_packets: int = MIN_PACKETS):
        self.flow_timeout = flow_timeout
        self.min_packets = min_packets
        self.active: dict[tuple, Flow] = {}

    @staticmethod
    def _key(pkt: Packet) -> tuple:
        a, b = (pkt.src, pkt.sport), (pkt.dst, pkt.dport)
        return (a, b, pkt.proto) if a <= b else (b, a, pkt.proto)

    def add(self, pkt: Packet) -> list[Flow]:
        done = []
        key = self._key(pkt)
        flow = self.active.get(key)
        if flow is not None and pkt.ts - flow.start > self.flow_timeout:
            done.append(self.active.pop(key))
            flow = None
        if flow is None:
            flow = Flow(pkt.src, pkt.dst, pkt.sport, pkt.dport, pkt.proto, start=pkt.ts)
            self.active[key] = flow
        flow.add(pkt)
        if pkt.proto == 6 and pkt.flags & TCP_FIN:
            flow.closed = True
            done.append(self.active.pop(key))
        return [f for f in done if f.packets >= self.min_packets]

    def expire(self, now: float, idle_timeout: float) -> list[Flow]:
        """Finish flows idle for ``idle_timeout`` seconds or older than the flow timeout."""
        stale = [
            k
            for k, f in self.active.items()
            if now - f.last > idle_timeout or now - f.start > self.flow_timeout
        ]
        done = [self.active.pop(k) for k in stale]
        return [f for f in done if f.packets >= self.min_packets]

    def flush(self) -> list[Flow]:
        done = list(self.active.values())
        self.active.clear()
        return [f for f in done if f.packets >= self.min_packets]
