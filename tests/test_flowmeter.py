import io
import math
import struct

import pytest

from ddos.features import FEATURES
from ddos.flowmeter import FlowMeter
from ddos.pcapio import TCP_ACK, TCP_FIN, TCP_SYN, iter_packets


def ip_bytes(addr: str) -> bytes:
    return bytes(int(x) for x in addr.split("."))


def frame(src, dst, sport, dport, proto, payload, flags=TCP_ACK, window=5840) -> bytes:
    if proto == 6:
        l4 = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, window, 0, 0)
    else:
        l4 = struct.pack("!HHHH", sport, dport, 8 + payload, 0)
    body = l4 + b"x" * payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(body), 0, 0, 64, proto, 0, ip_bytes(src), ip_bytes(dst))
    eth = b"\x00" * 12 + b"\x08\x00"
    return eth + ip + body


def pcap(packets, snaplen=None) -> io.BytesIO:
    out = io.BytesIO()
    out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for ts, data in packets:
        cap = data[:snaplen] if snaplen else data
        out.write(struct.pack("<IIII", int(ts), round((ts % 1) * 1e6), len(cap), len(data)))
        out.write(cap)
    out.seek(0)
    return out


def run(packets, snaplen=None):
    meter = FlowMeter()
    done = []
    for pkt in iter_packets(pcap(packets, snaplen)):
        done += meter.add(pkt)
    return done + meter.flush()


A, B = "10.0.0.1", "10.0.0.100"


def test_tcp_flow_matches_cic_conventions():
    pkts = [
        (100.000000, frame(A, B, 40000, 80, 6, 0, TCP_SYN, window=64240)),
        (100.000100, frame(B, A, 80, 40000, 6, 0, TCP_SYN | TCP_ACK, window=65160)),
        (100.000300, frame(A, B, 40000, 80, 6, 120, TCP_ACK, window=502)),
        (100.001300, frame(B, A, 80, 40000, 6, 900, TCP_ACK, window=509)),
        (100.002300, frame(A, B, 40000, 80, 6, 0, TCP_FIN | TCP_ACK, window=502)),
    ]
    (flow,) = run(pkts)
    f = flow.features()
    assert list(f) == FEATURES
    assert f["Protocol"] == 6
    assert f["Flow Duration"] == 2300
    assert (f["Total Fwd Packets"], f["Total Backward Packets"]) == (3, 2)
    assert (f["Total Length of Fwd Packets"], f["Total Length of Bwd Packets"]) == (120, 900)
    assert f["Fwd Packet Length Mean"] == pytest.approx(40)
    assert f["Fwd Packet Length Std"] == pytest.approx(math.sqrt(((0 - 40) ** 2 * 2 + 80**2) / 2))
    assert f["Init_Win_bytes_forward"] == 64240 and f["Init_Win_bytes_backward"] == 65160
    assert f["Flow IAT Mean"] == pytest.approx(2300 / 4)
    assert f["Flow IAT Max"] == pytest.approx(1000) and f["Flow IAT Min"] == pytest.approx(100)
    assert f["Fwd IAT Total"] == pytest.approx(2300)
    assert f["Bwd IAT Total"] == pytest.approx(1200)
    assert f["Flow Bytes/s"] == pytest.approx(1020 / 0.0023)
    assert f["Down/Up Ratio"] == 0
    # First packet (0 bytes) counted twice in the overall length statistics.
    lengths = [0, 0, 0, 120, 900, 0]
    mean = sum(lengths) / 6
    assert f["Packet Length Mean"] == pytest.approx(mean)
    assert f["Packet Length Variance"] == pytest.approx(sum((x - mean) ** 2 for x in lengths) / 5)
    assert f["Average Packet Size"] == pytest.approx(f["Packet Length Mean"] * 6 / 5)
    assert f["Min Packet Length"] == 0 and f["Max Packet Length"] == 900


def test_udp_fwd_only_two_packets_and_snaplen():
    pkts = [(5.0, frame(A, B, 5000, 53, 17, 300)), (5.000010, frame(A, B, 5000, 53, 17, 100))]
    (flow,) = run(pkts, snaplen=64)  # payload length must come from IP header, not capture
    f = flow.features()
    assert f["Total Length of Fwd Packets"] == 400
    assert f["Packet Length Mean"] == pytest.approx((300 + 100 + 300) / 3)
    assert f["Fwd Packet Length Std"] == pytest.approx(200 / math.sqrt(2))
    assert f["Init_Win_bytes_forward"] == -1 and f["Init_Win_bytes_backward"] == -1
    assert f["Bwd Packet Length Max"] == 0 and f["Bwd IAT Total"] == 0


def test_zero_duration_rates_use_floor():
    pkts = [(7.0, frame(A, B, 1, 2, 17, 10)), (7.0, frame(A, B, 1, 2, 17, 10))]
    (flow,) = run(pkts)
    f = flow.features()
    assert f["Flow Duration"] == 0
    assert f["Flow Packets/s"] == pytest.approx(2e6)
    assert f["Fwd Packets/s"] == pytest.approx(2e6)


def test_single_packet_flows_dropped_and_fin_splits_flows():
    pkts = [
        (1.0, frame(A, B, 1111, 80, 6, 0, TCP_SYN)),  # 1 packet: never emitted
        (2.0, frame(A, B, 2222, 80, 6, 0, TCP_SYN)),
        (2.1, frame(A, B, 2222, 80, 6, 0, TCP_FIN | TCP_ACK)),
        (2.2, frame(A, B, 2222, 80, 6, 10, TCP_ACK)),  # new flow after FIN
        (2.3, frame(A, B, 2222, 80, 6, 10, TCP_ACK)),
    ]
    flows = run(pkts)
    assert [f.packets for f in flows] == [2, 2]


def test_flow_timeout_starts_new_flow():
    pkts = [(0.0, frame(A, B, 9, 9, 17, 1)), (1.0, frame(A, B, 9, 9, 17, 1)),
            (130.0, frame(A, B, 9, 9, 17, 1)), (131.0, frame(A, B, 9, 9, 17, 1))]
    assert [f.packets for f in run(pkts)] == [2, 2]
