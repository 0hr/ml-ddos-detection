"""Small pcap reader and IPv4/TCP/UDP header parser, no extra libraries.

Works on files and on live streams (``tcpdump -U -w -``), so the offline converter and
the live monitor use the same code.
"""

import struct
from typing import BinaryIO, Iterator, NamedTuple

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113

_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6),
    b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9),
    b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20


class Packet(NamedTuple):
    ts: float
    src: str
    dst: str
    sport: int
    dport: int
    proto: int
    payload_len: int  # transport payload bytes, as CICFlowMeter's "packet length"
    flags: int  # TCP flags, 0 for UDP
    window: int  # TCP window, -1 for UDP


def _read_exact(fh: BinaryIO, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = fh.read(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def iter_records(fh: BinaryIO, tee: BinaryIO | None = None) -> Iterator[tuple[float, int, bytes]]:
    """Yield (timestamp, linktype, frame bytes). Optionally copy the raw stream to ``tee``."""
    header = _read_exact(fh, 24)
    if len(header) < 24:
        return
    if header[:4] not in _MAGIC:
        raise ValueError("not a classic pcap stream (pcapng is not supported; use tcpdump -w)")
    endian, tick = _MAGIC[header[:4]]
    linktype = struct.unpack(endian + "I", header[20:24])[0]
    if tee is not None:
        tee.write(header)
    rec = struct.Struct(endian + "IIII")
    while True:
        rh = _read_exact(fh, 16)
        if len(rh) < 16:
            return
        sec, frac, incl, _orig = rec.unpack(rh)
        data = _read_exact(fh, incl)
        if len(data) < incl:
            return
        if tee is not None:
            tee.write(rh)
            tee.write(data)
        yield sec + frac * tick, linktype, data


def parse_frame(ts: float, linktype: int, data: bytes) -> Packet | None:
    """Parse an IPv4 TCP/UDP frame. Returns None for anything else (ARP, IPv6, fragments)."""
    if linktype == LINKTYPE_ETHERNET:
        if len(data) < 14:
            return None
        off, ethertype = 14, struct.unpack_from("!H", data, 12)[0]
        while ethertype in (0x8100, 0x88A8) and len(data) >= off + 4:
            ethertype = struct.unpack_from("!H", data, off + 2)[0]
            off += 4
    elif linktype == LINKTYPE_LINUX_SLL:
        if len(data) < 16:
            return None
        off, ethertype = 16, struct.unpack_from("!H", data, 14)[0]
    elif linktype == LINKTYPE_RAW:
        off, ethertype = 0, 0x0800
    else:
        return None
    if ethertype != 0x0800 or len(data) < off + 20:
        return None

    vihl = data[off]
    if vihl >> 4 != 4:
        return None
    ihl = (vihl & 0x0F) * 4
    total_len, frag, proto = struct.unpack_from("!H2xH1xB", data, off + 2)
    if frag & 0x1FFF:  # non-first fragment: no transport header
        return None
    src = ".".join(map(str, data[off + 12 : off + 16]))
    dst = ".".join(map(str, data[off + 16 : off + 20]))
    l4 = off + ihl
    # Use the IP total length, not the captured length: captures may be truncated (snaplen).
    l4_len = total_len - ihl

    if proto == 6:
        if len(data) < l4 + 16:
            return None
        sport, dport, doff_flags, window = struct.unpack_from("!HH8xHH", data, l4)
        thl = (doff_flags >> 12) * 4
        return Packet(ts, src, dst, sport, dport, 6, max(l4_len - thl, 0), doff_flags & 0x3F, window)
    if proto == 17:
        if len(data) < l4 + 8:
            return None
        sport, dport = struct.unpack_from("!HH", data, l4)
        return Packet(ts, src, dst, sport, dport, 17, max(l4_len - 8, 0), 0, -1)
    return None


def iter_packets(fh: BinaryIO, tee: BinaryIO | None = None) -> Iterator[Packet]:
    for ts, linktype, data in iter_records(fh, tee):
        pkt = parse_frame(ts, linktype, data)
        if pkt is not None:
            yield pkt
