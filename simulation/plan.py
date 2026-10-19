"""The session plan of a data collection: which traffic runs, for how long, and its label.

A collection is a list of sessions, each captured into its own pcap. Normal clients run in
every session; attack sessions add one flood type from the attacker hosts on top.
Repetitions change the intensity of both, so the dataset is not one traffic level per class.

The truth comes from the session design, not from the packets: attacker hosts send nothing
but their flood, so in an attack session every flow they start gets that session's attack
label and every other flow is BENIGN.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

ATTACK_LABELS = {"udp": "Sim-UDP-flood", "conn": "Sim-TCP-connect-flood", "http": "Sim-HTTP-flood"}
BENIGN = "BENIGN"
PROFILES = ("browse", "api", "download", "monitor")


@dataclass
class Session:
    name: str
    rep: int
    duration: float                 # seconds of capture
    benign_rate: float              # requests/s per HTTP client worker
    benign_workers: int
    udp_rate: float                 # lookups/s per UDP client (0 = none)
    udp_share: float                # fraction of clients that also use the UDP service
    profiles: list[str] = field(default_factory=lambda: list(PROFILES))  # rotated over clients
    attack: str | None = None       # udp | conn | http
    attack_threads: int = 0
    attack_dport_pool: int = 16     # udp only: destination ports per thread
    attack_delay: float = 10.0      # legitimate-only lead-in before the attack starts
    attack_duration: float = 0.0
    seed: int = 1
    index: int = 0                  # position in the plan, set by make_plan

    @property
    def id(self) -> str:
        return f"r{self.rep}_{self.index:02d}_{self.name}"

    @property
    def label(self) -> str:
        return ATTACK_LABELS[self.attack] if self.attack else BENIGN

    def as_dict(self) -> dict:
        return {**asdict(self), "id": self.id, "label": self.label}


def make_plan(reps: int = 3, attacks: tuple[str, ...] = ("udp", "conn", "http"), quick: bool = False,
              benign_s: float = 60, attack_s: float = 45) -> list[Session]:
    """Three normal sessions (quiet, mixed, busy) and one per attack type, per repetition.
    Each repetition steps the intensities up: attack threads 2 -> 4 -> 8, UDP destination-port
    pool 4 -> 16 -> 64, and higher normal request rates."""
    unknown = [a for a in attacks if a not in ATTACK_LABELS]
    if unknown:
        raise ValueError(f"unknown attack type(s) {unknown}; choose from {sorted(ATTACK_LABELS)}")
    if quick:
        benign_s, attack_s = 30, 30
    threads, pools, scale = (2, 4, 8), (4, 16, 64), (1.0, 1.5, 2.0)
    plan: list[Session] = []
    for rep in range(1, reps + 1):
        k = (rep - 1) % 3
        s = scale[k]
        base = dict(rep=rep, duration=benign_s)
        sessions = [
            Session(name="benign_quiet", benign_rate=0.5 * s, benign_workers=1, udp_rate=0.5, udp_share=0.34,
                    profiles=["browse", "monitor"], **base),
            Session(name="benign_mixed", benign_rate=1.5 * s, benign_workers=2, udp_rate=1.0, udp_share=0.5, **base),
            Session(name="benign_busy", benign_rate=5.0 * s, benign_workers=3, udp_rate=2.0, udp_share=0.5,
                    profiles=["browse", "api", "download"], **base),
        ]
        delay = 5.0 if quick else 10.0
        for a in attacks:
            sessions.append(Session(
                name=f"attack_{a}", rep=rep, duration=attack_s, benign_rate=1.5 * s, benign_workers=2,
                udp_rate=1.0, udp_share=0.5, attack=a, attack_threads=threads[k], attack_dport_pool=pools[k],
                attack_delay=delay, attack_duration=attack_s - delay - 5.0))
        for i, sess in enumerate(sessions, start=1):
            sess.index = len(plan) + 1
            sess.seed = rep * 1000 + i
            plan.append(sess)
    return plan


def describe(plan: list[Session]) -> str:
    lines = [f"{'session':26s} {'seconds':>7s}  legitimate traffic                 attack"]
    for s in plan:
        legit = f"{s.benign_rate:.2g} req/s x{s.benign_workers}" + (f", UDP {s.udp_rate:g}/s" if s.udp_rate else "")
        attack = (f"{s.attack} flood, {s.attack_threads} threads, {s.attack_duration:.0f} s from t={s.attack_delay:.0f}s"
                  if s.attack else "-")
        lines.append(f"{s.id:26s} {s.duration:7.0f}  {legit:34s} {attack}")
    total = sum(s.duration for s in plan)
    lines.append(f"{len(plan)} sessions, {total / 60:.0f} min of traffic (about {total / 60 * 1.25:.0f} min with setup)")
    return "\n".join(lines)
