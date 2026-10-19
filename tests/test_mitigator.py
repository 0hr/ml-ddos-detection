"""Block decision logic of the traffic monitor (no controller, no model needed)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from traffic.monitor import Mitigator


class FakeMitigator(Mitigator):
    """Records block requests and answers them with a scripted response."""

    def __init__(self, responses=None, **kw):
        defaults = dict(controller="http://controller", window=6.0, min_flows=5, ratio=0.8, block_s=20,
                        cooldown=0.0, whitelist=["10.0.0.100"], events=None)
        super().__init__(**{**defaults, **kw})
        self.requests = []
        self.responses = list(responses or [])

    def _post(self, path, payload):
        self.requests.append(payload)
        return self.responses.pop(0) if self.responses else {"ip": payload["ip"], "duration": payload["duration"]}


def feed(mit, src, verdicts, t0=100.0, step=0.1):
    for i, attack in enumerate(verdicts):
        mit.observe(src, ("flow", src, i, t0), t0 + i * step, attack, 0.99 if attack else 0.01)


def test_blocks_only_when_count_and_share_are_met():
    mit = FakeMitigator()
    feed(mit, "10.0.0.1", [True] * 4)
    assert not mit.requests  # 4 attack flows: below --min-flows
    feed(mit, "10.0.0.1", [True], t0=101.0)
    assert [r["ip"] for r in mit.requests] == ["10.0.0.1"]


def test_benign_source_with_a_few_flagged_flows_is_not_blocked():
    mit = FakeMitigator()
    feed(mit, "10.0.0.2", [False] * 40 + [True] * 9)  # 9 attack flows but only 18 % of its traffic
    assert not mit.requests


def test_one_vote_per_flow_latest_verdict_wins():
    mit = FakeMitigator()
    for i in range(10):  # the same flow re-scored ten times is still one vote
        mit.observe("10.0.0.1", "same-flow", 100.0 + i, True, 0.99, final=False)
    assert not mit.requests


def test_old_verdicts_leave_the_window():
    mit = FakeMitigator()
    feed(mit, "10.0.0.1", [True] * 4, t0=100.0)
    feed(mit, "10.0.0.1", [True] * 4, t0=110.0)  # the first four are older than the 6 s window
    assert not mit.requests


def test_whitelisted_source_is_never_blocked():
    mit = FakeMitigator()
    feed(mit, "10.0.0.100", [True] * 20)
    assert not mit.requests


def test_no_second_request_while_blocked():
    mit = FakeMitigator()
    feed(mit, "10.0.0.1", [True] * 30)
    assert len(mit.requests) == 1


def test_failed_request_is_retried_soon():
    mit = FakeMitigator(responses=[{"error": "no switch connected", "status": 503}])
    feed(mit, "10.0.0.1", [True] * 10, t0=100.0)           # first request fails
    assert len(mit.requests) == 1 and mit.counts["blocks"] == 0
    feed(mit, "10.0.0.1", [True] * 3, t0=100.0 + mit.retry_s + 1)
    assert len(mit.requests) == 2 and mit.counts["blocks"] == 1


def test_suppressed_block_is_logged_once_and_lands_when_mitigation_returns():
    off = {"dry_run": True, "suppressed": True}
    mit = FakeMitigator(responses=[off, off])
    feed(mit, "10.0.0.1", [True] * 10, t0=100.0)
    feed(mit, "10.0.0.1", [True] * 3, t0=103.0)
    assert len(mit.requests) == 2 and mit.counts["blocks"] == 1  # asked twice, decision logged once
    feed(mit, "10.0.0.1", [True] * 3, t0=106.0)                  # mitigation back on: real block
    assert len(mit.requests) == 3 and mit.counts["blocks"] == 2
    feed(mit, "10.0.0.1", [True] * 3, t0=108.0)
    assert len(mit.requests) == 3                                # now blocked for block_s


def test_quiet_sources_are_pruned():
    mit = FakeMitigator()
    feed(mit, "10.0.0.7", [False] * 3, t0=100.0)
    feed(mit, "10.0.0.8", [False] * 3, t0=200.0)  # > PRUNE_EVERY_S later
    assert "10.0.0.7" not in mit.history and "10.0.0.8" in mit.history


def burst(mit, src, n, t0, seconds, attack=False):
    """n flows from src spread evenly over `seconds`."""
    for i in range(n):
        mit.observe(src, ("flow", src, t0, i), t0 + seconds * i / n, attack, 0.99 if attack else 0.02)


def test_rate_rule_blocks_a_flood_the_model_calls_benign():
    mit = FakeMitigator()                      # default: 100 flows/s over a 6 s window
    burst(mit, "10.0.0.1", 2000, t0=100.0, seconds=5.0)   # 400 flows/s, every flow scored benign
    assert len(mit.requests) == 1
    assert mit.requests[0]["ip"] == "10.0.0.1" and "flows/s" in mit.requests[0]["reason"]
    assert mit.requests[0]["score"] is None    # not a model decision, so no model score is claimed


def test_rate_rule_leaves_a_flash_crowd_alone():
    mit = FakeMitigator()
    burst(mit, "10.0.0.2", 1080, t0=100.0, seconds=30.0)  # 36 flows/s, the busiest client measured
    assert not mit.requests


def test_rate_rule_is_a_rate_not_a_total():
    mit = FakeMitigator()
    burst(mit, "10.0.0.2", 3000, t0=100.0, seconds=60.0)  # many flows, but only 50 per second
    assert not mit.requests


def test_rate_rule_can_be_switched_off():
    mit = FakeMitigator(max_flow_rate=0)
    burst(mit, "10.0.0.1", 2000, t0=100.0, seconds=5.0)
    assert not mit.requests


def test_model_rule_wins_when_both_apply():
    mit = FakeMitigator()
    burst(mit, "10.0.0.1", 2000, t0=100.0, seconds=5.0, attack=True)
    assert len(mit.requests) == 1 and mit.requests[0]["reason"] == "5/5 flows"
    assert mit.requests[0]["score"] == 0.99


def test_running_totals_match_a_recount():
    mit = FakeMitigator(max_flow_rate=0, min_flows=10**9)   # never blocks: only the bookkeeping runs
    import random
    rng = random.Random(3)
    t = 100.0
    for i in range(5000):
        t += rng.random() * 0.01
        key = rng.randrange(1500)                            # flows are re-scored and change verdict
        mit.observe("10.0.0.9", key, t, rng.random() < 0.4, rng.random())
    votes = mit.history["10.0.0.9"]
    live = [(a, p) for ts, a, p in votes.votes.values()]
    assert votes.attacks == sum(a for a, _ in live)
    assert abs(votes.proba_sum - sum(p for a, p in live if a)) < 1e-6
    assert all(t - ts <= mit.window + 0.25 for ts, _, _ in votes.votes.values())  # swept within SCAN_EVERY_S
