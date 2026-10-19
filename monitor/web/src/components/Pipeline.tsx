import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn, compact, fmtDuration } from "@/lib/utils";
import type { Incident, Snapshot } from "@/types";

type StageState = "done" | "active" | "pending" | "skipped";

interface Stage {
  label: string;
  value: string;
  sub: string;
  state: StageState;
  color: string;
}

const RED = "hsl(var(--attack))";
const BLUE = "hsl(var(--info))";
const AMBER = "hsl(var(--blocked))";
const GREEN = "hsl(var(--benign))";
const KIND: Record<string, string> = { udp: "UDP flood", conn: "TCP connection flood", http: "HTTP request flood" };

// The step after the last finished one is "active" while the attack is still running.
function stateOf(done: boolean, prevDone: boolean, inc: Incident, skipped = false): StageState {
  if (done) return "done";
  if (skipped) return "skipped";
  return prevDone && inc.active ? "active" : "pending";
}

function stages(snap: Snapshot): Stage[] {
  const inc = snap.incident;
  const k = snap.kpis;
  if (!inc) {
    const idle = (label: string, sub: string, color: string): Stage => ({ label, value: "—", sub, state: "pending", color });
    return [
      idle("Attack starts", "no attack yet", RED),
      idle("Flagged by the model", "per-source flow vote", BLUE),
      idle("Block requested", "monitor → controller", AMBER),
      idle("Rule on the switches", "confirmed by OpenFlow barrier", AMBER),
      idle("Traffic dropped", "at the switch, before the server", GREEN),
    ];
  }
  const detected = inc.detected_s != null;
  const requested = inc.requested_s != null;
  const confirmed = inc.confirmed_s != null;
  const dropping = inc.dropping_s != null;
  const off = inc.suppressed || (snap.mitigation === false && !requested);
  return [
    { label: "Attack starts", value: "t = 0", sub: KIND[inc.kind] ?? "flood", state: "done", color: RED },
    {
      label: inc.rule === "rate" ? "Flagged by the rate limit" : "Flagged by the model", color: BLUE,
      value: detected ? `+${fmtDuration(inc.detected_s!)}` : "…",
      sub: detected ? `${inc.flagged} of ${inc.attackers} sources flagged` : "scoring flows",
      state: stateOf(detected, true, inc),
    },
    {
      label: "Block requested", color: AMBER,
      value: requested ? (inc.api_ms != null ? `${inc.api_ms.toFixed(1)} ms` : "sent") : off ? "off" : "…",
      sub: requested ? "controller API round trip" : off ? "mitigation off: logged only" : "monitor → controller",
      state: stateOf(requested, detected, inc, off),
    },
    {
      label: "Rule on the switches", color: AMBER,
      value: confirmed ? (inc.confirm_ms != null ? `${inc.confirm_ms.toFixed(1)} ms` : "installed") : off ? "off" : "…",
      sub: confirmed ? `${inc.blocked} of ${inc.attackers} sources blocked` : off ? "no rule installed" : "waiting for barrier reply",
      state: stateOf(confirmed, requested, inc, off),
    },
    {
      label: "Traffic dropped", color: GREEN,
      // While the attack runs: the live drop rate. Afterwards: what the rules dropped in total.
      value: dropping ? (inc.active || k.blocked_pps > 0 ? `${compact(k.blocked_pps)} pps` : compact(k.dropped_packets))
        : confirmed && !k.dropped_visible ? "dropping" : off ? "off" : "…",
      sub: dropping ? (inc.active || k.blocked_pps > 0 ? `${compact(k.dropped_packets)} packets dropped so far` : "packets dropped in total")
        : confirmed && !k.dropped_visible ? "drop counters not recorded in this run"
        : off ? "attack reaches the server" : "first counter sample",
      state: stateOf(dropping || (confirmed && !k.dropped_visible), confirmed, inc, off),
    },
  ];
}

function summary(snap: Snapshot): { text: string; color?: string } {
  const inc = snap.incident;
  if (!inc) return { text: "waiting for an attack" };
  if (inc.confirmed_s != null) return { text: `mitigated ${fmtDuration(inc.confirmed_s)} after the attack started`, color: GREEN };
  if (inc.suppressed || (snap.mitigation === false && inc.detected_s != null)) {
    return { text: `detected in ${fmtDuration(inc.detected_s ?? 0)}, not mitigated (mitigation off)`, color: RED };
  }
  if (!inc.active) return { text: "attack ended before a block was needed" };
  return { text: `attack running for ${inc.age_s.toFixed(0)} s`, color: RED };
}

export function Pipeline({ snap }: { snap: Snapshot }) {
  const list = stages(snap);
  const sum = summary(snap);
  return (
    <Card>
      <CardHeader>
        <CardTitle>Mitigation timeline</CardTitle>
        {snap.incident && <span className="tabnum text-2xs text-muted-foreground">attack #{snap.incident.n}</span>}
        <span className="ml-auto text-2xs" style={{ color: sum.color ?? "hsl(var(--muted-foreground))" }}>{sum.text}</span>
      </CardHeader>
      <CardContent>
        <ol className="grid grid-cols-2 gap-y-4 sm:grid-cols-5">
          {list.map((s, i) => {
            const lit = s.state === "done" || s.state === "active";
            return (
              <li key={s.label} className={cn("min-w-0", s.state === "pending" || s.state === "skipped" ? "opacity-55" : "")}>
                <div className="flex items-center">
                  <span className="relative flex h-2 w-2 shrink-0">
                    {s.state === "active" && (
                      <span className="absolute inline-flex h-full w-full animate-ping rounded-full opacity-60" style={{ background: s.color }} />
                    )}
                    <span className="relative inline-flex h-2 w-2 rounded-full"
                      style={lit ? { background: s.color } : { border: "1.5px solid hsl(var(--muted-foreground))" }} />
                  </span>
                  {i < list.length - 1 && (
                    <span className="mx-2 hidden h-px flex-1 sm:block"
                      style={{ background: list[i + 1].state === "done" ? s.color : "hsl(var(--border))" }} />
                  )}
                </div>
                <div className="mt-2 truncate pr-3 text-xs text-muted-foreground">{s.label}</div>
                <div className="tabnum mt-0.5 truncate pr-3 text-lg font-semibold leading-tight tracking-tight">{s.value}</div>
                <div className="mt-0.5 truncate pr-3 text-2xs text-muted-foreground">{s.sub}</div>
              </li>
            );
          })}
        </ol>
      </CardContent>
    </Card>
  );
}
