import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { compact } from "@/lib/utils";
import type { Host, Snapshot, VoteRule } from "@/types";

const RED = "hsl(var(--attack))";
const GREEN = "hsl(var(--benign))";
const AMBER = "hsl(var(--blocked))";
const MUTED = "hsl(var(--muted-foreground))";

// The monitor's vote for one source: share of its recent flows classified as attack,
// against the share the block rule needs (the tick mark).
function Vote({ h, rule }: { h: Host; rule: VoteRule }) {
  if (h.blocked) return <span className="text-2xs" style={{ color: AMBER }}>blocked · not visible at the tap</span>;
  if (h.flows === 0) return <span className="text-2xs text-muted-foreground">no flows scored</span>;
  const share = h.attack_flows / h.flows;
  const over = share >= rule.ratio && h.attack_flows >= rule.min_flows;
  const rate = h.flows / rule.window_s;
  const tooFast = rate > rule.max_flow_rate;
  return (
    <div className="flex items-center gap-2">
      <div className="relative h-1 flex-1 rounded-full bg-muted">
        <div className="h-full rounded-full" style={{ width: `${share * 100}%`, background: over ? RED : share > 0 ? AMBER : GREEN }} />
        <span className="absolute -top-0.5 h-2 w-px bg-foreground/40" style={{ left: `${rule.ratio * 100}%` }} />
      </div>
      <span className="tabnum w-14 shrink-0 text-right text-2xs text-muted-foreground">{h.attack_flows}/{h.flows}</span>
      <span className="tabnum w-12 shrink-0 text-right text-2xs" style={{ color: tooFast ? RED : MUTED }}
        title={`flows per second over the last ${rule.window_s.toFixed(0)} s (limit ${rule.max_flow_rate})`}>
        {rate < 10 ? rate.toFixed(1) : Math.round(rate)}/s
      </span>
    </div>
  );
}

function dot(h: Host) {
  if (h.blocked) return AMBER;
  if (h.state === "attacking") return RED;
  return h.state === "idle" ? MUTED : GREEN;
}

export function Sources({ snap, onBlock, onUnblock }: {
  snap: Snapshot; onBlock: (ip: string) => void; onUnblock: (ip: string) => void;
}) {
  const hosts = snap.hosts.filter((h) => h.role !== "server");
  const rule = snap.vote_rule;
  const can = snap.controls.manual_block;
  return (
    <Card className="flex h-full flex-col">
      <CardHeader>
        <CardTitle>Sources</CardTitle>
        <span className="ml-auto text-2xs text-muted-foreground">
          block at ≥ {rule.min_flows} attack flows and ≥ {Math.round(rule.ratio * 100)} % in {rule.window_s.toFixed(0)} s, or &gt; {rule.max_flow_rate} flows/s
        </span>
      </CardHeader>
      <CardContent className="min-h-0 flex-1 overflow-y-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="text-left text-2xs text-muted-foreground">
              <th className="pb-1.5 font-normal">host</th>
              <th className="pb-1.5 text-right font-normal">rate</th>
              <th className="pb-1.5 pl-4 font-normal">attack share of recent flows · flow rate</th>
              {can && <th className="pb-1.5" />}
            </tr>
          </thead>
          <tbody className="divide-y">
            {hosts.map((h) => (
              <tr key={h.id}>
                <td className="py-1.5">
                  <span className="flex items-center gap-2">
                    <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: dot(h) }} />
                    <span className="font-medium">{h.id}</span>
                    <span className="tabnum text-2xs text-muted-foreground">{h.ip}</span>
                  </span>
                </td>
                <td className="tabnum py-1.5 text-right">
                  {h.blocked && snap.kpis.dropped_visible
                    ? <span style={{ color: AMBER }}>{compact(h.drop_pps)} dropped</span>
                    : <>{compact(h.pps)} <span className="text-2xs text-muted-foreground">pps</span></>}
                </td>
                <td className="w-[46%] py-1.5 pl-4"><Vote h={h} rule={rule} /></td>
                {can && (
                  <td className="py-1.5 pl-3 text-right">
                    <button onClick={() => (h.blocked ? onUnblock(h.ip) : onBlock(h.ip))}
                      className="text-2xs text-muted-foreground transition-colors hover:text-foreground">
                      {h.blocked ? "unblock" : "block"}
                    </button>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </CardContent>
    </Card>
  );
}
