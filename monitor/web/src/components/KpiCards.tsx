import { motion } from "framer-motion";
import { compact, fmtDuration } from "@/lib/utils";
import type { Snapshot } from "@/types";

function Stat({ label, value, unit, sub, dot }: {
  label: string; value: string; unit?: string; sub: string; dot?: string;
}) {
  return (
    <div className="min-w-0 px-5 py-4">
      <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
        {dot && <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: dot }} />}
        {label}
      </div>
      <div className="mt-1.5 flex items-baseline gap-1">
        <motion.span key={value} initial={{ opacity: 0.4 }} animate={{ opacity: 1 }} transition={{ duration: 0.3 }}
          className="tabnum text-[26px] font-semibold leading-none tracking-tight">
          {value}
        </motion.span>
        {unit && <span className="text-xs text-muted-foreground">{unit}</span>}
      </div>
      <div className="mt-1.5 truncate text-2xs text-muted-foreground">{sub}</div>
    </div>
  );
}

export function KpiCards({ snap }: { snap: Snapshot }) {
  const k = snap.kpis;
  const avail = k.availability;
  const availDot = avail == null ? undefined
    : avail > 0.9 ? "hsl(var(--benign))" : avail > 0.5 ? "hsl(var(--blocked))" : "hsl(var(--attack))";

  const attackSub = k.blocked_sources > 0
    ? `${k.blocked_sources} source${k.blocked_sources > 1 ? "s" : ""} blocked at the switch`
    : k.attack_pps > 100 ? "not mitigated" : "no attack traffic";
  const dropSub = !k.dropped_visible ? "drop counters not recorded"
    : k.dropped_packets > 0 ? `${compact(k.dropped_packets)} packets dropped in total` : "nothing dropped yet";
  const detect = k.detection_latency_s;
  const mitigate = k.mitigation_latency_s;

  const availSub = {
    simulated: "simulated benign success rate",
    measured: "benign requests ok, last 5 s",
    unavailable: "no client logs in this run",
  }[k.availability_source];

  return (
    <div className="grid grid-cols-2 rounded-xl border bg-card md:grid-cols-3 xl:grid-cols-6 xl:divide-x">
      <Stat label="Traffic" value={compact(k.total_pps)} unit="pps"
        sub={`${compact(k.server_pps)} pps reaching the server`} />
      <Stat label="Attack at server" value={compact(k.attack_pps)} unit="pps" sub={attackSub}
        dot={k.attack_pps > 100 ? "hsl(var(--attack))" : undefined} />
      <Stat label="Dropped at switch" value={k.dropped_visible ? compact(k.blocked_pps) : "—"}
        unit={k.dropped_visible ? "pps" : undefined} sub={dropSub}
        dot={k.blocked_pps > 0 ? "hsl(var(--blocked))" : undefined} />
      <Stat label="Availability" value={avail == null ? "—" : (avail * 100).toFixed(0)}
        unit={avail == null ? undefined : "%"} sub={availSub} dot={availDot} />
      <Stat label="Time to detect" value={detect == null ? "—" : fmtDuration(detect).split(" ")[0]}
        unit={detect == null ? undefined : fmtDuration(detect).split(" ")[1]} sub="attack start → block decision" />
      <Stat label="Time to mitigate" value={mitigate == null ? "—" : fmtDuration(mitigate).split(" ")[0]}
        unit={mitigate == null ? undefined : fmtDuration(mitigate).split(" ")[1]}
        sub={snap.mitigation === false ? "mitigation off" : `attack start → rule on switches · ${k.active_blocks} active`}
        dot={k.active_blocks ? "hsl(var(--blocked))" : undefined} />
    </div>
  );
}
