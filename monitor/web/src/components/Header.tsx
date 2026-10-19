import { useState } from "react";
import { Moon, Sun } from "lucide-react";
import { Switch } from "@/components/ui/switch";
import { cn } from "@/lib/utils";
import type { Health, ScenarioMeta, Snapshot } from "@/types";

const PHASE: Record<string, { label: string; color: string }> = {
  baseline: { label: "Normal", color: "hsl(var(--benign))" },
  attack: { label: "Under attack", color: "hsl(var(--attack))" },
  mitigated: { label: "Mitigating", color: "hsl(var(--blocked))" },
  recovered: { label: "Attack ended", color: "hsl(var(--benign))" },
};
const ATTACK_LABEL: Record<string, string> = { udp: "UDP flood", conn: "TCP connect flood", http: "HTTP flood" };

// Always say where the numbers come from: simulated data must never pass for a real run.
function sourceLabel(snap: Snapshot) {
  if (snap.mode === "simulate") return "Simulated data";
  if (snap.mode === "replay") return `Replay · ${snap.scenario}`;
  return `Live · ${snap.scenario}`;
}

function Chip({ ok, label, title }: { ok: boolean | null; label: string; title: string }) {
  return (
    <span className="flex items-center gap-1.5 text-xs text-muted-foreground" title={title}>
      <span className={cn("h-1.5 w-1.5 rounded-full", ok == null ? "bg-muted-foreground/50" : ok ? "bg-benign" : "bg-attack")} />
      {label}
    </span>
  );
}

// Live runs only: is the data on screen current, and can the controls reach the testbed?
function HealthChips({ h }: { h: Health }) {
  const mon = {
    ok: `Monitor${h.monitor_lag_ms != null ? ` · ${h.monitor_lag_ms < 1000 ? `${Math.round(h.monitor_lag_ms)} ms` : `${(h.monitor_lag_ms / 1000).toFixed(1)} s`} behind` : ""}`,
    stale: `Monitor silent ${h.telemetry_age_s?.toFixed(0) ?? "?"} s`,
    waiting: "Waiting for the monitor",
    finished: "Run finished",
    recorded: "Monitor",
  }[h.monitor];
  return (
    <>
      <Chip ok={h.monitor === "ok" ? true : h.monitor === "stale" ? false : null} label={mon}
        title="traffic monitor: capture → flow features → model. 'behind' is how far it lags the wire." />
      <Chip ok={h.controller === "ok"}
        label={h.controller === "ok" ? `Controller · ${h.switches ?? 0} switch${h.switches === 1 ? "" : "es"}` : "Controller unreachable"}
        title="SDN controller REST API (drop rules, counters)" />
    </>
  );
}

const btn = "rounded-md border px-2.5 py-1 text-xs transition-colors";

export function Header({
  snap, scenarios, connected, notice, theme, onScenario, onMitigation, onAttack, onLoad, onToggleTheme,
}: {
  snap: Snapshot | null;
  scenarios: ScenarioMeta[];
  connected: boolean;
  notice: string | null;
  theme: "dark" | "light";
  onScenario: (id: string) => void;
  onMitigation: (on: boolean) => void;
  onAttack: (action: "start" | "stop", type?: string, duration?: number) => void;
  onLoad: (action: "start" | "stop", duration?: number) => void;
  onToggleTheme: () => void;
}) {
  const [attackType, setAttackType] = useState("udp");
  const phase = snap ? PHASE[snap.phase] : null;
  const sess = snap?.session ?? null;
  return (
    <header className="flex flex-wrap items-center gap-x-6 gap-y-2 px-5 py-3">
      <div className="flex items-center gap-3">
        <span className="text-sm font-semibold tracking-tight">DDoS Monitor</span>
        {phase && (
          <span className="flex items-center gap-1.5 text-xs" style={{ color: phase.color }}>
            <span className="relative flex h-1.5 w-1.5">
              {snap!.phase !== "baseline" && (
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full opacity-60"
                  style={{ background: phase.color }} />
              )}
              <span className="relative inline-flex h-1.5 w-1.5 rounded-full" style={{ background: phase.color }} />
            </span>
            {phase.label}
          </span>
        )}
      </div>

      <div className="ml-auto flex flex-wrap items-center gap-x-5 gap-y-2">
        {notice && <span className="max-w-xs truncate text-xs text-attack">{notice}</span>}

        {snap?.controls.scenario && scenarios.length > 0 && (
          <div className="flex items-center rounded-lg bg-secondary/70 p-0.5">
            {scenarios.map((s) => (
              <button
                key={s.id}
                onClick={() => onScenario(s.id)}
                title={s.desc}
                className={cn(
                  "rounded-md px-2.5 py-1 text-xs transition-colors",
                  snap.scenario === s.id
                    ? "bg-card font-medium text-foreground shadow-sm"
                    : "text-muted-foreground hover:text-foreground"
                )}
              >
                {s.label}
              </button>
            ))}
          </div>
        )}

        {snap?.controls.attack && sess && (
          <div className="flex items-center gap-2">
            {sess.attack ? (
              <button onClick={() => onAttack("stop")} className={cn(btn, "border-attack/50 text-attack hover:bg-attack/10")}>
                Stop attack · <span className="tabnum">{Math.ceil(sess.attack.remaining_s)} s</span>
              </button>
            ) : (
              <>
                <select value={attackType} onChange={(e) => setAttackType(e.target.value)} aria-label="Attack type"
                  className="rounded-md border bg-card px-1.5 py-1 text-xs text-muted-foreground outline-none">
                  {sess.attack_types.map((t) => <option key={t} value={t}>{ATTACK_LABEL[t] ?? t}</option>)}
                </select>
                <button onClick={() => onAttack("start", attackType, 30)}
                  title={`30 s flood from ${sess.attackers.join(", ")} toward the server`}
                  className={cn(btn, "border-attack/50 text-attack hover:bg-attack/10")}>
                  Launch attack
                </button>
              </>
            )}
            {snap.controls.load && (
              <button onClick={() => onLoad(sess.load ? "stop" : "start", 30)}
                title="30 s of heavy legitimate traffic from the benign clients: it must not be blocked"
                className={cn(btn, "text-muted-foreground hover:text-foreground")}>
                {sess.load ? <>Stop crowd · <span className="tabnum">{Math.ceil(sess.load.remaining_s)} s</span></> : "Flash crowd"}
              </button>
            )}
          </div>
        )}

        {snap?.controls.mitigation_toggle ? (
          <label className="flex cursor-pointer items-center gap-2 text-xs text-muted-foreground">
            Mitigation
            <Switch checked={!!snap.mitigation} onCheckedChange={onMitigation} />
          </label>
        ) : snap && snap.mitigation !== null && (
          <span className="text-xs text-muted-foreground">Mitigation {snap.mitigation ? "on" : "off"}</span>
        )}

        {snap?.mode === "live" && <HealthChips h={snap.health} />}

        {snap && (
          <span className="flex items-center gap-1.5 text-xs text-muted-foreground"
            title={connected ? "connected to the dashboard server" : "disconnected"}>
            <span className={cn("h-1.5 w-1.5 rounded-full", connected ? "bg-benign" : "bg-attack")} />
            {sourceLabel(snap)}
          </span>
        )}

        <button onClick={onToggleTheme} aria-label="Toggle theme"
          className="grid h-7 w-7 place-items-center rounded-md text-muted-foreground transition-colors hover:bg-secondary hover:text-foreground">
          {theme === "dark" ? <Sun className="h-3.5 w-3.5" /> : <Moon className="h-3.5 w-3.5" />}
        </button>
      </div>
    </header>
  );
}
