import { useEffect, useState } from "react";
import { useTelemetry } from "@/hooks/useTelemetry";
import { Header } from "@/components/Header";
import { KpiCards } from "@/components/KpiCards";
import { COLORS, Topology } from "@/components/Topology";
import { AvailabilityChart, TrafficChart } from "@/components/Charts";
import { MitigationPanel } from "@/components/MitigationPanel";
import { Pipeline } from "@/components/Pipeline";
import { Sources } from "@/components/Sources";
import { EventFeed } from "@/components/EventFeed";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

const LEGEND: [string, string][] = [
  ["benign", COLORS.benign], ["attack", COLORS.attack], ["blocked", COLORS.blocked], ["server", COLORS.server],
];

function initialTheme(): "dark" | "light" {
  try {
    const saved = localStorage.getItem("ddos-monitor-theme");
    if (saved === "dark" || saved === "light") return saved;
  } catch {
    /* storage unavailable */
  }
  return "dark";
}

export default function App() {
  const t = useTelemetry();
  const [theme, setTheme] = useState<"dark" | "light">(initialTheme);

  useEffect(() => {
    document.documentElement.classList.toggle("dark", theme === "dark");
    try {
      localStorage.setItem("ddos-monitor-theme", theme);
    } catch {
      /* storage unavailable */
    }
  }, [theme]);

  const snap = t.snap;
  return (
    <div className="flex h-screen flex-col bg-background text-foreground">
      <Header snap={snap} scenarios={t.scenarios} connected={t.connected} notice={t.notice} theme={theme}
        onScenario={t.setScenario} onMitigation={t.setMitigation} onAttack={t.attack} onLoad={t.load}
        onToggleTheme={() => setTheme((v) => (v === "dark" ? "light" : "dark"))} />

      {!snap ? (
        <div className="grid flex-1 place-items-center text-sm text-muted-foreground">
          <div className="flex items-center gap-2.5">
            <div className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-muted-foreground/30 border-t-foreground" />
            {t.connected ? "Waiting for data…" : "Connecting to the dashboard server…"}
          </div>
        </div>
      ) : (
        <main className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto px-5 pb-5">
          <KpiCards snap={snap} />
          <Pipeline snap={snap} />

          <div className="grid min-h-0 flex-1 gap-3 xl:grid-cols-3">
            <Card className="flex min-h-[380px] flex-col xl:col-span-2">
              <CardHeader>
                <CardTitle>Network</CardTitle>
                <div className="ml-auto flex items-center gap-3">
                  {LEGEND.map(([label, color]) => (
                    <span key={label} className="flex items-center gap-1.5 text-2xs text-muted-foreground">
                      <span className="h-1.5 w-1.5 rounded-full" style={{ background: color }} />
                      {label}
                    </span>
                  ))}
                </div>
              </CardHeader>
              <CardContent className="min-h-0 flex-1">
                <Topology snap={snap} />
              </CardContent>
            </Card>

            <div className="flex min-h-0 flex-col gap-3">
              <div className="min-h-[170px] flex-1">
                <MitigationPanel blocks={snap.blocks} canUnblock={snap.controls.manual_block} onUnblock={t.unblock} />
              </div>
              <div className="min-h-[200px] flex-1">
                <EventFeed events={t.events} startTs={snap.t - snap.elapsed} />
              </div>
            </div>
          </div>

          <div className="grid gap-3 lg:grid-cols-3">
            <div className="h-60"><Sources snap={snap} onBlock={t.block} onUnblock={t.unblock} /></div>
            <div className="h-60"><TrafficChart history={t.history} droppedVisible={snap.kpis.dropped_visible} /></div>
            <div className="h-60"><AvailabilityChart history={t.history} source={snap.kpis.availability_source} /></div>
          </div>
        </main>
      )}
    </div>
  );
}
