import { Area, AreaChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { compact } from "@/lib/utils";
import type { AvailabilitySource, HistoryPoint } from "@/types";

const GREEN = "hsl(var(--benign))";
const RED = "hsl(var(--attack))";
const AMBER = "hsl(var(--blocked))";
const BLUE = "hsl(var(--info))";
const GRID = "hsl(var(--grid))";
const AXIS = "hsl(var(--muted-foreground))";

function ChartTooltip({ active, payload, label, unit }: any) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-lg border bg-card/95 px-2.5 py-1.5 text-2xs shadow-sm backdrop-blur">
      <div className="mb-1 tabnum text-muted-foreground">t + {Number(label).toFixed(1)} s</div>
      {payload.map((p: any) => (
        <div key={p.dataKey} className="flex items-center gap-2">
          <span className="h-1.5 w-1.5 rounded-full" style={{ background: p.color }} />
          <span className="text-muted-foreground">{p.name}</span>
          <span className="ml-auto tabnum font-medium text-foreground">
            {p.value == null ? "—" : `${compact(p.value)}${unit}`}
          </span>
        </div>
      ))}
    </div>
  );
}

function Legend({ items }: { items: [string, string][] }) {
  return (
    <div className="ml-auto flex items-center gap-3">
      {items.map(([label, color]) => (
        <span key={label} className="flex items-center gap-1.5 text-2xs text-muted-foreground">
          <span className="h-1.5 w-1.5 rounded-full" style={{ background: color }} />
          {label}
        </span>
      ))}
    </div>
  );
}

const axis = { stroke: "transparent", tick: { fontSize: 10, fill: AXIS }, tickLine: false };
const xAxis = { ...axis, dataKey: "t", tickFormatter: (v: number) => `${Math.round(v)}s`,
  interval: "preserveStartEnd" as const, minTickGap: 48 };

export function TrafficChart({ history, droppedVisible }: { history: HistoryPoint[]; droppedVisible: boolean }) {
  const items: [string, string][] = [["benign", GREEN], ["attack at server", RED]];
  if (droppedVisible) items.push(["dropped at switch", AMBER]);
  return (
    <Card className="flex h-full flex-col">
      <CardHeader>
        <CardTitle>Traffic</CardTitle>
        <span className="text-2xs text-muted-foreground">packets / s</span>
        <Legend items={items} />
      </CardHeader>
      <CardContent className="min-h-0 flex-1">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={history} margin={{ top: 6, right: 8, left: 2, bottom: 0 }}>
            <CartesianGrid stroke={GRID} vertical={false} />
            <XAxis {...xAxis} />
            <YAxis {...axis} tickFormatter={(v) => compact(v)} width={46} />
            <Tooltip content={<ChartTooltip unit=" pps" />} isAnimationActive={false} cursor={{ stroke: GRID }} />
            {droppedVisible && (
              <Area type="monotone" dataKey="blocked_pps" name="dropped at switch" stackId="1" stroke={AMBER}
                fill={AMBER} fillOpacity={0.08} strokeWidth={1.25} isAnimationActive={false} />
            )}
            <Area type="monotone" dataKey="attack_pps" name="attack at server" stackId="1" stroke={RED}
              fill={RED} fillOpacity={0.08} strokeWidth={1.25} isAnimationActive={false} />
            <Area type="monotone" dataKey="benign_pps" name="benign" stackId="1" stroke={GREEN}
              fill={GREEN} fillOpacity={0.1} strokeWidth={1.25} isAnimationActive={false} />
          </AreaChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  );
}

const SOURCE_NOTE: Record<AvailabilitySource, string> = {
  simulated: "simulated",
  measured: "measured from benign client requests",
  unavailable: "not recorded in this run",
};

export function AvailabilityChart({ history, source }: { history: HistoryPoint[]; source: AvailabilitySource }) {
  const data = history.map((p) => ({ t: p.t, avail: p.availability == null ? null : p.availability * 100 }));
  return (
    <Card className="flex h-full flex-col">
      <CardHeader>
        <CardTitle>Service availability</CardTitle>
        <span className="text-2xs text-muted-foreground">%, {SOURCE_NOTE[source]}</span>
      </CardHeader>
      <CardContent className="min-h-0 flex-1">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={data} margin={{ top: 6, right: 8, left: 2, bottom: 0 }}>
            <CartesianGrid stroke={GRID} vertical={false} />
            <XAxis {...xAxis} />
            <YAxis {...axis} domain={[0, 100]} ticks={[0, 25, 50, 75, 100]} width={46} />
            <Tooltip content={<ChartTooltip unit="%" />} isAnimationActive={false} cursor={{ stroke: GRID }} />
            <Line type="monotone" dataKey="avail" name="availability" stroke={BLUE} strokeWidth={1.75}
              dot={false} connectNulls={false} isAnimationActive={false} />
          </LineChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  );
}
