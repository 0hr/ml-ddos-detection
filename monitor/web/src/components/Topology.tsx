import { memo } from "react";
import type { Host, Link, Snapshot } from "@/types";
import { compact } from "@/lib/utils";

const W = 1000;
const H = 500;

// Layout mirrors testbed/topology.py: srv + attackers on s1, benign clients on s2.
const POS: Record<string, { x: number; y: number }> = {
  controller: { x: 520, y: 52 },
  srv: { x: 150, y: 220 },
  s1: { x: 400, y: 220 },
  s2: { x: 640, y: 220 },
  h1: { x: 300, y: 410 }, h3: { x: 400, y: 410 }, h5: { x: 500, y: 410 },
  h2: { x: 580, y: 410 }, h4: { x: 680, y: 410 }, h6: { x: 780, y: 410 },
};

export const COLORS = {
  benign: "hsl(var(--benign))",
  attack: "hsl(var(--attack))",
  blocked: "hsl(var(--blocked))",
  server: "hsl(var(--info))",
  muted: "hsl(var(--muted-foreground))",
  line: "hsl(var(--border))",
};

const LINK_COLOR: Record<string, string> = {
  benign: COLORS.benign, attack: COLORS.attack, blocked: COLORS.blocked, server: COLORS.server,
};

// Packets travelling along an active link; count and speed scale gently with the rate.
function Packets({ a, b, color, pps, fast }: {
  a: { x: number; y: number }; b: { x: number; y: number }; color: string; pps: number; fast: boolean;
}) {
  const n = pps > 4000 ? 3 : pps > 400 ? 2 : 1;
  const dur = fast ? 1.1 : 2;
  return (
    <>
      {Array.from({ length: n }, (_, i) => (
        <circle key={i} r={2.2} fill={color}>
          <animateMotion dur={`${dur}s`} begin={`${(i * dur) / n}s`} repeatCount="indefinite"
            path={`M${a.x},${a.y} L${b.x},${b.y}`} />
        </circle>
      ))}
    </>
  );
}

function Edge({ link }: { link: Link }) {
  const a = POS[link.src];
  const b = POS[link.dst];
  if (!a || !b) return null;
  if (link.kind === "control") {
    // Lit while the controller is pushing a drop rule to the switches.
    return (
      <g>
        <line x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke={link.active ? COLORS.blocked : COLORS.muted}
          strokeOpacity={link.active ? 0.9 : 0.35} strokeWidth={link.active ? 1.5 : 1}
          strokeDasharray="1 5" strokeLinecap="round" />
        {link.active && (
          <circle r={2.6} fill={COLORS.blocked}>
            <animateMotion dur="0.7s" repeatCount="indefinite" path={`M${a.x},${a.y} L${b.x},${b.y}`} />
          </circle>
        )}
      </g>
    );
  }
  const color = LINK_COLOR[link.kind];
  const flowing = !!color && link.pps > 5;
  return (
    <g>
      <line x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke={color ?? COLORS.line}
        strokeOpacity={color ? 0.45 : 1} strokeWidth={color ? 1.5 : 1} strokeLinecap="round" />
      {flowing && <Packets a={a} b={b} color={color} pps={link.pps}
        fast={link.kind === "attack" || link.kind === "blocked"} />}
    </g>
  );
}

function hostColor(h: Host) {
  if (h.role === "server") return COLORS.server;
  if (h.blocked) return COLORS.blocked;
  if (h.state === "attacking") return COLORS.attack;
  return h.state === "idle" ? COLORS.muted : COLORS.benign;
}

function caption(h: Host) {
  if (h.blocked) return h.drop_pps > 5 ? `${compact(h.drop_pps)} dropped` : "blocked";
  return h.pps > 5 ? `${compact(h.pps)} pps` : "idle";
}

function HostNode({ h }: { h: Host }) {
  const p = POS[h.id];
  if (!p) return null;
  const w = 68, ht = 40;
  const color = hostColor(h);
  const pulse = h.state === "attacking" || h.blocked;
  return (
    <g transform={`translate(${p.x - w / 2}, ${p.y - ht / 2})`} opacity={h.state === "idle" ? 0.5 : 1}>
      <rect width={w} height={ht} rx={10} fill="hsl(var(--card))" stroke={COLORS.line} strokeWidth={1} />
      <circle cx={12} cy={13} r={2.75} fill={color}>
        {pulse && <animate attributeName="opacity" values="1;0.3;1" dur="1.6s" repeatCount="indefinite" />}
      </circle>
      <text x={w / 2 + 4} y={17} textAnchor="middle" className="fill-foreground" style={{ fontSize: 12, fontWeight: 600 }}>
        {h.id}
      </text>
      <text x={w / 2} y={31} textAnchor="middle" className="fill-muted-foreground tabnum" style={{ fontSize: 9.5 }}>
        {caption(h)}
      </text>
      {h.blocked && (
        <text x={w / 2} y={ht + 13} textAnchor="middle" className="tabnum"
          style={{ fontSize: 9.5, fontWeight: 600, fill: COLORS.blocked }}>
          drop rule · {Math.ceil(h.remaining_block_s)}s
        </text>
      )}
    </g>
  );
}

function SwitchNode({ id }: { id: string }) {
  const p = POS[id];
  const w = 60, h = 34;
  return (
    <g transform={`translate(${p.x - w / 2}, ${p.y - h / 2})`}>
      <rect width={w} height={h} rx={8} fill="hsl(var(--secondary))" stroke={COLORS.line} strokeWidth={1} />
      <text x={w / 2} y={15} textAnchor="middle" className="fill-foreground" style={{ fontSize: 12, fontWeight: 600 }}>{id}</text>
      <text x={w / 2} y={26.5} textAnchor="middle" className="fill-muted-foreground" style={{ fontSize: 8.5 }}>switch</text>
    </g>
  );
}

function ControllerNode() {
  const p = POS.controller;
  const w = 188, h = 34;
  return (
    <g transform={`translate(${p.x - w / 2}, ${p.y - h / 2})`}>
      <rect width={w} height={h} rx={17} fill="hsl(var(--card))" stroke={COLORS.line} strokeWidth={1} />
      <text x={w / 2} y={21.5} textAnchor="middle" style={{ fontSize: 11.5 }}>
        <tspan className="fill-foreground" style={{ fontWeight: 600 }}>SDN controller</tspan>
        <tspan className="fill-muted-foreground" dx={6}>OpenFlow 1.3</tspan>
      </text>
    </g>
  );
}

export const Topology = memo(function Topology({ snap }: { snap: Snapshot }) {
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="h-full w-full" role="img"
      aria-label="Network topology with live traffic between hosts, switches and the server">
      {snap.links.map((l, i) => <Edge key={`${l.src}-${l.dst}-${i}`} link={l} />)}
      <ControllerNode />
      {snap.switches.map((s) => <SwitchNode key={s} id={s} />)}
      {snap.hosts.map((h) => <HostNode key={h.id} h={h} />)}
    </svg>
  );
});
