// Mirrors the snapshot emitted by monitor/server (engine.py Engine.snapshot()).

export type Mode = "simulate" | "live" | "replay";
export type HostRole = "server" | "attacker" | "benign";
export type HostStateName = "server" | "blocked" | "attacking" | "active" | "idle";
export type LinkKind = "benign" | "attack" | "blocked" | "server" | "control" | "idle";
export type Phase = "baseline" | "attack" | "mitigated" | "recovered";
export type EventType = "info" | "attack" | "detect" | "block" | "unblock";
export type AvailabilitySource = "simulated" | "measured" | "unavailable";

export interface Host {
  id: string;
  ip: string;
  role: HostRole;
  switch: string;
  pps: number; // seen at the capture point on the server link
  bps: number;
  drop_pps: number; // being dropped at the switches (from the drop rules' counters)
  blocked: boolean;
  remaining_block_s: number;
  state: HostStateName;
  flows: number; // flows the model scored for this source in the vote window
  attack_flows: number; // ... of which it classified as attack
}

export interface Link {
  src: string;
  dst: string;
  pps: number;
  kind: LinkKind;
  active?: boolean; // control links: a rule is being pushed right now
}

export interface Kpis {
  total_pps: number;
  benign_pps: number;
  attack_pps: number; // attack traffic reaching the server
  blocked_pps: number; // dropped at the switch (only countable when dropped_visible)
  dropped_visible: boolean;
  dropped_packets: number; // total dropped by drop rules in this run
  server_pps: number;
  active_blocks: number;
  blocked_sources: number;
  availability: number | null; // null = not known (never invented)
  availability_source: AvailabilitySource;
  detection_latency_s: number | null; // attack start -> first block decision
  mitigation_latency_s: number | null; // attack start -> rule confirmed by the switches
}

// One attack, stage by stage. Times are seconds after the attack started; null = not yet.
export interface Incident {
  n: number;
  kind: string;
  attack_at: number;
  age_s: number;
  active: boolean;
  detected_s: number | null;
  requested_s: number | null;
  confirmed_s: number | null;
  dropping_s: number | null;
  ended_s: number | null;
  api_ms: number | null;
  confirm_ms: number | null;
  suppressed: boolean; // decision taken while mitigation was off
  rule: "model" | "rate"; // what flagged it: the model's verdicts or the flow-rate limit
  flagged: number;
  blocked: number;
  attackers: number;
}

export interface Health {
  monitor: "ok" | "stale" | "waiting" | "finished" | "recorded";
  telemetry_age_s: number | null;
  monitor_lag_ms: number | null;
  controller: "ok" | "down" | "recorded";
  switches: number | null;
  session: boolean;
}

export interface SessionRun {
  type?: string;
  started: number;
  ends: number;
  remaining_s: number;
}

// The interactive testbed session (testbed/live.py), when one is running.
export interface SessionState {
  uptime_s: number;
  remaining_s: number;
  attack: SessionRun | null;
  load: SessionRun | null;
  attack_types: string[];
  attackers: string[];
  max_attack_s: number;
}

export interface VoteRule {
  window_s: number;
  min_flows: number;
  ratio: number;
  max_flow_rate: number; // flows/s per source
}

export interface BlockInfo {
  ip: string;
  host: string;
  reason: string;
  score: number;
  remaining_s: number;
  duration_s: number;
  confirm_ms: number;
  renewals: number;
  dropped_packets: number;
  drop_pps: number;
  age_s: number;
}

export interface EventItem {
  id: number;
  t: number;
  type: EventType;
  title: string;
  detail: string;
  ip: string;
  host: string;
}

export interface HistoryPoint {
  t: number;
  benign_pps: number;
  attack_pps: number;
  blocked_pps: number;
  availability: number | null;
  active_blocks: number;
}

export interface Controls {
  scenario: boolean;
  mitigation_toggle: boolean;
  manual_block: boolean;
  attack: boolean;
  load: boolean;
}

export interface Snapshot {
  t: number;
  mode: Mode;
  scenario: string;
  mitigation: boolean | null; // null = unknown (live run without scenario.json yet)
  controls: Controls;
  elapsed: number;
  phase: Phase;
  health: Health;
  session: SessionState | null;
  vote_rule: VoteRule;
  kpis: Kpis;
  incident: Incident | null;
  hosts: Host[];
  switches: string[];
  links: Link[];
  blocks: BlockInfo[];
  history_point: HistoryPoint;
  events: EventItem[];
}

export interface ScenarioMeta {
  id: string;
  label: string;
  desc: string;
}
