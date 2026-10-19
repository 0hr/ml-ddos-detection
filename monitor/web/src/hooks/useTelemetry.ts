import { useCallback, useEffect, useRef, useState } from "react";
import type { EventItem, HistoryPoint, ScenarioMeta, Snapshot } from "@/types";

const HISTORY = 180; // 45 s at 4 Hz
const MAX_EVENTS = 120;

export interface Telemetry {
  snap: Snapshot | null;
  history: HistoryPoint[];
  events: EventItem[];
  scenarios: ScenarioMeta[];
  connected: boolean;
  notice: string | null;
  setScenario: (name: string) => void;
  setMitigation: (on: boolean) => void;
  block: (ip: string) => void;
  unblock: (ip: string) => void;
  attack: (action: "start" | "stop", type?: string, duration?: number) => void;
  load: (action: "start" | "stop", duration?: number) => void;
}

export function useTelemetry(): Telemetry {
  const [snap, setSnap] = useState<Snapshot | null>(null);
  const [history, setHistory] = useState<HistoryPoint[]>([]);
  const [events, setEvents] = useState<EventItem[]>([]);
  const [scenarios, setScenarios] = useState<ScenarioMeta[]>([]);
  const [connected, setConnected] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const lastT = useRef(-1);
  const noticeTimer = useRef<number | undefined>(undefined);

  const flash = useCallback((msg: string) => {
    setNotice(msg);
    window.clearTimeout(noticeTimer.current);
    noticeTimer.current = window.setTimeout(() => setNotice(null), 5000);
  }, []);

  const post = useCallback(async (path: string, body: unknown) => {
    try {
      const r = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      if (!r.ok) flash((await r.json().catch(() => ({}))).error ?? `request failed (${r.status})`);
    } catch {
      flash("dashboard server unreachable");
    }
  }, [flash]);

  useEffect(() => {
    fetch("/api/config").then((r) => r.json()).then((c) => setScenarios(c.scenarios ?? [])).catch(() => {});
    const es = new EventSource("/events");
    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false);
    es.onmessage = (e) => {
      const s: Snapshot = JSON.parse(e.data);
      setSnap(s);
      const p = s.history_point;
      if (p) {
        // Time going backwards = the source restarted (scenario switch or replay loop).
        if (p.t < lastT.current) {
          setHistory([]);
          setEvents([]);
        }
        if (p.t !== lastT.current) {
          lastT.current = p.t;
          setHistory((h) => [...h, p].slice(-HISTORY));
        }
      }
      if (s.events?.length) {
        setEvents((prev) => {
          const seen = new Set(prev.map((x) => x.id));
          const fresh = s.events.filter((x) => !seen.has(x.id));
          if (!fresh.length) return prev;
          return [...fresh, ...prev].sort((a, b) => b.t - a.t || b.id - a.id).slice(0, MAX_EVENTS);
        });
      }
    };
    return () => es.close();
  }, []);

  const setScenario = useCallback((name: string) => {
    setHistory([]);
    lastT.current = -1;
    post("/api/scenario", { name });
  }, [post]);
  const setMitigation = useCallback((on: boolean) => post("/api/mitigation", { enabled: on }), [post]);
  const block = useCallback((ip: string) => post("/api/block", { ip }), [post]);
  const unblock = useCallback((ip: string) => post("/api/unblock", { ip }), [post]);
  const attack = useCallback((action: "start" | "stop", type = "udp", duration = 30) =>
    post("/api/attack", { action, type, duration }), [post]);
  const load = useCallback((action: "start" | "stop", duration = 30) =>
    post("/api/load", { action, duration }), [post]);

  return { snap, history, events, scenarios, connected, notice, setScenario, setMitigation, block, unblock, attack, load };
}
