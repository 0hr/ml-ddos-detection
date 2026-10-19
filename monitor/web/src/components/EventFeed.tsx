import { AnimatePresence, motion } from "framer-motion";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { EventItem, EventType } from "@/types";

// Color follows what happened, not how "bad" it sounds: a block is a mitigation (amber),
// the attack itself is red, a model decision is blue.
const DOT: Record<EventType, string> = {
  attack: "hsl(var(--attack))",
  detect: "hsl(var(--info))",
  block: "hsl(var(--blocked))",
  unblock: "hsl(var(--benign))",
  info: "hsl(var(--muted-foreground))",
};

export function EventFeed({ events, startTs }: { events: EventItem[]; startTs: number }) {
  return (
    <Card className="flex h-full flex-col">
      <CardHeader><CardTitle>Activity</CardTitle></CardHeader>
      <CardContent className="min-h-0 flex-1 overflow-y-auto">
        {events.length === 0 ? (
          <div className="grid h-full min-h-[96px] place-items-center text-xs text-muted-foreground">No events yet</div>
        ) : (
          <div className="space-y-0.5">
            <AnimatePresence initial={false}>
              {events.map((e) => (
                <motion.div key={e.id} layout initial={{ opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }}
                  className="flex items-start gap-2.5 py-1.5">
                  <span className="mt-[5px] h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: DOT[e.type] ?? DOT.info }} />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-baseline gap-2">
                      <span className="truncate text-xs font-medium">{e.title}</span>
                      <span className="tabnum ml-auto shrink-0 text-2xs text-muted-foreground">
                        {e.t >= startTs ? `+${(e.t - startTs).toFixed(1)}s` : ""}
                      </span>
                    </div>
                    {e.detail && <div className="truncate text-2xs text-muted-foreground">{e.detail}</div>}
                  </div>
                </motion.div>
              ))}
            </AnimatePresence>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
