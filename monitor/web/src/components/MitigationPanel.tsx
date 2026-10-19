import { AnimatePresence, motion } from "framer-motion";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { compact } from "@/lib/utils";
import type { BlockInfo } from "@/types";

export function MitigationPanel({ blocks, canUnblock, onUnblock }: {
  blocks: BlockInfo[]; canUnblock: boolean; onUnblock: (ip: string) => void;
}) {
  return (
    <Card className="flex h-full flex-col">
      <CardHeader>
        <CardTitle>Drop rules</CardTitle>
        <span className="ml-auto tabnum text-2xs text-muted-foreground">{blocks.length} active</span>
      </CardHeader>
      <CardContent className="min-h-0 flex-1 overflow-y-auto">
        {blocks.length === 0 ? (
          <div className="grid h-full min-h-[96px] place-items-center text-xs text-muted-foreground">
            No active drop rules
          </div>
        ) : (
          <div className="divide-y">
            <AnimatePresence initial={false}>
              {blocks.map((b) => {
                const pct = Math.max(0, Math.min(100, (b.remaining_s / b.duration_s) * 100));
                return (
                  <motion.div key={b.ip} layout initial={{ opacity: 0 }} animate={{ opacity: 1 }}
                    exit={{ opacity: 0 }} className="py-2.5 first:pt-0">
                    <div className="flex items-baseline gap-2">
                      <span className="text-sm font-medium">{b.host || b.ip}</span>
                      <span className="tabnum text-2xs text-muted-foreground">{b.ip}</span>
                      {canUnblock && (
                        <button onClick={() => onUnblock(b.ip)}
                          className="ml-auto text-2xs text-muted-foreground transition-colors hover:text-foreground">
                          remove
                        </button>
                      )}
                    </div>
                    <div className="mt-0.5 truncate text-2xs text-muted-foreground">
                      {b.reason}
                      {b.score > 0 && ` · score ${b.score.toFixed(2)}`}
                      {b.confirm_ms > 0 && ` · confirmed in ${b.confirm_ms.toFixed(1)} ms`}
                    </div>
                    {(b.dropped_packets > 0 || b.renewals > 0) && (
                      <div className="mt-0.5 truncate text-2xs">
                        <span className="tabnum text-blocked">{compact(b.drop_pps)} pps</span>
                        <span className="text-muted-foreground">
                          {` dropping · ${compact(b.dropped_packets)} packets`}
                          {b.renewals > 0 && ` · renewed ${b.renewals}×`}
                        </span>
                      </div>
                    )}
                    <div className="mt-2 flex items-center gap-2">
                      <div className="h-[2px] flex-1 overflow-hidden rounded-full bg-muted">
                        <motion.div className="h-full rounded-full bg-blocked" animate={{ width: `${pct}%` }}
                          transition={{ ease: "linear", duration: 0.25 }} />
                      </div>
                      <span className="tabnum w-7 text-right text-2xs text-muted-foreground">{Math.ceil(b.remaining_s)}s</span>
                    </div>
                  </motion.div>
                );
              })}
            </AnimatePresence>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
