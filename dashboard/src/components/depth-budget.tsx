import type { DepthReport } from "@/lib/types";
import { cn } from "@/lib/utils";

/**
 * The CKKS "noise budget": how many multiplicative levels of the modulus chain a computation has
 * consumed. One segment per level; the text beneath carries the same information for assistive
 * technology (the bar itself is decorative).
 */
export function DepthBudget({ report, planned, compact = false }: { report: DepthReport | null | undefined; planned?: DepthReport | null; compact?: boolean }) {
  if (!report) return <p className="text-sm text-fg-muted">No depth report yet.</p>;
  const total = Math.max(report.levels_total, 1);
  const consumed = Math.min(report.levels_consumed, total);
  const ratio = consumed / total;
  const tone = ratio >= 1 ? "bg-danger" : ratio >= 0.75 ? "bg-warning" : "bg-primary";
  return (
    <figure className="w-full">
      <div className="flex gap-1" aria-hidden="true" data-testid="depth-segments">
        {Array.from({ length: total }, (_, i) => (
          <span key={i} className={cn("h-3 flex-1 rounded-sm border border-border", i < consumed ? tone : "bg-surface-muted")} />
        ))}
      </div>
      <figcaption className={cn("mt-2 text-sm text-fg", compact && "text-xs")}>
        <span className="font-medium">
          {consumed} of {report.levels_total} levels consumed
        </span>
        {", "}
        {report.levels_remaining} remaining · about {report.precision_bits} bits of precision
        {report.precision_measured ? " (measured" : " (estimated"}
        {report.precision_class === "slotwise" ? ", slot-wise operations)" : ", rotating operations)"}
        {planned && planned.levels_consumed !== report.levels_consumed ? (
          <span className="text-danger"> · planned {planned.levels_consumed}</span>
        ) : null}
      </figcaption>
    </figure>
  );
}
