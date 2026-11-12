"use client";

import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";

import { buildUrl } from "@/lib/api";
import { isTerminal } from "@/lib/format";
import { streamEvents } from "@/lib/sse";
import type { Job } from "@/lib/types";

import { DepthBudget } from "./depth-budget";
import { StatusBadge } from "./status-badge";

const STEPS = ["queued", "running", "succeeded"] as const;

/**
 * Live job state over Server-Sent Events. Updates are announced politely to screen readers and
 * written into the React Query cache so every view of the job stays in sync.
 */
export function JobProgress({ job, stream = streamEvents }: { job: Job; stream?: typeof streamEvents }) {
  const queryClient = useQueryClient();
  const [current, setCurrent] = useState<Job>(job);
  const [connection, setConnection] = useState<"live" | "closed" | "error">(isTerminal(job.status) ? "closed" : "live");

  useEffect(() => setCurrent(job), [job]);

  useEffect(() => {
    if (isTerminal(job.status)) return;
    const controller = new AbortController();
    stream(
      buildUrl(`v1/jobs/${job.id}/events`),
      (message) => {
        if (message.event !== "status") return;
        const update = JSON.parse(message.data) as Job;
        setCurrent(update);
        queryClient.setQueryData(["job", job.id], update);
        if (isTerminal(update.status)) {
          void queryClient.invalidateQueries({ queryKey: ["jobs"] });
        }
      },
      { signal: controller.signal },
    )
      .then(() => setConnection("closed"))
      .catch((error: unknown) => {
        if (!controller.signal.aborted) {
          console.error("job event stream failed", error);
          setConnection("error");
        }
      });
    return () => controller.abort();
  }, [job.id, job.status, queryClient, stream]);

  const reached = current.status === "failed" || current.status === "cancelled" ? -1 : STEPS.indexOf(current.status as (typeof STEPS)[number]);
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <StatusBadge status={current.status} />
        <p className="text-sm text-fg-muted" aria-live="polite" aria-atomic="true">
          {current.status === "running" ? `Computing on ciphertexts (attempt ${current.attempts})…` : `Job ${current.status}.`}
          {connection === "error" ? " Live updates unavailable; refresh to see the latest state." : ""}
        </p>
      </div>
      <ol className="flex gap-2" aria-label="Job progress">
        {STEPS.map((step, i) => (
          <li
            key={step}
            aria-current={STEPS[reached] === step ? "step" : undefined}
            className={`flex-1 rounded-md border px-3 py-2 text-xs font-medium ${i <= reached ? "border-primary text-primary" : "border-border text-fg-muted"}`}
          >
            {step}
          </li>
        ))}
      </ol>
      <DepthBudget report={current.depth_report} planned={current.plan.report} />
      {current.error ? (
        <p className="text-sm text-danger" role="alert">
          {current.error.code}: {current.error.message}
        </p>
      ) : null}
    </div>
  );
}
