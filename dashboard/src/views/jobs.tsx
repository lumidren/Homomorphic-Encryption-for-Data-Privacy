"use client";

import Link from "next/link";
import { useState } from "react";

import { PageHeader } from "@/components/app-shell";
import { DepthBudget } from "@/components/depth-budget";
import { JobProgress } from "@/components/job-progress";
import { QueryState } from "@/components/query-state";
import { StatusBadge } from "@/components/status-badge";
import { Card, CardHeader, Field, Mono, Select, Table, Td, Th } from "@/components/ui/primitives";
import { describeParams, formatBytes, formatDate, formatDuration, shortId } from "@/lib/format";
import { useJob, useJobs } from "@/lib/queries";
import type { JobStatus } from "@/lib/types";

const STATUSES: Array<JobStatus | ""> = ["", "queued", "running", "succeeded", "failed", "cancelled"];

export function JobsView() {
  const [status, setStatus] = useState<JobStatus | "">("");
  const jobs = useJobs({ status });
  return (
    <>
      <PageHeader title="Jobs" description="Homomorphic computations across all projects." />
      <Card>
        <div className="mb-4 max-w-xs">
          <Field id="job-status-filter" label="Status">
            <Select value={status} onChange={(e) => setStatus(e.target.value as JobStatus | "")}>
              {STATUSES.map((s) => (
                <option key={s || "all"} value={s}>
                  {s || "All"}
                </option>
              ))}
            </Select>
          </Field>
        </div>
        <QueryState query={jobs} label="jobs" isEmpty={(p) => p.items.length === 0} empty="No jobs match this filter.">
          {(page) => (
            <Table caption="Jobs">
              <thead>
                <tr>
                  <Th>Job</Th>
                  <Th>Operation</Th>
                  <Th>Status</Th>
                  <Th>Depth used</Th>
                  <Th>Compute</Th>
                  <Th>Submitted</Th>
                </tr>
              </thead>
              <tbody>
                {page.items.map((job) => (
                  <tr key={job.id}>
                    <Td>
                      <Link className="font-mono text-primary underline underline-offset-2" href={`/jobs/${job.id}`}>
                        {shortId(job.id)}
                      </Link>
                    </Td>
                    <Td>{job.operation}</Td>
                    <Td>
                      <StatusBadge status={job.status} />
                    </Td>
                    <Td>
                      {(job.depth_report ?? job.plan.report).levels_consumed}/{(job.depth_report ?? job.plan.report).levels_total}
                    </Td>
                    <Td>{formatDuration(job.compute_seconds)}</Td>
                    <Td>{formatDate(job.created_at)}</Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          )}
        </QueryState>
      </Card>
    </>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid gap-1 py-2 sm:grid-cols-[12rem_1fr]">
      <dt className="text-sm text-fg-muted">{label}</dt>
      <dd className="break-all text-sm text-fg">{children}</dd>
    </div>
  );
}

export function JobDetailView({ jobId }: { jobId: string }) {
  const job = useJob(jobId);
  return (
    <QueryState query={job} label="job">
      {(j) => (
        <>
          <PageHeader
            title={`${j.operation} job`}
            description={
              <>
                Job <Mono>{j.id}</Mono> in{" "}
                <Link className="text-primary underline underline-offset-2" href={`/projects/${j.project_id}`}>
                  its project
                </Link>
              </>
            }
          />
          <div className="grid gap-6 lg:grid-cols-[3fr_2fr]">
            <Card>
              <CardHeader title="Progress" description="Live over Server-Sent Events." />
              <JobProgress job={j} />
            </Card>
            <Card>
              <CardHeader title="Planned depth" description="What the server checked before accepting the job." />
              <DepthBudget report={j.plan.report} compact />
              <p className="mt-3 text-xs text-fg-muted">{describeParams(j.plan.params)}</p>
            </Card>
          </div>
          <Card className="mt-6">
            <CardHeader title="Details" />
            <dl className="divide-y divide-border">
              <Row label="Arguments (visible to server)">
                <Mono>{JSON.stringify(j.args)}</Mono>
              </Row>
              <Row label="Inputs">
                {j.input_ids.map((id, i) => (
                  <span key={id} className="block">
                    <Mono>{id}</Mono> <span className="text-fg-muted">{j.input_fingerprints[i]}</span>
                  </span>
                ))}
              </Row>
              <Row label="Manifest hash">
                <Mono>{j.manifest_hash}</Mono>
              </Row>
              <Row label="Result">
                {j.result_fingerprint ? (
                  <>
                    {j.result_length} values · {formatBytes(j.result_size_bytes)} · <Mono>{j.result_fingerprint}</Mono>
                  </>
                ) : (
                  "—"
                )}
              </Row>
              <Row label="Attempts / compute">
                {j.attempts} · {formatDuration(j.compute_seconds)}
              </Row>
              <Row label="Submitted / finished">
                {formatDate(j.created_at)} · {formatDate(j.finished_at)}
              </Row>
            </dl>
            {j.status === "succeeded" ? (
              <div className="mt-4 rounded-md bg-surface-muted p-4 text-sm text-fg">
                <p className="font-medium">Decrypt the result on your machine</p>
                <p className="mt-1 text-fg-muted">The dashboard cannot decrypt: it never has your secret key.</p>
                <pre className="mt-2 overflow-x-auto font-mono text-xs">ciphercompute jobs result {j.id} ./keys</pre>
              </div>
            ) : null}
          </Card>
        </>
      )}
    </QueryState>
  );
}
