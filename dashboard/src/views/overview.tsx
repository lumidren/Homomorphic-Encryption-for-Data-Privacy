"use client";

import Link from "next/link";

import { PageHeader } from "@/components/app-shell";
import { QueryState } from "@/components/query-state";
import { StatusBadge } from "@/components/status-badge";
import { Card, CardHeader, Table, Td, Th } from "@/components/ui/primitives";
import { formatBytes, formatDate, formatDuration, shortId } from "@/lib/format";
import { useChainVerification, useJobs, useMe, useUsage } from "@/lib/queries";

function Stat({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <Card className="p-4">
      <p className="text-sm text-fg-muted">{label}</p>
      <p className="mt-1 text-2xl font-semibold text-fg">{value}</p>
      {hint ? <p className="mt-1 text-xs text-fg-muted">{hint}</p> : null}
    </Card>
  );
}

export function OverviewView() {
  const me = useMe();
  const usage = useUsage(30);
  const jobs = useJobs();
  const chain = useChainVerification(true);
  return (
    <>
      <PageHeader
        title="Overview"
        description={me.data ? `Signed in as ${me.data.email ?? "API key"} (${me.data.role}). Keys and plaintext stay on your machines — only ciphertexts reach this service.` : undefined}
      />
      <QueryState query={usage} label="usage">
        {(u) => (
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <Stat label="Jobs (30 days)" value={String(Object.values(u.jobs_by_status).reduce((a, b) => a + (b ?? 0), 0))} />
            <Stat label="Succeeded" value={String(u.jobs_by_status.succeeded ?? 0)} hint={`${u.jobs_by_status.failed ?? 0} failed`} />
            <Stat label="Compute time" value={formatDuration(u.compute_seconds)} hint="billed on homomorphic compute" />
            <Stat label="Encrypted storage" value={formatBytes(u.storage_bytes.total)} />
          </div>
        )}
      </QueryState>
      <div className="mt-6 grid gap-6 lg:grid-cols-[2fr_1fr]">
        <Card>
          <CardHeader
            title="Recent jobs"
            actions={
              <Link className="text-sm font-medium text-primary underline underline-offset-2" href="/jobs">
                All jobs
              </Link>
            }
          />
          <QueryState query={jobs} label="jobs" isEmpty={(p) => p.items.length === 0} empty="No jobs yet. Submit one from a project.">
            {(page) => (
              <Table caption="Recent jobs">
                <thead>
                  <tr>
                    <Th>Job</Th>
                    <Th>Operation</Th>
                    <Th>Status</Th>
                    <Th>Submitted</Th>
                  </tr>
                </thead>
                <tbody>
                  {page.items.slice(0, 8).map((job) => (
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
                      <Td>{formatDate(job.created_at)}</Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            )}
          </QueryState>
        </Card>
        <Card>
          <CardHeader title="Audit chain" description="Every access and job is recorded in a hash-chained, append-only log." />
          <QueryState query={chain} label="audit verification">
            {(c) => (
              <p className={`text-sm font-medium ${c.valid ? "text-success" : "text-danger"}`} role="status">
                {c.valid ? `Intact — ${c.checked} events verified` : `Broken at event ${c.first_broken_seq}: ${c.reason}`}
              </p>
            )}
          </QueryState>
        </Card>
      </div>
    </>
  );
}
