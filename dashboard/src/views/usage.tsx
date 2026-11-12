"use client";

import { useState } from "react";

import { PageHeader } from "@/components/app-shell";
import { BarChart } from "@/components/bar-chart";
import { QueryState } from "@/components/query-state";
import { Card, CardHeader, Field, Select, Table, Td, Th } from "@/components/ui/primitives";
import { formatBytes, formatDuration } from "@/lib/format";
import { useUsage } from "@/lib/queries";

export function UsageView() {
  const [days, setDays] = useState(30);
  const usage = useUsage(days);
  return (
    <>
      <PageHeader
        title="Usage"
        description="Billing is based on homomorphic compute time and encrypted storage."
        actions={
          <div className="w-40">
            <Field id="usage-window" label="Window">
              <Select value={days} onChange={(e) => setDays(Number(e.target.value))}>
                <option value={7}>7 days</option>
                <option value={30}>30 days</option>
                <option value={90}>90 days</option>
              </Select>
            </Field>
          </div>
        }
      />
      <QueryState query={usage} label="usage">
        {(u) => (
          <div className="grid gap-6 lg:grid-cols-2">
            <Card>
              <CardHeader title="Jobs per day" />
              <BarChart title="Jobs per day" data={u.jobs_per_day.map((d) => ({ label: d.date, value: d.jobs }))} />
            </Card>
            <Card>
              <CardHeader title="Compute by operation" description={`Total ${formatDuration(u.compute_seconds)}`} />
              <Table caption="Compute time by operation">
                <thead>
                  <tr>
                    <Th>Operation</Th>
                    <Th>Jobs</Th>
                    <Th>Compute</Th>
                  </tr>
                </thead>
                <tbody>
                  {u.jobs_by_operation.map((op) => (
                    <tr key={op.operation}>
                      <Td>{op.operation}</Td>
                      <Td>{op.jobs}</Td>
                      <Td>{formatDuration(op.compute_seconds)}</Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </Card>
            <Card>
              <CardHeader title="Encrypted storage" />
              <dl className="grid grid-cols-2 gap-3 text-sm">
                {(["ciphertexts", "key_bundles", "results", "total"] as const).map((k) => (
                  <div key={k}>
                    <dt className="text-fg-muted">{k.replace("_", " ")}</dt>
                    <dd className="text-lg font-semibold text-fg">{formatBytes(u.storage_bytes[k])}</dd>
                  </div>
                ))}
              </dl>
            </Card>
            <Card>
              <CardHeader title="Jobs by status" />
              <BarChart title="Jobs by status" data={Object.entries(u.jobs_by_status).map(([label, value]) => ({ label, value: value ?? 0 }))} />
            </Card>
          </div>
        )}
      </QueryState>
    </>
  );
}
