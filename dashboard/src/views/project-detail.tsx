"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { type FormEvent, useMemo, useState } from "react";

import { PageHeader } from "@/components/app-shell";
import { QueryState } from "@/components/query-state";
import { StatusBadge } from "@/components/status-badge";
import { Button } from "@/components/ui/button";
import { Alert, Badge, Card, CardHeader, Field, Input, Mono, Select, Table, Td, Textarea, Th } from "@/components/ui/primitives";
import { ApiError, api } from "@/lib/api";
import { describeParams, formatBytes, formatDate, shortId } from "@/lib/format";
import { useBundles, useCiphertexts, useDatasets, useJobs, useOperations, useProject } from "@/lib/queries";
import type { Ciphertext, Dataset, Job, KeyBundle } from "@/lib/types";

function BundlesCard({ projectId }: { projectId: string }) {
  const bundles = useBundles(projectId);
  const queryClient = useQueryClient();
  const revoke = useMutation({
    mutationFn: (id: string) => api.request<KeyBundle>(`v1/key-bundles/${id}/revoke`, { method: "POST" }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["bundles", projectId] }),
  });
  return (
    <Card>
      <CardHeader
        title="Public key bundles"
        description={
          <>
            Upload with the SDK or CLI: <Mono>ciphercompute bundles upload {shortId(projectId)} ./keys</Mono>. Secret keys never leave your machine; the
            server rejects any bundle that contains one.
          </>
        }
      />
      {revoke.error ? <Alert title="Could not revoke">{revoke.error instanceof ApiError ? revoke.error.message : "Unexpected error."}</Alert> : null}
      <QueryState query={bundles} label="key bundles" isEmpty={(b) => b.length === 0} empty="No key bundles yet.">
        {(items) => (
          <Table caption="Key bundles">
            <thead>
              <tr>
                <Th>Ring</Th>
                <Th>Parameters</Th>
                <Th>Size</Th>
                <Th>Status</Th>
                <Th>
                  <span className="sr-only">Actions</span>
                </Th>
              </tr>
            </thead>
            <tbody>
              {items.map((b) => (
                <tr key={b.id}>
                  <Td>
                    <Mono>{b.ring_id?.slice(0, 12) ?? "—"}</Mono>
                  </Td>
                  <Td>{describeParams(b.params)}</Td>
                  <Td>{formatBytes(b.size_bytes)}</Td>
                  <Td>
                    <Badge tone={b.status === "active" ? "success" : "muted"}>{b.status}</Badge>
                  </Td>
                  <Td>
                    {b.status === "active" ? (
                      <Button variant="danger" size="sm" onClick={() => revoke.mutate(b.id)} aria-label={`Revoke bundle ${b.ring_id?.slice(0, 12) ?? b.id}`}>
                        Revoke
                      </Button>
                    ) : null}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </QueryState>
    </Card>
  );
}

function CiphertextList({ dataset }: { dataset: Dataset }) {
  const ciphertexts = useCiphertexts(dataset.id);
  return (
    <QueryState query={ciphertexts} label="ciphertexts" isEmpty={(p) => p.items.length === 0} empty="No ciphertexts uploaded yet.">
      {(page) => (
        <ul className="space-y-1 text-sm">
          {page.items.map((c) => (
            <li key={c.id} className="flex flex-wrap items-center gap-2">
              <span className="font-medium text-fg">{c.label}</span>
              <Badge tone={c.status === "ready" ? "success" : "warning"}>{c.status}</Badge>
              <span className="text-fg-muted">
                {c.length ?? "?"} values · {formatBytes(c.size_bytes ?? c.declared_size_bytes)} · {c.levels_consumed ?? 0} levels used
              </span>
            </li>
          ))}
        </ul>
      )}
    </QueryState>
  );
}

function DatasetsCard({ projectId, bundles }: { projectId: string; bundles: KeyBundle[] }) {
  const datasets = useDatasets(projectId);
  const queryClient = useQueryClient();
  const create = useMutation({
    mutationFn: (body: { name: string; key_bundle_id: string }) => api.request<Dataset>(`v1/projects/${projectId}/datasets`, { method: "POST", body }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["datasets", projectId] }),
  });
  const active = bundles.filter((b) => b.status === "active");
  function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    create.mutate({ name: String(form.get("name")), key_bundle_id: String(form.get("bundle")) });
    event.currentTarget.reset();
  }
  return (
    <Card>
      <CardHeader title="Encrypted datasets" description="Ciphertexts are uploaded from your machine with the SDK; the dashboard shows their metadata only." />
      {active.length > 0 ? (
        <form className="mb-5 grid gap-3 sm:grid-cols-[1fr_1fr_auto] sm:items-end" onSubmit={onSubmit}>
          <Field id="dataset-name" label="New dataset name">
            <Input name="name" required maxLength={120} />
          </Field>
          <Field id="dataset-bundle" label="Encrypted under">
            <Select name="bundle" required defaultValue={active[0]?.id}>
              {active.map((b) => (
                <option key={b.id} value={b.id}>
                  {b.ring_id?.slice(0, 12)} — {describeParams(b.params)}
                </option>
              ))}
            </Select>
          </Field>
          <Button type="submit" disabled={create.isPending}>
            Create dataset
          </Button>
        </form>
      ) : null}
      {create.error ? <Alert title="Could not create the dataset">{create.error instanceof ApiError ? create.error.message : "Unexpected error."}</Alert> : null}
      <QueryState query={datasets} label="datasets" isEmpty={(p) => p.items.length === 0} empty="No datasets yet.">
        {(page) => (
          <div className="space-y-4">
            {page.items.map((d) => (
              <div key={d.id} className="rounded-md border border-border p-4">
                <h3 className="font-medium text-fg">{d.name}</h3>
                <p className="mb-2 text-xs text-fg-muted">
                  id <Mono>{d.id}</Mono>
                </p>
                <CiphertextList dataset={d} />
              </div>
            ))}
          </div>
        )}
      </QueryState>
    </Card>
  );
}

/** The part of the JSON args the server can read; shown so users see what they disclose. */
export function parseArgs(text: string): { ok: true; value: Record<string, unknown> } | { ok: false; error: string } {
  if (!text.trim()) return { ok: true, value: {} };
  try {
    const value: unknown = JSON.parse(text);
    if (value === null || typeof value !== "object" || Array.isArray(value)) return { ok: false, error: "Arguments must be a JSON object." };
    return { ok: true, value: value as Record<string, unknown> };
  } catch (error) {
    return { ok: false, error: `Invalid JSON: ${(error as Error).message}` };
  }
}

function SubmitJobCard({ projectId, datasets }: { projectId: string; datasets: Dataset[] }) {
  const router = useRouter();
  const operations = useOperations();
  const [datasetId, setDatasetId] = useState(datasets[0]?.id ?? "");
  const ciphertexts = useCiphertexts(datasetId, { enabled: Boolean(datasetId) });
  const [selected, setSelected] = useState<string[]>([]);
  const [argsError, setArgsError] = useState<string | null>(null);
  const ready = useMemo(() => (ciphertexts.data?.items ?? []).filter((c: Ciphertext) => c.status === "ready"), [ciphertexts.data]);
  const submit = useMutation({
    mutationFn: (body: { operation: string; inputs: string[]; args: Record<string, unknown> }) =>
      api.request<Job>(`v1/projects/${projectId}/jobs`, { method: "POST", body, headers: { "Idempotency-Key": `dash-${crypto.randomUUID()}` } }),
    onSuccess: (job) => router.push(`/jobs/${job.id}`),
  });
  function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const args = parseArgs(String(form.get("args") ?? ""));
    if (!args.ok) {
      setArgsError(args.error);
      return;
    }
    setArgsError(null);
    submit.mutate({ operation: String(form.get("operation")), inputs: selected, args: args.value });
  }
  const error = submit.error instanceof ApiError ? submit.error : null;
  const suggestion = error?.code === "depth_exhausted" ? (error.details as { suggested_params?: { poly_modulus_degree: number; coeff_mod_bit_sizes: number[]; scale_bits: number; security_level: number } | null })?.suggested_params : null;
  return (
    <Card>
      <CardHeader title="Submit a job" description="Computation runs on ciphertexts. Plaintext arguments (weights, scalars, matrices) are visible to the server." />
      {datasets.length === 0 ? (
        <p className="text-sm text-fg-muted">Create a dataset and upload ciphertexts first.</p>
      ) : (
        <form className="space-y-4" onSubmit={onSubmit}>
          {submit.error ? (
            <Alert title={error?.code === "depth_exhausted" ? "Not enough multiplicative depth" : "Job refused"}>
              <p>{error?.message ?? "Unexpected error."}</p>
              {suggestion ? (
                <p className="mt-1">
                  Re-encrypt under: {describeParams(suggestion)}. <Link className="text-primary underline" href="/advisor">Open the parameter advisor</Link>
                </p>
              ) : null}
            </Alert>
          ) : null}
          <div className="grid gap-4 sm:grid-cols-2">
            <Field id="job-operation" label="Operation">
              <Select name="operation" required>
                {(operations.data ?? []).map((op) => (
                  <option key={op.name} value={op.name}>
                    {op.name}
                  </option>
                ))}
              </Select>
            </Field>
            <Field id="job-dataset" label="Dataset">
              <Select
                value={datasetId}
                onChange={(e) => {
                  setDatasetId(e.target.value);
                  setSelected([]);
                }}
              >
                {datasets.map((d) => (
                  <option key={d.id} value={d.id}>
                    {d.name}
                  </option>
                ))}
              </Select>
            </Field>
          </div>
          <fieldset>
            <legend className="mb-1.5 text-sm font-medium text-fg">Inputs (in order)</legend>
            {ready.length === 0 ? <p className="text-sm text-fg-muted">No confirmed ciphertexts in this dataset.</p> : null}
            <div className="flex flex-wrap gap-3">
              {ready.map((c) => (
                <label key={c.id} className="flex min-h-10 items-center gap-2 rounded-md border border-input-border px-3 text-sm text-fg">
                  <input
                    type="checkbox"
                    checked={selected.includes(c.id)}
                    onChange={(e) => setSelected((prev) => (e.target.checked ? [...prev, c.id] : prev.filter((id) => id !== c.id)))}
                  />
                  {c.label} <span className="text-fg-muted">({c.length})</span>
                </label>
              ))}
            </div>
          </fieldset>
          <Field id="job-args" label="Arguments (JSON)" hint='For example {"weights": [0.8, -0.3], "intercept": -1.2, "layout": "columns", "degree": 3}' error={argsError}>
            <Textarea name="args" placeholder="{}" />
          </Field>
          <Button type="submit" disabled={submit.isPending || selected.length === 0}>
            {submit.isPending ? "Submitting…" : "Submit job"}
          </Button>
        </form>
      )}
    </Card>
  );
}

function ProjectJobs({ projectId }: { projectId: string }) {
  const jobs = useJobs({ projectId });
  return (
    <Card>
      <CardHeader title="Jobs" />
      <QueryState query={jobs} label="jobs" isEmpty={(p) => p.items.length === 0} empty="No jobs in this project yet.">
        {(page) => (
          <Table caption="Jobs in this project">
            <thead>
              <tr>
                <Th>Job</Th>
                <Th>Operation</Th>
                <Th>Status</Th>
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
                  <Td>{formatDate(job.created_at)}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </QueryState>
    </Card>
  );
}

export function ProjectDetailView({ projectId }: { projectId: string }) {
  const project = useProject(projectId);
  const bundles = useBundles(projectId);
  const datasets = useDatasets(projectId);
  return (
    <QueryState query={project} label="project">
      {(p) => (
        <>
          <PageHeader title={p.name} description={p.description || `Project ${p.id}`} />
          <div className="space-y-6">
            <BundlesCard projectId={projectId} />
            <DatasetsCard projectId={projectId} bundles={bundles.data ?? []} />
            <SubmitJobCard key={datasets.data?.items.length ?? 0} projectId={projectId} datasets={datasets.data?.items ?? []} />
            <ProjectJobs projectId={projectId} />
          </div>
        </>
      )}
    </QueryState>
  );
}
