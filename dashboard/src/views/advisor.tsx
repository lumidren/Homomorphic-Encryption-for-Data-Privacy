"use client";

import { useMutation } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";

import { PageHeader } from "@/components/app-shell";
import { DepthBudget } from "@/components/depth-budget";
import { QueryState } from "@/components/query-state";
import { Button } from "@/components/ui/button";
import { Alert, Badge, Card, CardHeader, Field, Input, Mono, Select, Table, Td, Textarea, Th } from "@/components/ui/primitives";
import { ApiError, api } from "@/lib/api";
import { describeParams } from "@/lib/format";
import { useOperations, useParameterSets } from "@/lib/queries";
import type { Advice } from "@/lib/types";

import { parseArgs } from "./project-detail";

interface AdvisorRequest {
  steps: Array<{ operation: string; args: Record<string, unknown> }>;
  input_lengths: number[];
  security_level: number;
  min_precision_bits: number;
  prefer: "balanced" | "deep";
}

export function AdvisorView() {
  const operations = useOperations();
  const sets = useParameterSets();
  const [argsError, setArgsError] = useState<string | null>(null);
  const advise = useMutation({ mutationFn: (body: AdvisorRequest) => api.request<Advice>("v1/advisor", { method: "POST", body }) });

  function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const args = parseArgs(String(form.get("args") ?? ""));
    if (!args.ok) {
      setArgsError(args.error);
      return;
    }
    setArgsError(null);
    advise.mutate({
      steps: [{ operation: String(form.get("operation")), args: args.value }],
      input_lengths: [Number(form.get("length"))],
      security_level: Number(form.get("security")),
      min_precision_bits: Number(form.get("precision") || 0),
      prefer: form.get("prefer") === "deep" ? "deep" : "balanced",
    });
  }

  return (
    <>
      <PageHeader
        title="Parameter advisor"
        description="Pick the computation; get the smallest CKKS parameter set that can carry it at your security level, with measured precision."
      />
      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader title="Describe the computation" />
          <form className="space-y-4" onSubmit={onSubmit}>
            <Field id="adv-operation" label="Operation">
              <Select name="operation" defaultValue="logistic_regression">
                {(operations.data ?? []).map((op) => (
                  <option key={op.name} value={op.name}>
                    {op.name}
                  </option>
                ))}
              </Select>
            </Field>
            <Field id="adv-args" label="Arguments (JSON)" error={argsError} hint="Weights decide the depth of regression; degree decides the sigmoid cost.">
              <Textarea name="args" defaultValue={'{"weights": [0.5, -0.2, 0.1], "degree": 3}'} />
            </Field>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field id="adv-length" label="Vector length">
                <Input name="length" type="number" min={1} max={16384} defaultValue={3} required />
              </Field>
              <Field id="adv-security" label="Security level">
                <Select name="security" defaultValue="128">
                  <option value="128">128-bit</option>
                  <option value="192">192-bit</option>
                  <option value="256">256-bit</option>
                </Select>
              </Field>
              <Field id="adv-precision" label="Minimum precision (bits)" hint="0 = any">
                <Input name="precision" type="number" min={0} max={50} defaultValue={0} />
              </Field>
              <Field id="adv-prefer" label="Prefer">
                <Select name="prefer" defaultValue="balanced">
                  <option value="balanced">Precision (balanced)</option>
                  <option value="deep">Depth (deep)</option>
                </Select>
              </Field>
            </div>
            <Button type="submit" disabled={advise.isPending}>
              {advise.isPending ? "Working…" : "Recommend parameters"}
            </Button>
          </form>
        </Card>
        <Card aria-live="polite">
          <CardHeader title="Recommendation" />
          {advise.error ? <Alert title="No parameter set fits">{advise.error instanceof ApiError ? advise.error.message : "Unexpected error."}</Alert> : null}
          {advise.data ? (
            <div className="space-y-4">
              <p className="text-sm text-fg">
                <Badge tone="info">{advise.data.profile}</Badge> {describeParams(advise.data.params)}
              </p>
              <p className="text-sm text-fg-muted">
                Primes <Mono>[{advise.data.params.coeff_mod_bit_sizes.join(", ")}]</Mono> — this computation needs {advise.data.required_depth} level(s).
              </p>
              <DepthBudget report={advise.data.report} />
              <pre className="overflow-x-auto rounded-md bg-surface-muted p-3 font-mono text-xs text-fg">
                {`ciphercompute keys generate ./keys --degree ${advise.data.params.poly_modulus_degree} --security ${advise.data.params.security_level} --profile ${advise.data.profile}`}
              </pre>
              {advise.data.alternatives.length ? (
                <p className="text-sm text-fg-muted">Also viable: {advise.data.alternatives.map((a) => `${a.profile} N=${a.params.poly_modulus_degree}`).join(", ")}.</p>
              ) : null}
            </div>
          ) : !advise.error ? (
            <p className="text-sm text-fg-muted">Submit the form to see a recommendation.</p>
          ) : null}
        </Card>
      </div>
      <Card className="mt-6">
        <CardHeader title="Standard parameter sets" description="Precision is measured across many key rings, with a 16x safety margin (bits after 0, 1, 2… levels)." />
        <QueryState query={sets} label="parameter sets">
          {(items) => (
            <Table caption="Standard CKKS parameter sets">
              <thead>
                <tr>
                  <Th>N</Th>
                  <Th>Security</Th>
                  <Th>Profile</Th>
                  <Th>Levels</Th>
                  <Th>Scale</Th>
                  <Th>Slots</Th>
                  <Th>Precision bits by level</Th>
                </tr>
              </thead>
              <tbody>
                {items.map((s) => (
                  <tr key={`${s.poly_modulus_degree}-${s.security_level}-${s.profile}`}>
                    <Td>{s.poly_modulus_degree}</Td>
                    <Td>{s.security_level}-bit</Td>
                    <Td>{s.profile}</Td>
                    <Td>{s.depth}</Td>
                    <Td>2^{s.scale_bits}</Td>
                    <Td>{s.slots}</Td>
                    <Td className="font-mono text-xs">{Object.values(s.precision_bits_by_level).join(" · ")}</Td>
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
