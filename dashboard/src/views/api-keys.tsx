"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";

import { PageHeader } from "@/components/app-shell";
import { QueryState } from "@/components/query-state";
import { Button } from "@/components/ui/button";
import { Alert, Badge, Card, CardHeader, Field, Input, Mono, Table, Td, Th } from "@/components/ui/primitives";
import { ApiError, api } from "@/lib/api";
import { formatDate } from "@/lib/format";
import { useApiKeys } from "@/lib/queries";
import type { ApiKey } from "@/lib/types";

export const SCOPES = [
  "projects:read",
  "projects:write",
  "datasets:read",
  "datasets:write",
  "keys:write",
  "jobs:read",
  "jobs:write",
  "audit:read",
  "api_keys:manage",
  "members:manage",
] as const;

export function ApiKeysView() {
  const keys = useApiKeys();
  const queryClient = useQueryClient();
  const [secret, setSecret] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const create = useMutation({
    mutationFn: (body: { name: string; scopes: string[]; expires_in_days: number | null }) =>
      api.request<{ api_key: ApiKey; secret: string }>("v1/api-keys", { method: "POST", body }),
    onSuccess: async (data) => {
      setSecret(data.secret);
      setCopied(false);
      await queryClient.invalidateQueries({ queryKey: ["api-keys"] });
    },
  });
  const revoke = useMutation({
    mutationFn: (id: string) => api.request<ApiKey>(`v1/api-keys/${id}`, { method: "DELETE" }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["api-keys"] }),
  });

  function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const days = Number(form.get("expires") || 0);
    create.mutate({ name: String(form.get("name")), scopes: form.getAll("scope").map(String), expires_in_days: days > 0 ? days : null });
  }

  return (
    <>
      <PageHeader title="API keys" description="For the SDK, the CLI and CI pipelines. Keys are stored as hashes; the secret is shown once." />
      <div className="grid gap-6 lg:grid-cols-[2fr_3fr]">
        <Card>
          <CardHeader title="Create a key" />
          <form className="space-y-4" onSubmit={onSubmit}>
            {create.error ? <Alert title="Could not create the key">{create.error instanceof ApiError ? create.error.message : "Unexpected error."}</Alert> : null}
            <Field id="key-name" label="Name">
              <Input name="name" required maxLength={120} />
            </Field>
            <fieldset>
              <legend className="mb-1.5 text-sm font-medium text-fg">Scopes</legend>
              <div className="grid grid-cols-2 gap-2">
                {SCOPES.map((scope) => (
                  <label key={scope} className="flex min-h-10 items-center gap-2 text-sm text-fg">
                    <input type="checkbox" name="scope" value={scope} defaultChecked={scope.endsWith(":read")} />
                    <Mono>{scope}</Mono>
                  </label>
                ))}
              </div>
            </fieldset>
            <Field id="key-expires" label="Expires after (days)" hint="Leave empty for no expiry.">
              <Input name="expires" type="number" min={1} max={365} />
            </Field>
            <Button type="submit" disabled={create.isPending}>
              Create key
            </Button>
          </form>
          {secret ? (
            <div className="mt-5" role="status">
              <Alert tone="warning" title="Copy this secret now — it will not be shown again">
                <div className="mt-2 flex flex-wrap items-center gap-2">
                  <Mono>{secret}</Mono>
                  <Button
                    size="sm"
                    variant="secondary"
                    onClick={async () => {
                      await navigator.clipboard.writeText(secret);
                      setCopied(true);
                    }}
                  >
                    {copied ? "Copied" : "Copy"}
                  </Button>
                </div>
              </Alert>
            </div>
          ) : null}
        </Card>
        <Card>
          <CardHeader title="Keys" />
          <QueryState query={keys} label="API keys" isEmpty={(k) => k.length === 0} empty="No API keys yet.">
            {(items) => (
              <Table caption="API keys">
                <thead>
                  <tr>
                    <Th>Name</Th>
                    <Th>Prefix</Th>
                    <Th>Role</Th>
                    <Th>Last used</Th>
                    <Th>
                      <span className="sr-only">Actions</span>
                    </Th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((k) => (
                    <tr key={k.id}>
                      <Td>{k.name}</Td>
                      <Td>
                        <Mono>{k.prefix}…</Mono>
                      </Td>
                      <Td>{k.role}</Td>
                      <Td>{formatDate(k.last_used_at)}</Td>
                      <Td>
                        {k.revoked_at ? (
                          <Badge tone="muted">revoked</Badge>
                        ) : (
                          <Button variant="danger" size="sm" onClick={() => revoke.mutate(k.id)} aria-label={`Revoke key ${k.name}`}>
                            Revoke
                          </Button>
                        )}
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            )}
          </QueryState>
        </Card>
      </div>
    </>
  );
}
