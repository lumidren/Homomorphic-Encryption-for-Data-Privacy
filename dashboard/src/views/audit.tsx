"use client";

import { useState } from "react";

import { PageHeader } from "@/components/app-shell";
import { QueryState } from "@/components/query-state";
import { Button } from "@/components/ui/button";
import { Alert, Card, CardHeader, Field, Input, Mono, Table, Td, Th } from "@/components/ui/primitives";
import { formatDate, shortId } from "@/lib/format";
import { useAudit, useChainVerification } from "@/lib/queries";

export function AuditView() {
  const [action, setAction] = useState("");
  const [cursors, setCursors] = useState<number[]>([]);
  const beforeSeq = cursors.at(-1) ?? null;
  const events = useAudit({ action: action || undefined, beforeSeq });
  const [verifyRequested, setVerifyRequested] = useState(false);
  const verification = useChainVerification(verifyRequested);

  return (
    <>
      <PageHeader
        title="Audit log"
        description="Append-only and hash-chained: each event commits to the previous one, so editing or deleting history is detectable."
        actions={
          <Button
            variant="secondary"
            onClick={() => {
              setVerifyRequested(true);
              void verification.refetch();
            }}
          >
            Verify chain
          </Button>
        }
      />
      {verifyRequested && verification.data ? (
        <div className="mb-6">
          {verification.data.valid ? (
            <Alert tone="success" title="Chain intact">
              {verification.data.checked} events verified; head <Mono>{verification.data.head_hash?.slice(0, 16)}</Mono>
            </Alert>
          ) : (
            <Alert title="Chain broken">
              First broken event #{verification.data.first_broken_seq}: {verification.data.reason}
            </Alert>
          )}
        </div>
      ) : null}
      <Card>
        <CardHeader title="Events" />
        <div className="mb-4 max-w-sm">
          <Field id="audit-action" label="Filter by action" hint="For example job.submitted or ciphertext.accessed">
            <Input
              value={action}
              onChange={(e) => {
                setAction(e.target.value.trim());
                setCursors([]);
              }}
            />
          </Field>
        </div>
        <QueryState query={events} label="audit events" isEmpty={(p) => p.items.length === 0} empty="No matching events.">
          {(page) => (
            <>
              <Table caption="Audit events">
                <thead>
                  <tr>
                    <Th>#</Th>
                    <Th>When</Th>
                    <Th>Action</Th>
                    <Th>Actor</Th>
                    <Th>Resource</Th>
                    <Th>Hash</Th>
                  </tr>
                </thead>
                <tbody>
                  {page.items.map((e) => (
                    <tr key={e.id}>
                      <Td>{e.seq}</Td>
                      <Td>{formatDate(e.occurred_at)}</Td>
                      <Td>
                        <Mono>{e.action}</Mono>
                      </Td>
                      <Td>
                        {e.actor_type} {shortId(e.actor_id)}
                      </Td>
                      <Td>
                        {e.resource_type} {shortId(e.resource_id)}
                      </Td>
                      <Td>
                        <Mono>{e.hash.slice(0, 12)}</Mono>
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
              <div className="mt-4 flex gap-2">
                <Button variant="secondary" disabled={cursors.length === 0} onClick={() => setCursors((c) => c.slice(0, -1))}>
                  Newer
                </Button>
                <Button variant="secondary" disabled={!page.next_cursor} onClick={() => page.next_cursor && setCursors((c) => [...c, Number(page.next_cursor)])}>
                  Older
                </Button>
              </div>
            </>
          )}
        </QueryState>
      </Card>
    </>
  );
}
