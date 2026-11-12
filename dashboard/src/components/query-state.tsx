import type * as React from "react";

import { ApiError } from "@/lib/api";

import { Alert } from "./ui/primitives";

/** Uniform loading / error / empty rendering for a query result. */
export function QueryState<T>({
  query,
  empty,
  isEmpty,
  children,
  label,
}: {
  query: { isPending: boolean; isError: boolean; error: unknown; data: T | undefined };
  label: string;
  empty?: React.ReactNode;
  isEmpty?: (data: T) => boolean;
  children: (data: T) => React.ReactNode;
}) {
  if (query.isPending) {
    return (
      <p className="text-sm text-fg-muted" role="status">
        Loading {label}…
      </p>
    );
  }
  if (query.isError || query.data === undefined) {
    const error = query.error;
    const message = error instanceof ApiError ? `${error.message}${error.requestId ? ` (request ${error.requestId})` : ""}` : "Unexpected error.";
    return <Alert title={`Could not load ${label}`}>{message}</Alert>;
  }
  if (isEmpty?.(query.data)) return <div className="rounded-md border border-dashed border-border p-6 text-center text-sm text-fg-muted">{empty}</div>;
  return <>{children(query.data)}</>;
}
