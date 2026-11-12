import { STATUS_TONE } from "@/lib/format";
import type { JobStatus } from "@/lib/types";

import { Badge } from "./ui/primitives";

export function StatusBadge({ status }: { status: JobStatus }) {
  return <Badge tone={STATUS_TONE[status]}>{status}</Badge>;
}
