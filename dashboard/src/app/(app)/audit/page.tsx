import type { Metadata } from "next";

import { AuditView } from "@/views/audit";

export const metadata: Metadata = { title: "Audit log" };

export default function Page() {
  return <AuditView />;
}
