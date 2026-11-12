import type { Metadata } from "next";

import { AdvisorView } from "@/views/advisor";

export const metadata: Metadata = { title: "Parameter advisor" };

export default function Page() {
  return <AdvisorView />;
}
