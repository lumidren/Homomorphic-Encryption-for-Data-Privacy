import type { Metadata } from "next";

import { JobDetailView } from "@/views/jobs";

export const metadata: Metadata = { title: "Job" };

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return <JobDetailView jobId={id} />;
}
