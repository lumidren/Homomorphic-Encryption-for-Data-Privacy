import type { Metadata } from "next";

import { ProjectDetailView } from "@/views/project-detail";

export const metadata: Metadata = { title: "Project" };

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return <ProjectDetailView projectId={id} />;
}
