import type { Metadata } from "next";

import { ProjectsView } from "@/views/projects";

export const metadata: Metadata = { title: "Projects" };

export default function Page() {
  return <ProjectsView />;
}
