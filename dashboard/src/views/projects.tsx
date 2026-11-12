"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus } from "lucide-react";
import Link from "next/link";
import { type FormEvent, useState } from "react";

import { PageHeader } from "@/components/app-shell";
import { QueryState } from "@/components/query-state";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogTrigger } from "@/components/ui/dialog";
import { Alert, Card, Field, Input, Table, Td, Th, Textarea } from "@/components/ui/primitives";
import { ApiError, api } from "@/lib/api";
import { formatDate } from "@/lib/format";
import { useProjects } from "@/lib/queries";
import type { Project } from "@/lib/types";

export function CreateProjectDialog() {
  const [open, setOpen] = useState(false);
  const queryClient = useQueryClient();
  const create = useMutation({
    mutationFn: (body: { name: string; description: string }) => api.request<Project>("v1/projects", { method: "POST", body }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["projects"] });
      setOpen(false);
    },
  });
  function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    create.mutate({ name: String(form.get("name") ?? ""), description: String(form.get("description") ?? "") });
  }
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button>
          <Plus aria-hidden="true" />
          New project
        </Button>
      </DialogTrigger>
      <DialogContent title="New project" description="A project groups key bundles, datasets and jobs.">
        <form className="space-y-4" onSubmit={onSubmit}>
          {create.error ? <Alert title="Could not create the project">{create.error instanceof ApiError ? create.error.message : "Unexpected error."}</Alert> : null}
          <Field id="project-name" label="Name">
            <Input name="name" required maxLength={120} />
          </Field>
          <Field id="project-description" label="Description" hint="Optional.">
            <Textarea name="description" maxLength={2000} className="font-sans" />
          </Field>
          <Button type="submit" disabled={create.isPending}>
            {create.isPending ? "Creating…" : "Create project"}
          </Button>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export function ProjectsView() {
  const projects = useProjects();
  return (
    <>
      <PageHeader title="Projects" description="Each project holds its own key bundles, encrypted datasets and jobs." actions={<CreateProjectDialog />} />
      <Card>
        <QueryState query={projects} label="projects" isEmpty={(p) => p.items.length === 0} empty="No projects yet. Create one to upload your public keys.">
          {(page) => (
            <Table caption="Projects">
              <thead>
                <tr>
                  <Th>Name</Th>
                  <Th>Description</Th>
                  <Th>Created</Th>
                </tr>
              </thead>
              <tbody>
                {page.items.map((project) => (
                  <tr key={project.id}>
                    <Td>
                      <Link className="font-medium text-primary underline underline-offset-2" href={`/projects/${project.id}`}>
                        {project.name}
                      </Link>
                    </Td>
                    <Td className="text-fg-muted">{project.description || "—"}</Td>
                    <Td>{formatDate(project.created_at)}</Td>
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
