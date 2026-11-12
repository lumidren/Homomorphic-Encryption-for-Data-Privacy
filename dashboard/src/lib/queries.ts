"use client";

import { type UseQueryOptions, useQuery } from "@tanstack/react-query";

import { api } from "./api";
import type {
  ApiKey,
  AuditEvent,
  ChainVerification,
  Ciphertext,
  Dataset,
  Job,
  JobStatus,
  KeyBundle,
  Me,
  Operation,
  Page,
  ParameterSet,
  Project,
  Usage,
} from "./types";

type Opts<T> = Omit<UseQueryOptions<T>, "queryKey" | "queryFn">;

export const useMe = () => useQuery({ queryKey: ["me"], queryFn: () => api.request<Me>("v1/auth/me") });

export const useProjects = () => useQuery({ queryKey: ["projects"], queryFn: () => api.request<Page<Project>>("v1/projects", { query: { limit: 200 } }) });

export const useProject = (id: string) => useQuery({ queryKey: ["project", id], queryFn: () => api.request<Project>(`v1/projects/${id}`) });

export const useBundles = (projectId: string) =>
  useQuery({ queryKey: ["bundles", projectId], queryFn: () => api.request<KeyBundle[]>(`v1/projects/${projectId}/key-bundles`) });

export const useDatasets = (projectId: string) =>
  useQuery({ queryKey: ["datasets", projectId], queryFn: () => api.request<Page<Dataset>>(`v1/projects/${projectId}/datasets`, { query: { limit: 200 } }) });

export const useCiphertexts = (datasetId: string, options: Opts<Page<Ciphertext>> = {}) =>
  useQuery({
    queryKey: ["ciphertexts", datasetId],
    queryFn: () => api.request<Page<Ciphertext>>(`v1/datasets/${datasetId}/ciphertexts`, { query: { limit: 200 } }),
    ...options,
  });

export const useJobs = (filters: { projectId?: string; status?: JobStatus | "" } = {}) =>
  useQuery({
    queryKey: ["jobs", filters],
    queryFn: () => api.request<Page<Job>>("v1/jobs", { query: { project_id: filters.projectId, status: filters.status, limit: 100 } }),
  });

export const useJob = (id: string) => useQuery({ queryKey: ["job", id], queryFn: () => api.request<Job>(`v1/jobs/${id}`) });

export const useOperations = () => useQuery({ queryKey: ["operations"], queryFn: () => api.request<Operation[]>("v1/operations"), staleTime: Infinity });

export const useParameterSets = () =>
  useQuery({ queryKey: ["parameter-sets"], queryFn: () => api.request<ParameterSet[]>("v1/parameter-sets"), staleTime: Infinity });

export const useAudit = (filters: { action?: string; beforeSeq?: number | null }) =>
  useQuery({
    queryKey: ["audit", filters],
    queryFn: () => api.request<Page<AuditEvent>>("v1/audit", { query: { action: filters.action, before_seq: filters.beforeSeq, limit: 50 } }),
  });

export const useChainVerification = (enabled: boolean) =>
  useQuery({ queryKey: ["audit-verify"], queryFn: () => api.request<ChainVerification>("v1/audit/verify"), enabled });

export const useApiKeys = () => useQuery({ queryKey: ["api-keys"], queryFn: () => api.request<ApiKey[]>("v1/api-keys") });

export const useUsage = (days: number) => useQuery({ queryKey: ["usage", days], queryFn: () => api.request<Usage>("v1/usage", { query: { days } }) });
