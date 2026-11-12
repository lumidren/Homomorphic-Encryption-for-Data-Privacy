import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type * as React from "react";

import { ApiError } from "@/lib/api";
import type { SseMessage } from "@/lib/sse";
import type { DepthReport, Job } from "@/lib/types";

import { AppShell, NAV, PageHeader, isActive } from "./app-shell";
import { AuthForm, describeAuthError, safeNext } from "./auth-form";
import { BarChart } from "./bar-chart";
import { DepthBudget } from "./depth-budget";
import { JobProgress } from "./job-progress";
import { Providers, makeQueryClient } from "./providers";
import { QueryState } from "./query-state";
import { StatusBadge } from "./status-badge";
import { THEME_KEY, THEME_SCRIPT, ThemeToggle, applyTheme } from "./theme-toggle";
import { Button } from "./ui/button";
import { Dialog, DialogContent, DialogTrigger } from "./ui/dialog";
import { Alert, Badge, Card, CardHeader, Field, Input, Mono, Select, Table, Td, Textarea, Th } from "./ui/primitives";

const router = { replace: vi.fn(), refresh: vi.fn(), push: vi.fn() };
let pathname = "/";
let search = new URLSearchParams();
vi.mock("next/navigation", () => ({
  useRouter: () => router,
  usePathname: () => pathname,
  useSearchParams: () => search,
}));

const report = (consumed: number, total = 4, extra: Partial<DepthReport> = {}): DepthReport => ({
  poly_modulus_degree: 8192,
  security_level: 128,
  scale_bits: 30,
  levels_total: total,
  levels_consumed: consumed,
  levels_remaining: total - consumed,
  precision_bits: 10,
  precision_measured: true,
  ...extra,
});

const job = (overrides: Partial<Job> = {}): Job => ({
  id: "job-1",
  project_id: "p",
  key_bundle_id: "b",
  operation: "logistic_regression",
  args: {},
  input_ids: ["c1"],
  input_fingerprints: ["sha256:aa"],
  manifest_hash: "m",
  status: "queued",
  attempts: 0,
  plan: { params: { poly_modulus_degree: 8192, coeff_mod_bit_sizes: [45, 30, 30, 30, 30, 45], scale_bits: 30, security_level: 128 }, report: report(3), steps: [] },
  depth_report: report(3),
  result_fingerprint: null,
  result_length: null,
  result_size_bytes: null,
  error: null,
  created_at: "2026-11-12T10:00:00Z",
  started_at: null,
  finished_at: null,
  compute_seconds: null,
  ...overrides,
});

function withQuery(ui: React.ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return { client, ...render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>) };
}

describe("DepthBudget (noise-budget visualization)", () => {
  it("renders one segment per level and a text equivalent", () => {
    render(<DepthBudget report={report(3, 4)} />);
    expect(screen.getByTestId("depth-segments").children).toHaveLength(4);
    expect(screen.getByText(/3 of 4 levels consumed/)).toBeInTheDocument();
    expect(screen.getByText(/about 10 bits of precision \(measured\)/)).toBeInTheDocument();
  });

  it("flags plan/actual mismatch, estimated precision, exhaustion and missing reports", () => {
    const { rerender } = render(<DepthBudget report={report(4, 4, { precision_measured: false })} planned={report(3, 4)} compact />);
    expect(screen.getByText(/planned 3/)).toBeInTheDocument();
    expect(screen.getByText(/estimated/)).toBeInTheDocument();
    expect(screen.getByTestId("depth-segments").children[0]).toHaveClass("bg-danger");
    rerender(<DepthBudget report={report(1, 4)} />);
    expect(screen.getByTestId("depth-segments").children[0]).toHaveClass("bg-primary");
    rerender(<DepthBudget report={null} />);
    expect(screen.getByText("No depth report yet.")).toBeInTheDocument();
  });
});

describe("JobProgress (live over SSE)", () => {
  it("applies streamed updates, announces them and writes the cache", async () => {
    let push: (m: SseMessage) => void = () => undefined;
    let finish: () => void = () => undefined;
    const stream = vi.fn(
      (_url: string, onMessage: (m: SseMessage) => void) =>
        new Promise<void>((resolve) => {
          push = onMessage;
          finish = resolve;
        }),
    );
    const { client } = withQuery(<JobProgress job={job()} stream={stream} />);
    expect(stream).toHaveBeenCalledWith("/api/proxy/v1/jobs/job-1/events", expect.any(Function), expect.objectContaining({ signal: expect.any(AbortSignal) }));
    act(() => push({ event: "heartbeat", data: "" }));
    act(() => push({ event: "status", data: JSON.stringify(job({ status: "running", attempts: 1 })) }));
    expect(screen.getByText(/Computing on ciphertexts \(attempt 1\)/)).toBeInTheDocument();
    expect(screen.getByRole("listitem", { current: "step" })).toHaveTextContent("running");
    act(() => push({ event: "status", data: JSON.stringify(job({ status: "succeeded", attempts: 1 })) }));
    expect(screen.getByText("Job succeeded.")).toBeInTheDocument();
    expect(client.getQueryData<Job>(["job", "job-1"])?.status).toBe("succeeded");
    await act(async () => finish());
  });

  it("does not stream finished jobs and reports stream failures", async () => {
    const stream = vi.fn(async () => undefined);
    withQuery(<JobProgress job={job({ status: "failed", error: { code: "input_integrity", message: "tampered" } })} stream={stream} />);
    expect(stream).not.toHaveBeenCalled();
    expect(screen.getByRole("alert")).toHaveTextContent("input_integrity: tampered");
    const failing = vi.fn(async () => {
      throw new Error("network");
    });
    const spy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    withQuery(<JobProgress job={job({ id: "job-2" })} stream={failing} />);
    await waitFor(() => expect(screen.getByText(/Live updates unavailable/)).toBeInTheDocument());
    spy.mockRestore();
  });
});

describe("AuthForm", () => {
  beforeEach(() => {
    router.replace.mockReset();
    search = new URLSearchParams("next=/jobs");
  });

  it("accepts only same-site next paths", () => {
    expect(safeNext("/jobs")).toBe("/jobs");
    for (const evil of ["https://evil.example", "//evil.example", "/\\evil", null]) expect(safeNext(evil)).toBe("/");
  });

  it("explains validation errors field by field", () => {
    const err = new ApiError(422, "validation_error", "request validation failed", [
      { loc: ["body", "email"], msg: "value is not a valid email address" },
      { loc: ["body", "organization_name"], msg: "Value error, too short" },
      { loc: ["body", "extra"] },
    ]);
    expect(describeAuthError(err)).toBe("Email: value is not a valid email address Organization name: too short extra: invalid");
    expect(describeAuthError(new ApiError(401, "unauthorized", "invalid email or password"))).toBe("invalid email or password");
    expect(describeAuthError(new ApiError(422, "validation_error", "bad", []))).toBe("bad");
  });

  it("logs in through the session route and follows next", async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ role: "owner" }), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    render(<AuthForm mode="login" />);
    await userEvent.type(screen.getByLabelText("Email"), "ada@example.com");
    await userEvent.type(screen.getByLabelText("Password"), "correct horse battery");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    await waitFor(() => expect(router.replace).toHaveBeenCalledWith("/jobs"));
    expect(fetchMock).toHaveBeenCalledWith("/api/session?mode=login", expect.objectContaining({ method: "POST", credentials: "same-origin" }));
    vi.unstubAllGlobals();
  });

  it("shows API errors and network failures on registration", async () => {
    const responses = [
      new Response(JSON.stringify({ error: { code: "conflict", message: "an account with this email already exists" } }), { status: 409 }),
    ];
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        const next = responses.shift();
        if (!next) throw new TypeError("offline");
        return next;
      }),
    );
    render(<AuthForm mode="register" />);
    await userEvent.type(screen.getByLabelText("Email"), "ada@example.com");
    await userEvent.type(screen.getByLabelText("Password"), "correct horse battery");
    await userEvent.type(screen.getByLabelText("Organization name"), "Clinic");
    await userEvent.click(screen.getByRole("button", { name: "Create your organization" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("already exists");
    await userEvent.click(screen.getByRole("button", { name: "Create your organization" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Could not reach the server");
    expect(screen.getByRole("link", { name: "Sign in" })).toHaveAttribute("href", "/login");
    vi.unstubAllGlobals();
  });
});

describe("AppShell and navigation", () => {
  it("marks the active page and offers a skip link and sign-out", async () => {
    pathname = "/projects/abc";
    const fetchMock = vi.fn(async () => new Response(null, { status: 204 }));
    vi.stubGlobal("fetch", fetchMock);
    render(
      <AppShell>
        <PageHeader title="Projects" description="d" actions={<span>act</span>} />
      </AppShell>,
    );
    const nav = screen.getByRole("navigation", { name: "Main" });
    expect(within(nav).getAllByRole("link")).toHaveLength(NAV.length);
    expect(within(nav).getByRole("link", { name: "Projects" })).toHaveAttribute("aria-current", "page");
    expect(within(nav).getByRole("link", { name: "Overview" })).not.toHaveAttribute("aria-current");
    expect(screen.getByRole("link", { name: "Skip to content" })).toHaveAttribute("href", "#main");
    expect(screen.getByRole("heading", { level: 1, name: "Projects" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Sign out" }));
    await waitFor(() => expect(router.replace).toHaveBeenCalledWith("/login"));
    expect(fetchMock).toHaveBeenCalledWith("/api/session", expect.objectContaining({ method: "DELETE" }));
    vi.unstubAllGlobals();
    expect(isActive("/", "/")).toBe(true);
    expect(isActive("/jobs", "/")).toBe(false);
    expect(isActive("/jobs/1", "/jobs")).toBe(true);
    render(<PageHeader title="Bare" />);
  });
});

describe("theme", () => {
  it("toggles dark mode, persists it, and survives storage failures", async () => {
    document.documentElement.classList.remove("dark");
    render(<ThemeToggle />);
    await userEvent.click(screen.getByRole("button", { name: "Switch to dark theme" }));
    expect(document.documentElement).toHaveClass("dark");
    expect(localStorage.getItem(THEME_KEY)).toBe("dark");
    expect(screen.getByRole("button", { name: "Switch to light theme" })).toBeInTheDocument();
    const setItem = vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("denied");
    });
    applyTheme("light");
    expect(document.documentElement).not.toHaveClass("dark");
    setItem.mockRestore();
    expect(THEME_SCRIPT).toContain(THEME_KEY);
  });
});

describe("charts, badges, query states and primitives", () => {
  it("renders an accessible bar chart with a data table", () => {
    const { rerender } = render(<BarChart title="Jobs per day" unit=" jobs" data={[{ label: "a", value: 2 }, { label: "b", value: 0 }]} />);
    expect(screen.getByRole("img", { name: "Jobs per day: bar chart" })).toBeInTheDocument();
    expect(screen.getByRole("table")).toHaveTextContent("2 jobs");
    rerender(<BarChart title="Empty" data={[]} />);
    expect(screen.getByText("No data for this period.")).toBeInTheDocument();
  });

  it("maps statuses to badges", () => {
    render(<StatusBadge status="failed" />);
    expect(screen.getByText("failed")).toHaveClass("text-danger");
  });

  it("renders loading, error, empty and data states", () => {
    const base = { isPending: false, isError: false, error: null, data: [1] as number[] | undefined };
    const { rerender } = render(<QueryState query={{ ...base, isPending: true }} label="jobs">{() => null}</QueryState>);
    expect(screen.getByRole("status")).toHaveTextContent("Loading jobs");
    rerender(<QueryState query={{ ...base, isError: true, error: new ApiError(500, "x", "boom", null, "r9") }} label="jobs">{() => null}</QueryState>);
    expect(screen.getByRole("alert")).toHaveTextContent("boom (request r9)");
    rerender(<QueryState query={{ ...base, isError: true, error: new Error("?") }} label="jobs">{() => null}</QueryState>);
    expect(screen.getByRole("alert")).toHaveTextContent("Unexpected error.");
    rerender(<QueryState query={{ ...base, data: [] }} label="jobs" isEmpty={(d) => d.length === 0} empty="none">{() => null}</QueryState>);
    expect(screen.getByText("none")).toBeInTheDocument();
    rerender(<QueryState query={base} label="jobs">{(d) => <p>{d.length} items</p>}</QueryState>);
    expect(screen.getByText("1 items")).toBeInTheDocument();
  });

  it("wires labels, hints and errors for assistive technology", () => {
    render(
      <Card>
        <CardHeader title="Form" description="desc" actions={<Badge>b</Badge>} level={3} />
        <Field id="f1" label="Name" hint="Your name" error="Required">
          <Input />
        </Field>
        <Field id="f2" label="Notes">
          <Textarea />
        </Field>
        <Field id="f3" label="Kind">
          <Select>
            <option>a</option>
          </Select>
        </Field>
        <Alert tone="success" title="Saved">
          done
        </Alert>
        <Table caption="T">
          <thead>
            <tr>
              <Th>h</Th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <Td>
                <Mono>c</Mono>
              </Td>
            </tr>
          </tbody>
        </Table>
        <Button asChild variant="secondary">
          <a href="/x">link</a>
        </Button>
      </Card>,
    );
    const input = screen.getByLabelText("Name");
    expect(input).toHaveAttribute("aria-invalid", "true");
    expect(input).toHaveAttribute("aria-describedby", "f1-hint f1-error");
    expect(screen.getByLabelText("Notes")).not.toHaveAttribute("aria-describedby");
    expect(screen.getByRole("status")).toHaveTextContent("Saved");
    expect(screen.getByRole("heading", { level: 3, name: "Form" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "link" })).not.toHaveAttribute("type");
    expect(screen.getByRole("table", { name: "T" })).toBeInTheDocument();
  });

  it("opens an accessible dialog", async () => {
    render(
      <Dialog>
        <DialogTrigger asChild>
          <Button>Open</Button>
        </DialogTrigger>
        <DialogContent title="New project" description="Describe it">
          <p>body</p>
        </DialogContent>
      </Dialog>,
    );
    await userEvent.click(screen.getByRole("button", { name: "Open" }));
    const dialog = screen.getByRole("dialog", { name: "New project" });
    expect(dialog).toHaveAccessibleDescription("Describe it");
    await userEvent.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
});

describe("query client defaults", () => {
  it("retries only transient failures", () => {
    const retry = makeQueryClient().getDefaultOptions().queries?.retry as (n: number, e: unknown) => boolean;
    expect(retry(0, new ApiError(404, "not_found", "x"))).toBe(false);
    expect(retry(0, new ApiError(503, "unavailable", "x"))).toBe(true);
    expect(retry(2, new Error("network"))).toBe(false);
    render(
      <Providers>
        <p>child</p>
      </Providers>,
    );
    expect(screen.getByText("child")).toBeInTheDocument();
  });
});
