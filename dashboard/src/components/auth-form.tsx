"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { type FormEvent, useState } from "react";

import { type ApiError, parseError } from "@/lib/api";

import { ThemeToggle } from "./theme-toggle";
import { Button } from "./ui/button";
import { Alert, Card, Field, Input } from "./ui/primitives";

const FIELD_NAMES: Record<string, string> = { email: "Email", password: "Password", organization_name: "Organization name" };

/** Turn the API's validation details into field-specific sentences instead of a generic guess. */
export function describeAuthError(error: ApiError): string {
  if (error.code === "validation_error" && Array.isArray(error.details)) {
    const lines = (error.details as Array<{ loc?: unknown[]; msg?: string }>).map((d) => {
      const field = String(d.loc?.[d.loc.length - 1] ?? "");
      return `${FIELD_NAMES[field] ?? field}: ${(d.msg ?? "invalid").replace(/^Value error, /, "")}`;
    });
    if (lines.length) return lines.join(" ");
  }
  return error.message;
}

/** Only same-site relative paths are honoured as post-login destinations (no open redirect). */
export function safeNext(next: string | null): string {
  return next && next.startsWith("/") && !next.startsWith("//") && !next.startsWith("/\\") ? next : "/";
}

export function AuthForm({ mode }: { mode: "login" | "register" }) {
  const router = useRouter();
  const params = useSearchParams();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setBusy(true);
    const form = new FormData(event.currentTarget);
    const body =
      mode === "login"
        ? { email: form.get("email"), password: form.get("password") }
        : { email: form.get("email"), password: form.get("password"), organization_name: form.get("organization") };
    try {
      const response = await fetch(`/api/session?mode=${mode}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
        credentials: "same-origin",
      });
      if (!response.ok) {
        setError(describeAuthError(await parseError(response)));
        return;
      }
      router.replace(safeNext(params.get("next")));
      router.refresh();
    } catch {
      setError("Could not reach the server. Check your connection and try again.");
    } finally {
      setBusy(false);
    }
  }

  const title = mode === "login" ? "Sign in" : "Create your organization";
  return (
    <div className="mx-auto flex min-h-screen max-w-md flex-col justify-center px-4 py-10">
      <div className="mb-6 flex items-center justify-between">
        <p className="text-lg font-semibold text-fg">CipherCompute</p>
        <ThemeToggle />
      </div>
      <main>
        <Card>
          <h1 className="text-xl font-semibold text-fg">{title}</h1>
          <p className="mt-1 text-sm text-fg-muted">Your data is encrypted on your machine. This dashboard never sees keys or plaintext.</p>
          <form className="mt-5 space-y-4" onSubmit={onSubmit} noValidate={false}>
            {error ? <Alert title={mode === "login" ? "Sign-in failed" : "Registration failed"}>{error}</Alert> : null}
            <Field id="email" label="Email">
              <Input name="email" type="email" autoComplete="email" required />
            </Field>
            <Field id="password" label="Password" hint={mode === "register" ? "At least 12 characters." : undefined}>
              <Input name="password" type="password" autoComplete={mode === "login" ? "current-password" : "new-password"} minLength={mode === "register" ? 12 : 1} required />
            </Field>
            {mode === "register" ? (
              <Field id="organization" label="Organization name">
                <Input name="organization" autoComplete="organization" minLength={2} required />
              </Field>
            ) : null}
            <Button type="submit" className="w-full" disabled={busy}>
              {busy ? "Please wait…" : title}
            </Button>
          </form>
          <p className="mt-4 text-sm text-fg-muted">
            {mode === "login" ? (
              <>
                New here?{" "}
                <Link className="font-medium text-primary underline underline-offset-2" href="/register">
                  Create an organization
                </Link>
              </>
            ) : (
              <>
                Already registered?{" "}
                <Link className="font-medium text-primary underline underline-offset-2" href="/login">
                  Sign in
                </Link>
              </>
            )}
          </p>
        </Card>
      </main>
    </div>
  );
}
