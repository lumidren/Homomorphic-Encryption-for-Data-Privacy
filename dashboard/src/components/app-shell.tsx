"use client";

import { Activity, BarChart3, FolderKanban, KeyRound, LogOut, ScrollText, SlidersHorizontal, Workflow } from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import type * as React from "react";

import { cn } from "@/lib/utils";

import { ThemeToggle } from "./theme-toggle";
import { Button } from "./ui/button";

export const NAV = [
  { href: "/", label: "Overview", icon: Activity },
  { href: "/projects", label: "Projects", icon: FolderKanban },
  { href: "/jobs", label: "Jobs", icon: Workflow },
  { href: "/advisor", label: "Parameter advisor", icon: SlidersHorizontal },
  { href: "/audit", label: "Audit log", icon: ScrollText },
  { href: "/api-keys", label: "API keys", icon: KeyRound },
  { href: "/usage", label: "Usage", icon: BarChart3 },
] as const;

export function isActive(pathname: string, href: string): boolean {
  return href === "/" ? pathname === "/" : pathname === href || pathname.startsWith(`${href}/`);
}

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  async function logout() {
    await fetch("/api/session", { method: "DELETE", credentials: "same-origin" });
    router.replace("/login");
  }
  return (
    <div className="min-h-screen md:grid md:grid-cols-[15rem_1fr]">
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:left-3 focus:top-3 focus:z-50 focus:rounded-md focus:bg-surface focus:px-3 focus:py-2">
        Skip to content
      </a>
      <header className="border-b border-border bg-surface md:min-h-screen md:border-b-0 md:border-r">
        <div className="flex items-center justify-between gap-2 px-4 py-4">
          <Link href="/" className="text-base font-semibold text-fg">
            CipherCompute
          </Link>
          <ThemeToggle />
        </div>
        <nav aria-label="Main">
          <ul className="flex gap-1 overflow-x-auto px-2 pb-3 md:flex-col md:overflow-visible">
            {NAV.map(({ href, label, icon: Icon }) => {
              const active = isActive(pathname, href);
              return (
                <li key={href}>
                  <Link
                    href={href}
                    aria-current={active ? "page" : undefined}
                    className={cn(
                      "flex min-h-10 items-center gap-2 whitespace-nowrap rounded-md px-3 py-2 text-sm",
                      active ? "bg-surface-muted font-medium text-fg" : "text-fg-muted hover:bg-surface-muted hover:text-fg",
                    )}
                  >
                    <Icon className="size-4" aria-hidden="true" />
                    {label}
                  </Link>
                </li>
              );
            })}
          </ul>
        </nav>
        <div className="px-2 pb-4">
          <Button variant="ghost" className="w-full justify-start" onClick={logout}>
            <LogOut aria-hidden="true" />
            Sign out
          </Button>
        </div>
      </header>
      <main id="main" className="mx-auto w-full max-w-6xl px-4 py-6 md:px-8 md:py-8">
        {children}
      </main>
    </div>
  );
}

export function PageHeader({ title, description, actions }: { title: string; description?: React.ReactNode; actions?: React.ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 className="text-2xl font-semibold text-fg">{title}</h1>
        {description ? <p className="mt-1 max-w-3xl text-sm text-fg-muted">{description}</p> : null}
      </div>
      {actions}
    </div>
  );
}
