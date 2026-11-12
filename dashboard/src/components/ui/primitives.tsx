import * as LabelPrimitive from "@radix-ui/react-label";
import * as React from "react";

import { cn } from "@/lib/utils";

export function Card({ className, ...props }: React.HTMLAttributes<HTMLElement>) {
  return <section className={cn("rounded-lg border border-border bg-surface p-5 shadow-sm", className)} {...props} />;
}

export function CardHeader({ title, description, actions, level = 2 }: { title: string; description?: React.ReactNode; actions?: React.ReactNode; level?: 2 | 3 }) {
  const Heading = level === 2 ? "h2" : "h3";
  return (
    <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
      <div>
        <Heading className="text-base font-semibold text-fg">{title}</Heading>
        {description ? <p className="mt-1 text-sm text-fg-muted">{description}</p> : null}
      </div>
      {actions ? <div className="flex flex-wrap gap-2">{actions}</div> : null}
    </div>
  );
}

export const Input = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(({ className, ...props }, ref) => (
  <input
    ref={ref}
    className={cn(
      "min-h-10 w-full rounded-md border border-input-border bg-surface px-3 py-2 text-sm text-fg placeholder:text-fg-muted aria-[invalid=true]:border-danger",
      className,
    )}
    {...props}
  />
));
Input.displayName = "Input";

export const Textarea = React.forwardRef<HTMLTextAreaElement, React.TextareaHTMLAttributes<HTMLTextAreaElement>>(({ className, ...props }, ref) => (
  <textarea ref={ref} className={cn("min-h-24 w-full rounded-md border border-input-border bg-surface px-3 py-2 font-mono text-sm text-fg", className)} {...props} />
));
Textarea.displayName = "Textarea";

export const Select = React.forwardRef<HTMLSelectElement, React.SelectHTMLAttributes<HTMLSelectElement>>(({ className, ...props }, ref) => (
  <select ref={ref} className={cn("min-h-10 w-full rounded-md border border-input-border bg-surface px-3 py-2 text-sm text-fg", className)} {...props} />
));
Select.displayName = "Select";

export function Label({ className, ...props }: React.ComponentProps<typeof LabelPrimitive.Root>) {
  return <LabelPrimitive.Root className={cn("mb-1.5 block text-sm font-medium text-fg", className)} {...props} />;
}

export function Field({ id, label, hint, error, children }: { id: string; label: string; hint?: string; error?: string | null; children: React.ReactElement<{ "aria-describedby"?: string; "aria-invalid"?: boolean; id?: string }> }) {
  const describedBy = [hint ? `${id}-hint` : null, error ? `${id}-error` : null].filter(Boolean).join(" ") || undefined;
  return (
    <div>
      <Label htmlFor={id}>{label}</Label>
      {React.cloneElement(children, { id, "aria-describedby": describedBy, "aria-invalid": error ? true : undefined })}
      {hint ? (
        <p id={`${id}-hint`} className="mt-1 text-xs text-fg-muted">
          {hint}
        </p>
      ) : null}
      {error ? (
        <p id={`${id}-error`} className="mt-1 text-sm text-danger">
          {error}
        </p>
      ) : null}
    </div>
  );
}

const TONES = {
  neutral: "border-border text-fg",
  info: "border-info text-info",
  success: "border-success text-success",
  danger: "border-danger text-danger",
  warning: "border-warning text-warning",
  muted: "border-border text-fg-muted",
} as const;

export type Tone = keyof typeof TONES;

export function Badge({ tone = "neutral", children, className }: { tone?: Tone; children: React.ReactNode; className?: string }) {
  return <span className={cn("inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium", TONES[tone], className)}>{children}</span>;
}

export function Alert({ tone = "danger", title, children }: { tone?: Tone; title: string; children?: React.ReactNode }) {
  return (
    <div role={tone === "danger" ? "alert" : "status"} className={cn("rounded-md border bg-surface p-4 text-sm", TONES[tone])}>
      <p className="font-semibold">{title}</p>
      {children ? <div className="mt-1 text-fg">{children}</div> : null}
    </div>
  );
}

export function Table({ caption, children }: { caption: string; children: React.ReactNode }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-left text-sm">
        <caption className="sr-only">{caption}</caption>
        {children}
      </table>
    </div>
  );
}

export function Th({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <th scope="col" className={cn("border-b border-border px-3 py-2 font-medium text-fg-muted", className)}>
      {children}
    </th>
  );
}

export function Td({ children, className }: { children: React.ReactNode; className?: string }) {
  return <td className={cn("border-b border-border px-3 py-2 align-top text-fg", className)}>{children}</td>;
}

export function Mono({ children }: { children: React.ReactNode }) {
  return <code className="rounded bg-surface-muted px-1 py-0.5 font-mono text-xs text-fg">{children}</code>;
}
