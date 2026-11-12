import type { Metadata, Viewport } from "next";

import { Providers } from "@/components/providers";
import { THEME_SCRIPT } from "@/components/theme-toggle";

import "./globals.css";

export const metadata: Metadata = {
  title: { default: "CipherCompute", template: "%s · CipherCompute" },
  description: "Compute statistics and model inference on encrypted data. The server never sees a plaintext value.",
  robots: { index: false, follow: false },
};

export const viewport: Viewport = {
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#f8fafc" },
    { media: "(prefers-color-scheme: dark)", color: "#0b1120" },
  ],
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        {/* Applies the saved/system theme before first paint, so there is no flash. */}
        <script dangerouslySetInnerHTML={{ __html: THEME_SCRIPT }} />
      </head>
      <body className="min-h-screen bg-bg text-fg">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
