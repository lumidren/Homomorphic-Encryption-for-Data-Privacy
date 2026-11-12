import { fileURLToPath } from "node:url";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
      // the real package throws outside a React Server Component bundle
      "server-only": fileURLToPath(new URL("./src/test/server-only.ts", import.meta.url)),
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
    coverage: {
      provider: "v8",
      include: ["src/lib/**", "src/components/**"],
      // types.ts is declarations only; queries.ts is thin React Query wiring exercised end to end
      exclude: ["src/lib/types.ts", "src/lib/queries.ts", "src/**/*.test.*"],
      thresholds: { lines: 90, functions: 90, statements: 90, branches: 80 },
    },
  },
});
