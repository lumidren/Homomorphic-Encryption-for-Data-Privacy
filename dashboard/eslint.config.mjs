import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { FlatCompat } from "@eslint/eslintrc";

const compat = new FlatCompat({ baseDirectory: dirname(fileURLToPath(import.meta.url)) });

const config = [
  ...compat.extends("next/core-web-vitals", "next/typescript"),
  {
    rules: {
      "@typescript-eslint/no-explicit-any": "error",
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_" }],
      "jsx-a11y/no-autofocus": "error",
      "jsx-a11y/anchor-is-valid": "error",
      "no-console": ["error", { allow: ["error"] }],
    },
  },
  { ignores: [".next/**", "node_modules/**", "coverage/**", "next-env.d.ts"] },
];

export default config;
