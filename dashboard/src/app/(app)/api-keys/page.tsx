import type { Metadata } from "next";

import { ApiKeysView } from "@/views/api-keys";

export const metadata: Metadata = { title: "API keys" };

export default function Page() {
  return <ApiKeysView />;
}
