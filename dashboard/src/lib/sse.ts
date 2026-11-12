/**
 * Server-Sent Events over fetch. EventSource cannot send credentials headers or be aborted
 * cleanly, so the stream is read and parsed directly (text/event-stream framing).
 */

export interface SseMessage {
  event: string;
  data: string;
}

/** Split a growing buffer into complete SSE messages; returns the unconsumed remainder. */
export function parseSse(buffer: string): { messages: SseMessage[]; rest: string } {
  const normalized = buffer.replace(/\r\n/g, "\n");
  const blocks = normalized.split("\n\n");
  const rest = blocks.pop() ?? "";
  const messages: SseMessage[] = [];
  for (const block of blocks) {
    let event = "message";
    const data: string[] = [];
    for (const line of block.split("\n")) {
      if (line.startsWith(":")) continue; // comment / heartbeat
      const colon = line.indexOf(":");
      const field = colon === -1 ? line : line.slice(0, colon);
      const value = colon === -1 ? "" : line.slice(colon + 1).replace(/^ /, "");
      if (field === "event") event = value;
      else if (field === "data") data.push(value);
    }
    if (data.length) messages.push({ event, data: data.join("\n") });
  }
  return { messages, rest };
}

export async function streamEvents(
  url: string,
  onMessage: (message: SseMessage) => void,
  { signal, fetchImpl = fetch }: { signal?: AbortSignal; fetchImpl?: typeof fetch } = {},
): Promise<void> {
  const response = await fetchImpl(url, { headers: { Accept: "text/event-stream" }, credentials: "same-origin", signal });
  if (!response.ok || !response.body) throw new Error(`event stream failed (${response.status})`);
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const { messages, rest } = parseSse(buffer);
    buffer = rest;
    messages.forEach(onMessage);
  }
}
