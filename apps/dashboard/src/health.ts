export type BackendStatus = "checking" | "online" | "offline";

export async function checkBackend(signal: AbortSignal): Promise<BackendStatus> {
  try {
    const response = await fetch("/api/health", { signal });
    if (!response.ok) return "offline";
    const data: unknown = await response.json();
    return typeof data === "object" &&
      data !== null &&
      "status" in data &&
      data.status === "ok" &&
      "mode" in data &&
      data.mode === "scaffold"
      ? "online"
      : "offline";
  } catch {
    return "offline";
  }
}
