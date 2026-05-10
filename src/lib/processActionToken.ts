/** Matches Rust `confirm_token_hex`: SHA-256 (hex, lowercase) of `PREFIX:pid:exe`. */

export async function sha256HexUtf8(s: string): Promise<string> {
  const data = new TextEncoder().encode(s);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function killConfirmPayload(pid: number, exePath: string | null) {
  return `KILL:${pid}:${exePath ?? ""}`;
}

export function quarantineConfirmPayload(pid: number, exePath: string | null) {
  return `QUARANTINE:${pid}:${exePath ?? ""}`;
}
