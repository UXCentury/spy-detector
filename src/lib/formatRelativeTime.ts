/** Relative time for UI badges (English, compact). */
export function formatRelativeTime(iso: string | null | undefined): string {
  if (!iso) return "Never";
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return "Unknown";
  const sec = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (sec < 45) return "moments ago";
  if (sec < 120) return "about a minute ago";
  if (sec < 3600) return `${Math.floor(sec / 60)} minutes ago`;
  if (sec < 86400) return `${Math.floor(sec / 3600)} hours ago`;
  return `${Math.floor(sec / 86400)} days ago`;
}
