export type SeverityTier = "low" | "warn" | "high";

export function severityTier(
  score: number,
  warnThreshold: number,
  alertThreshold: number,
): SeverityTier {
  if (score >= alertThreshold) return "high";
  if (score >= warnThreshold) return "warn";
  return "low";
}

export function tierColorVar(tier: SeverityTier): string {
  switch (tier) {
    case "high":
      return "var(--severity-high)";
    case "warn":
      return "var(--severity-warn)";
    default:
      return "var(--severity-low)";
  }
}
