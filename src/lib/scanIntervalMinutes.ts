/** Allowed periodic scan intervals (minutes), matching stepped UX rules. */
export function buildAllowedScanMinutes(): number[] {
  const s = new Set<number>();
  for (let m = 1; m <= 30; m++) s.add(m);
  for (let m = 35; m <= 120; m += 5) s.add(m);
  for (let m = 150; m <= 1440; m += 30) s.add(m);
  return [...s].sort((a, b) => a - b);
}

export function nearestAllowedMinutes(
  minutes: number,
  allowed: readonly number[],
): number {
  if (allowed.length === 0) return Math.round(minutes);
  let best = allowed[0];
  let bestDiff = Math.abs(best - minutes);
  for (const v of allowed) {
    const d = Math.abs(v - minutes);
    if (d < bestDiff) {
      best = v;
      bestDiff = d;
    }
  }
  return best;
}

export function formatMinutesDuration(minutes: number): string {
  if (minutes === 1440) return "1 day";
  if (minutes < 60) {
    return `${minutes} minute${minutes === 1 ? "" : "s"}`;
  }
  const h = Math.floor(minutes / 60);
  const m = minutes % 60;
  const hourPart = `${h} hour${h === 1 ? "" : "s"}`;
  if (m === 0) return hourPart;
  return `${hourPart} ${m} minute${m === 1 ? "" : "s"}`;
}
