/**
 * The registry program keys ledger segments by `day_utc` encoded as the UTC
 * calendar date YYYYMMDD (see `utc_day` in onchain/programs/onelayer-registry).
 * It is not a count of days since the Unix epoch.
 */
export function ledgerDay(now: Date): number {
  const time = now.getTime();
  if (!Number.isFinite(time)) throw new RangeError("invalid ledger date");
  return now.getUTCFullYear() * 10_000 + (now.getUTCMonth() + 1) * 100 + now.getUTCDate();
}
