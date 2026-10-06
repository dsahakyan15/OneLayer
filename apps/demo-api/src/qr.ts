export function qrHashHex(value: string | null): string | null {
  if (value === null || !/^[A-Za-z0-9_-]{43}$/.test(value)) return null;
  const decoded = Buffer.from(value, "base64url");
  if (decoded.length !== 32 || decoded.toString("base64url") !== value) return null;
  return decoded.toString("hex");
}
