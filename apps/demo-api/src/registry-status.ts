export type WorkingRegistryStatus = "WORKING" | "PAUSED" | "UNAVAILABLE";

export interface RegistryConfigReader {
  getRegistryConfig(address: string): Promise<{ paused: boolean } | null>;
}

/**
 * The on-chain pause flag is the single lifecycle signal used by the MVP.
 * QR issuance and consumption must fail closed when the registry is paused or
 * its status cannot be read.
 */
export async function workingRegistryStatus(
  reader: RegistryConfigReader,
  configAddress: string,
): Promise<WorkingRegistryStatus> {
  try {
    const config = await reader.getRegistryConfig(configAddress);
    if (config === null || typeof config.paused !== "boolean") return "UNAVAILABLE";
    return config.paused ? "PAUSED" : "WORKING";
  } catch {
    return "UNAVAILABLE";
  }
}
