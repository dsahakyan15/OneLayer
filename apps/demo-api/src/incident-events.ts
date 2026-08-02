// Decoding of finalized `IncidentOpened` / `IncidentResolved` program events.
// The index is built from these events only — the fixture table is a separate,
// clearly marked local source (OL-C-14, §2.3).
import { createHash } from "node:crypto";

export const INCIDENT_OPENED = "IncidentOpened";
export const INCIDENT_RESOLVED = "IncidentResolved";

export interface IncidentOpenedEvent {
  kind: "OPENED";
  registry: Uint8Array;
  incidentSequence: bigint;
  firstSuspectBatch: bigint;
  lastSuspectBatch: bigint;
  incidentType: number;
  evidenceManifestHash: Uint8Array;
}

export interface IncidentResolvedEvent {
  kind: "RESOLVED";
  registry: Uint8Array;
  incidentSequence: bigint;
  status: number;
  resolutionHash: Uint8Array;
}

export type IncidentEvent = IncidentOpenedEvent | IncidentResolvedEvent;

/** Anchor event discriminator: sha256("event:<Name>")[0..8]. */
export function eventDiscriminator(name: string): Uint8Array {
  return new Uint8Array(createHash("sha256").update(`event:${name}`).digest().subarray(0, 8));
}

const OPENED_DISCRIMINATOR = eventDiscriminator(INCIDENT_OPENED);
const RESOLVED_DISCRIMINATOR = eventDiscriminator(INCIDENT_RESOLVED);

function startsWith(data: Uint8Array, prefix: Uint8Array): boolean {
  return data.length >= prefix.length && prefix.every((byte, index) => data[index] === byte);
}

function decodeOpened(data: Uint8Array): IncidentOpenedEvent | null {
  // 8 discriminator + 32 registry + 3×u64 + u16 + 32 evidence hash
  if (data.length !== 8 + 32 + 24 + 2 + 32) return null;
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  return {
    kind: "OPENED",
    registry: data.slice(8, 40),
    incidentSequence: view.getBigUint64(40, true),
    firstSuspectBatch: view.getBigUint64(48, true),
    lastSuspectBatch: view.getBigUint64(56, true),
    incidentType: view.getUint16(64, true),
    evidenceManifestHash: data.slice(66, 98),
  };
}

function decodeResolved(data: Uint8Array): IncidentResolvedEvent | null {
  // 8 discriminator + 32 registry + u64 + u8 + 32 resolution hash
  if (data.length !== 8 + 32 + 8 + 1 + 32) return null;
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  return {
    kind: "RESOLVED",
    registry: data.slice(8, 40),
    incidentSequence: view.getBigUint64(40, true),
    status: data[48],
    resolutionHash: data.slice(49, 81),
  };
}

export function decodeIncidentEvent(data: Uint8Array): IncidentEvent | null {
  if (startsWith(data, OPENED_DISCRIMINATOR)) return decodeOpened(data);
  if (startsWith(data, RESOLVED_DISCRIMINATOR)) return decodeResolved(data);
  return null;
}

/**
 * Extracts incident events emitted by the given registry config account.
 * Log lines that are not base64 `Program data:` payloads, or that decode to
 * other events, are ignored rather than failing the scan.
 */
export function incidentEventsFromLogs(
  logs: readonly string[],
  registryConfig: Uint8Array,
): IncidentEvent[] {
  if (registryConfig.length !== 32) throw new RangeError("registryConfig must be 32 bytes");
  const events: IncidentEvent[] = [];
  for (const line of logs) {
    const payload = /^Program data: ([A-Za-z0-9+/=]+)$/.exec(line)?.[1];
    if (payload === undefined) continue;
    let data: Buffer;
    try {
      data = Buffer.from(payload, "base64");
    } catch {
      continue;
    }
    if (data.toString("base64") !== payload) continue;
    const event = decodeIncidentEvent(new Uint8Array(data));
    if (event === null) continue;
    if (!registryConfig.every((byte, index) => event.registry[index] === byte)) continue;
    events.push(event);
  }
  return events;
}
