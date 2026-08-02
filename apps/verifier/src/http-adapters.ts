import type {
  IncidentIndex,
  IncidentIndexResponse,
  IncidentNotice,
  LifecycleIndex,
  RecordLifecycle,
} from "./verify.ts";
import type { PublicLookup } from "./server.ts";

async function json(response: Response): Promise<any> {
  if (!response.ok) {
    if (response.status === 404) return null;
    throw new TypeError(`upstream HTTP ${response.status}`);
  }
  return response.json();
}

function unsigned(value: unknown, label: string): bigint {
  if ((typeof value !== "string" && typeof value !== "number") || !/^(?:0|[1-9][0-9]*)$/.test(String(value))) {
    throw new TypeError(`${label} is invalid`);
  }
  return BigInt(value);
}

export class HttpIncidentIndex implements IncidentIndex {
  private readonly baseUrl: string;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl;
  }

  async query(registryId: string, batchSequence: bigint): Promise<IncidentIndexResponse | null> {
    const url = new URL("/v1/incidents", this.baseUrl);
    url.searchParams.set("registryId", registryId);
    url.searchParams.set("batchSequence", batchSequence.toString());
    const body = await json(await fetch(url, { headers: { accept: "application/json" } }));
    if (body === null) return null;
    if (body.registryId !== registryId || !Array.isArray(body.incidents)) throw new TypeError("incident index response is invalid");
    const incidents: IncidentNotice[] = body.incidents.map((incident: any) => {
      if (incident.status !== "OPEN" && incident.status !== "RESOLVED") throw new TypeError("incident status is invalid");
      return {
        firstBatchSequence: unsigned(incident.firstBatchSequence, "firstBatchSequence"),
        lastBatchSequence: unsigned(incident.lastBatchSequence, "lastBatchSequence"),
        status: incident.status,
      };
    });
    return {
      registryId,
      indexedThroughSlot: unsigned(body.indexedThroughSlot, "indexedThroughSlot"),
      incidents,
    };
  }
}

export class HttpLifecycleIndex implements LifecycleIndex {
  private readonly baseUrl: string;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl;
  }

  async query(registryId: string, certificateId: string): Promise<RecordLifecycle | null> {
    const url = new URL(`/v1/certificates/${certificateId}/lifecycle`, this.baseUrl);
    url.searchParams.set("registryId", registryId);
    const body = await json(await fetch(url, { headers: { accept: "application/json" } }));
    if (body === null) return null;
    if (
      body.certificateStatus !== "ACTIVE" &&
      body.certificateStatus !== "SUPERSEDED" &&
      body.certificateStatus !== "REVOKED"
    ) {
      throw new TypeError("certificateStatus is invalid");
    }
    if (typeof body.registryId !== "string") throw new TypeError("registryId is invalid");
    return {
      registryId: body.registryId,
      currentRecordVersion: unsigned(body.currentRecordVersion, "currentRecordVersion"),
      certificateStatus: body.certificateStatus,
    };
  }
}

export class HttpPublicLookup implements PublicLookup {
  private readonly baseUrl: string;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl;
  }

  async getAnchor(batchSequence: bigint): Promise<unknown | null> {
    return json(await fetch(new URL(`/v1/anchors/${batchSequence}`, this.baseUrl), { headers: { accept: "application/json" } }));
  }

  async getCertificateStatus(certificateId: string): Promise<unknown | null> {
    return json(await fetch(new URL(`/v1/certificates/${certificateId}/status`, this.baseUrl), { headers: { accept: "application/json" } }));
  }
}
