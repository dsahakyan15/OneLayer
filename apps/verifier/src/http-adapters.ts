import { assertCertificateId, assertRegistryId, assertUnsigned, validatedBaseUrl, validatedServiceToken } from "./service-auth.ts";
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

/**
 * The verifier's outbound reads carry an optional scoped service bearer. A
 * configured token is sent only to a base origin that `validatedBaseUrl`
 * accepted, `redirect: "error"` stops a 3xx from forwarding the bearer to a
 * redirect target, and a 401/403 stays an error so a failed read never turns
 * into an absent resource. Without a token the request is anonymous, which is
 * the demo default.
 */
async function upstream(base: URL, token: string | undefined, path: string): Promise<any> {
  const headers: Record<string, string> = { accept: "application/json" };
  if (token !== undefined) headers.authorization = `Bearer ${token}`;
  return json(await fetch(new URL(path, base), { headers, redirect: "error" }));
}

export class HttpIncidentIndex implements IncidentIndex {
  private readonly base: URL;
  private readonly token: string | undefined;

  constructor(baseUrl: string, options: { serviceToken?: string } = {}) {
    this.base = validatedBaseUrl(baseUrl, options);
    this.token = options.serviceToken === undefined ? undefined : validatedServiceToken(options.serviceToken);
  }

  async query(registryId: string, batchSequence: bigint): Promise<IncidentIndexResponse | null> {
    assertRegistryId(registryId, this.token !== undefined);
    assertUnsigned(batchSequence.toString(), "batchSequence");
    const url = new URL("/v1/incidents", this.base);
    url.searchParams.set("registryId", registryId);
    url.searchParams.set("batchSequence", batchSequence.toString());
    const body = await upstream(this.base, this.token, url.pathname + url.search);
    if (body === null) return null;
    if (body.registryId !== registryId || !Array.isArray(body.incidents)) throw new TypeError("incident index response is invalid");
    const incidents: IncidentNotice[] = body.incidents.map((incident: any) => {
      if (incident.status !== "OPEN" && incident.status !== "RESOLVED") throw new TypeError("incident status is invalid");
      const resolution = incident.resolutionStatus;
      if (resolution !== undefined && !["OPEN", "CONFIRMED", "FALSE_POSITIVE", "RESOLVED"].includes(resolution)) {
        throw new TypeError("incident resolutionStatus is invalid");
      }
      if (incident.blocking !== undefined && typeof incident.blocking !== "boolean") throw new TypeError("incident blocking is invalid");
      return {
        firstBatchSequence: unsigned(incident.firstBatchSequence, "firstBatchSequence"),
        lastBatchSequence: unsigned(incident.lastBatchSequence, "lastBatchSequence"),
        status: incident.status,
        ...(resolution === undefined ? {} : { resolutionStatus: resolution }),
        ...(incident.blocking === undefined ? {} : { blocking: incident.blocking }),
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
  private readonly base: URL;
  private readonly token: string | undefined;

  constructor(baseUrl: string, options: { serviceToken?: string } = {}) {
    this.base = validatedBaseUrl(baseUrl, options);
    this.token = options.serviceToken === undefined ? undefined : validatedServiceToken(options.serviceToken);
  }

  async query(registryId: string, certificateId: string): Promise<RecordLifecycle | null> {
    assertRegistryId(registryId, this.token !== undefined);
    assertCertificateId(certificateId);
    const url = new URL(`/v1/certificates/${certificateId}/lifecycle`, this.base);
    url.searchParams.set("registryId", registryId);
    const body = await upstream(this.base, this.token, url.pathname + url.search);
    if (body === null) return null;
    if (
      body.certificateStatus !== "ACTIVE" &&
      body.certificateStatus !== "SUPERSEDED" &&
      body.certificateStatus !== "REVOKED"
    ) {
      throw new TypeError("certificateStatus is invalid");
    }
    // The response must describe the resource that was requested: a lifecycle
    // answer for another registry or certificate is not a usable answer for
    // this verification, even if its shape is valid.
    if (body.registryId !== registryId || body.certificateId !== certificateId) {
      throw new TypeError("lifecycle response does not match the requested certificate");
    }
    return {
      registryId,
      certificateId,
      currentRecordVersion: unsigned(body.currentRecordVersion, "currentRecordVersion"),
      certificateStatus: body.certificateStatus,
    };
  }
}

export class HttpPublicLookup implements PublicLookup {
  private readonly base: URL;
  private readonly token: string | undefined;

  constructor(baseUrl: string, options: { serviceToken?: string } = {}) {
    this.base = validatedBaseUrl(baseUrl, options);
    this.token = options.serviceToken === undefined ? undefined : validatedServiceToken(options.serviceToken);
  }

  async getAnchor(batchSequence: bigint): Promise<unknown | null> {
    assertUnsigned(batchSequence.toString(), "batchSequence");
    return upstream(this.base, this.token, `/v1/anchors/${batchSequence}`);
  }

  async getCertificateStatus(certificateId: string): Promise<unknown | null> {
    assertCertificateId(certificateId);
    return upstream(this.base, this.token, `/v1/certificates/${certificateId}/status`);
  }
}
