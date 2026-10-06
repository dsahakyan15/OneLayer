import type { SignedCertificate } from "../../../packages/canonical-ts/src/index.ts";
import { verifyCertificate, type ChainReader, type IncidentIndex, type VerifyOptions, type IncidentIndexStatus, type RecordLifecycle } from "./verify.ts";

export type VerificationStatusV2 = "INVALID" | "DISPUTED" | "REVOKED" | "HISTORICAL" | "UNKNOWN";
export type LifecycleCodeV2 = "LIFECYCLE_UNAVAILABLE" | "LIFECYCLE_RESPONSE_INVALID" | "LIFECYCLE_UNAUTHENTICATED";

export interface ReportedLifecycleV2 {
  certificateStatus: RecordLifecycle["certificateStatus"];
  currentRecordVersion: string;
}

/** The wire contract of /v2/verify. No member can assert proven currentness. */
export interface VerificationResultV2 {
  resultVersion: 2;
  status: VerificationStatusV2;
  code: string;
  checkedAt: string;
  certificateId: string;
  recordVersion: string;
  batchSequence: string;
  proofs: { status: "NOT_ESTABLISHED" | "VERIFIED"; anchorSlot?: string };
  registry: { registryId: string; status: "NOT_ESTABLISHED" | "CHECKED" };
  incidents: {
    status: IncidentIndexStatus | "NOT_CHECKED";
    indexedThroughSlot?: string;
    finalizedHeadSlot?: string;
    lagSlots?: string;
  };
  lifecycle: {
    status: "UNAUTHENTICATED" | "UNKNOWN";
    code: LifecycleCodeV2;
    reported?: ReportedLifecycleV2;
  };
  warnings: string[];
  disclosureMode?: SignedCertificate["body"]["disclosureMode"];
  disclosedFields?: Record<string, string | boolean | null>;
}

const MAX_U64 = 0xffff_ffff_ffff_ffffn;

/** V2 deliberately has no CURRENT until a complete, authenticated lifecycle source exists. */
export async function verifyCertificateV2(
  signed: SignedCertificate, chain: ChainReader, incidents: IncidentIndex, options: VerifyOptions = {},
): Promise<VerificationResultV2> {
  const result = await verifyCertificate(signed, chain, incidents, { ...options, lifecycle: undefined });
  let reported: ReportedLifecycleV2 | undefined;
  let lifecycleCode: LifecycleCodeV2 = "LIFECYCLE_UNAVAILABLE";
  if (result.status !== "INVALID" && options.lifecycle) {
    try {
      const value = await options.lifecycle.query(signed.body.registryId, result.certificateId);
      if (value && value.registryId === signed.body.registryId && value.certificateId === result.certificateId
        && typeof value.currentRecordVersion === "bigint" && value.currentRecordVersion >= signed.body.recordVersion
        && value.currentRecordVersion <= MAX_U64
        && ["ACTIVE", "SUPERSEDED", "REVOKED"].includes(value.certificateStatus)) {
        reported = { certificateStatus: value.certificateStatus, currentRecordVersion: value.currentRecordVersion.toString() };
        lifecycleCode = "LIFECYCLE_UNAUTHENTICATED";
      } else if (value) lifecycleCode = "LIFECYCLE_RESPONSE_INVALID";
    } catch { /* Unavailable lifecycle never upgrades the verdict. */ }
  }
  const status: VerificationStatusV2 = result.status === "INVALID" ? "INVALID"
    : result.status === "DISPUTED" ? "DISPUTED"
    : reported?.certificateStatus === "REVOKED" ? "REVOKED"
    : reported && (reported.certificateStatus === "SUPERSEDED" || BigInt(reported.currentRecordVersion) > signed.body.recordVersion)
      ? "HISTORICAL" : "UNKNOWN";
  return {
    resultVersion: 2,
    status,
    code: result.code ?? lifecycleCode,
    checkedAt: new Date().toISOString(),
    certificateId: result.certificateId,
    recordVersion: signed.body.recordVersion.toString(),
    batchSequence: result.batchSequence,
    proofs: { status: result.status === "INVALID" ? "NOT_ESTABLISHED" : "VERIFIED", anchorSlot: result.solanaSlot },
    registry: { registryId: signed.body.registryId, status: result.status === "INVALID" ? "NOT_ESTABLISHED" : "CHECKED" },
    incidents: { status: result.incidentIndexStatus ?? "NOT_CHECKED", indexedThroughSlot: result.indexedThroughSlot,
      finalizedHeadSlot: result.rpcFinalizedHeadSlot, lagSlots: result.indexLagSlots },
    lifecycle: { status: reported ? "UNAUTHENTICATED" : "UNKNOWN", code: lifecycleCode, reported },
    warnings: [...result.warnings, "Current suitability is not proven. Lifecycle reports are advisory until an authenticated complete source is implemented."],
    disclosureMode: result.disclosureMode,
    disclosedFields: result.disclosedFields,
  };
}
