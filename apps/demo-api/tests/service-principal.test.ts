import test from "node:test";
import assert from "node:assert/strict";
import { auditableRegistryId, carriesHumanSession, carriesServiceBearer, DEFAULT_SERVICE_CREDENTIAL_MAX_TTL_DAYS,
  normalizeServiceScope, parseMaxTtlDays, parseServiceBearer, SERVICE_CREDENTIAL_TTL_CEILING_DAYS, ServiceRequestGate } from "../src/service-principal.ts";

const id = "A".repeat(22), secret = "b".repeat(43);

test("service bearer parsing is exact and never a proof of identity", () => {
  assert.deepEqual(parseServiceBearer(`Bearer olsp_${id}.${secret}`), { credentialId: id, secret });
  for (const header of [undefined, "", `olsp_${id}.${secret}`, `bearer olsp_${id}.${secret}`, `Bearer  olsp_${id}.${secret}`,
    `Bearer olsp_${id}.${secret} `, `Bearer olsp_${id}.${secret}=`, `Bearer olsp_${id}${secret}`, `Bearer olsp_${id.slice(1)}.${secret}`,
    `Bearer ${secret}`, `Bearer olsp_${id}.${secret}, Bearer olsp_${id}.${secret}`]) {
    assert.equal(parseServiceBearer(header), null, String(header));
  }
  // Detection used to refuse service bearers on human routes is deliberately broader than parsing.
  assert.ok(carriesServiceBearer(`Bearer olsp_anything`));
  assert.ok(carriesServiceBearer(` bearer   olsp_x`));
  assert.ok(!carriesServiceBearer("Bearer synthetic-internal-token"));
  assert.ok(!carriesServiceBearer(undefined));
  assert.ok(carriesHumanSession("a=1; onelayer_admin_session=x"));
  assert.ok(!carriesHumanSession("onelayer_admin_session_other=x"));
});

test("service scope is an explicit allowlist without wildcard, extra claims or duplicates", () => {
  assert.deepEqual(normalizeServiceScope({ registryIds: ["b.reg", "a.reg"], actions: ["integrity.reconcile", "artifacts.register"] }),
    { actions: ["artifacts.register", "integrity.reconcile"], registryIds: ["a.reg", "b.reg"] });
  for (const scope of [null, [], {}, { actions: ["artifacts.register"] }, { actions: ["artifacts.register"], registryIds: ["a.reg"], role: "operator" },
    { actions: ["access.manage"], registryIds: ["a.reg"] }, { actions: [], registryIds: ["a.reg"] }, { actions: ["artifacts.register"], registryIds: [] },
    { actions: ["artifacts.register"], registryIds: ["*"] }, { actions: ["artifacts.register"], registryIds: [" a.reg"] },
    { actions: ["artifacts.register"], registryIds: ["a.reg", "a.reg"] }, { actions: ["artifacts.register"], registryIds: [1] }]) {
    assert.throws(() => normalizeServiceScope(scope), TypeError, JSON.stringify(scope));
  }
});

test("internal request gate bounds concurrency and per-credential and global rate before any DB work", () => {
  let now = 0;
  const gate = new ServiceRequestGate({ maxConcurrent: 2, keyBurst: 3, keyPerSecond: 1, globalBurst: 5, globalPerSecond: 2, maxKeys: 2 }, () => now);
  const a1 = gate.enter("a"), a2 = gate.enter("a");
  assert.equal(typeof a1, "function"); assert.equal(typeof a2, "function");
  assert.equal(gate.enter("b"), "BUSY");
  (a1 as () => void)(); (a1 as () => void)(); // release is idempotent
  assert.equal(gate.inFlight, 1);
  (a2 as () => void)();
  const a3 = gate.enter("a") as () => void; a3();
  assert.equal(gate.enter("a"), "RATE_LIMITED"); // burst of 3 used
  const b = gate.enter("b") as () => void; b();
  const c = gate.enter("c") as () => void; c(); // global burst of 5 used; "a" evicted (maxKeys 2)
  assert.equal(gate.enter("d"), "RATE_LIMITED");
  now += 1000; // refill: global +2, key +1
  const again = gate.enter("b"); assert.equal(typeof again, "function"); (again as () => void)();
  assert.equal(gate.inFlight, 0);
});

test("only well-formed registry IDs are auditable", () => {
  assert.equal(auditableRegistryId("gov.registry.land"), "gov.registry.land");
  for (const value of ["gov", "Gov.land", "gov..land", "gov.land ", "*", "", 1, null, "a.".repeat(70) + "b", "gov.land\n", "x'); drop"]) {
    assert.equal(auditableRegistryId(value), null, String(value));
  }
});

test("service credential TTL configuration fails closed at explicit boundaries", () => {
  assert.equal(DEFAULT_SERVICE_CREDENTIAL_MAX_TTL_DAYS, 90);
  assert.equal(SERVICE_CREDENTIAL_TTL_CEILING_DAYS, 366);
  assert.equal(parseMaxTtlDays(undefined), 90);
  assert.equal(parseMaxTtlDays("1"), 1);
  assert.equal(parseMaxTtlDays("90"), 90);
  assert.equal(parseMaxTtlDays("366"), 366);
  for (const raw of ["0", "367", "-1", "1.5", "abc", "", "NaN", "Infinity"]) {
    assert.throws(() => parseMaxTtlDays(raw), TypeError, raw);
  }
});
