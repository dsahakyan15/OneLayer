// OL-A-04 — large PDA allocation spike.
//
// Вопрос: выделяется ли PDA размером 20 840 байт прямым `init` через CPI к
// system program, или прирост данных за инструкцию ограничен 10 240 байтами.
// Ответ определяет схему ledger (§8.2 плана): A, B или C.
//
// Тест не «проверяет корректность» — он **измеряет** поведение runtime и
// печатает результат. Ассерты стоят только там, где поведение уже известно
// и его нарушение означало бы ошибку в самом spike.

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { assert } from "chai";

const ENTRY_SIZE = 216;
const HEADER_SIZE = 96;
const DISCRIMINATOR = 8;
const MAX_PERMITTED_DATA_INCREASE = 10 * 1024;

const ledgerSize = (capacity: number) =>
  DISCRIMINATOR + HEADER_SIZE + capacity * ENTRY_SIZE;

// seed совпадает с `capacity.to_le_bytes()` в программе.
const u32le = (n: number) => {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n);
  return b;
};

const CASES = [
  // Граница: 104 + 216·46 = 10 040 <= 10 240 < 10 256 = 104 + 216·47.
  { name: "граница снизу", capacity: 46 },
  { name: "граница сверху", capacity: 47 },
  { name: "C: полудневной ledger", capacity: 48 },
  { name: "A: дневной ledger", capacity: 96 },
  { name: "A+: дневной с запасом на backlog", capacity: 192 },
];

describe("OL-A-04: выделение PDA больше 10 КБ", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.allocSpike as Program;

  const results: Record<string, string> = {};

  after(() => {
    console.log("\n=== OL-A-04: сводка ===");
    for (const [k, v] of Object.entries(results)) {
      console.log(`  ${k}: ${v}`);
    }
  });

  for (const { name, capacity } of CASES) {
    it(`прямой init: ${name} (capacity=${capacity}, ${ledgerSize(capacity)} байт)`, async () => {
      const space = ledgerSize(capacity);
      const [pda] = anchor.web3.PublicKey.findProgramAddressSync(
        [Buffer.from("ledger"), u32le(capacity)],
        program.programId,
      );

      const label = `init_direct capacity=${capacity} (${space} б)`;
      try {
        const sig = await program.methods
          .initDirect(capacity)
          .accounts({
            ledger: pda,
            payer: provider.wallet.publicKey,
            systemProgram: anchor.web3.SystemProgram.programId,
          })
          .rpc();

        const info = await provider.connection.getAccountInfo(pda);
        assert.isNotNull(info, "аккаунт создан, но не читается");
        assert.equal(
          info!.data.length,
          space,
          "фактический размер данных не совпал с запрошенным",
        );

        const rentSol =
          info!.lamports / anchor.web3.LAMPORTS_PER_SOL;
        results[label] =
          `УСПЕХ, data=${info!.data.length} б, rent-exempt=${rentSol.toFixed(4)} SOL, sig=${sig.slice(0, 12)}…`;
      } catch (e: any) {
        const logs: string[] = e?.logs ?? [];
        results[label] =
          `ОТКАЗ: ${e?.message?.split("\n")[0] ?? e}` +
          (logs.length ? ` | ${logs[logs.length - 1]}` : "");
        // Отказ — валидный результат spike, а не провал теста.
      }
    });
  }

  it("вариант B: init 10 240 байт + доращивание до 20 840", async () => {
    const capacity = 96;
    const target = ledgerSize(capacity);
    const [pda] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("grown"), u32le(capacity)],
      program.programId,
    );

    await program.methods
      .initSmall(capacity)
      .accounts({
        ledger: pda,
        payer: provider.wallet.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    let info = await provider.connection.getAccountInfo(pda);
    assert.equal(info!.data.length, MAX_PERMITTED_DATA_INCREASE);

    const sizes: number[] = [info!.data.length];
    let steps = 0;
    while (info!.data.length < target) {
      await program.methods
        .grow(target)
        .accounts({
          ledger: pda,
          payer: provider.wallet.publicKey,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .rpc();
      info = await provider.connection.getAccountInfo(pda);
      sizes.push(info!.data.length);
      steps += 1;
      assert.isBelow(steps, 10, "рост не сходится");
    }

    assert.equal(info!.data.length, target);
    results[`вариант B (init 10240 + grow → ${target} б)`] =
      `УСПЕХ за ${steps} вызовов grow, путь: ${sizes.join(" → ")}`;
  });

  it("grow не уменьшает аккаунт", async () => {
    const capacity = 96;
    const [pda] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("grown"), u32le(capacity)],
      program.programId,
    );
    try {
      await program.methods
        .grow(1024)
        .accounts({
          ledger: pda,
          payer: provider.wallet.publicKey,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .rpc();
      assert.fail("уменьшение должно отклоняться");
    } catch (e: any) {
      assert.include(String(e), "ShrinkNotAllowed");
    }
  });
});
