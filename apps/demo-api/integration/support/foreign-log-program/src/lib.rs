//! Test-only "foreign" program used by `incident-chain.test.ts`.
//!
//! Instruction data: `[mode, payload...]`
//! - 0: log `payload` with `sol_log_data` (a forged `Program data:` line) and succeed.
//! - 1: log `payload` like mode 0, then fail the transaction.
//! - 2: CPI into `accounts[0]` (the target program) with `payload` as instruction
//!      data and `accounts[1..]` as its accounts, then succeed.
//! - 3: CPI like mode 2, then fail the transaction.
#![allow(unexpected_cfgs)]

use anchor_lang::solana_program::{
    account_info::AccountInfo,
    entrypoint,
    instruction::{AccountMeta, Instruction},
    log::sol_log_data,
    program::invoke,
    program_error::ProgramError,
    pubkey::Pubkey,
};

entrypoint!(process);

fn process(_program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> Result<(), ProgramError> {
    let (&mode, payload) = data.split_first().ok_or(ProgramError::InvalidInstructionData)?;
    match mode {
        0 | 1 => sol_log_data(&[payload]),
        2 | 3 => {
            let (target, forwarded) = accounts.split_first().ok_or(ProgramError::NotEnoughAccountKeys)?;
            let metas = forwarded
                .iter()
                .map(|account| AccountMeta {
                    pubkey: *account.key,
                    is_signer: account.is_signer,
                    is_writable: account.is_writable,
                })
                .collect();
            let instruction = Instruction { program_id: *target.key, accounts: metas, data: payload.to_vec() };
            invoke(&instruction, forwarded)?;
        }
        _ => return Err(ProgramError::InvalidInstructionData),
    }
    if mode % 2 == 1 {
        return Err(ProgramError::Custom(0x0f0f));
    }
    Ok(())
}
