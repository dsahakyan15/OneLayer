//! `OL-A-04` — large PDA allocation spike.
//!
//! Вопрос, на который отвечает spike (§8.2 плана): выделяется ли PDA размером
//! 20 840 байт **прямым** `init` через CPI к system program, или прирост
//! данных аккаунта за инструкцию ограничен 10 240 байтами и требуется
//! доращивание.
//!
//! Результат определяет схему ledger:
//!   A — прямой `init`, capacity 192;
//!   B — `init` 10 240 + доращивание отдельной инструкцией до первого anchor;
//!   C — полудневной ledger, capacity 96.
//!
//! Это spike. Код в продукт не переносится: zero-copy layout здесь
//! намеренно вырожденный, инвариантов `publish_anchor` нет, авторизации нет.

use anchor_lang::prelude::*;

declare_id!("ApAD9vA6UX8F31AYjCE36a3w3iVFR4ujM9Xo2o97PwQj");

/// Размеры из §8.2 плана: entry 216 байт, header 96 + 8 дискриминатор.
pub const ENTRY_SIZE: usize = 216;
pub const HEADER_SIZE: usize = 96;
pub const DISCRIMINATOR: usize = 8;

/// Прирост данных аккаунта за одну инструкцию (Solana runtime).
pub const MAX_PERMITTED_DATA_INCREASE: usize = 10 * 1024;

/// Полный дневной ledger: 96 entries. 20 840 байт.
pub const CAPACITY_FULL_DAY: usize = 96;
/// Полудневной ledger (вариант C): 48 entries. 10 472 байта.
pub const CAPACITY_HALF_DAY: usize = 48;
/// Вариант A с запасом на backlog: 192 entries. 41 576 байт.
pub const CAPACITY_DOUBLE: usize = 192;

pub const fn ledger_size(capacity: usize) -> usize {
    DISCRIMINATOR + HEADER_SIZE + capacity * ENTRY_SIZE
}

#[program]
pub mod alloc_spike {
    use super::*;

    /// Вариант A/C: прямой `init` на полный размер.
    /// Если runtime отвергает CPI create_account с `space > 10240`,
    /// инструкция упадёт здесь — это и есть измеряемый результат.
    pub fn init_direct(ctx: Context<InitDirect>, capacity: u32) -> Result<()> {
        let ledger = &mut ctx.accounts.ledger;
        ledger.capacity = capacity;
        ledger.used = 0;
        ledger.day_utc = 0;
        msg!(
            "init_direct: capacity={} space={}",
            capacity,
            ledger_size(capacity as usize)
        );
        Ok(())
    }

    /// Вариант B, шаг 1: `init` на 10 240 байт.
    pub fn init_small(ctx: Context<InitSmall>, capacity: u32) -> Result<()> {
        let ledger = &mut ctx.accounts.ledger;
        ledger.capacity = capacity;
        ledger.used = 0;
        ledger.day_utc = 0;
        msg!("init_small: space={}", MAX_PERMITTED_DATA_INCREASE);
        Ok(())
    }

    /// Вариант B, шаг 2: доращивание до `target_len`, не более
    /// `MAX_PERMITTED_DATA_INCREASE` за вызов.
    ///
    /// `realloc` в Anchor переносит rent-exempt разницу с плательщика.
    /// Инструкция идемпотентна по достижении цели: повторный вызов на
    /// нужном размере ничего не делает.
    pub fn grow(ctx: Context<Grow>, target_len: u32) -> Result<()> {
        let account = ctx.accounts.ledger.to_account_info();
        let current = account.data_len();
        let target = target_len as usize;

        require!(target >= current, SpikeError::ShrinkNotAllowed);
        if target == current {
            msg!("grow: уже {} байт, роста не требуется", current);
            return Ok(());
        }

        let step = core::cmp::min(target - current, MAX_PERMITTED_DATA_INCREASE);
        let new_len = current + step;

        // Доплата ренты до rent-exempt для нового размера.
        let rent = Rent::get()?;
        let needed = rent.minimum_balance(new_len);
        let have = account.lamports();
        if needed > have {
            let diff = needed - have;
            anchor_lang::system_program::transfer(
                CpiContext::new(
                    ctx.accounts.system_program.key(),
                    anchor_lang::system_program::Transfer {
                        from: ctx.accounts.payer.to_account_info(),
                        to: account.clone(),
                    },
                ),
                diff,
            )?;
        }

        account.resize(new_len)?;
        msg!("grow: {} -> {} (цель {})", current, new_len, target);
        Ok(())
    }
}

/// Вырожденный header: spike измеряет выделение, а не layout.
#[account]
pub struct LedgerHeader {
    pub capacity: u32,
    pub used: u32,
    pub day_utc: i64,
}

#[derive(Accounts)]
#[instruction(capacity: u32)]
pub struct InitDirect<'info> {
    #[account(
        init,
        payer = payer,
        space = DISCRIMINATOR + HEADER_SIZE + (capacity as usize) * ENTRY_SIZE,
        seeds = [b"ledger".as_ref(), capacity.to_le_bytes().as_ref()],
        bump
    )]
    pub ledger: Account<'info, LedgerHeader>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(capacity: u32)]
pub struct InitSmall<'info> {
    #[account(
        init,
        payer = payer,
        space = MAX_PERMITTED_DATA_INCREASE,
        seeds = [b"grown".as_ref(), capacity.to_le_bytes().as_ref()],
        bump
    )]
    pub ledger: Account<'info, LedgerHeader>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Grow<'info> {
    /// CHECK: spike работает с сырой длиной данных; десериализация header-а
    /// для измерения роста не нужна.
    #[account(mut)]
    pub ledger: UncheckedAccount<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[error_code]
pub enum SpikeError {
    #[msg("уменьшение аккаунта в spike не проверяется")]
    ShrinkNotAllowed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_match_plan_section_8_2() {
        assert_eq!(ledger_size(CAPACITY_FULL_DAY), 20_840);
        assert_eq!(ledger_size(CAPACITY_DOUBLE), 41_576);
        assert_eq!(ledger_size(CAPACITY_HALF_DAY), 10_472);
    }

    #[test]
    fn half_day_ledger_exceeds_single_increase_limit() {
        // Даже вариант C больше 10 240: прямой init обязателен и для него.
        assert!(ledger_size(CAPACITY_HALF_DAY) > MAX_PERMITTED_DATA_INCREASE);
    }

    #[test]
    fn growth_steps_needed_for_full_day() {
        let target = ledger_size(CAPACITY_FULL_DAY);
        let mut current = MAX_PERMITTED_DATA_INCREASE;
        let mut steps = 0;
        while current < target {
            current += core::cmp::min(target - current, MAX_PERMITTED_DATA_INCREASE);
            steps += 1;
        }
        // 10240 -> 20480 -> 20840: два вызова grow.
        assert_eq!(steps, 2);
    }
}
