#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;
use sha2::{Digest, Sha256};

declare_id!("6A2LSwaJKdwVAEggAfHjZVAKb2ATWM7AXBrgDEqczEo");

pub const ACCOUNT_VERSION_V1: u8 = 1;
pub const LEDGER_CAPACITY: usize = 46;
pub const ENTRY_SIZE: usize = 216;
pub const SEGMENT_HEADER_SIZE: usize = 96;
pub const SEGMENT_ACCOUNT_SIZE: usize = 8 + SEGMENT_HEADER_SIZE + LEDGER_CAPACITY * ENTRY_SIZE;

pub const PERM_PUBLISH_ANCHOR: u32 = 1 << 0;
pub const PERM_CREATE_LEDGER: u32 = 1 << 1;
pub const PERM_SEAL_LEDGER: u32 = 1 << 2;
pub const PERM_REPORT_INCIDENT: u32 = 1 << 3;

const DOMAIN_ANCHOR: &[u8] = b"ONELAYER:ANCHOR:V1";
const DOMAIN_GENESIS: &[u8] = b"ONELAYER:GENESIS:V1";
const DOMAIN_DAY_ENTRIES: &[u8] = b"ONELAYER:DAYENTRIES:V1";

pub const INCIDENT_OPEN: u8 = 1;
pub const INCIDENT_CONFIRMED: u8 = 2;
pub const INCIDENT_FALSE_POSITIVE: u8 = 3;
pub const INCIDENT_RESOLVED: u8 = 4;

#[program]
pub mod onelayer_registry {
    use super::*;

    pub fn initialize_registry(
        ctx: Context<InitializeRegistry>,
        args: InitializeRegistryArgs,
    ) -> Result<()> {
        require!(
            args.max_entries_per_day > 0,
            RegistryError::InvalidLedgerCapacity
        );
        let now = Clock::get()?.unix_timestamp;
        let config = &mut ctx.accounts.config;
        config.version = ACCOUNT_VERSION_V1;
        config.bump = ctx.bumps.config;
        config.registry_id_hash = args.registry_id_hash;
        config.governance_authority = ctx.accounts.governance.key();
        config.emergency_authority = args.emergency_authority;
        config.current_batch_sequence = 0;
        config.current_registry_version = 0;
        config.last_anchor_hash = genesis_anchor_hash(&args.registry_id_hash);
        config.incident_count = 0;
        config.schema_version = args.schema_version;
        config.hash_algorithm = args.hash_algorithm;
        config.tree_algorithm = args.tree_algorithm;
        config.anchor_interval_seconds = args.anchor_interval_seconds;
        config.max_entries_per_day = args.max_entries_per_day;
        config.paused = false;
        config.created_at = now;
        config.reserved = [0; 96];
        emit!(RegistryInitialized {
            registry: config.key(),
            registry_id_hash: config.registry_id_hash,
            governance: config.governance_authority,
            emergency: config.emergency_authority,
        });
        Ok(())
    }

    pub fn grant_operator(ctx: Context<GrantOperator>, args: GrantOperatorArgs) -> Result<()> {
        require!(args.permissions != 0, RegistryError::MissingPermission);
        require!(
            args.valid_until == 0 || args.valid_until >= args.valid_from,
            RegistryError::OperatorInactive
        );
        let role = &mut ctx.accounts.role;
        role.version = ACCOUNT_VERSION_V1;
        role.bump = ctx.bumps.role;
        role.registry = ctx.accounts.config.key();
        role.operator = ctx.accounts.operator.key();
        role.permissions = args.permissions;
        role.valid_from = args.valid_from;
        role.valid_until = args.valid_until;
        role.revoked_at = 0;
        role.key_id_hash = args.key_id_hash;
        role.reserved = [0; 32];
        emit!(OperatorGranted {
            registry: role.registry,
            operator: role.operator,
            permissions: role.permissions,
            valid_from: role.valid_from,
            valid_until: role.valid_until,
        });
        Ok(())
    }

    pub fn revoke_operator(ctx: Context<RevokeOperator>) -> Result<()> {
        let role = &mut ctx.accounts.role;
        require_keys_eq!(
            role.registry,
            ctx.accounts.config.key(),
            RegistryError::OperatorMismatch
        );
        require!(role.revoked_at == 0, RegistryError::OperatorInactive);
        role.revoked_at = Clock::get()?.unix_timestamp;
        emit!(OperatorRevoked {
            registry: role.registry,
            operator: role.operator,
            revoked_at: role.revoked_at,
        });
        Ok(())
    }

    pub fn create_ledger_segment(
        ctx: Context<CreateLedgerSegment>,
        args: CreateLedgerSegmentArgs,
    ) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        validate_role(
            &ctx.accounts.config,
            &ctx.accounts.role,
            &ctx.accounts.operator.key(),
            PERM_CREATE_LEDGER,
            now,
        )?;
        require!(!ctx.accounts.config.paused, RegistryError::RegistryPaused);
        require!(
            args.capacity as usize == LEDGER_CAPACITY,
            RegistryError::InvalidLedgerCapacity
        );
        require!(args.day_utc == utc_day(now)?, RegistryError::WrongLedgerDay);

        match (args.segment_index, &ctx.accounts.previous_segment) {
            (0, None) => {}
            (0, Some(_)) | (_, None) => return err!(RegistryError::BadSegmentIndex),
            (index, Some(previous)) => {
                let expected_previous = Pubkey::find_program_address(
                    &[
                        b"ledger",
                        ctx.accounts.config.key().as_ref(),
                        &args.day_utc.to_be_bytes(),
                        &(index - 1).to_le_bytes(),
                    ],
                    ctx.program_id,
                )
                .0;
                require_keys_eq!(expected_previous, previous.key(), RegistryError::SegmentGap);
                let previous = previous.load()?;
                require_keys_eq!(
                    previous.registry,
                    ctx.accounts.config.key(),
                    RegistryError::LedgerRegistryMismatch
                );
                require!(
                    previous.day_utc == args.day_utc,
                    RegistryError::WrongLedgerDay
                );
                require!(
                    previous.segment_index.checked_add(1) == Some(index),
                    RegistryError::BadSegmentIndex
                );
                require!(
                    previous.entry_count == previous.capacity,
                    RegistryError::BadSegmentIndex
                );
            }
        }

        let mut segment = ctx.accounts.segment.load_init()?;
        segment.version = ACCOUNT_VERSION_V1;
        segment.bump = ctx.bumps.segment;
        segment.sealed = 0;
        segment._pad0 = 0;
        segment.registry = ctx.accounts.config.key();
        segment.day_utc = args.day_utc;
        segment.segment_index = args.segment_index;
        segment.entry_count = 0;
        segment.capacity = LEDGER_CAPACITY as u16;
        segment._pad1 = [0; 2];
        segment.created_at = now;
        segment.sealed_at = 0;
        segment.entries_hash = [0; 32];
        emit!(LedgerSegmentCreated {
            registry: segment.registry,
            day_utc: segment.day_utc,
            segment_index: segment.segment_index,
            capacity: segment.capacity,
        });
        Ok(())
    }

    pub fn publish_anchor(ctx: Context<PublishAnchor>, input: AnchorEntryInputV1) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let config = &mut ctx.accounts.config;
        validate_role(
            config,
            &ctx.accounts.role,
            &ctx.accounts.operator.key(),
            PERM_PUBLISH_ANCHOR,
            now,
        )?;
        require!(!config.paused, RegistryError::RegistryPaused);
        require!(
            input.batch_sequence
                == config
                    .current_batch_sequence
                    .checked_add(1)
                    .ok_or(RegistryError::BadSequence)?,
            RegistryError::BadSequence
        );
        require!(
            input.registry_version >= config.current_registry_version,
            RegistryError::RegistryVersionRollback
        );
        require!(
            input.source_cursor_start <= input.source_cursor_end,
            RegistryError::InvalidCursorRange
        );
        require!(
            input.previous_anchor_hash == config.last_anchor_hash,
            RegistryError::BrokenAnchorChain
        );
        require!(
            input.schema_version == config.schema_version,
            RegistryError::SchemaMismatch
        );
        require!(
            input.hash_algorithm == config.hash_algorithm,
            RegistryError::HashAlgorithmMismatch
        );
        require!(
            input.tree_algorithm == config.tree_algorithm,
            RegistryError::TreeAlgorithmMismatch
        );
        require!(input.leaf_count > 0, RegistryError::EmptyBatch);

        let mut segment = ctx.accounts.segment.load_mut()?;
        let expected_segment = Pubkey::find_program_address(
            &[
                b"ledger",
                config.key().as_ref(),
                &segment.day_utc.to_be_bytes(),
                &segment.segment_index.to_le_bytes(),
            ],
            ctx.program_id,
        )
        .0;
        require_keys_eq!(
            expected_segment,
            ctx.accounts.segment.key(),
            RegistryError::SegmentGap
        );
        require_keys_eq!(
            segment.registry,
            config.key(),
            RegistryError::LedgerRegistryMismatch
        );
        require!(
            segment.day_utc == utc_day(now)?,
            RegistryError::WrongLedgerDay
        );
        require!(segment.sealed == 0, RegistryError::LedgerSealed);
        require!(
            segment.capacity as usize == LEDGER_CAPACITY,
            RegistryError::InvalidLedgerCapacity
        );
        require!(
            segment.entry_count < segment.capacity,
            RegistryError::LedgerFull
        );

        let entry_index = segment.entry_count;
        let entry = input.into_entry(ctx.accounts.operator.key(), now);
        let new_anchor_hash = anchor_hash(&config.registry_id_hash, &entry);
        segment.entries[entry_index as usize] = entry;
        segment.entry_count = entry_index + 1;
        config.current_batch_sequence = input.batch_sequence;
        config.current_registry_version = input.registry_version;
        config.last_anchor_hash = new_anchor_hash;
        emit!(AnchorPublished {
            registry: config.key(),
            batch_sequence: input.batch_sequence,
            segment_index: segment.segment_index,
            entry_index,
            anchor_hash: new_anchor_hash,
            manifest_hash: input.manifest_hash,
        });
        Ok(())
    }

    pub fn seal_daily_ledger(ctx: Context<SealDailyLedger>, day_utc: u32) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        validate_role(
            &ctx.accounts.config,
            &ctx.accounts.role,
            &ctx.accounts.operator.key(),
            PERM_SEAL_LEDGER,
            now,
        )?;
        require!(
            !ctx.remaining_accounts.is_empty(),
            RegistryError::EmptyLedgerDay
        );

        let mut owned_entries: Vec<(u16, Vec<AnchorEntryV1>)> =
            Vec::with_capacity(ctx.remaining_accounts.len());
        let mut total_entries = 0usize;
        for (expected_index, account_info) in ctx.remaining_accounts.iter().enumerate() {
            let expected_pda = Pubkey::find_program_address(
                &[
                    b"ledger",
                    ctx.accounts.config.key().as_ref(),
                    &day_utc.to_be_bytes(),
                    &(expected_index as u16).to_le_bytes(),
                ],
                ctx.program_id,
            )
            .0;
            require_keys_eq!(expected_pda, account_info.key(), RegistryError::SegmentGap);
            let loader = AccountLoader::<DailyAnchorLedgerSegment>::try_from(account_info)?;
            let segment = loader.load()?;
            require_keys_eq!(
                segment.registry,
                ctx.accounts.config.key(),
                RegistryError::LedgerRegistryMismatch
            );
            require!(segment.day_utc == day_utc, RegistryError::WrongLedgerDay);
            require!(
                segment.segment_index as usize == expected_index,
                RegistryError::SegmentGap
            );
            require!(segment.sealed == 0, RegistryError::LedgerSealed);
            let entries = segment.entries[..segment.entry_count as usize].to_vec();
            total_entries += entries.len();
            owned_entries.push((segment.segment_index, entries));
        }
        require!(total_entries > 0, RegistryError::EmptyLedgerDay);
        let borrowed: Vec<(u16, &[AnchorEntryV1])> = owned_entries
            .iter()
            .map(|(index, entries)| (*index, entries.as_slice()))
            .collect();
        let entries_hash = day_entries_hash(
            &ctx.accounts.config.key(),
            day_utc,
            &borrowed,
            &ctx.accounts.config.registry_id_hash,
        );
        for account_info in ctx.remaining_accounts {
            let loader = AccountLoader::<DailyAnchorLedgerSegment>::try_from(account_info)?;
            let mut segment = loader.load_mut()?;
            segment.sealed = 1;
            segment.sealed_at = now;
            segment.entries_hash = entries_hash;
        }
        emit!(DailyLedgerSealed {
            registry: ctx.accounts.config.key(),
            day_utc,
            segment_count: ctx.remaining_accounts.len() as u16,
            entries_hash,
        });
        Ok(())
    }

    pub fn pause_registry(ctx: Context<PauseRegistry>) -> Result<()> {
        require!(!ctx.accounts.config.paused, RegistryError::RegistryPaused);
        ctx.accounts.config.paused = true;
        emit!(RegistryPaused {
            registry: ctx.accounts.config.key(),
            authority: ctx.accounts.emergency_authority.key(),
            occurred_at: Clock::get()?.unix_timestamp,
        });
        Ok(())
    }

    pub fn resume_registry(ctx: Context<ResumeRegistry>) -> Result<()> {
        require!(ctx.accounts.config.paused, RegistryError::RegistryNotPaused);
        ctx.accounts.config.paused = false;
        emit!(RegistryResumed {
            registry: ctx.accounts.config.key(),
            authority: ctx.accounts.governance_authority.key(),
            occurred_at: Clock::get()?.unix_timestamp,
        });
        Ok(())
    }

    pub fn open_incident(ctx: Context<OpenIncident>, args: OpenIncidentArgs) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        validate_role(
            &ctx.accounts.config,
            &ctx.accounts.role,
            &ctx.accounts.operator.key(),
            PERM_REPORT_INCIDENT,
            now,
        )?;
        require!(
            args.first_suspect_batch <= args.last_suspect_batch,
            RegistryError::InvalidIncidentRange
        );
        let sequence = ctx.accounts.config.incident_count;
        let incident = &mut ctx.accounts.incident;
        incident.version = ACCOUNT_VERSION_V1;
        incident.bump = ctx.bumps.incident;
        incident.registry = ctx.accounts.config.key();
        incident.incident_sequence = sequence;
        incident.first_suspect_batch = args.first_suspect_batch;
        incident.last_suspect_batch = args.last_suspect_batch;
        incident.incident_type = args.incident_type;
        incident.status = INCIDENT_OPEN;
        incident.evidence_manifest_hash = args.evidence_manifest_hash;
        incident.opened_by = ctx.accounts.operator.key();
        incident.opened_at = now;
        incident.resolved_at = 0;
        incident.resolution_hash = [0; 32];
        ctx.accounts.config.incident_count =
            sequence.checked_add(1).ok_or(RegistryError::BadSequence)?;
        emit!(IncidentOpened {
            registry: incident.registry,
            incident_sequence: sequence,
            first_suspect_batch: incident.first_suspect_batch,
            last_suspect_batch: incident.last_suspect_batch,
            incident_type: incident.incident_type,
            evidence_manifest_hash: incident.evidence_manifest_hash,
        });
        Ok(())
    }

    pub fn resolve_incident(
        ctx: Context<ResolveIncident>,
        status: u8,
        resolution_hash: [u8; 32],
    ) -> Result<()> {
        require!(
            matches!(
                status,
                INCIDENT_CONFIRMED | INCIDENT_FALSE_POSITIVE | INCIDENT_RESOLVED
            ),
            RegistryError::InvalidIncidentStatus
        );
        let incident = &mut ctx.accounts.incident;
        require!(
            incident.status == INCIDENT_OPEN,
            RegistryError::IncidentAlreadyResolved
        );
        require_keys_eq!(
            incident.registry,
            ctx.accounts.config.key(),
            RegistryError::LedgerRegistryMismatch
        );
        incident.status = status;
        incident.resolution_hash = resolution_hash;
        incident.resolved_at = Clock::get()?.unix_timestamp;
        emit!(IncidentResolved {
            registry: incident.registry,
            incident_sequence: incident.incident_sequence,
            status,
            resolution_hash,
        });
        Ok(())
    }

    pub fn transition_algorithm(
        ctx: Context<TransitionAlgorithm>,
        args: TransitionAlgorithmArgs,
    ) -> Result<()> {
        let config = &mut ctx.accounts.config;
        require!(config.paused, RegistryError::RegistryNotPaused);
        require!(
            valid_algorithm_transition(
                config.schema_version,
                config.hash_algorithm,
                config.tree_algorithm,
                &args,
            ),
            RegistryError::InvalidAlgorithmTransition
        );
        let previous_schema_version = config.schema_version;
        let previous_hash_algorithm = config.hash_algorithm;
        let previous_tree_algorithm = config.tree_algorithm;
        config.schema_version = args.schema_version;
        config.hash_algorithm = args.hash_algorithm;
        config.tree_algorithm = args.tree_algorithm;
        emit!(AlgorithmTransitioned {
            registry: config.key(),
            previous_schema_version,
            new_schema_version: config.schema_version,
            previous_hash_algorithm,
            new_hash_algorithm: config.hash_algorithm,
            previous_tree_algorithm,
            new_tree_algorithm: config.tree_algorithm,
        });
        Ok(())
    }

    pub fn rotate_governance(ctx: Context<RotateGovernance>) -> Result<()> {
        let config = &mut ctx.accounts.config;
        let previous_governance = config.governance_authority;
        let new_governance = ctx.accounts.new_governance_authority.key();
        require_keys_neq!(
            previous_governance,
            new_governance,
            RegistryError::InvalidGovernanceAuthority
        );
        config.governance_authority = new_governance;
        emit!(GovernanceRotated {
            registry: config.key(),
            previous_governance,
            new_governance,
        });
        Ok(())
    }
}

#[account]
#[derive(InitSpace)]
pub struct RegistryConfig {
    pub version: u8,
    pub bump: u8,
    pub registry_id_hash: [u8; 32],
    pub governance_authority: Pubkey,
    pub emergency_authority: Pubkey,
    pub current_batch_sequence: u64,
    pub current_registry_version: u64,
    pub last_anchor_hash: [u8; 32],
    pub incident_count: u64,
    pub schema_version: u16,
    pub hash_algorithm: u8,
    pub tree_algorithm: u8,
    pub anchor_interval_seconds: u32,
    pub max_entries_per_day: u16,
    pub paused: bool,
    pub created_at: i64,
    pub reserved: [u8; 96],
}

#[account]
#[derive(InitSpace)]
pub struct OperatorRole {
    pub version: u8,
    pub bump: u8,
    pub registry: Pubkey,
    pub operator: Pubkey,
    pub permissions: u32,
    pub valid_from: i64,
    pub valid_until: i64,
    pub revoked_at: i64,
    pub key_id_hash: [u8; 32],
    pub reserved: [u8; 32],
}

impl OperatorRole {
    pub fn is_active(&self, now: i64) -> bool {
        self.revoked_at == 0
            && now >= self.valid_from
            && (self.valid_until == 0 || now <= self.valid_until)
    }

    pub fn has_permission(&self, permission: u32) -> bool {
        self.permissions & permission == permission
    }
}

#[zero_copy]
#[derive(Default)]
pub struct AnchorEntryV1 {
    pub batch_sequence: u64,
    pub registry_version: u64,
    pub source_cursor_start: u64,
    pub source_cursor_end: u64,
    pub merkle_root: [u8; 32],
    pub manifest_hash: [u8; 32],
    pub snapshot_hash: [u8; 32],
    pub previous_anchor_hash: [u8; 32],
    pub leaf_count: u32,
    pub schema_version: u16,
    pub flags: u16,
    pub hash_algorithm: u8,
    pub tree_algorithm: u8,
    pub _pad0: [u8; 6],
    pub operator: Pubkey,
    pub published_at: i64,
}

#[account(zero_copy)]
pub struct DailyAnchorLedgerSegment {
    pub version: u8,
    pub bump: u8,
    pub sealed: u8,
    pub _pad0: u8,
    pub registry: Pubkey,
    pub day_utc: u32,
    pub segment_index: u16,
    pub entry_count: u16,
    pub capacity: u16,
    pub _pad1: [u8; 2],
    pub created_at: i64,
    pub sealed_at: i64,
    pub entries_hash: [u8; 32],
    pub entries: [AnchorEntryV1; LEDGER_CAPACITY],
}

#[account]
#[derive(InitSpace)]
pub struct IncidentNotice {
    pub version: u8,
    pub bump: u8,
    pub registry: Pubkey,
    pub incident_sequence: u64,
    pub first_suspect_batch: u64,
    pub last_suspect_batch: u64,
    pub incident_type: u16,
    pub status: u8,
    pub evidence_manifest_hash: [u8; 32],
    pub opened_by: Pubkey,
    pub opened_at: i64,
    pub resolved_at: i64,
    pub resolution_hash: [u8; 32],
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnchorEntryInputV1 {
    pub batch_sequence: u64,
    pub registry_version: u64,
    pub source_cursor_start: u64,
    pub source_cursor_end: u64,
    pub merkle_root: [u8; 32],
    pub manifest_hash: [u8; 32],
    pub snapshot_hash: [u8; 32],
    pub previous_anchor_hash: [u8; 32],
    pub leaf_count: u32,
    pub schema_version: u16,
    pub flags: u16,
    pub hash_algorithm: u8,
    pub tree_algorithm: u8,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct InitializeRegistryArgs {
    pub registry_id_hash: [u8; 32],
    pub emergency_authority: Pubkey,
    pub schema_version: u16,
    pub hash_algorithm: u8,
    pub tree_algorithm: u8,
    pub anchor_interval_seconds: u32,
    pub max_entries_per_day: u16,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct GrantOperatorArgs {
    pub permissions: u32,
    pub valid_from: i64,
    pub valid_until: i64,
    pub key_id_hash: [u8; 32],
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct CreateLedgerSegmentArgs {
    pub day_utc: u32,
    pub segment_index: u16,
    pub capacity: u16,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct OpenIncidentArgs {
    pub first_suspect_batch: u64,
    pub last_suspect_batch: u64,
    pub incident_type: u16,
    pub evidence_manifest_hash: [u8; 32],
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct TransitionAlgorithmArgs {
    pub schema_version: u16,
    pub hash_algorithm: u8,
    pub tree_algorithm: u8,
}

#[derive(Accounts)]
#[instruction(args: InitializeRegistryArgs)]
pub struct InitializeRegistry<'info> {
    #[account(
        init,
        payer = governance,
        space = 8 + RegistryConfig::INIT_SPACE,
        seeds = [b"registry", args.registry_id_hash.as_ref()],
        bump
    )]
    pub config: Account<'info, RegistryConfig>,
    #[account(mut)]
    pub governance: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct GrantOperator<'info> {
    #[account(
        has_one = governance_authority @ RegistryError::UnauthorizedGovernance
    )]
    pub config: Account<'info, RegistryConfig>,
    #[account(
        init,
        payer = governance_authority,
        space = 8 + OperatorRole::INIT_SPACE,
        seeds = [b"operator", config.key().as_ref(), operator.key().as_ref()],
        bump
    )]
    pub role: Account<'info, OperatorRole>,
    /// CHECK: only the public key is stored in the role PDA.
    pub operator: UncheckedAccount<'info>,
    #[account(mut)]
    pub governance_authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RevokeOperator<'info> {
    #[account(
        has_one = governance_authority @ RegistryError::UnauthorizedGovernance
    )]
    pub config: Account<'info, RegistryConfig>,
    #[account(mut)]
    pub role: Account<'info, OperatorRole>,
    pub governance_authority: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(args: CreateLedgerSegmentArgs)]
pub struct CreateLedgerSegment<'info> {
    pub config: Account<'info, RegistryConfig>,
    #[account(
        constraint = role.registry == config.key() @ RegistryError::OperatorMismatch,
        constraint = role.operator == operator.key() @ RegistryError::OperatorMismatch
    )]
    pub role: Account<'info, OperatorRole>,
    #[account(mut)]
    pub operator: Signer<'info>,
    #[account(
        init,
        payer = operator,
        space = SEGMENT_ACCOUNT_SIZE,
        seeds = [
            b"ledger",
            config.key().as_ref(),
            args.day_utc.to_be_bytes().as_ref(),
            args.segment_index.to_le_bytes().as_ref()
        ],
        bump
    )]
    pub segment: AccountLoader<'info, DailyAnchorLedgerSegment>,
    pub previous_segment: Option<AccountLoader<'info, DailyAnchorLedgerSegment>>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct PublishAnchor<'info> {
    #[account(mut)]
    pub config: Account<'info, RegistryConfig>,
    #[account(
        constraint = role.registry == config.key() @ RegistryError::OperatorMismatch,
        constraint = role.operator == operator.key() @ RegistryError::OperatorMismatch
    )]
    pub role: Account<'info, OperatorRole>,
    pub operator: Signer<'info>,
    #[account(mut)]
    pub segment: AccountLoader<'info, DailyAnchorLedgerSegment>,
}

#[derive(Accounts)]
pub struct SealDailyLedger<'info> {
    pub config: Account<'info, RegistryConfig>,
    #[account(
        constraint = role.registry == config.key() @ RegistryError::OperatorMismatch,
        constraint = role.operator == operator.key() @ RegistryError::OperatorMismatch
    )]
    pub role: Account<'info, OperatorRole>,
    pub operator: Signer<'info>,
}

#[derive(Accounts)]
pub struct PauseRegistry<'info> {
    #[account(
        mut,
        has_one = emergency_authority @ RegistryError::UnauthorizedEmergency
    )]
    pub config: Account<'info, RegistryConfig>,
    pub emergency_authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct ResumeRegistry<'info> {
    #[account(
        mut,
        has_one = governance_authority @ RegistryError::UnauthorizedGovernance
    )]
    pub config: Account<'info, RegistryConfig>,
    pub governance_authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct OpenIncident<'info> {
    #[account(mut)]
    pub config: Account<'info, RegistryConfig>,
    #[account(
        constraint = role.registry == config.key() @ RegistryError::OperatorMismatch,
        constraint = role.operator == operator.key() @ RegistryError::OperatorMismatch
    )]
    pub role: Account<'info, OperatorRole>,
    #[account(mut)]
    pub operator: Signer<'info>,
    #[account(
        init,
        payer = operator,
        space = 8 + IncidentNotice::INIT_SPACE,
        seeds = [b"incident", config.key().as_ref(), config.incident_count.to_be_bytes().as_ref()],
        bump
    )]
    pub incident: Account<'info, IncidentNotice>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ResolveIncident<'info> {
    #[account(
        has_one = governance_authority @ RegistryError::UnauthorizedGovernance
    )]
    pub config: Account<'info, RegistryConfig>,
    #[account(mut)]
    pub incident: Account<'info, IncidentNotice>,
    pub governance_authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct TransitionAlgorithm<'info> {
    #[account(
        mut,
        has_one = governance_authority @ RegistryError::UnauthorizedGovernance
    )]
    pub config: Account<'info, RegistryConfig>,
    pub governance_authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct RotateGovernance<'info> {
    #[account(
        mut,
        has_one = governance_authority @ RegistryError::UnauthorizedGovernance
    )]
    pub config: Account<'info, RegistryConfig>,
    pub governance_authority: Signer<'info>,
    pub new_governance_authority: Signer<'info>,
}

#[event]
pub struct RegistryInitialized {
    pub registry: Pubkey,
    pub registry_id_hash: [u8; 32],
    pub governance: Pubkey,
    pub emergency: Pubkey,
}

#[event]
pub struct OperatorGranted {
    pub registry: Pubkey,
    pub operator: Pubkey,
    pub permissions: u32,
    pub valid_from: i64,
    pub valid_until: i64,
}

#[event]
pub struct OperatorRevoked {
    pub registry: Pubkey,
    pub operator: Pubkey,
    pub revoked_at: i64,
}

#[event]
pub struct LedgerSegmentCreated {
    pub registry: Pubkey,
    pub day_utc: u32,
    pub segment_index: u16,
    pub capacity: u16,
}

#[event]
pub struct AnchorPublished {
    pub registry: Pubkey,
    pub batch_sequence: u64,
    pub segment_index: u16,
    pub entry_index: u16,
    pub anchor_hash: [u8; 32],
    pub manifest_hash: [u8; 32],
}

#[event]
pub struct DailyLedgerSealed {
    pub registry: Pubkey,
    pub day_utc: u32,
    pub segment_count: u16,
    pub entries_hash: [u8; 32],
}

#[event]
pub struct RegistryPaused {
    pub registry: Pubkey,
    pub authority: Pubkey,
    pub occurred_at: i64,
}

#[event]
pub struct RegistryResumed {
    pub registry: Pubkey,
    pub authority: Pubkey,
    pub occurred_at: i64,
}

#[event]
pub struct AlgorithmTransitioned {
    pub registry: Pubkey,
    pub previous_schema_version: u16,
    pub new_schema_version: u16,
    pub previous_hash_algorithm: u8,
    pub new_hash_algorithm: u8,
    pub previous_tree_algorithm: u8,
    pub new_tree_algorithm: u8,
}

#[event]
pub struct GovernanceRotated {
    pub registry: Pubkey,
    pub previous_governance: Pubkey,
    pub new_governance: Pubkey,
}

#[event]
pub struct IncidentOpened {
    pub registry: Pubkey,
    pub incident_sequence: u64,
    pub first_suspect_batch: u64,
    pub last_suspect_batch: u64,
    pub incident_type: u16,
    pub evidence_manifest_hash: [u8; 32],
}

#[event]
pub struct IncidentResolved {
    pub registry: Pubkey,
    pub incident_sequence: u64,
    pub status: u8,
    pub resolution_hash: [u8; 32],
}

impl AnchorEntryInputV1 {
    pub fn into_entry(self, operator: Pubkey, published_at: i64) -> AnchorEntryV1 {
        AnchorEntryV1 {
            batch_sequence: self.batch_sequence,
            registry_version: self.registry_version,
            source_cursor_start: self.source_cursor_start,
            source_cursor_end: self.source_cursor_end,
            merkle_root: self.merkle_root,
            manifest_hash: self.manifest_hash,
            snapshot_hash: self.snapshot_hash,
            previous_anchor_hash: self.previous_anchor_hash,
            leaf_count: self.leaf_count,
            schema_version: self.schema_version,
            flags: self.flags,
            hash_algorithm: self.hash_algorithm,
            tree_algorithm: self.tree_algorithm,
            _pad0: [0; 6],
            operator,
            published_at,
        }
    }
}

fn validate_role(
    config: &Account<RegistryConfig>,
    role: &Account<OperatorRole>,
    operator: &Pubkey,
    permission: u32,
    now: i64,
) -> Result<()> {
    require_keys_eq!(role.registry, config.key(), RegistryError::OperatorMismatch);
    require_keys_eq!(role.operator, *operator, RegistryError::OperatorMismatch);
    require!(role.is_active(now), RegistryError::OperatorInactive);
    require!(
        role.has_permission(permission),
        RegistryError::MissingPermission
    );
    Ok(())
}

fn valid_algorithm_transition(
    current_schema_version: u16,
    current_hash_algorithm: u8,
    current_tree_algorithm: u8,
    next: &TransitionAlgorithmArgs,
) -> bool {
    next.schema_version > current_schema_version
        && next.hash_algorithm != 0
        && next.tree_algorithm != 0
        && (next.hash_algorithm != current_hash_algorithm
            || next.tree_algorithm != current_tree_algorithm)
}

fn utc_day(timestamp: i64) -> Result<u32> {
    let days = timestamp.div_euclid(86_400);
    let shifted = days
        .checked_add(719_468)
        .ok_or(RegistryError::WrongLedgerDay)?;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    let encoded = year
        .checked_mul(10_000)
        .and_then(|value| value.checked_add(month * 100 + day))
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(RegistryError::WrongLedgerDay)?;
    Ok(encoded)
}

#[error_code]
pub enum RegistryError {
    #[msg("UNAUTHORIZED_GOVERNANCE")]
    UnauthorizedGovernance,
    #[msg("UNAUTHORIZED_EMERGENCY")]
    UnauthorizedEmergency,
    #[msg("OPERATOR_MISMATCH")]
    OperatorMismatch,
    #[msg("OPERATOR_INACTIVE")]
    OperatorInactive,
    #[msg("MISSING_PERMISSION")]
    MissingPermission,
    #[msg("REGISTRY_PAUSED")]
    RegistryPaused,
    #[msg("REGISTRY_NOT_PAUSED")]
    RegistryNotPaused,
    #[msg("BAD_SEQUENCE")]
    BadSequence,
    #[msg("REGISTRY_VERSION_ROLLBACK")]
    RegistryVersionRollback,
    #[msg("INVALID_CURSOR_RANGE")]
    InvalidCursorRange,
    #[msg("BROKEN_ANCHOR_CHAIN")]
    BrokenAnchorChain,
    #[msg("SCHEMA_MISMATCH")]
    SchemaMismatch,
    #[msg("HASH_ALGORITHM_MISMATCH")]
    HashAlgorithmMismatch,
    #[msg("TREE_ALGORITHM_MISMATCH")]
    TreeAlgorithmMismatch,
    #[msg("INVALID_LEDGER_CAPACITY")]
    InvalidLedgerCapacity,
    #[msg("BAD_SEGMENT_INDEX")]
    BadSegmentIndex,
    #[msg("WRONG_LEDGER_DAY")]
    WrongLedgerDay,
    #[msg("LEDGER_REGISTRY_MISMATCH")]
    LedgerRegistryMismatch,
    #[msg("LEDGER_SEALED")]
    LedgerSealed,
    #[msg("LEDGER_FULL")]
    LedgerFull,
    #[msg("SEGMENT_GAP")]
    SegmentGap,
    #[msg("EMPTY_LEDGER_DAY")]
    EmptyLedgerDay,
    #[msg("EMPTY_BATCH")]
    EmptyBatch,
    #[msg("INVALID_INCIDENT_RANGE")]
    InvalidIncidentRange,
    #[msg("INCIDENT_ALREADY_RESOLVED")]
    IncidentAlreadyResolved,
    #[msg("INVALID_INCIDENT_STATUS")]
    InvalidIncidentStatus,
    #[msg("INVALID_ALGORITHM_TRANSITION")]
    InvalidAlgorithmTransition,
    #[msg("INVALID_GOVERNANCE_AUTHORITY")]
    InvalidGovernanceAuthority,
}

pub fn genesis_anchor_hash(registry_id_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_GENESIS);
    hasher.update(registry_id_hash);
    hasher.finalize().into()
}

pub fn anchor_hash(registry_id_hash: &[u8; 32], entry: &AnchorEntryV1) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_ANCHOR);
    hasher.update(registry_id_hash);
    hasher.update(entry.batch_sequence.to_be_bytes());
    hasher.update(entry.registry_version.to_be_bytes());
    hasher.update(entry.source_cursor_start.to_be_bytes());
    hasher.update(entry.source_cursor_end.to_be_bytes());
    hasher.update(entry.merkle_root);
    hasher.update(entry.manifest_hash);
    hasher.update(entry.snapshot_hash);
    hasher.update(entry.previous_anchor_hash);
    hasher.update(entry.leaf_count.to_be_bytes());
    hasher.update(entry.schema_version.to_be_bytes());
    hasher.update(entry.flags.to_be_bytes());
    hasher.update([entry.hash_algorithm]);
    hasher.update([entry.tree_algorithm]);
    hasher.update(entry.operator.to_bytes());
    hasher.update(entry.published_at.to_be_bytes());
    hasher.finalize().into()
}

pub fn day_entries_hash(
    registry: &Pubkey,
    day_utc: u32,
    segments: &[(u16, &[AnchorEntryV1])],
    registry_id_hash: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_DAY_ENTRIES);
    hasher.update(registry.to_bytes());
    hasher.update(day_utc.to_be_bytes());
    hasher.update((segments.len() as u16).to_be_bytes());
    for (segment_index, entries) in segments {
        hasher.update(segment_index.to_le_bytes());
        hasher.update((entries.len() as u16).to_be_bytes());
        for entry in *entries {
            hasher.update(anchor_hash(registry_id_hash, entry));
        }
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_zero_copy_sizes_match_adr() {
        assert_eq!(core::mem::size_of::<AnchorEntryV1>(), ENTRY_SIZE);
        assert_eq!(
            core::mem::size_of::<DailyAnchorLedgerSegment>(),
            SEGMENT_HEADER_SIZE + LEDGER_CAPACITY * ENTRY_SIZE
        );
        assert_eq!(SEGMENT_ACCOUNT_SIZE, 10_040);
    }

    #[test]
    fn role_validity_and_permissions_are_bounded() {
        let role = OperatorRole {
            version: 1,
            bump: 1,
            registry: Pubkey::new_unique(),
            operator: Pubkey::new_unique(),
            permissions: PERM_PUBLISH_ANCHOR | PERM_CREATE_LEDGER,
            valid_from: 100,
            valid_until: 200,
            revoked_at: 0,
            key_id_hash: [0; 32],
            reserved: [0; 32],
        };
        assert!(!role.is_active(99));
        assert!(role.is_active(100));
        assert!(role.is_active(200));
        assert!(!role.is_active(201));
        assert!(role.has_permission(PERM_PUBLISH_ANCHOR));
        assert!(!role.has_permission(PERM_REPORT_INCIDENT));
    }

    #[test]
    fn anchor_hash_binds_program_owned_fields() {
        let input = AnchorEntryInputV1 {
            batch_sequence: 1,
            registry_version: 1,
            source_cursor_start: 1,
            source_cursor_end: 10,
            merkle_root: [1; 32],
            manifest_hash: [2; 32],
            snapshot_hash: [0; 32],
            previous_anchor_hash: [3; 32],
            leaf_count: 2,
            schema_version: 1,
            flags: 0,
            hash_algorithm: 1,
            tree_algorithm: 1,
        };
        let first = input.into_entry(Pubkey::new_from_array([4; 32]), 100);
        let second = input.into_entry(Pubkey::new_from_array([5; 32]), 100);
        assert_ne!(
            anchor_hash(&[6; 32], &first),
            anchor_hash(&[6; 32], &second)
        );
    }

    #[test]
    fn day_hash_binds_segment_order() {
        let entry = AnchorEntryInputV1 {
            batch_sequence: 1,
            registry_version: 1,
            source_cursor_start: 1,
            source_cursor_end: 1,
            merkle_root: [1; 32],
            manifest_hash: [2; 32],
            snapshot_hash: [0; 32],
            previous_anchor_hash: [3; 32],
            leaf_count: 1,
            schema_version: 1,
            flags: 0,
            hash_algorithm: 1,
            tree_algorithm: 1,
        }
        .into_entry(Pubkey::new_from_array([4; 32]), 100);
        let registry = Pubkey::new_from_array([5; 32]);
        let first = day_entries_hash(&registry, 20260731, &[(0, &[entry])], &[6; 32]);
        let second = day_entries_hash(&registry, 20260731, &[(1, &[entry])], &[6; 32]);
        assert_ne!(first, second);
    }

    #[test]
    fn algorithm_transition_requires_new_schema_and_algorithm() {
        assert!(valid_algorithm_transition(
            1,
            1,
            1,
            &TransitionAlgorithmArgs {
                schema_version: 2,
                hash_algorithm: 2,
                tree_algorithm: 1,
            }
        ));
        for invalid in [
            TransitionAlgorithmArgs {
                schema_version: 1,
                hash_algorithm: 2,
                tree_algorithm: 1,
            },
            TransitionAlgorithmArgs {
                schema_version: 2,
                hash_algorithm: 1,
                tree_algorithm: 1,
            },
            TransitionAlgorithmArgs {
                schema_version: 2,
                hash_algorithm: 0,
                tree_algorithm: 2,
            },
        ] {
            assert!(!valid_algorithm_transition(1, 1, 1, &invalid));
        }
    }

    #[test]
    fn utc_day_matches_epoch_and_plan_date() {
        assert_eq!(utc_day(0).unwrap(), 19700101);
        assert_eq!(utc_day(1_785_456_000).unwrap(), 20260731);
    }
}
