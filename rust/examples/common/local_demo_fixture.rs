//! Shared local-validator fixture used by the session demo binaries.
//!
//! Spins up fresh keypairs over a real `solana-test-validator`, creates an
//! SPL mint, materialises the payer and payee ATAs, and pre-funds the payer
//! ATA so the session lifecycle can run end-to-end. The local demo and the
//! HTTP demo both boot the same fixture; the only thing that differs is
//! how server and client talk to each other (in-process calls vs HTTP).

use std::sync::Arc;
use std::time::{Duration, Instant};

use solana_commitment_config::CommitmentConfig;
use solana_hash::Hash;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::Message;
use solana_mpp::program::payment_channels::canonical_tx::pk_to_addr;
use solana_mpp::MppRpcClient;
use solana_pubkey::Pubkey;
use solana_rpc_client::nonblocking::rpc_client::RpcClient as RealRpcClient;
use solana_sdk::signature::Keypair;
use solana_sdk::signer::Signer as _;
use solana_signature::Signature;
use solana_transaction::Transaction;
use payment_channels_client::programs::PAYMENT_CHANNELS_ID;

pub const LAMPORTS_PER_SOL: u64 = 1_000_000_000;
pub const AIRDROP_LAMPORTS: u64 = 10 * LAMPORTS_PER_SOL;
pub const MINT_DECIMALS: u8 = 6;
pub const MINT_INITIAL_AMOUNT: u64 = 50_000_000;
pub const SPL_MINT_LEN: u64 = 82;

// Hand-rolled so the demos stay on solana-pubkey 3.x throughout,
// instead of bridging through the 2.x copies the upstream spl-*
// helpers compile against.
pub const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::from_str_const("11111111111111111111111111111111");
pub const SPL_TOKEN_PROGRAM_ID: Pubkey =
    Pubkey::from_str_const("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
pub const ASSOCIATED_TOKEN_PROGRAM_ID: Pubkey =
    Pubkey::from_str_const("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");

/// Fresh keypairs, mint, and ATA over a real validator. Both the local
/// in-process demo and the HTTP demo boot this exact shape.
#[allow(dead_code)] // payer_ata + raw_rpc are read by the HTTP demo
pub struct LocalDemoFixture {
    pub payer: Keypair,
    pub payee: Keypair,
    pub fee_payer: Keypair,
    pub mint: Pubkey,
    pub payer_ata: Pubkey,
    pub payee_ata: Pubkey,
    pub rpc: Arc<dyn MppRpcClient>,
    pub raw_rpc: Arc<RealRpcClient>,
    pub program_id: Pubkey,
}

impl LocalDemoFixture {
    pub async fn boot(rpc_url: &str) -> Result<Self, Box<dyn std::error::Error>> {
        println!("setting up local fixture (rpc={rpc_url})");
        let raw_rpc = Arc::new(RealRpcClient::new_with_commitment(
            rpc_url.to_string(),
            CommitmentConfig::confirmed(),
        ));
        let rpc: Arc<dyn MppRpcClient> = raw_rpc.clone();

        let payer = Keypair::new();
        let payee = Keypair::new();
        let fee_payer = Keypair::new();

        for (label, kp) in [
            ("payer", &payer),
            ("payee", &payee),
            ("fee_payer", &fee_payer),
        ] {
            airdrop(&raw_rpc, &keypair_pubkey(kp), AIRDROP_LAMPORTS).await?;
            println!("airdropped 10 SOL to {label} {}", kp.pubkey());
        }

        let mint_kp = Keypair::new();
        let mint = keypair_pubkey(&mint_kp);
        create_mint(&raw_rpc, &payer, &mint_kp, MINT_DECIMALS).await?;
        println!("created mint {mint} (decimals {MINT_DECIMALS})");

        let payer_pk = keypair_pubkey(&payer);
        let payee_pk = keypair_pubkey(&payee);
        let payer_ata = ata_address(&payer_pk, &mint, &SPL_TOKEN_PROGRAM_ID);
        let payee_ata = ata_address(&payee_pk, &mint, &SPL_TOKEN_PROGRAM_ID);
        create_ata(&raw_rpc, &payer, &payer_pk, &mint).await?;
        // Pre-create the payee's ATA so the close path's distribute ix
        // lands in one tx without preflight churn.
        create_ata(&raw_rpc, &payer, &payee_pk, &mint).await?;
        mint_to(&raw_rpc, &payer, &mint, &payer_ata, MINT_INITIAL_AMOUNT).await?;
        println!("minted {MINT_INITIAL_AMOUNT} base units to payer ATA {payer_ata}");

        let program_id = Pubkey::new_from_array(PAYMENT_CHANNELS_ID.to_bytes());

        Ok(Self {
            payer,
            payee,
            fee_payer,
            mint,
            payer_ata,
            payee_ata,
            rpc,
            raw_rpc,
            program_id,
        })
    }
}

pub fn keypair_pubkey(kp: &Keypair) -> Pubkey {
    Pubkey::new_from_array(kp.pubkey().to_bytes())
}

// rpc plumbing

pub async fn airdrop(
    rpc: &RealRpcClient,
    pk: &Pubkey,
    lamports: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let sig = rpc.request_airdrop(pk, lamports).await?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if rpc.confirm_transaction(&sig).await? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("timed out waiting for {sig} to confirm").into());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

pub async fn create_mint(
    rpc: &RealRpcClient,
    payer: &Keypair,
    mint_kp: &Keypair,
    decimals: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    let payer_pk = keypair_pubkey(payer);
    let mint_pk = keypair_pubkey(mint_kp);

    let rent = rpc
        .get_minimum_balance_for_rent_exemption(SPL_MINT_LEN as usize)
        .await?;
    let create_account_ix = solana_system_interface::instruction::create_account(
        &pk_to_addr(&payer_pk),
        &pk_to_addr(&mint_pk),
        rent,
        SPL_MINT_LEN,
        &pk_to_addr(&SPL_TOKEN_PROGRAM_ID),
    );
    // solana_system_interface already returns a 3.x Instruction; no bridging needed.

    let init_mint_ix = build_initialize_mint2_ix(&mint_pk, &payer_pk, decimals);

    let blockhash = rpc.get_latest_blockhash().await?;
    let tx = sign_two_kp_tx(
        vec![create_account_ix, init_mint_ix],
        payer,
        &[mint_kp],
        &blockhash,
    );
    rpc.send_and_confirm_transaction(&tx).await?;
    Ok(())
}

pub async fn create_ata(
    rpc: &RealRpcClient,
    funder: &Keypair,
    owner: &Pubkey,
    mint: &Pubkey,
) -> Result<(), Box<dyn std::error::Error>> {
    let funder_pk = keypair_pubkey(funder);
    let ix = build_create_ata_idempotent_ix(&funder_pk, owner, mint, &SPL_TOKEN_PROGRAM_ID);
    let blockhash = rpc.get_latest_blockhash().await?;
    let tx = sign_two_kp_tx(vec![ix], funder, &[], &blockhash);
    rpc.send_and_confirm_transaction(&tx).await?;
    Ok(())
}

pub async fn mint_to(
    rpc: &RealRpcClient,
    mint_authority: &Keypair,
    mint: &Pubkey,
    destination_ata: &Pubkey,
    amount: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let authority_pk = keypair_pubkey(mint_authority);
    let ix = build_mint_to_ix(mint, destination_ata, &authority_pk, amount);
    let blockhash = rpc.get_latest_blockhash().await?;
    let tx = sign_two_kp_tx(vec![ix], mint_authority, &[], &blockhash);
    rpc.send_and_confirm_transaction(&tx).await?;
    Ok(())
}

/// Sign a tx with the fee payer plus zero or more extra keypairs whose
/// pubkeys are required signers in the message. Used for the setup
/// helpers, not the SDK's own builds.
pub fn sign_two_kp_tx(
    ixs: Vec<Instruction>,
    fee_payer: &Keypair,
    extras: &[&Keypair],
    blockhash: &Hash,
) -> Transaction {
    let fee_payer_addr = pk_to_addr(&keypair_pubkey(fee_payer));
    let message = Message::new_with_blockhash(&ixs, Some(&fee_payer_addr), blockhash);
    let mut tx = Transaction::new_unsigned(message);
    let required = tx.message.header.num_required_signatures as usize;
    tx.signatures = vec![Signature::default(); required];

    sign_slot(&mut tx, fee_payer);
    for kp in extras {
        sign_slot(&mut tx, kp);
    }
    tx
}

pub fn sign_slot(tx: &mut Transaction, kp: &Keypair) {
    let pk_addr = pk_to_addr(&keypair_pubkey(kp));
    let idx = tx
        .message
        .account_keys
        .iter()
        .position(|k| *k == pk_addr)
        .expect("signer pubkey appears in account_keys");
    let sig_bytes = kp.sign_message(&tx.message_data()).as_ref().to_vec();
    let arr: [u8; 64] = sig_bytes.try_into().expect("ed25519 signature is 64 bytes");
    tx.signatures[idx] = Signature::from(arr);
}

pub async fn read_token_balance(
    rpc: &Arc<dyn MppRpcClient>,
    ata: &Pubkey,
) -> Result<u64, Box<dyn std::error::Error>> {
    let info = solana_client::rpc_config::RpcAccountInfoConfig {
        encoding: Some(solana_account_decoder_client_types::UiAccountEncoding::Base64),
        commitment: Some(CommitmentConfig::confirmed()),
        ..Default::default()
    };
    let resp = rpc.get_ui_account_with_config(ata, info).await?;
    let Some(ui) = resp.value else {
        return Ok(0);
    };
    let bytes = ui.data.decode().ok_or("ata account data not base64")?;
    let amount_bytes: [u8; 8] = bytes
        .get(64..72)
        .ok_or("ata account shorter than spl token layout")?
        .try_into()
        .expect("8-byte slice");
    Ok(u64::from_le_bytes(amount_bytes))
}

// hand-rolled ix builders
//
// The upstream spl-token / spl-associated-token-account-client crates on
// crates.io still compile against solana-pubkey 2.x. Building these ixs
// by hand keeps the demos on solana-pubkey 3.x throughout instead of
// bridging through bytes for every ix.

pub fn build_initialize_mint2_ix(
    mint: &Pubkey,
    mint_authority: &Pubkey,
    decimals: u8,
) -> Instruction {
    // SPL Token InitializeMint2 layout: [tag=20, decimals, mint_authority(32),
    // freeze_authority_option(1 + 32 if Some)].
    let mut data = Vec::with_capacity(1 + 1 + 32 + 1);
    data.push(20);
    data.push(decimals);
    data.extend_from_slice(&mint_authority.to_bytes());
    data.push(0); // COption::None for freeze authority
    Instruction {
        program_id: pk_to_addr(&SPL_TOKEN_PROGRAM_ID),
        accounts: vec![AccountMeta::new(pk_to_addr(mint), false)],
        data,
    }
}

pub fn build_create_ata_idempotent_ix(
    funder: &Pubkey,
    owner: &Pubkey,
    mint: &Pubkey,
    token_program: &Pubkey,
) -> Instruction {
    let ata = ata_address(owner, mint, token_program);
    Instruction {
        program_id: pk_to_addr(&ASSOCIATED_TOKEN_PROGRAM_ID),
        accounts: vec![
            AccountMeta::new(pk_to_addr(funder), true),
            AccountMeta::new(pk_to_addr(&ata), false),
            AccountMeta::new_readonly(pk_to_addr(owner), false),
            AccountMeta::new_readonly(pk_to_addr(mint), false),
            AccountMeta::new_readonly(pk_to_addr(&SYSTEM_PROGRAM_ID), false),
            AccountMeta::new_readonly(pk_to_addr(token_program), false),
        ],
        data: vec![1], // CreateIdempotent
    }
}

pub fn build_mint_to_ix(
    mint: &Pubkey,
    destination_ata: &Pubkey,
    authority: &Pubkey,
    amount: u64,
) -> Instruction {
    // SPL Token MintTo: [tag=7, amount(8 LE)].
    let mut data = Vec::with_capacity(1 + 8);
    data.push(7);
    data.extend_from_slice(&amount.to_le_bytes());
    Instruction {
        program_id: pk_to_addr(&SPL_TOKEN_PROGRAM_ID),
        accounts: vec![
            AccountMeta::new(pk_to_addr(mint), false),
            AccountMeta::new(pk_to_addr(destination_ata), false),
            AccountMeta::new_readonly(pk_to_addr(authority), true),
        ],
        data,
    }
}

pub fn ata_address(owner: &Pubkey, mint: &Pubkey, token_program: &Pubkey) -> Pubkey {
    let seeds = &[owner.as_ref(), token_program.as_ref(), mint.as_ref()];
    Pubkey::find_program_address(seeds, &ASSOCIATED_TOKEN_PROGRAM_ID).0
}
