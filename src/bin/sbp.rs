//! sbp: the Shielded Bitcoin probe CLI.

use anyhow::{Context, Result, ensure};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use clap::{Parser, Subcommand};
use shielded_probe::{
    chain::{DEFAULT_ELECTRUM, Electrum},
    circuit::{TransferCircuit, sample::sample_witness},
    envelope::Payout,
    indexer::{Deployment, Event, State},
    keys::Address,
    prover::Params,
    wallet::Wallet,
};
use std::{
    path::{Path, PathBuf},
    time::Instant,
};

#[derive(Parser)]
#[command(
    name = "sbp",
    about = "Shielded Bitcoin transfer-layer probe on Bitsaga Signet"
)]
struct Cli {
    /// Directory holding the Groth16 keys (generated on first use).
    #[arg(long, default_value = "params")]
    params: PathBuf,
    /// Indexer state directory (deployment.json and state.json).
    #[arg(long, default_value = "state")]
    state: PathBuf,
    #[arg(long, default_value = DEFAULT_ELECTRUM)]
    electrum: String,
    /// Wallet file, required by every wallet subcommand.
    #[arg(long, global = true)]
    wallet: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Constraint count, setup, prove and verify timings.
    Bench,
    /// Write the deployment profile: activation height, vault and operator.
    Deploy {
        #[arg(long)]
        activation: u32,
        /// Operator wallet file; its funding key becomes the vault and its
        /// shielded address the peg-out target.
        #[arg(long)]
        operator_wallet: PathBuf,
    },
    /// Create a wallet file.
    Init,
    /// Show the shielded address and the funding address.
    Address,
    /// Replay the chain into the indexer state.
    Sync,
    /// Peg in: pay the vault and mint a shielded note to yourself.
    Mint {
        #[arg(long)]
        amount: u64,
    },
    /// Scan replayed history for notes owned by this wallet.
    Scan,
    /// Release notes locked by a carrier that was dropped or reorged out.
    Unlock {
        #[arg(long)]
        txid: String,
        /// Unlock even if the carrier is still in the mempool or chain.
        #[arg(long)]
        force: bool,
    },
    /// Shielded transfer.
    Send {
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u64,
    },
    /// Peg out: send to the operator with a payout request.
    Redeem {
        #[arg(long)]
        amount: u64,
        /// Signet address to receive the transparent coins.
        #[arg(long)]
        to: String,
    },
    /// Operator: pay accepted peg-out requests from the vault.
    Payouts,
    /// Show replayed state.
    Status,
    /// Publish arbitrary envelope bytes from a wallet's funding key. Used to
    /// probe replay rules (double spends, stale anchors, malformed bytes).
    PublishRaw {
        #[arg(long)]
        hex: String,
    },
}

impl Cli {
    fn wallet(&self) -> Result<&Path> {
        self.wallet.as_deref().context("--wallet is required")
    }
}

fn load_state(dir: &Path) -> Result<State> {
    let dep: Deployment =
        serde_json::from_reader(std::fs::File::open(dir.join("deployment.json"))?)?;
    let sp = dir.join("state.json");
    if sp.exists() {
        Ok(State::load(&sp)?)
    } else {
        Ok(State::fresh(dep))
    }
}

fn synced_state(cli: &Cli, params: &Params) -> Result<(State, Electrum)> {
    let mut e = Electrum::connect(&cli.electrum)?;
    let mut st = load_state(&cli.state)?;
    ensure!(
        st.deployment.vk_fingerprint == params.vk_fingerprint(),
        "verifying key does not match the deployment"
    );
    let t = Instant::now();
    let n = st.sync(&mut e, params)?;
    st.save(&cli.state.join("state.json"))?;
    if n > 0 {
        log::info!(
            "replayed {n} blocks in {:.1}s, now at {}",
            t.elapsed().as_secs_f64(),
            st.replayed_height
        );
    }
    Ok((st, e))
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();
    match &cli.cmd {
        Cmd::Bench => bench(),
        Cmd::Deploy {
            activation,
            operator_wallet,
        } => deploy(&cli, *activation, operator_wallet),
        Cmd::Init => init(&cli),
        Cmd::Address => address(&cli),
        Cmd::Sync => sync(&cli),
        Cmd::Status => status(&cli),
        Cmd::Mint { amount } => mint(&cli, *amount),
        Cmd::Scan => scan(&cli),
        Cmd::Unlock { txid, force } => unlock(&cli, txid, *force),
        Cmd::Send { to, amount } => send(&cli, to, *amount),
        Cmd::Redeem { amount, to } => redeem(&cli, *amount, to),
        Cmd::PublishRaw { hex } => publish_raw(&cli, hex),
        Cmd::Payouts => payouts(&cli),
    }
}

fn bench() -> Result<()> {
    let (w, p) = sample_witness();
    let cs = ConstraintSystem::<shielded_probe::Fr>::new_ref();
    TransferCircuit {
        public: Some(p.clone()),
        witness: Some(w.clone()),
    }
    .generate_constraints(cs.clone())?;
    println!("constraints        {}", cs.num_constraints());
    println!("witness variables  {}", cs.num_witness_variables());
    let t = Instant::now();
    let params = Params::setup_insecure()?;
    println!("setup              {:.2}s", t.elapsed().as_secs_f64());
    let mut pk = Vec::new();
    ark_serialize::CanonicalSerialize::serialize_uncompressed(&params.pk, &mut pk)?;
    println!("proving key        {} MB", pk.len() / 1_000_000);
    for _ in 0..3 {
        let t = Instant::now();
        let proof = params.prove(&p, &w)?;
        let ps = t.elapsed().as_secs_f64();
        let t = Instant::now();
        let ok = params.verify(&p, &proof);
        println!(
            "prove {ps:.2}s  verify {:.1}ms  ok={ok}  proof {} bytes",
            t.elapsed().as_secs_f64() * 1000.0,
            proof.len()
        );
    }
    println!(
        "threads            {}",
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    );
    Ok(())
}

fn deploy(cli: &Cli, activation: u32, operator_wallet: &Path) -> Result<()> {
    let params = Params::load_or_setup(&cli.params)?;
    let op = Wallet::open(operator_wallet)?;
    let dep = Deployment {
        activation,
        vault_script_pubkey: op.vault().script_pubkey(),
        operator_address: op.address().to_string(),
        vk_fingerprint: params.vk_fingerprint(),
    };
    std::fs::create_dir_all(&cli.state)?;
    serde_json::to_writer_pretty(
        std::fs::File::create(cli.state.join("deployment.json"))?,
        &dep,
    )?;
    println!(
        "activation {activation}\nvault {}\noperator {}\nvk {}",
        op.vault().address(),
        dep.operator_address,
        dep.vk_fingerprint
    );
    Ok(())
}

fn init(cli: &Cli) -> Result<()> {
    let w = Wallet::create(cli.wallet()?)?;
    print_addresses(&w);
    Ok(())
}

fn address(cli: &Cli) -> Result<()> {
    let w = Wallet::open(cli.wallet()?)?;
    print_addresses(&w);
    Ok(())
}

fn sync(cli: &Cli) -> Result<()> {
    let params = Params::load_or_setup(&cli.params)?;
    let (st, _) = synced_state(cli, &params)?;
    print_status(&st);
    Ok(())
}

fn status(cli: &Cli) -> Result<()> {
    let st = load_state(&cli.state)?;
    print_status(&st);
    Ok(())
}

fn mint(cli: &Cli, amount: u64) -> Result<()> {
    let mut w = Wallet::open(cli.wallet()?)?;
    let st = load_state(&cli.state)?;
    let mut e = Electrum::connect(&cli.electrum)?;
    let (txid, bytes, vsize) = w.mint(&mut e, &st.deployment.vault_script_pubkey, amount)?;
    println!(
        "mint txid {txid}\nenvelope {bytes} bytes, carrier {vsize} vB, paid {amount} sat to the vault"
    );
    Ok(())
}

fn scan(cli: &Cli) -> Result<()> {
    let params = Params::load_or_setup(&cli.params)?;
    let (st, _) = synced_state(cli, &params)?;
    let mut w = Wallet::open(cli.wallet()?)?;
    let n = w.scan(&st)?;
    println!("{n} new notes, balance {} sat", w.balance());
    for note in &w.file.notes {
        println!(
            "  pos {:>4}  {:>10} sat  {}{}{}  from {}",
            note.pos,
            note.v,
            if note.is_mint { "mint " } else { "note " },
            if note.spent { "spent" } else { "unspent" },
            if note.locked_by.is_some() {
                " (locked)"
            } else {
                ""
            },
            note.source_txid
        );
    }
    for s in &w.file.sent {
        println!(
            "  sent {:>10} sat in {} output {} to {}...",
            s.v,
            s.txid,
            s.j,
            s.to.chars().take(20).collect::<String>()
        );
    }
    Ok(())
}

fn unlock(cli: &Cli, txid: &str, force: bool) -> Result<()> {
    let mut w = Wallet::open(cli.wallet()?)?;
    let mut e = Electrum::connect(&cli.electrum)?;
    let n = w.unlock(&mut e, &txid.parse()?, force)?;
    println!("unlocked {n} notes, balance {} sat", w.balance());
    Ok(())
}

fn send(cli: &Cli, to: &str, amount: u64) -> Result<()> {
    let params = Params::load_or_setup(&cli.params)?;
    let (st, mut e) = synced_state(cli, &params)?;
    let mut w = Wallet::open(cli.wallet()?)?;
    w.scan(&st)?;
    let to: Address = to.parse()?;
    let (txid, bytes, vsize, prove_s) = w.send(&mut e, &st, &params, &to, amount, None)?;
    println!(
        "send txid {txid}\nenvelope {bytes} bytes, carrier {vsize} vB, proof {prove_s:.2}s, anchor {}",
        st.replayed_height
    );
    Ok(())
}

fn redeem(cli: &Cli, amount: u64, to: &str) -> Result<()> {
    let params = Params::load_or_setup(&cli.params)?;
    let (st, mut e) = synced_state(cli, &params)?;
    let mut w = Wallet::open(cli.wallet()?)?;
    w.scan(&st)?;
    let op: Address = st.deployment.operator_address.parse()?;
    let addr: bitcoin::Address = to
        .parse::<bitcoin::Address<_>>()?
        .require_network(shielded_probe::chain::NETWORK)?;
    let payout = Payout {
        amount,
        script_pubkey: addr.script_pubkey().to_bytes(),
    };
    let (txid, bytes, vsize, prove_s) = w.send(&mut e, &st, &params, &op, amount, Some(payout))?;
    println!("redeem txid {txid}\nenvelope {bytes} bytes, carrier {vsize} vB, proof {prove_s:.2}s");
    Ok(())
}

fn publish_raw(cli: &Cli, hex: &str) -> Result<()> {
    let w = Wallet::open(cli.wallet()?)?;
    let mut e = Electrum::connect(&cli.electrum)?;
    let payload = hex::decode(hex)?;
    let utxos = w.funding_utxos(&mut e)?;
    let tx = w.funding.build_carrier(&utxos, &payload, vec![])?;
    let vsize = tx.vsize();
    let txid = e.broadcast(&tx)?;
    println!("published {} bytes in {txid}, {vsize} vB", payload.len());
    Ok(())
}

fn payouts(cli: &Cli) -> Result<()> {
    let params = Params::load_or_setup(&cli.params)?;
    let (st, mut e) = synced_state(cli, &params)?;
    let mut w = Wallet::open(cli.wallet()?)?;
    w.scan(&st)?;
    let done = w.process_payouts(&mut e, &st)?;
    for (req, amount, paid) in &done {
        println!("paid {amount} sat for {req} in {paid}");
    }
    if done.is_empty() {
        println!("nothing to pay");
    }
    Ok(())
}

fn print_addresses(w: &Wallet) {
    println!(
        "shielded {}\nfunding  {}\nvault    {}",
        w.address(),
        w.funding.address(),
        w.vault().address()
    );
}

fn print_status(st: &State) {
    println!(
        "activation {}  replayed to {}  leaves {}  nullifiers {}  events {}  rejections {}",
        st.deployment.activation,
        st.replayed_height,
        st.tree.len(),
        st.nullifiers.len(),
        st.events.len(),
        st.rejections.len()
    );
    for ev in &st.events {
        match ev {
            Event::Mint(m) => println!(
                "  block {} mint {} sat -> pos {}  {}",
                m.height, m.value, m.pos, m.txid
            ),
            Event::Transfer(t) => println!(
                "  block {} transfer -> pos {:?}  {}",
                t.height, t.positions, t.txid
            ),
        }
    }
    for r in &st.rejections {
        println!("  block {} REJECTED {}: {}", r.height, r.txid, r.reason);
    }
}
