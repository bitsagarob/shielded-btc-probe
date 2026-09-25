//! sbp: the Shielded Bitcoin probe CLI.

#![forbid(unsafe_code)]

use anyhow::{Context, Result, ensure};
use ark_ec::twisted_edwards::TECurveConfig;
use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use bitcoin::Network;
use clap::{Parser, Subcommand};
use serde_json::json;
use shielded_probe::{
    DIV_HASH_TRIES, Fr, Fs, N_IN, N_OUT,
    chain::{ChainSource, Electrum, default_electrum},
    circuit::{TransferCircuit, sample::sample_witness},
    envelope::{self, Payout},
    indexer::{Deployment, Event, State},
    keys::{self, Address, DIVERSIFIER_LEN, SCALAR_BITS},
    note::{self, CIPHERTEXT_LEN},
    poseidon::{self, tag},
    prover::Params,
    wallet::{Wallet, check_deposit},
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
    #[arg(long, global = true, default_value = "state")]
    state: PathBuf,
    /// Electrum server; defaults to 127.0.0.1:50001 for signet and
    /// 127.0.0.1:50011 for bitcoin.
    #[arg(long)]
    electrum: Option<String>,
    /// Wallet file, required by every wallet subcommand. Repeatable for
    /// export-js only.
    #[arg(long, global = true)]
    wallet: Vec<PathBuf>,
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
        #[arg(long, default_value = "signet", value_parser = parse_network)]
        network: Network,
        /// Fee rate in sat/vB for every carrier and payout on this deployment.
        #[arg(long, default_value_t = 2)]
        fee_rate: u64,
    },
    /// Create a wallet file.
    Init {
        /// Network for the printed addresses; the state dir's deployment
        /// wins when it exists.
        #[arg(long, value_parser = parse_network)]
        network: Option<Network>,
    },
    /// Show the shielded address and the funding address.
    Address {
        #[arg(long, value_parser = parse_network)]
        network: Option<Network>,
    },
    /// Replay the chain into the indexer state.
    Sync,
    /// Peg in: pay the vault and mint a shielded note to yourself.
    Mint {
        #[arg(long)]
        amount: u64,
        /// Allow a deposit over the cap on bitcoin.
        #[arg(long)]
        i_know: bool,
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
        /// Address on the deployment's network to receive the transparent coins.
        #[arg(long)]
        to: String,
    },
    /// Operator: pay accepted peg-out requests from the vault.
    Payouts {
        /// Pay only the request carried by this transaction; required on bitcoin.
        #[arg(long)]
        only: Option<String>,
    },
    /// Show replayed state.
    Status,
    /// Publish arbitrary envelope bytes from a wallet's funding key. Used to
    /// probe replay rules (double spends, stale anchors, malformed bytes).
    PublishRaw {
        #[arg(long)]
        hex: String,
    },
    /// Print the JSON the browser verifier needs: constants, viewing keys of
    /// the given wallets, accepted events and decryption test vectors.
    ExportJs {
        /// Written as network_label so the page can tell two exports apart.
        #[arg(long)]
        label: Option<String>,
    },
    /// Write the wallet's viewing keys and addresses to a new 0600 file.
    ExportViewing {
        #[arg(long)]
        out: PathBuf,
    },
    /// Print the wallet seed once, for a backup.
    Seed,
    /// Give an older wallet file its vault key.
    Migrate,
}

impl Cli {
    fn wallet(&self) -> Result<&Path> {
        ensure!(self.wallet.len() < 2, "--wallet given more than once");
        self.wallet
            .first()
            .map(PathBuf::as_path)
            .context("--wallet is required")
    }
}

fn parse_network(s: &str) -> Result<Network, String> {
    match s {
        "signet" => Ok(Network::Signet),
        "bitcoin" => Ok(Network::Bitcoin),
        _ => Err("expected signet or bitcoin".into()),
    }
}

fn load_deployment(dir: &Path) -> Result<Deployment> {
    let path = dir.join("deployment.json");
    let f = std::fs::File::open(&path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_reader(f).with_context(|| format!("parsing {}", path.display()))
}

/// The deployment's network when the state dir has one, else the flag, else signet.
fn network(cli: &Cli, flag: Option<Network>) -> Result<Network> {
    if cli.state.join("deployment.json").exists() {
        let n = load_deployment(&cli.state)?.network;
        ensure!(
            flag.is_none_or(|f| f == n),
            "the deployment in {} is on {n}",
            cli.state.display()
        );
        return Ok(n);
    }
    Ok(flag.unwrap_or(Network::Signet))
}

fn connect(cli: &Cli, network: Network) -> Result<Electrum> {
    let addr = cli.electrum.as_deref().unwrap_or(default_electrum(network));
    Ok(Electrum::connect_checked(addr, network)?)
}

/// The state file must belong to the deployment profile next to it.
fn load_state(dir: &Path) -> Result<State> {
    let dep = load_deployment(dir)?;
    let sp = dir.join("state.json");
    if !sp.exists() {
        return Ok(State::fresh(dep));
    }
    let st = State::load(&sp)?;
    ensure!(
        st.deployment.activation == dep.activation
            && st.deployment.vk_fingerprint == dep.vk_fingerprint,
        "{} was replayed for another deployment than {}",
        sp.display(),
        dir.join("deployment.json").display()
    );
    Ok(st)
}

fn synced_state(cli: &Cli, params: &Params) -> Result<(State, Electrum)> {
    let mut st = load_state(&cli.state)?;
    let mut e = connect(cli, st.deployment.network)?;
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
            network,
            fee_rate,
        } => deploy(&cli, *activation, operator_wallet, *network, *fee_rate),
        Cmd::Init { network } => init(&cli, *network),
        Cmd::Address { network } => address(&cli, *network),
        Cmd::Sync => sync(&cli),
        Cmd::Status => status(&cli),
        Cmd::Mint { amount, i_know } => mint(&cli, *amount, *i_know),
        Cmd::Scan => scan(&cli),
        Cmd::Unlock { txid, force } => unlock(&cli, txid, *force),
        Cmd::Send { to, amount } => send(&cli, to, *amount),
        Cmd::Redeem { amount, to } => redeem(&cli, *amount, to),
        Cmd::PublishRaw { hex } => publish_raw(&cli, hex),
        Cmd::Payouts { only } => payouts(&cli, only.as_deref()),
        Cmd::ExportJs { label } => export_js(&cli, label.as_deref()),
        Cmd::ExportViewing { out } => {
            Wallet::open(cli.wallet()?)?.export_viewing(out)?;
            println!("wrote viewing keys to {}", out.display());
            Ok(())
        }
        Cmd::Seed => {
            let w = Wallet::open(cli.wallet()?)?;
            eprintln!(
                "WARNING: this seed spends every note of the wallet; anyone who reads it can too"
            );
            println!("{}", hex::encode(w.file.seed));
            Ok(())
        }
        Cmd::Migrate => {
            let mut w = Wallet::open(cli.wallet()?)?;
            println!(
                "{}",
                if w.migrate()? {
                    "vault key added"
                } else {
                    "nothing to migrate"
                }
            );
            Ok(())
        }
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

fn deploy(
    cli: &Cli,
    activation: u32,
    operator_wallet: &Path,
    network: Network,
    fee_rate: u64,
) -> Result<()> {
    let params = Params::load_or_setup(&cli.params)?;
    let op = Wallet::open(operator_wallet)?;
    let mut e = connect(cli, network)?;
    let activation_hash = activation
        .checked_sub(1)
        .map(|h| e.block_hash(h))
        .transpose()?;
    let dep = Deployment {
        network,
        fee_rate_sat_vb: fee_rate,
        activation,
        activation_hash,
        vault_script_pubkey: op.vault_key()?.script_pubkey(),
        operator_address: op.address().to_string(),
        vk_fingerprint: params.vk_fingerprint(),
    };
    std::fs::create_dir_all(&cli.state)?;
    let mut text = serde_json::to_vec_pretty(&dep)?;
    text.push(b'\n');
    std::fs::write(cli.state.join("deployment.json"), text)?;
    println!(
        "network {network}\nfee rate {fee_rate} sat/vB\nactivation {activation}\nactivation hash {}\nvault {}\noperator {}\nvk {}",
        dep.activation_hash
            .map_or("none".to_owned(), |h| h.to_string()),
        op.vault_key()?.address(network),
        dep.operator_address,
        dep.vk_fingerprint
    );
    Ok(())
}

fn init(cli: &Cli, flag: Option<Network>) -> Result<()> {
    let network = network(cli, flag)?;
    let w = Wallet::create(cli.wallet()?)?;
    print_addresses(&w, network);
    Ok(())
}

fn address(cli: &Cli, flag: Option<Network>) -> Result<()> {
    let network = network(cli, flag)?;
    let w = Wallet::open(cli.wallet()?)?;
    print_addresses(&w, network);
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

fn mint(cli: &Cli, amount: u64, i_know: bool) -> Result<()> {
    let mut w = Wallet::open(cli.wallet()?)?;
    let st = load_state(&cli.state)?;
    check_deposit(st.deployment.network, amount, i_know)?;
    let mut e = connect(cli, st.deployment.network)?;

    let (txid, bytes, vsize, fee) = w.mint(&mut e, &st.deployment, amount)?;
    println!(
        "mint txid {txid}\nenvelope {bytes} bytes, carrier {vsize} vB, fee {fee} sat, paid {amount} sat to the vault"
    );
    Ok(())
}

fn scan(cli: &Cli) -> Result<()> {
    let params = Params::load_or_setup(&cli.params)?;
    let (st, _) = synced_state(cli, &params)?;
    let mut w = Wallet::open(cli.wallet()?)?;
    let n = w.scan(&st)?;
    println!("{n} new notes, balance {} sat", w.balance()?);
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
    let mut e = connect(cli, load_deployment(&cli.state)?.network)?;
    let n = w.unlock(&mut e, &txid.parse()?, force)?;
    println!("unlocked {n} notes, balance {} sat", w.balance()?);
    Ok(())
}

fn send(cli: &Cli, to: &str, amount: u64) -> Result<()> {
    let params = Params::load_or_setup(&cli.params)?;
    let (st, mut e) = synced_state(cli, &params)?;
    let mut w = Wallet::open(cli.wallet()?)?;
    w.scan(&st)?;
    let to: Address = to.parse()?;
    let (txid, built, vsize, fee) = w.send(&mut e, &st, &params, &to, amount, None)?;
    println!(
        "send txid {txid}\nenvelope {} bytes, carrier {vsize} vB, fee {fee} sat, proof {:.2}s, anchor {}",
        built.envelope.to_bytes().len(),
        built.prove_s,
        built.envelope.h_anchor
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
        .require_network(st.deployment.network)?;
    let payout = Payout {
        amount,
        script_pubkey: addr.script_pubkey().to_bytes(),
    };
    let (txid, built, vsize, fee) = w.send(&mut e, &st, &params, &op, amount, Some(payout))?;
    println!(
        "redeem txid {txid}\nenvelope {} bytes, carrier {vsize} vB, fee {fee} sat, proof {:.2}s, anchor {}",
        built.envelope.to_bytes().len(),
        built.prove_s,
        built.envelope.h_anchor
    );
    Ok(())
}

fn publish_raw(cli: &Cli, hex: &str) -> Result<()> {
    let w = Wallet::open(cli.wallet()?)?;
    let dep = load_deployment(&cli.state)?;
    let mut e = connect(cli, dep.network)?;
    let payload = hex::decode(hex)?;
    let utxos = w.funding_utxos(&mut e)?;
    let (tx, fee) =
        w.funding_key()?
            .build_carrier(&utxos, &payload, vec![], dep.fee_rate_sat_vb)?;
    let vsize = tx.vsize();
    let txid = e.broadcast(&tx)?;
    println!(
        "published {} bytes in {txid}, {vsize} vB, fee {fee} sat",
        payload.len()
    );
    Ok(())
}

fn payouts(cli: &Cli, only: Option<&str>) -> Result<()> {
    let only = only.map(str::parse).transpose()?;
    let params = Params::load_or_setup(&cli.params)?;
    let (st, mut e) = synced_state(cli, &params)?;
    let mut w = Wallet::open(cli.wallet()?)?;
    w.scan(&st)?;
    let done = w.process_payouts(&mut e, &st, only)?;

    for (req, amount, fee, paid) in &done {
        println!("paid {amount} sat for {req} in {paid}, fee {fee} sat");
    }

    if done.is_empty() {
        println!("nothing to pay");
    }
    Ok(())
}

/// Everything shielded-verify.js needs, and no secret: viewing keys only.
fn export_js(cli: &Cli, label: Option<&str>) -> Result<()> {
    let dec = |x: &Fr| x.to_string();
    let fr_hex = |x: &Fr| hex::encode(keys::fr_to_bytes(x));
    let cfg = poseidon::config();
    let st = load_state(&cli.state)?;
    ensure!(!cli.wallet.is_empty(), "--wallet is required");
    let mut wallets = Vec::new();
    for path in &cli.wallet {
        let w = Wallet::open(path)?;
        let vk = w.keys.viewing();
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("wallet");
        wallets.push((name.to_owned(), w.address().to_string(), vk));
    }
    let mut events = Vec::new();
    let mut vectors = Vec::new();
    for ev in &st.events {
        match ev {
            Event::Mint(m) => {
                let env = m.envelope()?;
                let leaf = note::mint_leaf(m.value, &env.d, &env.pk_d, &env.r_seed);
                events.push(json!({"txid": m.txid, "height": m.height, "kind": "mint",
                    "positions": [m.pos], "envelope": hex::encode(&m.bytes), "value": m.value}));
                for (name, _, vk) in &wallets {
                    if keys::address_for(vk, env.d).is_some_and(|a| a.pk_d == env.pk_d) {
                        vectors.push(
                            json!({"txid": m.txid, "wallet": name, "role": "mint", "j": 0,
                            "v": m.value, "d": hex::encode(env.d), "r_seed": fr_hex(&env.r_seed),
                            "leaf": fr_hex(&leaf)}),
                        );
                    }
                }
            }
            Event::Transfer(t) => {
                let env = t.envelope()?;
                let h_body = env.h_body();
                events.push(
                    json!({"txid": t.txid, "height": t.height, "kind": "transfer",
                    "positions": t.positions, "envelope": hex::encode(&t.bytes)}),
                );
                for (name, _, vk) in &wallets {
                    let mut push = |role: &str,
                                    j: usize,
                                    n: &note::NotePlaintext,
                                    to: Option<String>| {
                        let leaf = note::leaf(&h_body, j as u8, &env.pk_eph[j], &env.ct[j]);
                        vectors.push(json!({"txid": t.txid, "wallet": name, "role": role, "j": j,
                            "v": n.v, "d": hex::encode(n.d), "r_seed": fr_hex(&n.r_seed),
                            "leaf": fr_hex(&leaf), "to": to}));
                    };
                    for j in 0..N_OUT {
                        if let Some(n) =
                            note::decrypt_as_recipient(&env.ct[j], &env.pk_eph[j], &vk.sk_view)
                        {
                            push("recipient", j, &n, None);
                        }
                    }
                    let Some(records) =
                        note::decrypt_recovery(&env.ct_out, &env.recovery_binding(), &vk.vk_out)
                    else {
                        continue;
                    };
                    for (j, (pk_d, s)) in records.iter().take(N_OUT).enumerate() {
                        if let Some(n) =
                            note::decrypt_as_sender(&env.ct[j], &env.pk_eph[j], pk_d, s)
                        {
                            let to = Address {
                                d: n.d,
                                pk_d: *pk_d,
                            }
                            .to_string();
                            push("sender", j, &n, Some(to));
                        }
                    }
                }
            }
        }
    }
    let out = json!({
        "network_label": label,
        "fr_modulus": Fr::MODULUS.to_string(),
        "poseidon": {
            "full_rounds": cfg.full_rounds, "partial_rounds": cfg.partial_rounds,
            "alpha": cfg.alpha, "rate": cfg.rate, "capacity": cfg.capacity,
            "mds": cfg.mds.iter().map(|r| r.iter().map(dec).collect::<Vec<_>>()).collect::<Vec<_>>(),
            "ark": cfg.ark.iter().map(|r| r.iter().map(dec).collect::<Vec<_>>()).collect::<Vec<_>>(),
        },
        "jubjub": {
            "a": ark_ed_on_bls12_381::EdwardsConfig::COEFF_A.to_string(),
            "d": ark_ed_on_bls12_381::EdwardsConfig::COEFF_D.to_string(),
            "base_modulus": Fr::MODULUS.to_string(),
            "scalar_modulus": Fs::MODULUS.to_string(),
        },
        "tags": {
            "NF_KEY": tag::NF_KEY, "VK_IN": tag::VK_IN, "SK_VIEW": tag::SK_VIEW,
            "DIVERSIFY": tag::DIVERSIFY, "RHO": tag::RHO, "EPH": tag::EPH, "KDF": tag::KDF,
            "STREAM": tag::STREAM, "MAC": tag::MAC, "LEAF": tag::LEAF, "MINT_LEAF": tag::MINT_LEAF,
            "NF": tag::NF, "NODE": tag::NODE, "BODY": tag::BODY, "STMT": tag::STMT,
        },
        "DIVERSIFIER_LEN": DIVERSIFIER_LEN, "SCALAR_BITS": SCALAR_BITS,
        "DIV_HASH_TRIES": DIV_HASH_TRIES, "N_IN": N_IN, "N_OUT": N_OUT,
        "envelope": {
            "magic": hex::encode(envelope::MAGIC), "version": envelope::VERSION,
            "kind_transfer": envelope::KIND_TRANSFER, "kind_mint": envelope::KIND_MINT,
            "ciphertext_len": CIPHERTEXT_LEN, "ct_out_len": envelope::CT_OUT_LEN,
            "proof_len": envelope::PROOF_LEN,
            "const_salt": hex::encode(note::CONST_SALT), "aux_null": fr_hex(&note::aux_null()),
        },
        "wallets": wallets.iter().map(|(name, addr, vk)| json!({
            "name": name, "address": addr,
            "vk_in": fr_hex(&vk.vk_in), "vk_out": hex::encode(vk.vk_out),
        })).collect::<Vec<_>>(),
        "state": {
            "activation": st.deployment.activation,
            "operator_address": st.deployment.operator_address,
            "replayed_height": st.replayed_height,
            "leaves": st.tree.leaves().iter().map(fr_hex).collect::<Vec<_>>(),
            "events": events,
        },
        "vectors": vectors,
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

fn print_addresses(w: &Wallet, network: Network) {
    let addr = |k: Result<&shielded_probe::chain::FundingKey, _>| {
        k.map_or("none".to_owned(), |k| k.address(network).to_string())
    };
    println!(
        "shielded {}\nfunding  {}\nvault    {}",
        w.address(),
        addr(w.funding_key()),
        addr(w.vault_key())
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
