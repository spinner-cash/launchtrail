//! Fetch certificate of canister info and verify it.
//!
//! The public interface of Internet Computer (IC) offers a `read_state` API to query canister state.
//! Its return result is a time-stamped certificate that can be verified against the public key of the IC.
//! This is a powerful way of keeping a verifiable record of canister meta data such as module hash and controller list.
//!
//! This tool provides two commands:
//!
//! 1. `fetch canister_id`: call `read_state` on the given canister and print the result.
//!    The certificate is kept in its original CBOR encoding, represented as a hex-encoded string in JSON.
//!
//! 2. `verify`: read the result of `fetch` from standard input, verify its authenticity using IC's
//!    public key and print its info including module hash, controller list, and timestamp.
use clap::*;
use ic_agent::{
    agent::{http_transport::ReqwestHttpReplicaV2Transport, Agent, AgentError},
    hash_tree::{HashTree, Label},
    lookup_value, Certificate,
};
use ic_cdk::export::Principal;
use serde::{Deserialize, Serialize};
use serde_bytes_repr::{ByteFmtDeserializer, ByteFmtSerializer};
use serde_json::{Deserializer, Serializer};
use std::io::{stdin, Read};

const URL: &str = "https://ic0.app";

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Number of times to greet
    #[clap(long, default_value = "https://ic0.app")]
    url: String,

    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Fetch canister info
    Fetch { canister: String },
    /// Verify canister info
    Verify,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Delegation {
    #[serde(with = "serde_bytes")]
    pub subnet_id: Vec<u8>,

    #[serde(with = "serde_bytes")]
    pub certificate: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertificateExport<'a> {
    pub tree: HashTree<'a>,
    pub delegation: Option<Delegation>,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

impl<'a> From<Certificate<'a>> for CertificateExport<'a> {
    fn from(cert: Certificate<'a>) -> Self {
        CertificateExport {
            tree: cert.tree,
            signature: cert.signature,
            delegation: cert.delegation.map(|x| Delegation {
                subnet_id: x.subnet_id,
                certificate: x.certificate,
            }),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CanisterInfo {
    pub canister_id: Principal,
    #[serde(with = "serde_bytes")]
    pub certificate: Vec<u8>,
}

fn from_str<'a, T: Deserialize<'a>>(json: &'a str) -> Result<T, serde_json::Error> {
    let mut json_de = Deserializer::from_str(json);
    let bytefmt_json_de = ByteFmtDeserializer::new_hex(&mut json_de);
    T::deserialize(bytefmt_json_de)
}

fn to_string<T: Serialize>(msg: &T) -> String {
    let mut out = vec![];
    let mut ser = Serializer::new(&mut out);
    let ser = ByteFmtSerializer::hex(&mut ser);
    msg.serialize(ser).expect("Failed to serialize to JSON");
    String::from_utf8(out).expect("UTF8 conversion error")
}

pub async fn canister_info(
    agent: &Agent,
    canister_id: Principal,
) -> Result<CanisterInfo, AgentError> {
    let paths: Vec<Vec<Label>> = vec![
        vec!["canister".into(), canister_id.into(), "module_hash".into()],
        vec!["canister".into(), canister_id.into(), "controllers".into()],
    ];

    let cert = agent.read_state_raw(paths, canister_id, true).await?;
    let cert = CertificateExport::from(cert);
    let certificate = serde_cbor::to_vec(&cert)?;
    Ok(CanisterInfo {
        canister_id,
        certificate,
    })
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicInfo {
    canister_id: Principal,
    #[serde(with = "serde_bytes")]
    module_hash: Vec<u8>,
    controllers: Vec<Principal>,
    time: u64,
}

fn verify_info(
    agent: &Agent,
    info: &CanisterInfo,
) -> Result<PublicInfo, Box<dyn std::error::Error>> {
    let canister_id = info.canister_id;
    let cert: Certificate = serde_cbor::from_slice(&info.certificate)?;
    agent.verify(&cert, canister_id, true)?;
    let mut time = lookup_value(&cert, vec!["time".into()])?;
    let time = leb128::read::unsigned(&mut time)?;
    let module_hash = lookup_value(
        &cert,
        vec!["canister".into(), canister_id.into(), "module_hash".into()],
    )?
    .to_vec();
    let controllers = lookup_value(
        &cert,
        vec!["canister".into(), canister_id.into(), "controllers".into()],
    )?;
    let controllers: Vec<Principal> = serde_cbor::from_slice(controllers)?;
    Ok(PublicInfo {
        canister_id,
        module_hash,
        controllers,
        time,
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let fetch_root_key = args.url != URL;
    let transport = ReqwestHttpReplicaV2Transport::create(args.url)?;
    let agent = Agent::builder().with_transport(transport).build()?;
    if fetch_root_key {
        agent.fetch_root_key().await?;
    }
    match &args.command {
        Command::Fetch { canister } => {
            let canister_id =
                Principal::from_text(canister).map_err(|_| "Please give a valid principal id")?;
            let info = canister_info(&agent, canister_id).await?;
            println!("{}", to_string(&info));
        }
        Command::Verify => {
            let mut buffer = String::new();
            let mut input = stdin();
            input.read_to_string(&mut buffer)?;
            let info: CanisterInfo = from_str(&buffer)?;
            println!("{}", to_string(&verify_info(&agent, &info)?));
        }
    };
    Ok(())
}
