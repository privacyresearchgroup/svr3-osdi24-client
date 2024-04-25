//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
//! An example program demonstrating the backup and restore capabilities of a built-in Svr3Env.
//!
//! One would need to provide a valid auth secret value used to authenticate to the enclave,
//! as well as the password that will be used to protect the data being stored. Since the
//! actual stored secret data needs to be exactly 32 bytes long, it is generated randomly
//! at each invocation instead of being passed via the command line.
use std::fs::File;
use std::io::{BufWriter, Write};
use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime};
use svr3_osdi24_client::attest::svr2::RaftConfig;
use clap::Parser;

use base64::prelude::{Engine, BASE64_STANDARD};
use svr3_osdi24_client::net::infra::certs::RootCertificates;
use svr3_osdi24_client::net::infra::dns::DnsResolver;
use nonzero_ext::nonzero;
use rand_core::{CryptoRngCore, OsRng, RngCore};

use svr3_osdi24_client::net::auth::Auth;
use svr3_osdi24_client::net::enclave::{EnclaveEndpoint, EnclaveEndpointConnection, MrEnclave, Nitro, PpssSetup, SgxTest, Svr3Flavor};
use svr3_osdi24_client::net::env::DomainConfig;
use svr3_osdi24_client::net::{infra::tcp_ssl::UnsecuredConnector, svr::SvrConnection};
use svr3_osdi24_client::net::svr3::{OpaqueMaskedShareSet, PpssOps};


const TEST_SERVER_CERT: RootCertificates =
    RootCertificates::FromDer(include_bytes!("/home/rolfe/signal/git/libsignal-private/rust/net/res/sgx_test_server_cert.cer"));
const TEST_SERVER_RAFT_CONFIG: RaftConfig = RaftConfig {
    min_voting_replicas: 1,
    max_voting_replicas: 5,
    super_majority: 0,
    group_id: 7794251874196521851,
};

const TEST_SERVER_DOMAIN_CONFIG_NITRO: DomainConfig = DomainConfig {
    hostname: "localhost",
    ip_v4: &[Ipv4Addr::new(127, 0, 0, 1)],
    ip_v6: &[],
    cert: &TEST_SERVER_CERT,
    proxy_path: "/svr3-test",
    port: Some(8000u16),
};
const TEST_SERVER_DOMAIN_CONFIG_SGX: DomainConfig = DomainConfig {
    hostname: "localhost",
    ip_v4: &[Ipv4Addr::new(127, 0, 0, 1)], //127.0.0.1
    ip_v6: &[],
    cert: &TEST_SERVER_CERT,
    proxy_path: "/svr3-test",
    port: Some(8100u16),
};

pub struct TwoForTwoEnv<'a, A, B>(EnclaveEndpoint<'a, A>, EnclaveEndpoint<'a, B>)
where
    A: Svr3Flavor,
    B: Svr3Flavor;

impl<'a, A, B, S> PpssSetup<S> for TwoForTwoEnv<'a, A, B>
where
    A: Svr3Flavor + Send,
    B: Svr3Flavor + Send,
    S: Send,
{
    type Connections = (SvrConnection<A, S>, SvrConnection<B, S>);
    type ServerIds = [u64; 2];

    fn server_ids() -> Self::ServerIds {
        [0, 1]
    }
}

#[derive(Parser, Debug)]
struct Args {
    /// base64 encoding of the auth secret for enclaves
    #[arg(long)]
    enclave_secret: Option<String>,
    /// Password to be used to protect the data
    #[arg(long)]
    password: String,
    #[arg(long)]
    statfile: String,
    #[arg(long)]
    attest_doc: Option<String>,
}

#[tokio::main]
async fn main() {
    main_local().await;
}

async fn main_local() {

    let args = Args::parse();

    let enclave_secret: [u8; 32] = {
        let b64 = &args
            .enclave_secret
            .or_else(|| Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string()))
            .expect("Enclave secret is not set");
        parse_auth_secret(b64)
    };

    let statfile = File::create(args.statfile).unwrap();
    let mut writer = BufWriter::new(&statfile);
    let mut rng = OsRng;

    let sgx_nitro_env = {
        let endpoint_sgx = EnclaveEndpoint::<SgxTest> {
            domain_config: TEST_SERVER_DOMAIN_CONFIG_SGX,
            mr_enclave: MrEnclave::new(b"artifact"),
        };
        let endpoint_nitro = EnclaveEndpoint::<Nitro> {
                domain_config: TEST_SERVER_DOMAIN_CONFIG_NITRO,
                mr_enclave: MrEnclave::new(b"artifact"),
        };
        TwoForTwoEnv(endpoint_sgx, endpoint_nitro)
    };

    let  attest_doc = match &args.attest_doc {
        Some(fname) => fname,
        None => "",
    };

    write!(&mut writer, "prepare oprfs,call servers,finalize oprfs,compute backup,total backup time, total restore time\n").expect("write header");
    for i in 0..100 {

        let uid = {
            let mut bytes = [0u8; 16];
            rng.fill_bytes(&mut bytes[..]);
            bytes
        };
        let auth = Auth::from_uid_and_secret(uid, enclave_secret);
        let connect_local = || async {
            let connector = UnsecuredConnector::new(DnsResolver::default());
            let connection_a = EnclaveEndpointConnection::with_custom_properties(sgx_nitro_env.0, Duration::from_secs(10), Some(&TEST_SERVER_RAFT_CONFIG));
            let fut_a = SvrConnection::<SgxTest, _>::connect(auth.clone(), &connection_a, connector.clone());
            
            let connection_b = EnclaveEndpointConnection::with_custom_properties(sgx_nitro_env.1, Duration::from_secs(10), Some(&TEST_SERVER_RAFT_CONFIG));
            let fut_b = SvrConnection::<Nitro, _>::connect(auth.clone(), &connection_b, connector.clone());

            let (r_a, r_b) = futures::join!(fut_a, fut_b);
            let a= r_a.expect("can attestedly connect to SGX");
            let b= r_b.expect("can attestedly connect to Nitro");

            if i == 0 && attest_doc.len() > 0 {
                    match &b.inner.attestation_doc {
                        Some(doc) => {
                            let mut file = File::create(attest_doc).unwrap();
                            file.write_all(&doc).unwrap();
                        },
                        None => (),
                    }
                
            };
            (a,b)
        };

        let connections = connect_local().await;
        
        
        let secret = make_secret(&mut rng);
        println!("Secret to be stored: {}", hex::encode(secret));

        let backup_start = SystemTime::now();
        let share_set_bytes = {
            let opaque_share_set: OpaqueMaskedShareSet = TwoForTwoEnv::backup(
                connections,
                &args.password,
                secret,
                nonzero!(10u32),
                &mut rng,
            )
            .await
            .expect("can multi backup");
        write!(&mut writer, "{},{},{},{},", opaque_share_set.prep_oprf_dur, opaque_share_set.network_duration, opaque_share_set.finalize_oprf_dur, opaque_share_set.compute_backup_dur).expect("write");
            opaque_share_set.serialize().expect("can serialize")
        };
        let backup_duration = SystemTime::now().duration_since(backup_start);
        println!("Share set: {}", hex::encode(&share_set_bytes));

        let restore_connections = connect_local().await;
        let restore_start = SystemTime::now();
        let restored = {
            let opaque_share_set =
                OpaqueMaskedShareSet::deserialize(&share_set_bytes).expect("can deserialize");
                TwoForTwoEnv::restore(restore_connections, &args.password, opaque_share_set, &mut rng)
                .await
                .expect("can mutli restore")
        };
        let restore_duration = SystemTime::now().duration_since(restore_start);
        println!("Restored secret: {}", hex::encode(restored));
        write!(&mut writer, "{},{}\n", backup_duration.unwrap().as_micros(), restore_duration.unwrap().as_micros()).expect("write");
        assert_eq!(secret, restored);
    }
}

fn make_secret(rng: &mut impl CryptoRngCore) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes[..]);
    bytes
}

fn parse_auth_secret(b64: &str) -> [u8; 32] {
    BASE64_STANDARD
        .decode(b64)
        .expect("valid b64")
        .try_into()
        .expect("secret is 32 bytes")
}

