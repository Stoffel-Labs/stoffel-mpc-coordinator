//! Computes a node roster's digest from the certificate files themselves.
//!
//! The coordinator is the roster authority, so a node or client that fetches a roster is
//! trusting whatever that coordinator served. This binary is the independent half of that
//! trust: anyone holding the node certificates out of band can compute the digest here and
//! compare it with the one the coordinator prints, the one a node logs on fetch, or the one
//! they intend to pass as `--expect-roster-digest` / `STOFFEL_EXPECT_ROSTER_DIGEST`.
//!
//! It talks to nothing. The digest is a pure function of the threshold and the certificates,
//! computed by the same `NodeRoster::digest` the coordinator and every node use, so agreement
//! here is agreement on the roster — and a mismatch means the roster someone was handed is
//! not the roster these files describe.
//!
//! ```text
//! roster-digest --t 1 --node-certs ids/nodes/cert0.crt,ids/nodes/cert1.crt,...
//! ```

use clap::Parser;
use std::fs::read;
use std::process::ExitCode;
use stoffel_mpc_coordinator_shared::{NodeCertificateDer, NodeRoster};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The node certificates (DER), in any order — the digest is order-independent because
    /// `NodeRoster` sorts into canonical order before hashing.
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    node_certs: Vec<String>,

    /// The corruption threshold the roster is built with. It is part of the digest, so a
    /// roster with the same certificates but a different `t` is a different roster.
    #[arg(long)]
    t: u64,

    /// Optional: the digest you expect. When given, the exit status is the comparison —
    /// 0 when it matches, 1 when it does not — so this can gate a deployment script.
    #[arg(long)]
    expect: Option<String>,
}

fn main() -> ExitCode {
    let args = Args::parse();

    if args.node_certs.is_empty() {
        eprintln!("--node-certs must name at least one certificate file");
        return ExitCode::from(2);
    }

    let certificates = match args
        .node_certs
        .iter()
        .map(|path| read(path).map(NodeCertificateDer::from_der))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(certificates) => certificates,
        Err(error) => {
            eprintln!("could not read a node certificate: {error}");
            return ExitCode::from(2);
        }
    };

    let roster = match NodeRoster::new(args.t, certificates) {
        Ok(roster) => roster,
        Err(error) => {
            eprintln!("these files are not a valid roster: {error}");
            return ExitCode::from(2);
        }
    };

    let digest = roster.digest();
    println!("n={} t={}", roster.n(), args.t);
    println!("{digest}");

    match args.expect {
        None => ExitCode::SUCCESS,
        Some(expected) => {
            let expected = expected.trim();
            if expected.eq_ignore_ascii_case(&digest.to_string()) {
                println!("matches --expect");
                ExitCode::SUCCESS
            } else {
                eprintln!("DOES NOT MATCH --expect {expected}");
                eprintln!(
                    "the roster these certificates describe is not the roster that digest names"
                );
                ExitCode::FAILURE
            }
        }
    }
}
