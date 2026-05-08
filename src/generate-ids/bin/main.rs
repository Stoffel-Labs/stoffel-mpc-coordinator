use clap::Parser;
use std::fs;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    cert: String,

    #[arg(long)]
    key: String,

    #[arg(long, required=true, value_delimiter=',', num_args=1..)]
    subject_alt_names: Vec<String>,
}

fn main() {
    let args = Args::parse();
    let cert = rcgen::generate_simple_self_signed(args.subject_alt_names).unwrap();
    let cert_der = cert.cert.der().to_vec();
    let key_der = cert.signing_key.serialize_der();

    fs::write(args.cert, cert_der).unwrap();
    fs::write(args.key, key_der).unwrap();
}
