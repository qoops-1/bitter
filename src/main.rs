use bitter::{run, Settings};
use clap::Parser;
use std::{
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    process::exit,
};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::FmtSubscriber;

const REQUEST_PIECE_LEN: u32 = u32::pow(2, 14); // 16 KB

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long, default_value_t = LevelFilter::INFO)]
    log_level: LevelFilter,
    #[arg(short,long)]
    output_dir: Option<PathBuf>,
    metainfo: PathBuf,
}

fn main() {
    let args = Args::parse();

    let output_dir = args.output_dir.unwrap_or(PathBuf::from("./"));
    if !output_dir.is_dir() {
        eprintln!("failed to verify that {} is a directory", output_dir.to_string_lossy());
        exit(1);
    }
    let settings = Settings {
        port: 6881,
        ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        req_piece_len: REQUEST_PIECE_LEN,
        output_dir,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(args.log_level)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    run(args.metainfo, settings).unwrap_or_else(|err| {
        eprintln!("{}", err);
        exit(1)
    })
}
