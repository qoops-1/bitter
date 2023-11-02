use bitter::{run, Settings};
use std::{
    env,
    net::{IpAddr, Ipv4Addr},
    process::exit,
};

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() != 2 {
        eprint!(
            "Wrong number of arguments. Expected 1, given {}",
            args.len()
        );
        exit(1);
    }
    let filename = &args[1];

    let settings = Settings {
        port: 6881,
        ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
    };

    run(filename, settings).unwrap_or_else(|err| {
        eprintln!("{}", err);
        exit(1)
    })
}
