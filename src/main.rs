use clap::{crate_description, crate_version, Clap};
use env_logger::fmt::{Color, Formatter, Target};
use log::{error, info, Level, LevelFilter, Log, Metadata, Record};
use std::clone::Clone;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::{Arc, Mutex};

use pcap2socks::{self as lib, Forwarder, Redirector};

#[tokio::main]
async fn main() {
    // Parse arguments
    let flags = Flags::parse();

    // Log
    set_logger(flags.verbose);

    // Interface
    let inter = match lib::interface(flags.inter) {
        Some(inter) => inter,
        None => {
            error!("Cannot determine interface. Available interfaces are listed below, use -i <INTERFACE> to designate:");
            for inter in lib::interfaces().iter() {
                info!("    {}", inter);
            }
            return;
        }
    };
    info!("Listen on {}", inter);
    info!("Break packets with MTU {}", flags.mtu);

    // Publish
    if let Some(publish) = flags.publish {
        info!("Publish for {}", publish);
    }

    // Instructions
    show_info(
        flags.src,
        flags.publish.unwrap_or(inter.ip_addrs[0]),
        flags.mtu,
    );

    // Proxy
    let (tx, mut rx) = match inter.open() {
        Ok((tx, rx)) => (tx, rx),
        Err(ref e) => {
            error!("{}", e);
            return;
        }
    };
    let forwarder = Forwarder::new(
        tx,
        flags.mtu,
        inter.hardware_addr,
        flags.src,
        inter.ip_addrs[0],
    );
    let mut redirector = Redirector::new(
        Arc::new(Mutex::new(forwarder)),
        flags.src,
        flags.publish,
        flags.dst,
    );
    info!("Proxy {} to {}", flags.src, flags.dst);
    if let Err(ref e) = redirector.open(&mut rx).await {
        error!("{}", e);
    }
}

fn show_info(ip_addr: Ipv4Addr, gateway: Ipv4Addr, mtu: u16) {
    let ip_addr_octets = ip_addr.octets();
    let gateway_octets = gateway.octets();
    let mask = Ipv4Addr::new(
        !(ip_addr_octets[0] ^ gateway_octets[0]),
        !(ip_addr_octets[1] ^ gateway_octets[1]),
        !(ip_addr_octets[2] ^ gateway_octets[2]),
        0,
    );
    info!("Please set the network of your device which is going to be proxied with the following parameters:");
    info!("    ┌─{:─<10}─{:─>15}─┐", "", "");
    info!("    │ {:<10} {:>15} │", "IP Address", ip_addr);
    info!("    │ {:<10} {:>15} │", "Mask", mask);
    info!("    │ {:<10} {:>15} │", "Gateway", gateway);
    info!("    │─{:─<10}─{:─>15}─│", "", "");
    info!("    │ {:<10} {:>15} │", "MTU", mtu);
    info!("    └─{:─<10}─{:─>15}─┘", "", "");
}

#[derive(Clap, Clone, Debug, Eq, Hash, PartialEq)]
#[clap(
    version = crate_version!(),
    about = crate_description!()
)]
struct Flags {
    #[clap(
        long,
        short,
        about = "Prints verbose information (-vv for vverbose)",
        parse(from_occurrences)
    )]
    pub verbose: usize,
    #[clap(
        long = "interface",
        short,
        about = "Interface for listening",
        value_name = "INTERFACE"
    )]
    pub inter: Option<String>,
    #[clap(long, about = "MTU", value_name = "VALUE", default_value = "1400")]
    pub mtu: u16,
    #[clap(long, short, about = "ARP publishing address", value_name = "ADDRESS")]
    pub publish: Option<Ipv4Addr>,
    #[clap(long = "source", short, about = "Source", value_name = "ADDRESS")]
    pub src: Ipv4Addr,
    #[clap(
        long = "destination",
        short,
        about = "Destination",
        value_name = "ADDRESS",
        default_value = "127.0.0.1:1080"
    )]
    pub dst: SocketAddrV4,
}

/// Represents a logger.
pub struct Logger {
    stderr_logger: env_logger::Logger,
    stdout_logger: env_logger::Logger,
}

impl Logger {
    /// Initializes the global logger.
    pub fn init(level: LevelFilter) {
        let fmt = |buf: &mut Formatter, record: &Record| {
            let mut style = buf.style();

            let level = match &record.level() {
                Level::Error => style.set_bold(true).set_color(Color::Red).value("error: "),
                Level::Warn => style
                    .set_bold(true)
                    .set_color(Color::Yellow)
                    .value("warning: "),
                Level::Info => style.set_bold(true).set_color(Color::Green).value(""),
                _ => style.set_color(Color::Rgb(165, 165, 165)).value(""),
            };
            writeln!(buf, "{}{}", level, record.args())
        };

        let stderr_logger = env_logger::builder()
            .target(Target::Stderr)
            .filter_level(level)
            .format(fmt)
            .build();
        let stdout_logger = env_logger::builder()
            .target(Target::Stdout)
            .filter_level(level)
            .format(fmt)
            .build();

        let logger = Logger {
            stderr_logger,
            stdout_logger,
        };

        // Set the logger
        let r = log::set_boxed_logger(Box::new(logger));
        if r.is_ok() {
            log::set_max_level(level);
        }
    }
}

impl Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        match metadata.level() {
            Level::Error => self.stderr_logger.enabled(metadata),
            _ => self.stdout_logger.enabled(metadata),
        }
    }

    fn log(&self, record: &Record) {
        match record.metadata().level() {
            Level::Error => self.stderr_logger.log(record),
            _ => self.stdout_logger.log(record),
        }
    }

    fn flush(&self) {}
}

fn set_logger(verbose: usize) {
    let level = match verbose {
        0 => LevelFilter::Info,
        1 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };
    Logger::init(level);
}
