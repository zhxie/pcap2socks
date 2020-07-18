use env_logger::fmt::{Color, Formatter, Target};
use log::{error, info, Level, LevelFilter, Log, Metadata, Record};
use std::clone::Clone;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use structopt::StructOpt;

use pcap2socks::{self as lib, Forwarder, Redirector};

#[tokio::main]
async fn main() {
    // Parse arguments
    let flags = Flags::from_args();

    // Log
    set_logger(flags.verbose);

    // Interface
    let inter = match lib::interface(flags.inter) {
        Some(inter) => inter,
        None => {
            error!("Cannot determine the interface. Available interfaces are listed below, use -i <INTERFACE> to designate:");
            for inter in lib::interfaces().iter() {
                info!("    {}", inter);
            }
            return;
        }
    };
    info!("Listen on {}", inter);
    info!("Break packets with MTU {}", flags.mtu);

    // Route
    let src = match flags.preset {
        Some(ref preset) => match preset.as_str() {
            "t" | "tencent" => "10.6.0.1".parse().unwrap(),
            "n" | "netease" | "u" | "uu" => {
                let mut ip_octets = inter.ip_addrs[0].octets();
                ip_octets[0] = 172;
                ip_octets[1] = 24;
                ip_octets[2] = ip_octets[2].checked_add(1).unwrap_or(0);

                Ipv4Addr::from(ip_octets)
            }
            _ => {
                error!("The preset {} is not available", preset);
                return;
            }
        },
        None => flags.src.unwrap(),
    };
    let publish = match flags.preset {
        Some(ref preset) => match preset.as_str() {
            "t" | "tencent" => Some("10.6.0.2".parse().unwrap()),
            "n" | "netease" | "u" | "uu" => {
                let mut ip_octets = inter.ip_addrs[0].octets();
                ip_octets[0] = 172;
                ip_octets[1] = 24;

                Some(Ipv4Addr::from(ip_octets))
            }
            _ => {
                error!("The preset {} is not available", preset);
                return;
            }
        },
        None => flags.publish,
    };
    match publish {
        Some(publish) => {
            if src == publish {
                error!("The source cannot be the same with the publish");
                return;
            }
        }
        None => {
            if src == inter.ip_addrs[0] {
                error!("The source cannot be the same with the local address");
                return;
            }
        }
    }

    // Publish
    if let Some(publish) = publish {
        info!("Publish for {}", publish);
    }

    // Instructions
    show_info(src, publish.unwrap_or(inter.ip_addrs[0]), flags.mtu);

    // Proxy
    let (tx, mut rx) = match inter.open() {
        Ok((tx, rx)) => (tx, rx),
        Err(ref e) => {
            error!("{}", e);
            return;
        }
    };
    let forwarder = Forwarder::new(tx, flags.mtu, inter.hardware_addr, src, inter.ip_addrs[0]);
    let mut redirector = Redirector::new(Arc::new(Mutex::new(forwarder)), src, publish, flags.dst);
    info!("Proxy {} to {}", src, flags.dst);
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

#[derive(StructOpt, Clone, Debug, Eq, Hash, PartialEq)]
#[structopt(about)]
struct Flags {
    #[structopt(
        long,
        short,
        help = "Prints verbose information (-vv for vverbose)",
        parse(from_occurrences)
    )]
    pub verbose: usize,
    #[structopt(
        long = "interface",
        short,
        help = "Interface for listening",
        value_name = "INTERFACE"
    )]
    pub inter: Option<String>,
    #[structopt(long, help = "MTU", value_name = "VALUE", default_value = "1400")]
    pub mtu: u16,
    #[structopt(long, short = "P", help = "Preset", value_name = "PRESET")]
    pub preset: Option<String>,
    #[structopt(long, short, help = "ARP publishing address", value_name = "ADDRESS")]
    pub publish: Option<Ipv4Addr>,
    #[structopt(
        long = "source",
        short,
        help = "Source",
        value_name = "ADDRESS",
        required_unless("preset")
    )]
    pub src: Option<Ipv4Addr>,
    #[structopt(
        long = "destination",
        short,
        help = "Destination",
        value_name = "ADDRESS",
        default_value = "127.0.0.1:1080"
    )]
    pub dst: SocketAddrV4,
}

/// Represents a logger.
pub struct Logger {
    crate_name: &'static str,
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
            crate_name: env!("CARGO_PKG_NAME"),
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
        if metadata.target() != self.crate_name {
            return false;
        }
        match metadata.level() {
            Level::Error => self.stderr_logger.enabled(metadata),
            _ => self.stdout_logger.enabled(metadata),
        }
    }

    fn log(&self, record: &Record) {
        if record.metadata().target() != self.crate_name {
            return;
        }
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
