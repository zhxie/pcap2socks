use env_logger::fmt::{Color, Formatter, Target};
use log::{error, info, warn, Level, LevelFilter, Log, Metadata, Record};
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
            error!("Cannot determine the interface. Available interfaces are listed below, and please use -i <INTERFACE> to designate:");
            for inter in lib::interfaces().iter() {
                info!("    {}", inter);
            }
            return;
        }
    };
    info!("Listen on {}", inter);

    // MTU
    let mtu = match flags.mtu {
        Some(mtu) => mtu,
        None => {
            if inter.mtu() <= 0 {
                error!("Cannot obtain the MTU. Please use --mtu <VALUE> to set");
                return;
            }

            inter.mtu()
        }
    };
    info!("Use MTU {}", mtu);

    // Route
    let mut srcs = match flags.preset {
        Some(ref preset) => match preset.as_str() {
            "t" | "tencent" => {
                let mut srcs = Vec::new();
                srcs.push(Ipv4Addr::new(10, 6, 0, 1));

                srcs
            }
            "n" | "netease" | "u" | "uu" => {
                let mut srcs = Vec::new();

                let mut ip_octets = inter.ip_addr().unwrap().octets();
                ip_octets[0] = 172;
                ip_octets[1] = 24;
                ip_octets[2] = ip_octets[2].checked_add(1).unwrap_or(0);

                srcs.push(Ipv4Addr::from(ip_octets));

                srcs
            }
            _ => {
                error!("The preset {} is not available", preset);
                return;
            }
        },
        None => flags.srcs.unwrap(),
    };
    srcs.dedup();
    let publish = match flags.preset {
        Some(ref preset) => match preset.as_str() {
            "t" | "tencent" => Some(Ipv4Addr::new(10, 6, 0, 2)),
            "n" | "netease" | "u" | "uu" => {
                let mut ip_octets = inter.ip_addr().unwrap().octets();
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
    let srcs_set = srcs.iter().map(|i| i.clone()).collect();
    match publish {
        Some(publish) => {
            if srcs.contains(&publish) {
                error!("The sources cannot contain the publish");
                return;
            }
        }
        None => {
            if srcs.contains(&inter.ip_addr().unwrap()) {
                error!("The sources cannot contain the local address");
                return;
            }
        }
    }

    // Publish
    if let Some(publish) = publish {
        info!("Publish for {}", publish);
    }

    // Instructions
    info!("Please set the network of your device which is going to be proxied with the following parameters:");
    for src in &srcs {
        show_info(src, &publish.unwrap_or(inter.ip_addr().unwrap()), mtu);
    }

    // Proxy
    let (tx, mut rx) = match inter.open() {
        Ok((tx, rx)) => (tx, rx),
        Err(ref e) => {
            error!("{}", e);
            return;
        }
    };
    let forwarder = Forwarder::new(tx, mtu, inter.hardware_addr(), inter.ip_addr().unwrap());
    let auth = match flags.username {
        Some(ref username) => Some((username.clone(), flags.password.unwrap())),
        None => None,
    };
    let mut redirector = Redirector::new(
        Arc::new(Mutex::new(forwarder)),
        srcs_set,
        publish,
        flags.dst,
        flags.force_associate_dst,
        auth,
    );
    let srcs_str = srcs
        .iter()
        .map(|i| i.to_string())
        .collect::<Vec<String>>()
        .join(", ");
    match flags.username {
        Some(username) => info!("Proxy {} to {}@{}", srcs_str, username, flags.dst),
        None => info!("Proxy {} to {}", srcs_str, flags.dst),
    }
    if let Err(ref e) = redirector.open(&mut rx).await {
        error!("{}", e);
    }
}

fn show_info(ip_addr: &Ipv4Addr, gateway: &Ipv4Addr, mtu: usize) {
    let ip_addr_octets = ip_addr.octets();
    let gateway_octets = gateway.octets();
    let mut mask_value = u32::from_be_bytes([
        !(ip_addr_octets[0] ^ gateway_octets[0]),
        !(ip_addr_octets[1] ^ gateway_octets[1]),
        !(ip_addr_octets[2] ^ gateway_octets[2]),
        !(ip_addr_octets[3] ^ gateway_octets[3]),
    ]);

    let mut prefix: u8 = 0;
    for p in 0u8..32 {
        if mask_value % 2 == 0 {
            prefix = p + 1;
        }
        mask_value >>= 1;
    }
    let mask_value = match prefix {
        32 => 0,
        _ => u32::MAX << prefix,
    };
    let mask = Ipv4Addr::from(mask_value);

    info!("    ┌─{:─<10}─{:─>15}─┐", "", "");
    info!("    │ {:<10} {:>15} │", "IP Address", ip_addr);
    info!("    │ {:<10} {:>15} │", "Mask", mask);
    info!("    │ {:<10} {:>15} │", "Gateway", gateway);
    info!("    │─{:─<10}─{:─>15}─│", "", "");
    info!("    │ {:<10} {:>15} │", "MTU", format!("<={}", mtu));
    info!("    └─{:─<10}─{:─>15}─┘", "", "");
    if mask == Ipv4Addr::UNSPECIFIED {
        warn!("The mask is all zeros, which may cause potential problems");
    }
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
        value_name = "INTERFACE",
        display_order(0)
    )]
    pub inter: Option<String>,
    #[structopt(long, help = "MTU", value_name = "VALUE", display_order(1))]
    pub mtu: Option<usize>,
    #[structopt(
        long,
        short = "P",
        help = "Preset",
        value_name = "PRESET",
        display_order(2)
    )]
    pub preset: Option<String>,
    #[structopt(
        long = "sources",
        short,
        help = "Sources",
        value_name = "ADDRESS",
        required_unless("preset"),
        display_order(3)
    )]
    pub srcs: Option<Vec<Ipv4Addr>>,
    #[structopt(
        long,
        short,
        help = "ARP publishing address",
        value_name = "ADDRESS",
        display_order(4)
    )]
    pub publish: Option<Ipv4Addr>,
    #[structopt(
        long = "destination",
        short,
        help = "Destination",
        value_name = "ADDRESS",
        default_value = "127.0.0.1:1080",
        display_order(5)
    )]
    pub dst: SocketAddrV4,
    #[structopt(
        long = "force-associate-destination",
        help = "Force to associate with the destination",
        display_order(1000)
    )]
    pub force_associate_dst: bool,
    #[structopt(
        long,
        help = "Username",
        value_name = "VALUE",
        requires("password"),
        display_order(1000)
    )]
    pub username: Option<String>,
    #[structopt(
        long,
        help = "Password",
        value_name = "VALUE",
        requires("username"),
        display_order(1001)
    )]
    pub password: Option<String>,
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
