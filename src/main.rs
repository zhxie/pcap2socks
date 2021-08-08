use env_logger::fmt::{Color, Formatter, Target};
use ipnetwork::Ipv4Network;
use log::{error, info, warn, Level, LevelFilter, Log, Metadata, Record};
use std::clone::Clone;
use std::fmt::Display;
use std::io::{self, Write};
use std::net::{AddrParseError, IpAddr, Ipv4Addr, SocketAddrV4};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use structopt::StructOpt;

use pcap2socks::{self as lib, Forwarder, ProxyConfig, Redirector};

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
    let src = match flags.preset {
        Some(ref preset) => match preset.as_str() {
            "t" | "tencent" => Ipv4Network::new(Ipv4Addr::new(10, 6, 0, 1), 32).unwrap(),
            "n" | "netease" | "u" | "uu" => {
                let mut ip_octets = inter.ip_addr().unwrap().octets();
                ip_octets[0] = 172;
                ip_octets[1] = 24;
                ip_octets[2] = ip_octets[2].checked_add(1).unwrap_or(0);

                Ipv4Network::new(Ipv4Addr::from(ip_octets), 32).unwrap()
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

    // Publish
    if let Some(publish) = publish {
        info!("Publish for {}", publish);
    }

    // Gateway
    let gw = publish.unwrap_or(inter.ip_addr().unwrap());
    if src.size() == 1 && src.network() == gw {
        error!("The source cannot be the same with the gateway (publish)");
        return;
    }

    // Instructions
    show_info(src, gw, mtu);

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
        src,
        gw,
        publish,
        ProxyConfig::new_socks(
            flags.dst.addr(),
            flags.force_associate_dst,
            flags.force_associate_bind_addr,
            auth,
        ),
        None,
    );
    match flags.username {
        Some(username) => info!("Proxy {} to {}@{}", src, username, flags.dst),
        None => info!("Proxy {} to {}", src, flags.dst),
    }
    if let Err(ref e) = redirector.open(&mut rx).await {
        error!("{}", e);
    }
}

fn show_info(src: Ipv4Network, gw: Ipv4Addr, mtu: usize) {
    macro_rules! max {
        ($x: expr) => ($x);
        ($x: expr, $($z: expr),+) => (::std::cmp::max($x, max!($($z),*)));
    }

    let src_str = match src.size() {
        1 => src.network().to_string(),
        _ => format!("{} - {}", src.network(), src.nth(src.size() - 1).unwrap()),
    };
    let mtu_str = format!("<={}", mtu);
    let src_octets = src.network().octets();
    let mask_octets = src.mask().octets();
    let gw_octets = gw.octets();

    // Mask, align to 8 bytes
    let mut mask_octets = [
        !(src_octets[0] ^ gw_octets[0]) & mask_octets[0],
        !(src_octets[1] ^ gw_octets[1]) & mask_octets[1],
        !(src_octets[2] ^ gw_octets[2]) & mask_octets[2],
        !(src_octets[3] ^ gw_octets[3]) & mask_octets[3],
    ];
    let mut is_zero = false;
    mask_octets.iter_mut().for_each(|b| {
        if is_zero || *b != u8::MAX {
            *b = 0;
            is_zero = true;
        }
    });
    let mask_value = u32::from_be_bytes(mask_octets);
    let mask = Ipv4Addr::from(mask_value);

    let width = max!(
        src_str.len(),
        mask.to_string().len(),
        gw.to_string().len(),
        mtu_str.len()
    );
    info!("Please set the network of your device which is going to be proxied with the following parameters:");
    info!("    ┌─────────────{:─>w$}─┐", "", w = width);
    info!("    │ IP Address  {:>w$} │", src_str, w = width);
    info!("    │ Mask        {:>w$} │", mask, w = width);
    info!("    │ Gateway     {:>w$} │", gw, w = width);
    info!("    │─────────────{:─>w$}─│", "", w = width);
    info!("    │ MTU         {:>w$} │", mtu_str, w = width);
    info!("    └─────────────{:─>w$}─┘", "", w = width);
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
        long = "source",
        short,
        help = "Source",
        value_name = "ADDRESS",
        required_unless("preset"),
        display_order(3)
    )]
    pub src: Option<Ipv4Network>,
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
    pub dst: ResolvableSocketAddrV4,
    #[structopt(
        long = "force-associate-destination",
        help = "Force to associate with the destination",
        conflicts_with("force_associate_bind_addr"),
        display_order(1000)
    )]
    pub force_associate_dst: bool,
    #[structopt(
        long = "force-associate-bind-address",
        help = "Force to associate with the replied bind address",
        display_order(1001)
    )]
    pub force_associate_bind_addr: bool,
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
struct Logger {
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

#[derive(Debug)]
enum ResolvableAddrParseError {
    AddrParseError(AddrParseError),
    ResolveError(io::Error),
}

impl Display for ResolvableAddrParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolvableAddrParseError::AddrParseError(e) => write!(f, "{}", e),
            ResolvableAddrParseError::ResolveError(e) => write!(f, "{}", e),
        }
    }
}

impl From<AddrParseError> for ResolvableAddrParseError {
    fn from(s: AddrParseError) -> Self {
        ResolvableAddrParseError::AddrParseError(s)
    }
}

impl From<io::Error> for ResolvableAddrParseError {
    fn from(s: io::Error) -> Self {
        ResolvableAddrParseError::ResolveError(s)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ResolvableSocketAddrV4 {
    addr: SocketAddrV4,
    alias: Option<String>,
}

impl ResolvableSocketAddrV4 {
    fn addr(&self) -> SocketAddrV4 {
        self.addr
    }
}

impl Display for ResolvableSocketAddrV4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.alias {
            Some(alias) => write!(f, "{} ({})", alias, self.addr),
            None => write!(f, "{}", self.addr),
        }
    }
}

impl FromStr for ResolvableSocketAddrV4 {
    type Err = ResolvableAddrParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let has_alias;
        let addr = match s.parse() {
            Ok(addr) => {
                has_alias = false;

                addr
            }
            Err(e) => {
                has_alias = true;

                let v = s.split(":").collect::<Vec<_>>();
                if v.len() != 2 {
                    return Err(ResolvableAddrParseError::from(e));
                }

                let port = match v[1].parse() {
                    Ok(port) => port,
                    Err(_) => return Err(ResolvableAddrParseError::from(e)),
                };
                let ip = match dns_lookup::lookup_host(v[0]) {
                    Ok(addrs) => {
                        let mut ip = None;

                        for addr in addrs {
                            if let IpAddr::V4(addr) = addr {
                                ip = Some(addr);
                                break;
                            }
                        }

                        match ip {
                            Some(ip) => ip,
                            None => return Err(ResolvableAddrParseError::from(e)),
                        }
                    }
                    Err(e) => return Err(ResolvableAddrParseError::from(e)),
                };

                SocketAddrV4::new(ip, port)
            }
        };

        let alias = match has_alias {
            true => Some(String::from_str(s).unwrap()),
            false => None,
        };
        Ok(ResolvableSocketAddrV4 { addr, alias })
    }
}
