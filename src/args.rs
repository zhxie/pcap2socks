use clap::{crate_description, crate_version, Clap};
use std::clone::Clone;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::net::{AddrParseError, Ipv4Addr, SocketAddrV4};
use std::result;

/// Represents the flags of the application.
#[derive(Clap)]
#[clap(
    version = crate_version!(),
    about = crate_description!()
)]
pub struct Flags {
    #[clap(long, short, about = "Prints verbose information")]
    pub verbose: bool,
    #[clap(long, short = "V", about = "Prints vverbose information")]
    pub vverbose: bool,
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
    pub publish: Option<String>,
    #[clap(long = "source", short, about = "Source", value_name = "ADDRESS")]
    pub src: String,
    #[clap(
        long = "destination",
        short,
        about = "Destination",
        value_name = "ADDRESS",
        default_value = "127.0.0.1:1080"
    )]
    pub dst: String,
}

/// Parses the arguments.
pub fn parse() -> Flags {
    Flags::parse()
}

/// Represents an error when parse arguments.
#[derive(Debug)]
pub enum ParseError {
    AddrParseError(AddrParseError),
    OutOfRangeError(&'static str, &'static str),
}

impl Display for ParseError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match &self {
            ParseError::AddrParseError(ref e) => write!(f, "parse: {}", e),
            ParseError::OutOfRangeError(ref value, ref range) => {
                write!(f, "parse: {} is out of range {}", value, range)
            }
        }
    }
}

impl Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self {
            ParseError::AddrParseError(ref e) => Some(e),
            ParseError::OutOfRangeError(_, _) => None,
        }
    }
}

impl From<AddrParseError> for ParseError {
    fn from(s: AddrParseError) -> Self {
        ParseError::AddrParseError(s)
    }
}

type Result = result::Result<Opts, ParseError>;

/// Represents the options of the application.
pub struct Opts {
    pub verbose: bool,
    pub vverbose: bool,
    pub inter: Option<String>,
    pub mtu: u16,
    pub publish: Option<Ipv4Addr>,
    pub src: Ipv4Addr,
    pub dst: SocketAddrV4,
}

impl Opts {
    /// Creates a new empty `Opts`.
    pub fn new() -> Opts {
        Opts {
            verbose: false,
            vverbose: false,
            inter: None,
            mtu: 1400,
            publish: None,
            src: Ipv4Addr::UNSPECIFIED,
            dst: SocketAddrV4::new("127.0.0.1".parse().unwrap(), 1080),
        }
    }

    /// Validates flags and creates a new `Opts`.
    pub fn validate(flags: &Flags) -> Result {
        if flags.mtu < 576 {
            return Err(ParseError::OutOfRangeError("MTU", "[576, 65535]"));
        }
        let mut publish = None;
        if let Some(p) = &flags.publish {
            publish = Some(p.parse()?);
        }
        let src = flags.src.parse()?;
        let dst = flags.dst.parse()?;

        Ok(Opts {
            verbose: flags.verbose,
            vverbose: flags.vverbose,
            mtu: flags.mtu,
            inter: flags.inter.clone(),
            publish,
            src,
            dst,
        })
    }
}
