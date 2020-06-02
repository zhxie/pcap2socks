use pcap2socks;

fn main() {
    // Parse arguments
    let flags;
    match pcap2socks::parse() {
        Ok(f) => flags = f,
        Err(e) => {
            eprintln!("{}", &e);
            return;
        }
    }

    let inters = pcap2socks::interfaces();
    for inter in inters.iter() {
        println!("{}", inter);
    }
}
