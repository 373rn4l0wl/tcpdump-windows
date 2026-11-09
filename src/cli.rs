//! getopt-style argument parsing compatible with tcpdump's usual forms:
//! `-i 3`, `-i3`, `-nni 3`, `-w out.pcap`, `-c 10`, and a trailing filter expression.

#[derive(Debug, Default, PartialEq)]
pub struct Options {
    pub list_interfaces: bool,
    pub interface: Option<String>,
    pub write_file: Option<String>,
    pub count: Option<u64>,
    pub help: bool,
    pub version: bool,
    /// Filter expression (remaining arguments joined with spaces).
    pub filter: String,
}

pub const USAGE: &str = "\
Usage: tcpdump [-DhnU] [-c count] [-i interface] [-w file] [expression]

  -D            list interfaces that can be captured on
  -i interface  capture on this interface: a number from -D, an interface index,
                a name (e.g. \"Ethernet\"), the adapter GUID, or \"any\"
  -w file       write raw packets to a pcap file (\"-\" for stdout)
  -c count      exit after capturing count packets
  -n, -U        accepted for compatibility (names are never resolved;
                -w - is always packet-buffered)
  -h, --help    show this help
  --version     show version

Expression (pcap-filter subset):
  host ADDR, src [host] ADDR, dst [host] ADDR, [src|dst] port N,
  tcp | udp [src|dst] port N, tcp, udp, icmp, icmp6, ip, ip6, arp,
  combined with and/&&, or/||, not/!, and parentheses.
  Example: tcpdump -i Ethernet -w out.pcap host 10.0.0.5 and not port 3389

Must be run as Administrator.";

pub fn parse<I: IntoIterator<Item = String>>(args: I) -> Result<Options, String> {
    let mut o = Options::default();
    let mut rest = Vec::new();
    let mut it = args.into_iter();
    while let Some(arg) = it.next() {
        if arg == "--" {
            rest.extend(it.by_ref());
            break;
        }
        match arg.as_str() {
            "--help" => {
                o.help = true;
                continue;
            }
            "--version" => {
                o.version = true;
                continue;
            }
            "--list-interfaces" => {
                o.list_interfaces = true;
                continue;
            }
            _ => {}
        }
        // Map the long forms onto their short equivalents.
        let short = match arg.as_str() {
            "--interface" => "-i".to_string(),
            "--count" => "-c".to_string(),
            _ => arg.clone(),
        };
        if !short.starts_with('-') || short.len() < 2 || short.starts_with("--") {
            rest.push(arg);
            continue;
        }
        let chars: Vec<char> = short[1..].chars().collect();
        let mut j = 0;
        while j < chars.len() {
            let c = chars[j];
            j += 1;
            match c {
                'D' => o.list_interfaces = true,
                'h' => o.help = true,
                'n' | 'U' => {}
                'i' | 'w' | 'c' => {
                    let val: String = if j < chars.len() {
                        let v = chars[j..].iter().collect();
                        j = chars.len();
                        v
                    } else {
                        it.next().ok_or_else(|| format!("option requires an argument -- '{c}'"))?
                    };
                    match c {
                        'i' => o.interface = Some(val),
                        'w' => o.write_file = Some(val),
                        _ => {
                            let n: u64 = val.parse().map_err(|_| format!("invalid packet count {val}"))?;
                            if n == 0 {
                                return Err(format!("invalid packet count {val}"));
                            }
                            o.count = Some(n);
                        }
                    }
                }
                _ => return Err(format!("invalid option -- '{c}'")),
            }
        }
    }
    o.filter = rest.join(" ");
    Ok(o)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &[&str]) -> Result<Options, String> {
        parse(s.iter().map(|s| s.to_string()))
    }

    #[test]
    fn basic() {
        let o = p(&["-i", "3", "-w", "out.pcap", "host", "10.0.0.1", "and", "port", "80"]).unwrap();
        assert_eq!(o.interface.as_deref(), Some("3"));
        assert_eq!(o.write_file.as_deref(), Some("out.pcap"));
        assert_eq!(o.filter, "host 10.0.0.1 and port 80");
    }

    #[test]
    fn combined_and_attached() {
        let o = p(&["-nni", "Ethernet", "-c10", "-wout.pcap"]).unwrap();
        assert_eq!(o.interface.as_deref(), Some("Ethernet"));
        assert_eq!(o.count, Some(10));
        assert_eq!(o.write_file.as_deref(), Some("out.pcap"));
        assert!(p(&["-D"]).unwrap().list_interfaces);
    }

    #[test]
    fn quoted_filter_and_dash_dash() {
        let o = p(&["-i", "any", "port 53 or port 443"]).unwrap();
        assert_eq!(o.filter, "port 53 or port 443");
        let o = p(&["--", "-x"]).unwrap();
        assert_eq!(o.filter, "-x");
    }

    #[test]
    fn errors() {
        assert!(p(&["-i"]).is_err());
        assert!(p(&["-c", "abc"]).is_err());
        assert!(p(&["-z"]).is_err());
    }
}
