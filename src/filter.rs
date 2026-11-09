//! A small subset of the pcap-filter(7) language:
//!
//! ```text
//! expr    := term ( ("or" | "||") term )*
//! term    := factor ( ("and" | "&&") factor )*
//! factor  := ("not" | "!") factor | "(" expr ")" | prim
//! prim    := [proto] [dir] ("host" ADDR | "port" NUM)
//!          | dir ADDR                     -- "src 10.0.0.1" == "src host 10.0.0.1"
//!          | proto                        -- tcp, udp, icmp, icmp6, ip, ip6, arp
//!          | ADDR | NUM                   -- repeats the previous qualifier: "host a or b"
//! dir     := "src" | "dst" | "src or dst" | "src and dst"
//! ```

use std::net::{IpAddr, ToSocketAddrs};

use crate::packet::{Net, Packet, PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    Src,
    Dst,
    SrcOrDst,
    SrcAndDst,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Ip,
    Ip6,
    Arp,
    Tcp,
    Udp,
    Icmp,
    Icmp6,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    True,
    Host(Dir, Vec<IpAddr>),
    Port(Option<Proto>, Dir, u16),
    Proto(Proto),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
}

#[derive(Debug, PartialEq)]
pub struct ParseError {
    pub msg: String,
    /// Byte offset into the expression string where the error was found.
    pub pos: usize,
}

impl ParseError {
    /// Format the error with a caret pointing at the offending token.
    pub fn render(&self, src: &str) -> String {
        format!("{}\n  {}\n  {}^", self.msg, src, " ".repeat(src[..self.pos.min(src.len())].chars().count()))
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Word(String),
    LParen,
    RParen,
    And,
    Or,
    Not,
}

fn lex(s: &str) -> Result<Vec<(Tok, usize)>, ParseError> {
    let mut out = Vec::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        match c {
            b' ' | b'\t' | b'\r' | b'\n' => i += 1,
            b'(' => {
                out.push((Tok::LParen, i));
                i += 1
            }
            b')' => {
                out.push((Tok::RParen, i));
                i += 1
            }
            b'&' if b.get(i + 1) == Some(&b'&') => {
                out.push((Tok::And, i));
                i += 2
            }
            b'|' if b.get(i + 1) == Some(&b'|') => {
                out.push((Tok::Or, i));
                i += 2
            }
            b'!' => {
                out.push((Tok::Not, i));
                i += 1
            }
            _ if c.is_ascii_alphanumeric() || b".:-_%".contains(&c) => {
                let start = i;
                while i < b.len() && (b[i].is_ascii_alphanumeric() || b".:-_%".contains(&b[i])) {
                    i += 1;
                }
                let w = s[start..i].to_ascii_lowercase();
                let t = match w.as_str() {
                    "and" => Tok::And,
                    "or" => Tok::Or,
                    "not" => Tok::Not,
                    _ => Tok::Word(w),
                };
                out.push((t, start));
            }
            _ => {
                return Err(ParseError { msg: format!("syntax error: unexpected character '{}'", c as char), pos: i })
            }
        }
    }
    Ok(out)
}

/// What a bare value ("host a or b") should inherit.
#[derive(Clone, Copy)]
enum Qual {
    Host(Dir),
    Port(Option<Proto>, Dir),
}

struct Parser<'a> {
    toks: Vec<(Tok, usize)>,
    i: usize,
    end: usize,
    last: Option<Qual>,
    resolve: &'a dyn Fn(&str) -> Option<Vec<IpAddr>>,
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.i).map(|t| &t.0)
    }
    fn pos(&self) -> usize {
        self.toks.get(self.i).map_or(self.end, |t| t.1)
    }
    fn err<T>(&self, msg: impl Into<String>) -> Result<T, ParseError> {
        Err(ParseError { msg: msg.into(), pos: self.pos() })
    }
    fn word(&self) -> Option<&str> {
        match self.peek() {
            Some(Tok::Word(w)) => Some(w),
            _ => None,
        }
    }

    fn expr(&mut self) -> Result<Expr, ParseError> {
        let mut lhs = self.term()?;
        while self.peek() == Some(&Tok::Or) {
            self.i += 1;
            lhs = Expr::Or(Box::new(lhs), Box::new(self.term()?));
        }
        Ok(lhs)
    }

    fn term(&mut self) -> Result<Expr, ParseError> {
        let mut lhs = self.factor()?;
        while self.peek() == Some(&Tok::And) {
            self.i += 1;
            lhs = Expr::And(Box::new(lhs), Box::new(self.factor()?));
        }
        Ok(lhs)
    }

    fn factor(&mut self) -> Result<Expr, ParseError> {
        match self.peek() {
            Some(Tok::Not) => {
                self.i += 1;
                Ok(Expr::Not(Box::new(self.factor()?)))
            }
            Some(Tok::LParen) => {
                self.i += 1;
                let e = self.expr()?;
                if self.peek() != Some(&Tok::RParen) {
                    return self.err("syntax error: expected ')'");
                }
                self.i += 1;
                Ok(e)
            }
            Some(Tok::Word(_)) => self.prim(),
            None => self.err("syntax error: unexpected end of expression"),
            _ => self.err("syntax error"),
        }
    }

    /// Parse an optional direction qualifier.
    fn dir(&mut self) -> Option<Dir> {
        let d = match self.word()? {
            "src" => Dir::Src,
            "dst" => Dir::Dst,
            _ => return None,
        };
        self.i += 1;
        // "src or dst" / "src and dst" (lookahead so "src host a or dst host b" still works)
        let other = if d == Dir::Src { "dst" } else { "src" };
        if matches!(self.peek(), Some(Tok::Or) | Some(Tok::And))
            && matches!(self.toks.get(self.i + 1), Some((Tok::Word(w), _)) if w == other)
        {
            let combined = if self.peek() == Some(&Tok::Or) { Dir::SrcOrDst } else { Dir::SrcAndDst };
            self.i += 2;
            return Some(combined);
        }
        Some(d)
    }

    fn proto_word(w: &str) -> Option<Proto> {
        Some(match w {
            "ip" => Proto::Ip,
            "ip6" => Proto::Ip6,
            "arp" => Proto::Arp,
            "tcp" => Proto::Tcp,
            "udp" => Proto::Udp,
            "icmp" => Proto::Icmp,
            "icmp6" => Proto::Icmp6,
            _ => return None,
        })
    }

    fn prim(&mut self) -> Result<Expr, ParseError> {
        let mut proto = None;
        if let Some(p) = self.word().and_then(Self::proto_word) {
            self.i += 1;
            proto = Some(p);
        }
        let dir = self.dir();
        match self.word() {
            Some("host") => {
                if proto.is_some() {
                    return self.err("'host' with a protocol qualifier is not supported");
                }
                self.i += 1;
                let d = dir.unwrap_or(Dir::SrcOrDst);
                self.last = Some(Qual::Host(d));
                self.host_value(d)
            }
            Some("port") => {
                if matches!(proto, Some(p) if p != Proto::Tcp && p != Proto::Udp) {
                    return self.err("'port' is only valid with tcp or udp");
                }
                self.i += 1;
                let d = dir.unwrap_or(Dir::SrcOrDst);
                self.last = Some(Qual::Port(proto, d));
                self.port_value(proto, d)
            }
            Some(_) if dir.is_some() => {
                // "src 10.0.0.1"
                if proto.is_some() {
                    return self.err("expected 'host' or 'port'");
                }
                let d = dir.unwrap();
                self.last = Some(Qual::Host(d));
                self.host_value(d)
            }
            _ if dir.is_some() => self.err("syntax error: expected 'host', 'port' or an address"),
            _ if proto.is_some() => Ok(Expr::Proto(proto.unwrap())),
            Some(_) => match self.last {
                Some(Qual::Host(d)) => self.host_value(d),
                Some(Qual::Port(p, d)) => self.port_value(p, d),
                None => {
                    let w = self.word().unwrap_or_default().to_string();
                    self.err(format!("syntax error: unknown primitive '{w}' (supported: host, src, dst, port, tcp, udp, icmp, ip, ip6, arp)"))
                }
            },
            None => self.err("syntax error: expected a primitive"),
        }
    }

    fn host_value(&mut self, d: Dir) -> Result<Expr, ParseError> {
        let Some(w) = self.word().map(str::to_string) else {
            return self.err("syntax error: expected a host address or name");
        };
        let addrs = match w.parse::<IpAddr>() {
            Ok(a) => vec![a],
            Err(_) => match (self.resolve)(&w) {
                Some(v) if !v.is_empty() => v,
                _ => return self.err(format!("unknown host '{w}'")),
            },
        };
        self.i += 1;
        Ok(Expr::Host(d, addrs))
    }

    fn port_value(&mut self, p: Option<Proto>, d: Dir) -> Result<Expr, ParseError> {
        let Some(w) = self.word().map(str::to_string) else {
            return self.err("syntax error: expected a port number");
        };
        let port = match w.parse::<u16>() {
            Ok(n) => n,
            Err(_) => match service_port(&w) {
                Some(n) => n,
                None => return self.err(format!("unknown port '{w}'")),
            },
        };
        self.i += 1;
        Ok(Expr::Port(p, d, port))
    }
}

/// A few common service names so "port https" works like on Linux.
fn service_port(name: &str) -> Option<u16> {
    Some(match name {
        "ftp-data" => 20,
        "ftp" => 21,
        "ssh" => 22,
        "telnet" => 23,
        "smtp" => 25,
        "domain" | "dns" => 53,
        "bootps" => 67,
        "bootpc" => 68,
        "http" | "www" => 80,
        "kerberos" => 88,
        "pop3" => 110,
        "ntp" => 123,
        "netbios-ns" => 137,
        "netbios-dgm" => 138,
        "netbios-ssn" => 139,
        "imap" => 143,
        "snmp" => 161,
        "ldap" => 389,
        "https" => 443,
        "microsoft-ds" | "smb" => 445,
        "syslog" => 514,
        "ldaps" => 636,
        "mssql" => 1433,
        "mysql" => 3306,
        "rdp" | "ms-wbt-server" => 3389,
        "winrm" => 5985,
        _ => return None,
    })
}

fn system_resolve(name: &str) -> Option<Vec<IpAddr>> {
    let mut v: Vec<IpAddr> = (name, 0).to_socket_addrs().ok()?.map(|s| s.ip()).collect();
    v.dedup();
    Some(v)
}

/// Parse a filter expression, resolving hostnames with the system resolver.
pub fn parse(src: &str) -> Result<Expr, ParseError> {
    parse_with(src, &system_resolve)
}

pub fn parse_with(src: &str, resolve: &dyn Fn(&str) -> Option<Vec<IpAddr>>) -> Result<Expr, ParseError> {
    let toks = lex(src)?;
    if toks.is_empty() {
        return Ok(Expr::True);
    }
    let mut p = Parser { toks, i: 0, end: src.len(), last: None, resolve };
    let e = p.expr()?;
    if p.i != p.toks.len() {
        return p.err("syntax error: expected 'and' or 'or'");
    }
    Ok(e)
}

fn dir_match<T>(d: Dir, src: T, dst: T, want: impl Fn(&T) -> bool) -> bool {
    match d {
        Dir::Src => want(&src),
        Dir::Dst => want(&dst),
        Dir::SrcOrDst => want(&src) || want(&dst),
        Dir::SrcAndDst => want(&src) && want(&dst),
    }
}

impl Expr {
    pub fn matches(&self, p: &Packet) -> bool {
        match self {
            Expr::True => true,
            Expr::And(a, b) => a.matches(p) && b.matches(p),
            Expr::Or(a, b) => a.matches(p) || b.matches(p),
            Expr::Not(a) => !a.matches(p),
            Expr::Host(d, addrs) => {
                let (s, t) = match &p.net {
                    Net::Ip(ip) => (ip.src, ip.dst),
                    Net::Arp(a) => (IpAddr::V4(a.sender_ip), IpAddr::V4(a.target_ip)),
                    Net::Other => return false,
                };
                dir_match(*d, s, t, |a| addrs.iter().any(|x| canonical(x) == canonical(a)))
            }
            Expr::Port(proto, d, port) => {
                let Some((s, t)) = p.ports() else { return false };
                let proto_ok = match proto {
                    None => true,
                    Some(Proto::Tcp) => p.ip_proto() == Some(PROTO_TCP),
                    Some(Proto::Udp) => p.ip_proto() == Some(PROTO_UDP),
                    Some(_) => false,
                };
                proto_ok && dir_match(*d, s, t, |x| x == port)
            }
            Expr::Proto(proto) => match (proto, &p.net) {
                (Proto::Ip, Net::Ip(ip)) => ip.src.is_ipv4(),
                (Proto::Ip6, Net::Ip(ip)) => ip.src.is_ipv6(),
                (Proto::Arp, Net::Arp(_)) => true,
                (Proto::Tcp, Net::Ip(ip)) => ip.proto == PROTO_TCP,
                (Proto::Udp, Net::Ip(ip)) => ip.proto == PROTO_UDP,
                (Proto::Icmp, Net::Ip(ip)) => ip.proto == PROTO_ICMP && ip.src.is_ipv4(),
                (Proto::Icmp6, Net::Ip(ip)) => ip.proto == PROTO_ICMPV6,
                _ => false,
            },
        }
    }
}

/// Treat IPv4-mapped IPv6 addresses as their IPv4 form when comparing.
fn canonical(a: &IpAddr) -> IpAddr {
    match a {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(*a, IpAddr::V4),
        _ => *a,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::decode_ethernet;
    use crate::packet::tests::{ipv4_frame, ipv6_udp_frame};

    fn no_dns(_: &str) -> Option<Vec<IpAddr>> {
        None
    }
    fn p(s: &str) -> Expr {
        parse_with(s, &no_dns).unwrap_or_else(|e| panic!("{}", e.render(s)))
    }
    fn tcp(src: [u8; 4], dst: [u8; 4], sp: u16, dp: u16) -> Packet {
        decode_ethernet(&ipv4_frame(PROTO_TCP, src, dst, sp, dp)).unwrap()
    }
    fn udp(src: [u8; 4], dst: [u8; 4], sp: u16, dp: u16) -> Packet {
        decode_ethernet(&ipv4_frame(PROTO_UDP, src, dst, sp, dp)).unwrap()
    }

    #[test]
    fn empty_matches_everything() {
        assert_eq!(p(""), Expr::True);
        assert!(p("  ").matches(&tcp([1, 1, 1, 1], [2, 2, 2, 2], 1, 2)));
    }

    #[test]
    fn host_and_direction() {
        let pk = tcp([10, 0, 0, 2], [8, 8, 8, 8], 50000, 443);
        assert!(p("host 8.8.8.8").matches(&pk));
        assert!(p("host 10.0.0.2").matches(&pk));
        assert!(!p("host 1.2.3.4").matches(&pk));
        assert!(p("src host 10.0.0.2").matches(&pk));
        assert!(!p("src host 8.8.8.8").matches(&pk));
        assert!(p("dst 8.8.8.8").matches(&pk));
        assert!(p("src 10.0.0.2").matches(&pk));
        assert!(!p("dst 10.0.0.2").matches(&pk));
        assert!(p("src or dst host 8.8.8.8").matches(&pk));
        assert!(!p("src and dst host 8.8.8.8").matches(&pk));
    }

    #[test]
    fn ports() {
        let pk = tcp([10, 0, 0, 2], [8, 8, 8, 8], 50000, 443);
        assert!(p("port 443").matches(&pk));
        assert!(p("port https").matches(&pk));
        assert!(p("dst port 443").matches(&pk));
        assert!(!p("src port 443").matches(&pk));
        assert!(p("tcp port 443").matches(&pk));
        assert!(!p("udp port 443").matches(&pk));
        assert!(p("udp dst port 53").matches(&udp([10, 0, 0, 2], [10, 0, 0, 1], 5000, 53)));
    }

    #[test]
    fn boolean_ops_and_precedence() {
        let pk = tcp([10, 0, 0, 2], [8, 8, 8, 8], 50000, 443);
        assert!(p("host 8.8.8.8 and port 443").matches(&pk));
        assert!(!p("host 8.8.8.8 and not port 443").matches(&pk));
        assert!(p("host 1.1.1.1 or port 443").matches(&pk));
        assert!(p("port 22 or port 443 and host 8.8.8.8").matches(&pk));
        assert!(!p("(port 22 or port 80) and host 8.8.8.8").matches(&pk));
        assert!(p("! port 22 && host 8.8.8.8 || port 1").matches(&pk));
        assert!(p("tcp and not udp").matches(&pk));
    }

    #[test]
    fn repeated_qualifier() {
        // "host a or b" == "host a or host b"
        let pk = tcp([10, 0, 0, 2], [8, 8, 8, 8], 50000, 443);
        assert!(p("host 1.1.1.1 or 8.8.8.8").matches(&pk));
        assert!(p("port 80 or 443").matches(&pk));
    }

    #[test]
    fn ipv6_host() {
        let s: std::net::Ipv6Addr = "fe80::1".parse().unwrap();
        let d: std::net::Ipv6Addr = "ff02::fb".parse().unwrap();
        let pk = decode_ethernet(&ipv6_udp_frame(s, d, 5353, 5353)).unwrap();
        assert!(p("host fe80::1").matches(&pk));
        assert!(p("ip6 and udp port 5353").matches(&pk));
        assert!(!p("ip").matches(&pk));
    }

    #[test]
    fn resolves_hostnames() {
        let r = |n: &str| (n == "example").then(|| vec!["8.8.8.8".parse().unwrap()]);
        let e = parse_with("host example", &r).unwrap();
        assert!(e.matches(&tcp([10, 0, 0, 2], [8, 8, 8, 8], 1, 2)));
    }

    #[test]
    fn errors() {
        for bad in ["host", "port abc", "(host 1.1.1.1", "host 1.1.1.1 port 80", "foo", "src", "icmp port 1", "host 1.1.1.1 $"] {
            assert!(parse_with(bad, &no_dns).is_err(), "{bad} should fail");
        }
        let e = parse_with("host 1.1.1.1 port 80", &no_dns).unwrap_err();
        assert_eq!(e.pos, 13);
    }
}
