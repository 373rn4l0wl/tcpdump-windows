//! tcpdump-style one-line packet summaries.

use std::fmt::Write;
use std::net::IpAddr;

use crate::packet::{Net, Packet, Transport, PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP};

fn mac_str(m: &[u8; 6]) -> String {
    m.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

fn tcp_flags(f: u8) -> String {
    const FLAGS: [(u8, char); 8] =
        [(0x01, 'F'), (0x02, 'S'), (0x04, 'R'), (0x08, 'P'), (0x10, '.'), (0x20, 'U'), (0x40, 'E'), (0x80, 'W')];
    let s: String = FLAGS.iter().filter(|(bit, _)| f & bit != 0).map(|(_, c)| *c).collect();
    if s.is_empty() {
        "none".into()
    } else {
        s
    }
}

fn icmp4_name(t: u8, code: u8) -> String {
    match t {
        0 => "echo reply".into(),
        3 => format!("unreachable (code {code})"),
        5 => "redirect".into(),
        8 => "echo request".into(),
        11 => "time exceeded in-transit".into(),
        _ => format!("type {t}, code {code}"),
    }
}

fn icmp6_name(t: u8, code: u8) -> String {
    match t {
        1 => format!("destination unreachable (code {code})"),
        2 => "packet too big".into(),
        3 => "time exceeded in-transit".into(),
        128 => "echo request".into(),
        129 => "echo reply".into(),
        133 => "router solicitation".into(),
        134 => "router advertisement".into(),
        135 => "neighbor solicitation".into(),
        136 => "neighbor advertisement".into(),
        143 => "multicast listener report v2".into(),
        _ => format!("type {t}, code {code}"),
    }
}

fn endpoint(a: IpAddr, port: Option<u16>) -> String {
    match port {
        Some(p) => format!("{a}.{p}"),
        None => a.to_string(),
    }
}

/// Summary line without the timestamp, e.g.
/// `IP 10.0.0.2.51234 > 1.1.1.1.443: Flags [S], seq 1, win 64240, length 0`
pub fn summary(p: &Packet) -> String {
    match &p.net {
        Net::Ip(ip) => {
            let fam = if ip.src.is_ipv4() { "IP" } else { "IP6" };
            let (sp, dp) = p.ports().map_or((None, None), |(s, d)| (Some(s), Some(d)));
            let mut s = format!("{fam} {} > {}: ", endpoint(ip.src, sp), endpoint(ip.dst, dp));
            match &ip.transport {
                Transport::Tcp(t) => {
                    let _ = write!(s, "Flags [{}]", tcp_flags(t.flags));
                    if t.data_len > 0 {
                        let _ = write!(s, ", seq {}:{}", t.seq, t.seq.wrapping_add(t.data_len as u32));
                    } else if t.flags & 0x07 != 0 {
                        let _ = write!(s, ", seq {}", t.seq);
                    }
                    if t.flags & 0x10 != 0 {
                        let _ = write!(s, ", ack {}", t.ack);
                    }
                    let _ = write!(s, ", win {}, length {}", t.window, t.data_len);
                }
                Transport::Udp(u) => {
                    let _ = write!(s, "UDP, length {}", u.data_len);
                }
                Transport::Icmp { icmp_type, code, id, seq } => {
                    let echo = matches!((ip.proto, icmp_type), (PROTO_ICMP, 0 | 8) | (PROTO_ICMPV6, 128 | 129));
                    if ip.proto == PROTO_ICMP {
                        let _ = write!(s, "ICMP {}", icmp4_name(*icmp_type, *code));
                    } else {
                        let _ = write!(s, "ICMP6, {}", icmp6_name(*icmp_type, *code));
                    }
                    if echo {
                        let _ = write!(s, ", id {id}, seq {seq}");
                    }
                    let _ = write!(s, ", length {}", ip.payload_len);
                }
                Transport::None => {
                    let name = match ip.proto {
                        PROTO_TCP => "tcp".to_string(),
                        PROTO_UDP => "udp".to_string(),
                        PROTO_ICMP => "icmp".to_string(),
                        PROTO_ICMPV6 => "icmp6".to_string(),
                        n => format!("ip-proto-{n}"),
                    };
                    let frag = if ip.later_fragment { " (frag)" } else { "" };
                    let _ = write!(s, "{name}{frag} {}", ip.payload_len);
                }
            }
            s
        }
        Net::Arp(a) => {
            let len = p.frame_len.saturating_sub(14);
            match a.op {
                1 => format!("ARP, Request who-has {} tell {}, length {len}", a.target_ip, a.sender_ip),
                2 => format!("ARP, Reply {} is-at {}, length {len}", a.sender_ip, mac_str(&a.sender_mac)),
                op => format!("ARP, op {op}, length {len}"),
            }
        }
        Net::Other => {
            let len = p.frame_len.saturating_sub(14);
            if p.ethertype < 0x0600 {
                format!("802.3 LLC, length {len}")
            } else {
                format!("{} > {}, ethertype 0x{:04x}, length {len}", mac_str(&p.src_mac), mac_str(&p.dst_mac), p.ethertype)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::decode_ethernet;
    use crate::packet::tests::ipv4_frame;

    #[test]
    fn tcp_syn_line() {
        let p = decode_ethernet(&ipv4_frame(PROTO_TCP, [10, 0, 0, 2], [1, 1, 1, 1], 51234, 443)).unwrap();
        assert_eq!(summary(&p), "IP 10.0.0.2.51234 > 1.1.1.1.443: Flags [S], seq 1, win 65535, length 0");
    }

    #[test]
    fn udp_line() {
        let p = decode_ethernet(&ipv4_frame(PROTO_UDP, [10, 0, 0, 2], [10, 0, 0, 1], 5000, 53)).unwrap();
        assert_eq!(summary(&p), "IP 10.0.0.2.5000 > 10.0.0.1.53: UDP, length 0");
    }
}
