//! Bounds-checked decoding of Ethernet frames. Nothing here trusts length
//! fields from the wire: every access goes through `slice::get`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_VLAN: u16 = 0x8100;
pub const ETHERTYPE_QINQ: u16 = 0x88a8;
pub const ETHERTYPE_IPV6: u16 = 0x86dd;

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const PROTO_ICMPV6: u8 = 58;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub vlan: Option<u16>,
    pub ethertype: u16,
    pub frame_len: usize,
    pub net: Net,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Net {
    Ip(IpPacket),
    Arp(Arp),
    /// Unknown ethertype, or a header too short to decode.
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpPacket {
    pub src: IpAddr,
    pub dst: IpAddr,
    /// Upper-layer protocol (after IPv6 extension headers).
    pub proto: u8,
    /// Length of the IP payload as claimed by the IP header.
    pub payload_len: usize,
    /// True for a non-first IPv4/IPv6 fragment (no transport header present).
    pub later_fragment: bool,
    pub transport: Transport,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport {
    Tcp(Tcp),
    Udp(Udp),
    Icmp { icmp_type: u8, code: u8, id: u16, seq: u16 },
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tcp {
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub data_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Udp {
    pub sport: u16,
    pub dport: u16,
    pub data_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arp {
    pub op: u16,
    pub sender_mac: [u8; 6],
    pub sender_ip: Ipv4Addr,
    pub target_mac: [u8; 6],
    pub target_ip: Ipv4Addr,
}

impl Packet {
    pub fn ports(&self) -> Option<(u16, u16)> {
        match &self.net {
            Net::Ip(ip) => match &ip.transport {
                Transport::Tcp(t) => Some((t.sport, t.dport)),
                Transport::Udp(u) => Some((u.sport, u.dport)),
                _ => None,
            },
            _ => None,
        }
    }

    pub fn ip_proto(&self) -> Option<u8> {
        match &self.net {
            Net::Ip(ip) => Some(ip.proto),
            _ => None,
        }
    }
}

fn be16(b: &[u8], off: usize) -> Option<u16> {
    let s = b.get(off..off + 2)?;
    Some(u16::from_be_bytes([s[0], s[1]]))
}

fn be32(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off + 4)?;
    Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn mac(b: &[u8], off: usize) -> Option<[u8; 6]> {
    b.get(off..off + 6)?.try_into().ok()
}

/// Decode an Ethernet II frame. Returns `None` only if the frame is shorter
/// than an Ethernet header; anything undecodable above that becomes `Net::Other`.
pub fn decode_ethernet(frame: &[u8]) -> Option<Packet> {
    let dst_mac = mac(frame, 0)?;
    let src_mac = mac(frame, 6)?;
    let mut ethertype = be16(frame, 12)?;
    let mut off = 14;
    let mut vlan = None;
    // Up to two VLAN tags (802.1Q / QinQ).
    for _ in 0..2 {
        if ethertype == ETHERTYPE_VLAN || ethertype == ETHERTYPE_QINQ {
            let tci = be16(frame, off)?;
            vlan.get_or_insert(tci & 0x0fff);
            ethertype = be16(frame, off + 2)?;
            off += 4;
        }
    }
    let payload = &frame[off..];
    let net = match ethertype {
        ETHERTYPE_IPV4 => decode_ipv4(payload).map(Net::Ip),
        ETHERTYPE_IPV6 => decode_ipv6(payload).map(Net::Ip),
        ETHERTYPE_ARP => decode_arp(payload).map(Net::Arp),
        _ => None,
    }
    .unwrap_or(Net::Other);
    Some(Packet { src_mac, dst_mac, vlan, ethertype, frame_len: frame.len(), net })
}

fn decode_ipv4(b: &[u8]) -> Option<IpPacket> {
    let vihl = *b.first()?;
    if vihl >> 4 != 4 {
        return None;
    }
    let ihl = ((vihl & 0x0f) as usize) * 4;
    if ihl < 20 {
        return None;
    }
    let total_len = be16(b, 2)? as usize;
    let frag = be16(b, 6)?;
    let frag_offset = frag & 0x1fff;
    let proto = *b.get(9)?;
    let src = Ipv4Addr::from(be32(b, 12)?);
    let dst = Ipv4Addr::from(be32(b, 16)?);
    let payload_len = total_len.saturating_sub(ihl);
    let later_fragment = frag_offset != 0;
    // Clamp to what was actually captured (and ignore Ethernet padding).
    let end = total_len.clamp(ihl, b.len().max(ihl));
    let l4 = b.get(ihl..end).unwrap_or(&[]);
    let transport = if later_fragment { Transport::None } else { decode_transport(proto, l4, payload_len) };
    Some(IpPacket { src: IpAddr::V4(src), dst: IpAddr::V4(dst), proto, payload_len, later_fragment, transport })
}

fn decode_ipv6(b: &[u8]) -> Option<IpPacket> {
    if *b.first()? >> 4 != 6 {
        return None;
    }
    let mut payload_len = be16(b, 4)? as usize;
    let mut next = *b.get(6)?;
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(b.get(8..24)?).ok()?);
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(b.get(24..40)?).ok()?);
    let mut off = 40;
    let mut later_fragment = false;
    // Walk the common extension headers.
    for _ in 0..8 {
        match next {
            0 | 43 | 60 => {
                let hdr_next = *b.get(off)?;
                let len = (*b.get(off + 1)? as usize + 1) * 8;
                next = hdr_next;
                off += len;
                payload_len = payload_len.saturating_sub(len);
            }
            44 => {
                let hdr_next = *b.get(off)?;
                let frag_offset = be16(b, off + 2)? >> 3;
                later_fragment = frag_offset != 0;
                next = hdr_next;
                off += 8;
                payload_len = payload_len.saturating_sub(8);
            }
            _ => break,
        }
    }
    let end = (off + payload_len).min(b.len()).max(off.min(b.len()));
    let l4 = b.get(off.min(b.len())..end).unwrap_or(&[]);
    let transport = if later_fragment { Transport::None } else { decode_transport(next, l4, payload_len) };
    Some(IpPacket { src: IpAddr::V6(src), dst: IpAddr::V6(dst), proto: next, payload_len, later_fragment, transport })
}

fn decode_transport(proto: u8, b: &[u8], payload_len: usize) -> Transport {
    match proto {
        PROTO_TCP => (|| {
            let data_off = ((*b.get(12)? >> 4) as usize) * 4;
            Some(Transport::Tcp(Tcp {
                sport: be16(b, 0)?,
                dport: be16(b, 2)?,
                seq: be32(b, 4)?,
                ack: be32(b, 8)?,
                flags: *b.get(13)?,
                window: be16(b, 14)?,
                data_len: payload_len.saturating_sub(data_off),
            }))
        })()
        .unwrap_or(Transport::None),
        PROTO_UDP => (|| {
            Some(Transport::Udp(Udp {
                sport: be16(b, 0)?,
                dport: be16(b, 2)?,
                data_len: (be16(b, 4)? as usize).saturating_sub(8),
            }))
        })()
        .unwrap_or(Transport::None),
        PROTO_ICMP | PROTO_ICMPV6 => (|| {
            Some(Transport::Icmp {
                icmp_type: *b.first()?,
                code: *b.get(1)?,
                id: be16(b, 4).unwrap_or(0),
                seq: be16(b, 6).unwrap_or(0),
            })
        })()
        .unwrap_or(Transport::None),
        _ => Transport::None,
    }
}

fn decode_arp(b: &[u8]) -> Option<Arp> {
    // Only Ethernet/IPv4 ARP.
    if be16(b, 0)? != 1 || be16(b, 2)? != ETHERTYPE_IPV4 || *b.get(4)? != 6 || *b.get(5)? != 4 {
        return None;
    }
    Some(Arp {
        op: be16(b, 6)?,
        sender_mac: mac(b, 8)?,
        sender_ip: Ipv4Addr::from(be32(b, 14)?),
        target_mac: mac(b, 18)?,
        target_ip: Ipv4Addr::from(be32(b, 24)?),
    })
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// Build an Ethernet + IPv4 + TCP/UDP frame for tests.
    pub fn ipv4_frame(proto: u8, src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
        let mut f = vec![0xff; 6];
        f.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        f.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        let l4_len = if proto == PROTO_TCP { 20 } else { 8 };
        let total = (20 + l4_len) as u16;
        f.extend_from_slice(&[0x45, 0, total.to_be_bytes()[0], total.to_be_bytes()[1], 0, 1, 0x40, 0, 64, proto, 0, 0]);
        f.extend_from_slice(&src);
        f.extend_from_slice(&dst);
        f.extend_from_slice(&sport.to_be_bytes());
        f.extend_from_slice(&dport.to_be_bytes());
        if proto == PROTO_TCP {
            f.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0]);
        } else {
            f.extend_from_slice(&[0, 8, 0, 0]);
        }
        f
    }

    pub fn ipv6_udp_frame(src: Ipv6Addr, dst: Ipv6Addr, sport: u16, dport: u16) -> Vec<u8> {
        let mut f = vec![0x33, 0x33, 0, 0, 0, 1];
        f.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        f.extend_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
        f.extend_from_slice(&[0x60, 0, 0, 0, 0, 8, PROTO_UDP, 64]);
        f.extend_from_slice(&src.octets());
        f.extend_from_slice(&dst.octets());
        f.extend_from_slice(&sport.to_be_bytes());
        f.extend_from_slice(&dport.to_be_bytes());
        f.extend_from_slice(&[0, 8, 0, 0]);
        f
    }

    #[test]
    fn decodes_tcp() {
        let f = ipv4_frame(PROTO_TCP, [10, 0, 0, 2], [1, 1, 1, 1], 51234, 443);
        let p = decode_ethernet(&f).unwrap();
        let Net::Ip(ip) = &p.net else { panic!() };
        assert_eq!(ip.src, IpAddr::from([10, 0, 0, 2]));
        assert_eq!(ip.dst, IpAddr::from([1, 1, 1, 1]));
        let Transport::Tcp(t) = &ip.transport else { panic!() };
        assert_eq!((t.sport, t.dport, t.flags, t.data_len), (51234, 443, 0x02, 0));
    }

    #[test]
    fn decodes_ipv6_udp() {
        let s: Ipv6Addr = "fe80::1".parse().unwrap();
        let d: Ipv6Addr = "ff02::fb".parse().unwrap();
        let p = decode_ethernet(&ipv6_udp_frame(s, d, 5353, 5353)).unwrap();
        assert_eq!(p.ports(), Some((5353, 5353)));
        assert_eq!(p.ip_proto(), Some(PROTO_UDP));
    }

    #[test]
    fn decodes_vlan_tag() {
        let mut f = ipv4_frame(PROTO_UDP, [10, 0, 0, 2], [10, 0, 0, 3], 1000, 53);
        f.splice(12..12, [0x81, 0x00, 0x00, 0x64]);
        let p = decode_ethernet(&f).unwrap();
        assert_eq!(p.vlan, Some(100));
        assert_eq!(p.ports(), Some((1000, 53)));
    }

    #[test]
    fn decodes_arp() {
        let mut f = vec![0xff; 6];
        f.extend_from_slice(&[0, 1, 2, 3, 4, 5]);
        f.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());
        f.extend_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1, 0, 1, 2, 3, 4, 5, 10, 0, 0, 2, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1]);
        let p = decode_ethernet(&f).unwrap();
        let Net::Arp(a) = &p.net else { panic!() };
        assert_eq!(a.op, 1);
        assert_eq!(a.target_ip, Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn truncated_frames_never_panic() {
        let full = ipv4_frame(PROTO_TCP, [10, 0, 0, 2], [1, 1, 1, 1], 1, 2);
        for n in 0..full.len() {
            let _ = decode_ethernet(&full[..n]);
        }
        let v6 = ipv6_udp_frame(Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 1, 2);
        for n in 0..v6.len() {
            let _ = decode_ethernet(&v6[..n]);
        }
        // Garbage length fields.
        let mut bad = full.clone();
        bad[14] = 0x4f; // IHL = 60 bytes, longer than the packet
        bad[16] = 0xff;
        bad[17] = 0xff;
        let _ = decode_ethernet(&bad);
        assert!(decode_ethernet(&[0u8; 13]).is_none());
    }
}
