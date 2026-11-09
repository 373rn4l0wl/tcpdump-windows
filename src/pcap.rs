//! Classic libpcap file writer (readable by Wireshark, tcpdump -r, tshark).

use std::io::{self, Write};

pub const LINKTYPE_ETHERNET: u32 = 1;
pub const SNAPLEN: u32 = 262_144;

pub struct PcapWriter<W: Write> {
    out: W,
    /// Flush after every packet (used when writing to a pipe).
    flush_each: bool,
}

impl<W: Write> PcapWriter<W> {
    pub fn new(mut out: W, flush_each: bool) -> io::Result<Self> {
        let mut hdr = Vec::with_capacity(24);
        hdr.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes()); // magic, microsecond timestamps
        hdr.extend_from_slice(&2u16.to_le_bytes()); // version major
        hdr.extend_from_slice(&4u16.to_le_bytes()); // version minor
        hdr.extend_from_slice(&0i32.to_le_bytes()); // thiszone
        hdr.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
        hdr.extend_from_slice(&SNAPLEN.to_le_bytes());
        hdr.extend_from_slice(&LINKTYPE_ETHERNET.to_le_bytes());
        out.write_all(&hdr)?;
        if flush_each {
            out.flush()?;
        }
        Ok(PcapWriter { out, flush_each })
    }

    /// `ts_us` is microseconds since the Unix epoch.
    pub fn write_packet(&mut self, ts_us: u64, data: &[u8], orig_len: usize) -> io::Result<()> {
        let incl = data.len().min(SNAPLEN as usize);
        let mut rec = [0u8; 16];
        rec[0..4].copy_from_slice(&((ts_us / 1_000_000) as u32).to_le_bytes());
        rec[4..8].copy_from_slice(&((ts_us % 1_000_000) as u32).to_le_bytes());
        rec[8..12].copy_from_slice(&(incl as u32).to_le_bytes());
        rec[12..16].copy_from_slice(&(orig_len.max(incl) as u32).to_le_bytes());
        self.out.write_all(&rec)?;
        self.out.write_all(&data[..incl])?;
        if self.flush_each {
            self.out.flush()?;
        }
        Ok(())
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_and_record_layout() {
        let mut buf = Vec::new();
        {
            let mut w = PcapWriter::new(&mut buf, false).unwrap();
            w.write_packet(1_700_000_000_123_456, &[1, 2, 3], 3).unwrap();
            w.flush().unwrap();
        }
        assert_eq!(buf.len(), 24 + 16 + 3);
        assert_eq!(&buf[0..4], &[0xd4, 0xc3, 0xb2, 0xa1]);
        assert_eq!(u32::from_le_bytes(buf[20..24].try_into().unwrap()), LINKTYPE_ETHERNET);
        assert_eq!(u32::from_le_bytes(buf[24..28].try_into().unwrap()), 1_700_000_000);
        assert_eq!(u32::from_le_bytes(buf[28..32].try_into().unwrap()), 123_456);
        assert_eq!(u32::from_le_bytes(buf[32..36].try_into().unwrap()), 3);
        assert_eq!(u32::from_le_bytes(buf[36..40].try_into().unwrap()), 3);
        assert_eq!(&buf[40..], &[1, 2, 3]);
    }
}
