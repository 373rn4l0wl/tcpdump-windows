//! Network adapter enumeration via GetAdaptersAddresses.

use std::ffi::CStr;

use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
    GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
};
use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;

const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;

#[derive(Debug, Clone)]
pub struct Interface {
    /// 1-based position in the `-D` listing.
    pub number: usize,
    pub if_index: u32,
    pub guid: String,
    pub name: String,
    pub description: String,
    pub up: bool,
    pub has_gateway: bool,
}

/// What `-i` resolved to.
#[derive(Debug, Clone)]
pub enum Selection {
    Any,
    One(Interface),
}

impl Selection {
    pub fn describe(&self) -> String {
        match self {
            Selection::Any => "any".into(),
            Selection::One(i) => format!("{} ({})", i.name, i.description),
        }
    }
}

unsafe fn wide_to_string(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0;
    while *p.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
}

pub fn list() -> Result<Vec<Interface>, String> {
    let flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size: u32 = 32 * 1024;
    // u64 storage keeps the buffer suitably aligned for IP_ADAPTER_ADDRESSES_LH.
    let mut buf: Vec<u64>;
    loop {
        buf = vec![0u64; (size as usize).div_ceil(8)];
        let rc = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                flags,
                std::ptr::null(),
                buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                &mut size,
            )
        };
        match rc {
            NO_ERROR => break,
            ERROR_BUFFER_OVERFLOW => continue,
            e => return Err(format!("GetAdaptersAddresses failed: error {e}")),
        }
    }
    let mut out = Vec::new();
    let mut cur = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !cur.is_null() {
        // SAFETY: cur points into `buf`, a linked list built by GetAdaptersAddresses.
        let a = unsafe { &*cur };
        cur = a.Next;
        if a.IfType == IF_TYPE_SOFTWARE_LOOPBACK {
            continue;
        }
        let if_index = unsafe { a.Anonymous1.Anonymous.IfIndex };
        let guid = if a.AdapterName.is_null() {
            String::new()
        } else {
            unsafe { CStr::from_ptr(a.AdapterName as *const _) }.to_string_lossy().into_owned()
        };
        out.push(Interface {
            number: out.len() + 1,
            if_index,
            guid,
            name: unsafe { wide_to_string(a.FriendlyName) },
            description: unsafe { wide_to_string(a.Description) },
            up: a.OperStatus == IfOperStatusUp,
            has_gateway: !a.FirstGatewayAddress.is_null(),
        });
    }
    Ok(out)
}

/// Resolve the `-i` argument. With no argument, pick the first adapter that
/// is up and has a default gateway, falling back to "any".
pub fn select(arg: Option<&str>, all: &[Interface]) -> Result<Selection, String> {
    let Some(arg) = arg else {
        return Ok(all.iter().find(|i| i.up && i.has_gateway).cloned().map_or(Selection::Any, Selection::One));
    };
    if arg.eq_ignore_ascii_case("any") {
        return Ok(Selection::Any);
    }
    let a = arg.trim_matches(|c| c == '{' || c == '}');
    if arg.parse::<usize>() == Ok(all.len() + 1) {
        return Ok(Selection::Any);
    }
    let found = if let Ok(n) = arg.parse::<usize>() {
        // A number is a -D position first, like tcpdump; "if<N>" forces an ifIndex.
        all.iter().find(|i| i.number == n)
    } else if let Some(idx) = arg.strip_prefix("if").and_then(|s| s.parse::<u32>().ok()) {
        all.iter().find(|i| i.if_index == idx)
    } else {
        all.iter()
            .find(|i| i.name.eq_ignore_ascii_case(arg))
            .or_else(|| all.iter().find(|i| i.guid.trim_matches(|c| c == '{' || c == '}').eq_ignore_ascii_case(a)))
            .or_else(|| all.iter().find(|i| i.description.eq_ignore_ascii_case(arg)))
    };
    found
        .cloned()
        .map(Selection::One)
        .ok_or_else(|| format!("{arg}: No such device exists (use -D to list interfaces)"))
}

pub fn print_list(all: &[Interface]) {
    for i in all {
        let state = if i.up { "Up" } else { "Down" };
        println!("{}.{} ({}) [{}] [ifIndex {}] {}", i.number, i.guid, i.name, state, i.if_index, i.description);
    }
    println!("{}.any (Pseudo-device that captures on all interfaces) [Up]", all.len() + 1);
}
