//! Live packet capture through the Windows built-in NDIS capture filter
//! (ndiscap.sys), consumed as a real-time ETW session from the
//! Microsoft-Windows-NDIS-PacketCapture provider. This is the same source
//! `netsh trace capture=yes` and pktmon's legacy mode use, so no extra
//! driver is needed. All `unsafe` FFI in the program lives in this module
//! and interfaces.rs.

use std::ffi::c_void;
use std::mem::size_of;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::OnceLock;
use std::thread::JoinHandle;

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_CANCELLED, ERROR_SUCCESS, FILETIME, STILL_ACTIVE,
    SYSTEMTIME,
};
use windows_sys::Win32::System::Time::{FileTimeToSystemTime, SystemTimeToTzSpecificLocalTime};
use windows_sys::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace, QueryAllTracesW, StartTraceW,
    CONTROLTRACE_HANDLE, EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_RECORD, EVENT_TRACE_CONTROL_STOP,
    EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, PROCESSTRACE_HANDLE,
    PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME, WNODE_FLAG_TRACED_GUID,
};
use windows_sys::Win32::System::Threading::{GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

/// Microsoft-Windows-NDIS-PacketCapture
const NDISCAP_PROVIDER: GUID = GUID::from_u128(0x2ed6006e_4729_4609_b423_3ee7bcd678ef);
const EVENT_PACKET_FRAGMENT: u16 = 1001;

// Keywords from the ndiscap manifest (see microsoft/etl2pcapng).
const KW_MEDIA_WIRELESS_WAN: u64 = 0x200;
const KW_MEDIA_NATIVE_802_11: u64 = 0x10000;
const KW_PACKET_START: u64 = 0x4000_0000;
const KW_PACKET_END: u64 = 0x8000_0000;

const SESSION_PREFIX: &str = "tcpdump-win-";
const TRACE_LEVEL_VERBOSE: u8 = 5;
const CHANNEL_DEPTH: usize = 65_536;

#[derive(Debug)]
pub struct Frame {
    /// FILETIME: 100ns intervals since 1601-01-01 UTC.
    pub filetime: i64,
    pub miniport_if_index: u32,
    pub lower_if_index: u32,
    /// Always an Ethernet frame (raw-IP WWAN frames get a synthetic header).
    pub data: Vec<u8>,
}

impl Frame {
    /// Microseconds since the Unix epoch.
    pub fn unix_micros(&self) -> u64 {
        ((self.filetime / 10) - 11_644_473_600_000_000).max(0) as u64
    }

    /// Local wall-clock time as `HH:MM:SS.uuuuuu`, like tcpdump's default.
    pub fn local_time(&self) -> String {
        let ft = FILETIME { dwLowDateTime: self.filetime as u32, dwHighDateTime: (self.filetime >> 32) as u32 };
        // SAFETY: plain conversions between stack-allocated structs.
        unsafe {
            let mut utc: SYSTEMTIME = std::mem::zeroed();
            let mut local: SYSTEMTIME = std::mem::zeroed();
            if FileTimeToSystemTime(&ft, &mut utc) == 0 || SystemTimeToTzSpecificLocalTime(std::ptr::null(), &utc, &mut local) == 0 {
                local = utc;
            }
            let micros = (self.filetime / 10) % 1_000_000;
            format!("{:02}:{:02}:{:02}.{:06}", local.wHour, local.wMinute, local.wSecond, micros)
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Stats {
    /// Events the kernel dropped because the ETW buffers were full.
    pub kernel_lost: u64,
    /// Frames dropped because the consumer fell behind.
    pub queue_dropped: u64,
}

static QUEUE_DROPPED: AtomicU64 = AtomicU64::new(0);
static SESSION_NAME: OnceLock<Vec<u16>> = OnceLock::new();

struct CallbackCtx {
    tx: SyncSender<Frame>,
    /// Fragments of a multi-event packet (only emitted by pre-8.1 Windows).
    partial: Vec<u8>,
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// An EVENT_TRACE_PROPERTIES followed by room for the logger and log file names,
/// stored in u64s for alignment.
struct PropsBuf(Vec<u64>);

impl PropsBuf {
    const NAME_BYTES: usize = 1024 * 2;

    fn new() -> Self {
        let bytes = size_of::<EVENT_TRACE_PROPERTIES>() + 2 * Self::NAME_BYTES;
        let mut b = PropsBuf(vec![0u64; bytes.div_ceil(8)]);
        let p = b.props();
        p.Wnode.BufferSize = bytes as u32;
        p.LoggerNameOffset = size_of::<EVENT_TRACE_PROPERTIES>() as u32;
        p.LogFileNameOffset = (size_of::<EVENT_TRACE_PROPERTIES>() + Self::NAME_BYTES) as u32;
        b
    }

    /// Properties for our real-time capture session.
    fn for_session() -> Self {
        let mut b = Self::new();
        let p = b.props();
        p.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        p.Wnode.ClientContext = 1; // QPC timestamps (highest resolution)
        p.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        p.BufferSize = 256; // KB
        p.MinimumBuffers = 32;
        p.MaximumBuffers = 256;
        p.FlushTimer = 1; // seconds; keeps console output prompt on quiet links
        b
    }

    fn props(&mut self) -> &mut EVENT_TRACE_PROPERTIES {
        // SAFETY: the buffer is at least size_of::<EVENT_TRACE_PROPERTIES>() bytes and 8-aligned.
        unsafe { &mut *(self.0.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES) }
    }

    fn ptr(&mut self) -> *mut EVENT_TRACE_PROPERTIES {
        self.0.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES
    }

    fn logger_name(&self) -> String {
        let off = size_of::<EVENT_TRACE_PROPERTIES>();
        // SAFETY: the name region lies entirely within the buffer.
        let words = unsafe {
            std::slice::from_raw_parts((self.0.as_ptr() as *const u8).add(off) as *const u16, Self::NAME_BYTES / 2)
        };
        let len = words.iter().position(|&c| c == 0).unwrap_or(words.len());
        String::from_utf16_lossy(&words[..len])
    }
}

/// Stop a session by name. Returns the session's final loss counters.
fn stop_by_name(name: &[u16]) -> Option<u64> {
    let mut pb = PropsBuf::new();
    // SAFETY: name is NUL-terminated; pb is a correctly sized properties buffer.
    let rc = unsafe { ControlTraceW(CONTROLTRACE_HANDLE { Value: 0 }, name.as_ptr(), pb.ptr(), EVENT_TRACE_CONTROL_STOP) };
    if rc == ERROR_SUCCESS {
        let p = pb.props();
        Some(p.EventsLost as u64 + p.RealTimeBuffersLost as u64)
    } else {
        None
    }
}

fn process_alive(pid: u32) -> bool {
    // SAFETY: plain Win32 calls on a handle we own and close.
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return false;
        }
        let mut code = 0u32;
        let ok = GetExitCodeProcess(h, &mut code) != 0;
        CloseHandle(h);
        ok && code == STILL_ACTIVE as u32
    }
}

/// Stop sessions left behind by instances of this tool that were killed
/// without running their cleanup (ETW sessions outlive their process).
fn cleanup_stale_sessions() {
    const MAX: usize = 64;
    let mut bufs: Vec<PropsBuf> = (0..MAX).map(|_| PropsBuf::new()).collect();
    let mut ptrs: Vec<*mut EVENT_TRACE_PROPERTIES> = bufs.iter_mut().map(|b| b.ptr()).collect();
    let mut count = 0u32;
    // SAFETY: every pointer refers to a correctly initialised PropsBuf.
    let rc = unsafe { QueryAllTracesW(ptrs.as_mut_ptr(), MAX as u32, &mut count) };
    if rc != ERROR_SUCCESS {
        return;
    }
    for b in bufs.iter().take(count as usize) {
        let name = b.logger_name();
        let Some(pid) = name.strip_prefix(SESSION_PREFIX).and_then(|p| p.parse::<u32>().ok()) else { continue };
        if pid != std::process::id() && !process_alive(pid) {
            stop_by_name(&wide(&name));
        }
    }
}

/// Parse the payload of a PacketFragment event:
/// `MiniportIfIndex: u32, LowerIfIndex: u32, FragmentSize: u32, Fragment: [u8; FragmentSize]`.
fn parse_fragment(user_data: &[u8]) -> Option<(u32, u32, &[u8])> {
    let u32_at = |o: usize| user_data.get(o..o + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]));
    let miniport = u32_at(0)?;
    let lower = u32_at(4)?;
    let size = u32_at(8)? as usize;
    let frag = user_data.get(12..)?;
    Some((miniport, lower, &frag[..size.min(frag.len())]))
}

/// Raw IP (mobile broadband) frames get a fake Ethernet header so the whole
/// capture can use one link type.
fn add_fake_ethernet(ip: &[u8]) -> Vec<u8> {
    let ethertype: u16 = match ip.first().map(|b| b >> 4) {
        Some(6) => 0x86dd,
        _ => 0x0800,
    };
    let mut v = Vec::with_capacity(14 + ip.len());
    v.extend_from_slice(&[0; 12]);
    v.extend_from_slice(&ethertype.to_be_bytes());
    v.extend_from_slice(ip);
    v
}

unsafe extern "system" fn event_callback(rec: *mut EVENT_RECORD) {
    // SAFETY: ETW passes a valid record; UserContext is the CallbackCtx we installed.
    let rec = &*rec;
    let hdr = &rec.EventHeader;
    if hdr.ProviderId.data1 != NDISCAP_PROVIDER.data1
        || hdr.ProviderId.data2 != NDISCAP_PROVIDER.data2
        || hdr.ProviderId.data3 != NDISCAP_PROVIDER.data3
        || hdr.ProviderId.data4 != NDISCAP_PROVIDER.data4
        || hdr.EventDescriptor.Id != EVENT_PACKET_FRAGMENT
        || rec.UserContext.is_null()
        || rec.UserData.is_null()
    {
        return;
    }
    let ctx = &mut *(rec.UserContext as *mut CallbackCtx);
    let kw = hdr.EventDescriptor.Keyword;
    if kw & KW_MEDIA_NATIVE_802_11 != 0 {
        return; // raw 802.11 frames don't fit an Ethernet capture
    }
    let user = std::slice::from_raw_parts(rec.UserData as *const u8, rec.UserDataLength as usize);
    let Some((miniport, lower, frag)) = parse_fragment(user) else { return };

    // Reassemble multi-event packets (START .. END); single-event packets carry both bits.
    let start = kw & KW_PACKET_START != 0;
    let end = kw & KW_PACKET_END != 0;
    let data = if start && end || (!start && !end && ctx.partial.is_empty()) {
        frag.to_vec()
    } else {
        if start {
            ctx.partial.clear();
        }
        ctx.partial.extend_from_slice(frag);
        if !end {
            return;
        }
        std::mem::take(&mut ctx.partial)
    };
    let data = if kw & KW_MEDIA_WIRELESS_WAN != 0 { add_fake_ethernet(&data) } else { data };

    let frame = Frame {
        filetime: hdr.TimeStamp,
        miniport_if_index: miniport,
        lower_if_index: lower,
        data,
    };
    if let Err(TrySendError::Full(_)) = ctx.tx.try_send(frame) {
        QUEUE_DROPPED.fetch_add(1, Ordering::Relaxed);
    }
}

pub struct Capture {
    pub frames: Receiver<Frame>,
    worker: Option<JoinHandle<()>>,
}

/// Start a real-time session and begin delivering frames.
pub fn start() -> Result<Capture, String> {
    cleanup_stale_sessions();

    let name = format!("{SESSION_PREFIX}{}", std::process::id());
    let wname = SESSION_NAME.get_or_init(|| wide(&name)).clone();

    let mut handle = CONTROLTRACE_HANDLE { Value: 0 };
    // SAFETY: valid NUL-terminated name and properties buffer.
    let mut rc = unsafe { StartTraceW(&mut handle, wname.as_ptr(), PropsBuf::for_session().ptr()) };
    if rc == ERROR_ALREADY_EXISTS {
        stop_by_name(&wname);
        rc = unsafe { StartTraceW(&mut handle, wname.as_ptr(), PropsBuf::for_session().ptr()) };
    }
    match rc {
        ERROR_SUCCESS => {}
        ERROR_ACCESS_DENIED => {
            return Err("You don't have permission to capture. Run tcpdump from an elevated (Administrator) prompt.".into())
        }
        e => return Err(format!("StartTrace failed: error {e}")),
    }

    // SAFETY: handle is the session we just started.
    let rc = unsafe {
        EnableTraceEx2(
            handle,
            &NDISCAP_PROVIDER,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            TRACE_LEVEL_VERBOSE,
            u64::MAX,
            0,
            0,
            std::ptr::null(),
        )
    };
    if rc != ERROR_SUCCESS {
        stop_by_name(&wname);
        return Err(format!("EnableTraceEx2 (NDIS-PacketCapture) failed: error {rc}"));
    }

    let (tx, rx) = sync_channel(CHANNEL_DEPTH);
    let ctx = Box::into_raw(Box::new(CallbackCtx { tx, partial: Vec::new() }));

    let mut logfile: EVENT_TRACE_LOGFILEW = unsafe { std::mem::zeroed() };
    let mut consumer_name = wname.clone();
    logfile.LoggerName = consumer_name.as_mut_ptr();
    logfile.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.Anonymous2.EventRecordCallback = Some(event_callback);
    logfile.Context = ctx as *mut c_void;

    // SAFETY: logfile is fully initialised for a real-time consumer.
    let trace = unsafe { OpenTraceW(&mut logfile) };
    if trace.Value == u64::MAX {
        stop_by_name(&wname);
        drop(unsafe { Box::from_raw(ctx) });
        return Err(format!("OpenTrace failed: error {}", std::io::Error::last_os_error()));
    }

    let ctx_addr = ctx as usize;
    let worker = std::thread::spawn(move || {
        let _keep_name = consumer_name;
        let t: PROCESSTRACE_HANDLE = trace;
        // SAFETY: ProcessTrace blocks until the session is stopped; the
        // callback context stays alive until after it returns.
        unsafe {
            let rc = ProcessTrace(&t, 1, std::ptr::null(), std::ptr::null());
            if rc != ERROR_SUCCESS && rc != ERROR_CANCELLED {
                eprintln!("tcpdump: ProcessTrace ended with error {rc}");
            }
            CloseTrace(t);
            // Dropping the sender closes the channel and ends the main loop.
            drop(Box::from_raw(ctx_addr as *mut CallbackCtx));
        }
    });

    Ok(Capture { frames: rx, worker: Some(worker) })
}

/// Stop the running session (safe to call from the console control handler
/// and more than once). Returns kernel loss counters on the first call.
pub fn stop() -> Option<u64> {
    let name = SESSION_NAME.get()?;
    stop_by_name(name)
}

impl Capture {
    /// Stop capturing and wait for the consumer thread to finish.
    pub fn finish(mut self) -> Stats {
        let kernel_lost = stop().unwrap_or(0);
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
        Stats { kernel_lost, queue_dropped: QUEUE_DROPPED.load(Ordering::Relaxed) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragment_parsing_is_bounds_checked() {
        let mut ud = Vec::new();
        ud.extend_from_slice(&7u32.to_le_bytes());
        ud.extend_from_slice(&9u32.to_le_bytes());
        ud.extend_from_slice(&1000u32.to_le_bytes()); // claims more than present
        ud.extend_from_slice(&[1, 2, 3]);
        assert_eq!(parse_fragment(&ud), Some((7, 9, &[1u8, 2, 3][..])));
        assert_eq!(parse_fragment(&ud[..11]), None);
    }

    #[test]
    fn filetime_conversion() {
        let f = Frame { filetime: 116_444_736_000_000_000 + 10, miniport_if_index: 0, lower_if_index: 0, data: vec![] };
        assert_eq!(f.unix_micros(), 1);
    }
}
