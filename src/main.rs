//! tcpdump for Windows using the built-in NDIS capture driver.

mod capture;
mod cli;
mod filter;
mod interfaces;
mod output;
mod packet;
mod pcap;

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::process::ExitCode;

use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;

use crate::interfaces::Selection;
use crate::pcap::{PcapWriter, SNAPLEN};

unsafe extern "system" fn ctrl_handler(_ctrl_type: u32) -> i32 {
    // Stopping the ETW session makes ProcessTrace return, which closes the
    // frame channel and lets main() print statistics and flush the file.
    capture::stop();
    1
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("tcpdump: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let opts = cli::parse(std::env::args().skip(1)).map_err(|e| format!("{e}\n{}", cli::USAGE))?;
    if opts.help {
        println!("{}", cli::USAGE);
        return Ok(());
    }
    if opts.version {
        println!("tcpdump for Windows {} (NDIS-PacketCapture ETW backend)", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    let ifaces = interfaces::list()?;
    if opts.list_interfaces {
        interfaces::print_list(&ifaces);
        return Ok(());
    }

    let filter = filter::parse(&opts.filter).map_err(|e| e.render(&opts.filter))?;
    let selection = interfaces::select(opts.interface.as_deref(), &ifaces)?;

    let mut writer: Option<PcapWriter<Box<dyn Write>>> = match opts.write_file.as_deref() {
        None => None,
        Some("-") => Some(PcapWriter::new(Box::new(io::stdout().lock()) as Box<dyn Write>, true).map_err(|e| e.to_string())?),
        Some(path) => {
            let f = File::create(path).map_err(|e| format!("{path}: {e}"))?;
            Some(PcapWriter::new(Box::new(BufWriter::with_capacity(1 << 20, f)) as Box<dyn Write>, false).map_err(|e| format!("{path}: {e}"))?)
        }
    };

    let cap = capture::start()?;
    // SAFETY: registering a plain function as the console control handler.
    unsafe { SetConsoleCtrlHandler(Some(ctrl_handler), 1) };

    if writer.is_none() {
        eprintln!("tcpdump: verbose output suppressed, use -w to save full packets");
    }
    eprintln!(
        "listening on {}, link-type EN10MB (Ethernet), snapshot length {SNAPLEN} bytes",
        selection.describe()
    );

    let want_index = match &selection {
        Selection::Any => None,
        Selection::One(i) => Some(i.if_index),
    };
    let mut stdout = io::stdout().lock();
    let mut received: u64 = 0;
    let mut captured: u64 = 0;
    let mut io_error = None;

    for frame in cap.frames.iter() {
        if let Some(idx) = want_index {
            if frame.miniport_if_index != idx && frame.lower_if_index != idx {
                continue;
            }
        }
        received += 1;
        let Some(pkt) = packet::decode_ethernet(&frame.data) else { continue };
        if !filter.matches(&pkt) {
            continue;
        }
        captured += 1;
        let res = match writer.as_mut() {
            Some(w) => w.write_packet(frame.unix_micros(), &frame.data, frame.data.len()),
            None => writeln!(stdout, "{} {}", frame.local_time(), output::summary(&pkt)),
        };
        if let Err(e) = res {
            if e.kind() != io::ErrorKind::BrokenPipe {
                io_error = Some(e.to_string());
            }
            break;
        }
        if opts.count.is_some_and(|c| captured >= c) {
            break;
        }
    }

    let stats = cap.finish();
    if let Some(w) = writer.as_mut() {
        w.flush().map_err(|e| e.to_string())?;
    }
    let _ = stdout.flush();
    drop(stdout);

    eprintln!();
    eprintln!("{captured} packets captured");
    eprintln!("{received} packets received by filter");
    eprintln!("{} packets dropped by kernel", stats.kernel_lost + stats.queue_dropped);
    match io_error {
        Some(e) => Err(e),
        None => Ok(()),
    }
}
