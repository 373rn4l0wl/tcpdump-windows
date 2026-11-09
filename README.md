# tcpdump for Windows

> **This is a Claude Code project.** The design, code, tests and this README were
> written by [Claude Code](https://claude.com/claude-code), Anthropic's AI coding
> agent, working under the direction of the repository owner, who set the
> requirements, reviewed the work and ran the tests on real machines.

A small, portable clone of the Linux `tcpdump` utility for Windows. It uses the packet
capture driver that already ships with Windows (`ndiscap.sys`, the same one behind
`netsh trace` and `pktmon`), so there is **nothing to install**: no Npcap, no WinPcap,
no driver. Copy `tcpdump.exe` to a machine and run it from an elevated prompt.

The point is to use tcpdump syntax you already know instead of learning pktmon's.

## Supported operating systems

| OS | Status |
|---|---|
| Windows 11 | Supported, tested (Windows 11 Enterprise 10.0.26200) |
| Windows 10 | Supported |
| Windows Server 2025 / 2022 / 2019 / 2016 | Supported (Server 2019 testing pending) |
| Windows 8.1 / 7, Server 2012 R2 / 2008 R2 and older | **Not supported** (current Rust toolchains target Windows 10 and later) |

- Architecture: x64 (`x86_64-pc-windows-msvc`).
- **Must be run as Administrator.** Starting a packet capture session requires it.
- Single file, about 400 KB, with the C runtime statically linked. It only uses DLLs that are
  part of Windows (kernel32, advapi32, iphlpapi, ws2_32, ntdll).

## Supported switches

```
tcpdump [-DhnU] [-c count] [-i interface] [-w file] [expression]
```

| Switch | Meaning |
|---|---|
| `-i interface` | Interface to capture on. Accepts the number from `-D` (like Linux), `if<N>` for a Windows interface index (e.g. `if5`), the adapter's friendly name (e.g. `Ethernet0`), its GUID, or `any`. Default: the first adapter that is up and has a default gateway. |
| `-w file` | Write raw packets to a classic **pcap** file instead of printing them. The file opens in Wireshark, `tshark` and `tcpdump -r`. Use `-w -` to write pcap to stdout for piping. |
| `-D` | List the interfaces that can be captured on. |
| `-c count` | Exit after `count` packets have matched the filter. |
| `-n`, `-U` | Accepted for compatibility and ignored: names are never resolved, and `-w -` is always flushed per packet. |
| `-h`, `--help` | Show usage. |
| `--version` | Show version. |

Long forms `--interface`, `--count` and `--list-interfaces` are also accepted.
Short options can be combined or attached in the usual getopt way: `-nni Ethernet0`, `-c10`, `-wout.pcap`.

Press **Ctrl+C** to stop. On exit it prints the familiar summary:

```
42 packets captured
1310 packets received by filter
0 packets dropped by kernel
```

## Filter expressions

A subset of the pcap-filter language. Everything after the options is joined into one
expression, so quoting is optional.

| Primitive | Matches |
|---|---|
| `host ADDR` | IPv4/IPv6 packets (and ARP) to or from `ADDR` |
| `src host ADDR` / `src ADDR` | packets from `ADDR` |
| `dst host ADDR` / `dst ADDR` | packets to `ADDR` |
| `src or dst host ADDR`, `src and dst host ADDR` | either / both directions |
| `port N` | TCP or UDP packets with source or destination port `N` |
| `src port N` / `dst port N` | by direction |
| `tcp port N` / `udp port N` | limited to one protocol (directions allowed too: `udp dst port 53`) |
| `tcp`, `udp`, `icmp`, `icmp6`, `ip`, `ip6`, `arp` | by protocol |

- Combine with `and` / `&&`, `or` / `||`, `not` / `!`, and parentheses.
- `ADDR` can be an IPv4 or IPv6 address or a hostname. Hostnames are resolved once at startup and match any of their addresses.
- `N` can be a number or a common service name (`http`, `https`, `ssh`, `dns`, `rdp`, `smb`, `ldap`, `kerberos`, `winrm`, ...).
- As in tcpdump, a bare value repeats the previous qualifier: `host 10.0.0.1 or 10.0.0.2`, `port 80 or 443`.

### Examples

```powershell
tcpdump -D                                              # list interfaces
tcpdump -i 1 host 10.0.0.5                              # one host, printed to the console
tcpdump -i Ethernet0 -w capture.pcap port 443           # save HTTPS traffic for Wireshark
tcpdump -i any -c 20 src 10.0.0.5 and not port 3389     # 20 packets, excluding RDP
tcpdump "udp port 53 or (tcp and dst port 80)"
```

Console output looks like tcpdump's (sequence numbers are absolute, as with `-S`):

```
10:07:43.612902 IP 172.20.20.3.50334 > 172.20.16.1.53: UDP, length 40
10:07:43.631570 IP 172.20.16.1.53 > 172.20.20.3.50334: UDP, length 113
```

## How it works

The tool starts a real-time ETW (Event Tracing for Windows) session and enables the
`Microsoft-Windows-NDIS-PacketCapture` provider (`{2ED6006E-4729-4609-B423-3EE7BCD678EF}`).
That makes `ndiscap.sys` report every sent and received frame as an event (ID 1001) carrying
the complete Ethernet frame. Frames are filtered by interface index and the filter
expression, then printed or written to the pcap file.

The ETW session (`tcpdump-win-<pid>`) is stopped on exit or Ctrl+C. If a run is killed
without cleaning up, the next run finds and stops the leftover session.

Packet parsing is written in safe Rust with bounds checks on every access, because the
input is untrusted network data. The only `unsafe` code is the thin layer of Windows API calls.

## Limitations

- Loopback (`127.0.0.1` / `::1`) traffic is not visible, because ndiscap sits below the TCP/IP stack.
- Wi-Fi adapters reporting native 802.11 frames are skipped (normal Wi-Fi traffic is delivered as Ethernet and works).
- On hosts with Hyper-V virtual switches or NIC teams, `-i any` can show the same packet more than once. Pick a specific interface.
- Output is one summary line per packet. There's no `-v`, `-X`, `-e`, `-r` or BPF bytecode yet. For deep inspection, use `-w` and open the file in Wireshark.

## Building from source

Requirements: Visual Studio 2022 Build Tools (the "Desktop development with C++" workload) and
stable Rust from [rustup](https://rustup.rs).

```powershell
cargo test             # unit tests: filter parser, packet decoder, pcap writer, CLI
cargo build --release  # produces target\release\tcpdump.exe
```

`.cargo/config.toml` links the C runtime statically, so the exe has no VCRUNTIME dependency.

## Project layout

| File | Purpose |
|---|---|
| `src/main.rs` | Wires the pieces together, Ctrl+C handling, exit statistics |
| `src/cli.rs` | tcpdump-style option parsing |
| `src/interfaces.rs` | Adapter enumeration (`GetAdaptersAddresses`) and `-i` resolution |
| `src/capture.rs` | ETW real-time session for NDIS-PacketCapture |
| `src/packet.rs` | Ethernet / VLAN / IPv4 / IPv6 / ARP / TCP / UDP / ICMP decoder |
| `src/filter.rs` | Filter expression lexer, parser and evaluator |
| `src/output.rs` | tcpdump-style summary lines |
| `src/pcap.rs` | pcap file writer |

## License and disclaimer

This project is released into the **public domain** under [The Unlicense](LICENSE).
Anyone may use, copy, modify, publish, sell or distribute it, in source or compiled form,
for any purpose, commercial or not, with no conditions and no attribution required.

**No warranty.** The software is provided "as is", without warranty of any kind. There is
no guarantee or expectation that the code does what it is described to do, does it correctly,
or is fit for any particular purpose. It was written by an AI coding agent and has had only
limited testing. You use it entirely at your own risk; the authors accept no liability for
any damage, data loss or other consequences of using it.
