use std::collections::HashMap;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{self, Command, Stdio};
use std::time::{Duration, Instant};

use crate::dns::{
    DnsEvent, NetPacket, append_traffic_event, audit_log_path, extract_net_packet_from_eth,
    now_epoch, pcap_archive_dir, qtype_name,
};

unsafe extern "C" {
    fn fallocate(fd: i32, mode: i32, offset: i64, len: i64) -> i32;
}

const FALLOC_FL_KEEP_SIZE: i32 = 0x01;
const FALLOC_FL_PUNCH_HOLE: i32 = 0x02;
const DNS_QUERY_TIMEOUT: Duration = Duration::from_millis(850);
const TCP_HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(1_500);
const TCP_PAYLOAD_GRACE: Duration = Duration::from_millis(300);
const UDP_REPLY_TIMEOUT: Duration = Duration::from_millis(750);
const ICMP_REPLY_TIMEOUT: Duration = Duration::from_millis(1_000);
const MAX_ARCHIVE_BYTES: u64 = 50 * 1024 * 1024; // 50 MiB per session cap

struct PendingDns {
    txid: u16,
    domain: String,
    qtype: u16,
    dns_server: String,
    cmd: String,
    ts: u64,
    seen_at: Instant,
}

struct PendingTcp {
    src_port: u16,
    dst_ip: String,
    dst_port: u16,
    cmd: String,
    ts: u64,
    seen_at: Instant,
    connected_at: Option<Instant>,
    sni: Option<String>,
    http_host: Option<String>,
}

struct PendingUdp {
    src_port: u16,
    dst_ip: String,
    dst_port: u16,
    cmd: String,
    ts: u64,
    seen_at: Instant,
    got_reply: bool,
}

struct PendingIcmp {
    dst_ip: String,
    cmd: String,
    ts: u64,
    seen_at: Instant,
}

fn read_u32_endian(bytes: &[u8], little_endian: bool) -> u32 {
    let arr: [u8; 4] = [bytes[0], bytes[1], bytes[2], bytes[3]];
    if little_endian {
        u32::from_le_bytes(arr)
    } else {
        u32::from_be_bytes(arr)
    }
}

fn sanitize_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn pcap_audit_path(box_name: &str, pid: u32) -> PathBuf {
    let safe_name = sanitize_name(box_name);
    // pasta's SELinux policy (pasta_t) allows creating pcap files in user_tmp_t
    // ($XDG_RUNTIME_DIR, i.e. /run/user/<uid>), whereas /tmp (tmp_t) is denied.
    let dir = env::var("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            audit_log_path()
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("/tmp"))
        });
    dir.join(format!("box-pcap-{}-{}.pcap", safe_name, pid))
}

pub fn cmd_tracker_path(box_name: &str, pid: u32) -> PathBuf {
    let safe_name = sanitize_name(box_name);
    let dir = env::var("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            audit_log_path()
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("/tmp"))
        });
    dir.join(format!("box-cmd-{}-{}.txt", safe_name, pid))
}

fn read_active_cmd(cmd_file: Option<&Path>, fallback: &str, pkt_ts: u64) -> String {
    let Some(path) = cmd_file else {
        return fallback.to_string();
    };
    let Ok(raw) = fs::read_to_string(path) else {
        return fallback.to_string();
    };
    let line = raw.lines().next().unwrap_or("").trim();
    if line.is_empty() {
        return fallback.to_string();
    }
    if let Some(rest) = line.strip_prefix("run\t") {
        let c = rest.trim();
        if !c.is_empty() {
            return c.chars().take(240).collect();
        }
    } else if let Some(rest) = line.strip_prefix("done:") {
        if let Some((ts_part, cmd_part)) = rest.split_once('\t') {
            let done_ts = ts_part.trim().parse::<u64>().unwrap_or(0);
            let c = cmd_part.trim();
            if !c.is_empty() {
                if pkt_ts <= done_ts.saturating_add(3) {
                    return c.chars().take(240).collect();
                }
                return format!("{} (after: {})", fallback, c.chars().take(180).collect::<String>());
            }
        }
    } else {
        return line.chars().take(240).collect();
    }
    fallback.to_string()
}

/// Spawn the background PCAP traffic auditor targeting a specific capture file path.
pub fn spawn_pcap_dns_auditor_at(
    pcap_path: &Path,
    box_name: &str,
    env_label: &str,
    workspace: &Path,
    cmd_str: &str,
    net_mode: &str,
    cmd_file: Option<&Path>,
    keep_cmd_file: bool,
) {
    let parent_pid = process::id();
    let _ = fs::remove_file(pcap_path);

    let exe = env::current_exe().expect("Failed to locate current box binary");

    let mut command = Command::new(exe);
    command.args([
        "--dns-pcap-file",
        &pcap_path.display().to_string(),
        "--dns-proxy-box",
        box_name,
        "--dns-proxy-env",
        env_label,
        "--dns-proxy-workspace",
        &workspace.display().to_string(),
        "--dns-proxy-cmd",
        cmd_str,
        "--dns-proxy-parent-pid",
        &parent_pid.to_string(),
        "--dns-proxy-net",
        net_mode,
    ]);
    if let Some(cf) = cmd_file {
        command.args(["--dns-proxy-cmd-file", &cf.display().to_string()]);
    }
    if keep_cmd_file {
        command.arg("--dns-proxy-keep-cmd-file");
    }

    let _child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to spawn PCAP traffic auditor");
}

/// Spawn the background PCAP traffic auditor and return the capture file path for `pasta --pcap`.
pub fn spawn_pcap_dns_auditor(
    box_name: &str,
    env_label: &str,
    workspace: &Path,
    cmd_str: &str,
    net_mode: &str,
    cmd_file: Option<&Path>,
    keep_cmd_file: bool,
) -> PathBuf {
    let parent_pid = process::id();
    let pcap_path = pcap_audit_path(box_name, parent_pid);
    spawn_pcap_dns_auditor_at(
        &pcap_path,
        box_name,
        env_label,
        workspace,
        cmd_str,
        net_mode,
        cmd_file,
        keep_cmd_file,
    );
    pcap_path
}

fn proto_for_tcp(dst_port: u16, sni: Option<&str>, http_host: Option<&str>) -> String {
    if sni.is_some() || dst_port == 443 {
        "HTTPS".to_string()
    } else if http_host.is_some() || dst_port == 80 {
        "HTTP".to_string()
    } else {
        "TCP".to_string()
    }
}

/// Tail a pasta `--pcap` file in real time, archive frames to a Wireshark-ready `.pcap`
/// under `~/.local/share/box/pcaps/`, correlate DNS/TCP/UDP/ICMP traffic (including
/// blocked requests), punch holes in tmpfs RAM, and clean up the tmpfs file on exit.
pub fn run_pcap_dns_auditor(
    pcap_path: &Path,
    box_name: &str,
    env_label: &str,
    workspace: &str,
    cmd_str: &str,
    net_mode: &str,
    cmd_file: Option<&Path>,
    keep_cmd_file: bool,
    parent_pid: Option<u32>,
) {
    let is_local_mode = net_mode.eq_ignore_ascii_case("local");
    let parent_alive = || match parent_pid {
        Some(pid) => Path::new(&format!("/proc/{}", pid)).exists(),
        None => true,
    };

    // Wait for pasta to create the pcap file and write the 24-byte global header
    let (mut file, can_punch) = loop {
        if let Ok(meta) = fs::metadata(pcap_path) {
            if meta.len() >= 24 {
                match OpenOptions::new().read(true).write(true).open(pcap_path) {
                    Ok(f) => break (f, true),
                    Err(_) => {
                        if let Ok(f) = File::open(pcap_path) {
                            break (f, false);
                        }
                    }
                }
            }
        }
        if !parent_alive() {
            let _ = fs::remove_file(pcap_path);
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    };

    let mut global_hdr = [0u8; 24];
    if file.read_exact(&mut global_hdr).is_err() {
        let _ = fs::remove_file(pcap_path);
        return;
    }

    let magic = u32::from_le_bytes([global_hdr[0], global_hdr[1], global_hdr[2], global_hdr[3]]);
    let little_endian = match magic {
        0xa1b2c3d4 | 0xa1b23c4d => true,
        0xd4c3b2a1 | 0x4d3cb2a1 => false,
        _ => {
            let _ = fs::remove_file(pcap_path);
            return;
        }
    };

    // Persistent Wireshark-exportable archive under ~/.local/share/box/pcaps/
    let archive_name = format!("{}-{}.pcap", sanitize_name(box_name), now_epoch());
    let archive_path = pcap_archive_dir().join(&archive_name);
    let mut archive_file = File::create(&archive_path).ok();
    let mut archive_bytes: u64 = 0;
    if let Some(ref mut af) = archive_file {
        if af.write_all(&global_hdr).is_ok() {
            archive_bytes = 24;
            let _ = af.flush();
        }
    }

    let log_path = audit_log_path();
    let mut offset: u64 = 24;
    let mut punched_up_to: u64 = 0;
    let mut pkt_hdr = [0u8; 16];
    let mut pkt_buf: Vec<u8> = Vec::with_capacity(2048);

    let mut ip_to_domain: HashMap<String, String> = HashMap::new();
    let mut gw_mac: Option<[u8; 6]> = None;
    let mut pending_dns: Vec<PendingDns> = Vec::new();
    let mut pending_tcp: Vec<PendingTcp> = Vec::new();
    let mut pending_udp: Vec<PendingUdp> = Vec::new();
    let mut recent_udp_seen: HashMap<(String, u16), Instant> = HashMap::new();
    let mut pending_icmp: Vec<PendingIcmp> = Vec::new();
    let mut final_drain = false;
    let mut archive_dirty = false;

    let emit = |ts: u64,
                ev_cmd: String,
                domain: String,
                qtype: String,
                ips: Vec<String>,
                cnames: Vec<String>,
                dns_server: String,
                proto: String,
                dst_port: u16,
                blocked: bool,
                block_reason: String| {
        append_traffic_event(
            &log_path,
            &DnsEvent {
                ts,
                box_name: box_name.to_string(),
                env: env_label.to_string(),
                workspace: workspace.to_string(),
                cmd: ev_cmd,
                domain,
                qtype,
                ips,
                cnames,
                dns_server,
                proto,
                dst_port,
                blocked,
                block_reason,
                pcap_file: archive_name.clone(),
            },
        );
    };

    loop {
        let file_len = match file.metadata() {
            Ok(m) => m.len(),
            Err(_) => break,
        };

        while file_len >= offset + 16 {
            if file.seek(SeekFrom::Start(offset)).is_err() {
                break;
            }
            if file.read_exact(&mut pkt_hdr).is_err() {
                break;
            }
            let ts_sec = read_u32_endian(&pkt_hdr[0..4], little_endian) as u64;
            let incl_len = read_u32_endian(&pkt_hdr[8..12], little_endian) as usize;

            if incl_len > 262_144 {
                let _ = fs::remove_file(pcap_path);
                return;
            }
            if file_len < offset + 16 + incl_len as u64 {
                break;
            }

            pkt_buf.resize(incl_len, 0);
            if file.read_exact(&mut pkt_buf).is_err() {
                break;
            }
            offset += 16 + incl_len as u64;

            // Mirror raw frame into persistent Wireshark PCAP archive (up to 50 MiB cap)
            if let Some(ref mut af) = archive_file {
                let frame_total = 16 + incl_len as u64;
                if archive_bytes + frame_total <= MAX_ARCHIVE_BYTES {
                    if af.write_all(&pkt_hdr).is_ok() && af.write_all(&pkt_buf).is_ok() {
                        archive_bytes += frame_total;
                        archive_dirty = true;
                    }
                }
            }

            let ts = if ts_sec > 0 { ts_sec } else { now_epoch() };
            let now_inst = Instant::now();

            if let Some(pkt) = extract_net_packet_from_eth(&pkt_buf, &mut gw_mac) {
                let active_cmd = || read_active_cmd(cmd_file, cmd_str, ts);
                match pkt {
                    NetPacket::DnsQuery {
                        txid,
                        domain,
                        qtype,
                        dns_server,
                    } => {
                        let dup = pending_dns
                            .iter()
                            .any(|q| q.txid == txid && q.domain == domain && q.qtype == qtype);
                        if !dup {
                            pending_dns.push(PendingDns {
                                txid,
                                domain,
                                qtype,
                                dns_server,
                                cmd: active_cmd(),
                                ts,
                                seen_at: now_inst,
                            });
                        }
                    }
                    NetPacket::DnsResponse {
                        txid,
                        domain,
                        qtype,
                        dns_server,
                        rcode,
                        ips,
                        cnames,
                    } => {
                        for ip in &ips {
                            ip_to_domain.insert(ip.clone(), domain.clone());
                        }
                        let matched = pending_dns
                            .iter()
                            .position(|q| q.txid == txid && q.domain == domain && q.qtype == qtype)
                            .or_else(|| {
                                pending_dns
                                    .iter()
                                    .position(|q| q.txid == txid && q.domain == domain)
                            });

                        let (ev_ts, ev_dns_server, ev_cmd) = if let Some(idx) = matched {
                            let q = pending_dns.remove(idx);
                            (q.ts, q.dns_server, q.cmd)
                        } else {
                            (ts, dns_server, active_cmd())
                        };

                        let (blocked, reason) = if rcode == 5 {
                            (true, "DNS REFUSED by resolver".to_string())
                        } else {
                            (false, String::new())
                        };

                        emit(
                            ev_ts,
                            ev_cmd,
                            domain,
                            qtype_name(qtype).to_string(),
                            ips,
                            cnames,
                            ev_dns_server,
                            "DNS".to_string(),
                            53,
                            blocked,
                            reason,
                        );
                    }
                    NetPacket::TcpOutboundSyn {
                        src_port,
                        dst_ip,
                        dst_port,
                    } => {
                        let dup = pending_tcp.iter().any(|t| {
                            t.src_port == src_port && t.dst_ip == dst_ip && t.dst_port == dst_port
                        });
                        if !dup {
                            pending_tcp.push(PendingTcp {
                                src_port,
                                dst_ip,
                                dst_port,
                                cmd: active_cmd(),
                                ts,
                                seen_at: now_inst,
                                connected_at: None,
                                sni: None,
                                http_host: None,
                            });
                        }
                    }
                    NetPacket::TcpInboundSynAck {
                        guest_port,
                        remote_ip,
                        remote_port,
                    } => {
                        if let Some(t) = pending_tcp.iter_mut().find(|t| {
                            t.src_port == guest_port
                                && t.dst_ip == remote_ip
                                && t.dst_port == remote_port
                        }) {
                            if t.connected_at.is_none() {
                                t.connected_at = Some(now_inst);
                            }
                        }
                    }
                    NetPacket::TcpInboundRst {
                        guest_port,
                        remote_ip,
                        remote_port,
                    } => {
                        if let Some(idx) = pending_tcp.iter().position(|t| {
                            t.src_port == guest_port
                                && t.dst_ip == remote_ip
                                && t.dst_port == remote_port
                                && t.connected_at.is_none()
                        }) {
                            let t = pending_tcp.remove(idx);
                            let domain = ip_to_domain
                                .get(&t.dst_ip)
                                .cloned()
                                .unwrap_or_else(|| t.dst_ip.clone());
                            let proto = proto_for_tcp(t.dst_port, None, None);
                            let reason = if is_local_mode {
                                "blocked by local-only network interface (TCP RST)".to_string()
                            } else {
                                "blocked / refused by firewall or remote host (TCP RST)".to_string()
                            };
                            emit(
                                t.ts,
                                t.cmd,
                                domain,
                                format!(":{}", t.dst_port),
                                vec![t.dst_ip],
                                Vec::new(),
                                String::new(),
                                proto,
                                t.dst_port,
                                true,
                                reason,
                            );
                        }
                    }
                    NetPacket::TcpOutboundPayload {
                        src_port,
                        dst_ip,
                        dst_port,
                        sni,
                        http_host,
                    } => {
                        if let Some(idx) = pending_tcp.iter().position(|t| {
                            t.src_port == src_port && t.dst_ip == dst_ip && t.dst_port == dst_port
                        }) {
                            let mut t = pending_tcp.remove(idx);
                            if sni.is_some() {
                                t.sni = sni;
                            }
                            if http_host.is_some() {
                                t.http_host = http_host;
                            }
                            let domain = t
                                .sni
                                .clone()
                                .or_else(|| t.http_host.clone())
                                .or_else(|| ip_to_domain.get(&t.dst_ip).cloned())
                                .unwrap_or_else(|| t.dst_ip.clone());
                            let proto = proto_for_tcp(
                                t.dst_port,
                                t.sni.as_deref(),
                                t.http_host.as_deref(),
                            );
                            emit(
                                t.ts,
                                t.cmd,
                                domain,
                                format!(":{}", t.dst_port),
                                vec![t.dst_ip],
                                Vec::new(),
                                String::new(),
                                proto,
                                t.dst_port,
                                false,
                                String::new(),
                            );
                        }
                    }
                    NetPacket::UdpOutbound {
                        src_port,
                        dst_ip,
                        dst_port,
                    } => {
                        let key = (dst_ip.clone(), dst_port);
                        let recently_logged = recent_udp_seen
                            .get(&key)
                            .map(|last| now_inst.duration_since(*last) < Duration::from_secs(5))
                            .unwrap_or(false);
                        let already_pending = pending_udp
                            .iter()
                            .any(|u| u.dst_ip == dst_ip && u.dst_port == dst_port);
                        if !recently_logged && !already_pending {
                            recent_udp_seen.insert(key, now_inst);
                            pending_udp.push(PendingUdp {
                                src_port,
                                dst_ip,
                                dst_port,
                                cmd: active_cmd(),
                                ts,
                                seen_at: now_inst,
                                got_reply: false,
                            });
                        }
                    }
                    NetPacket::UdpInbound {
                        guest_port,
                        remote_ip,
                        remote_port,
                    } => {
                        if let Some(u) = pending_udp.iter_mut().find(|u| {
                            u.src_port == guest_port
                                && u.dst_ip == remote_ip
                                && u.dst_port == remote_port
                        }) {
                            u.got_reply = true;
                        }
                    }
                    NetPacket::IcmpOutboundEcho { dst_ip } => {
                        if !pending_icmp.iter().any(|i| i.dst_ip == dst_ip) {
                            pending_icmp.push(PendingIcmp {
                                dst_ip,
                                cmd: active_cmd(),
                                ts,
                                seen_at: now_inst,
                            });
                        }
                    }
                    NetPacket::IcmpInboundReply { remote_ip } => {
                        if let Some(idx) = pending_icmp.iter().position(|i| i.dst_ip == remote_ip) {
                            let ic = pending_icmp.remove(idx);
                            let domain = ip_to_domain
                                .get(&ic.dst_ip)
                                .cloned()
                                .unwrap_or_else(|| ic.dst_ip.clone());
                            emit(
                                ic.ts,
                                ic.cmd,
                                domain,
                                "ECHO".to_string(),
                                vec![ic.dst_ip],
                                Vec::new(),
                                String::new(),
                                "ICMP".to_string(),
                                0,
                                false,
                                String::new(),
                            );
                        }
                    }
                    NetPacket::IcmpInboundUnreachable { src_ip, code } => {
                        let reason = format!(
                            "ICMP destination unreachable (code {} from {})",
                            code, src_ip
                        );
                        if let Some(idx) = pending_tcp.iter().position(|t| t.connected_at.is_none())
                        {
                            let t = pending_tcp.remove(idx);
                            let domain = ip_to_domain
                                .get(&t.dst_ip)
                                .cloned()
                                .unwrap_or_else(|| t.dst_ip.clone());
                            let proto = proto_for_tcp(t.dst_port, None, None);
                            emit(
                                t.ts,
                                t.cmd,
                                domain,
                                format!(":{}", t.dst_port),
                                vec![t.dst_ip],
                                Vec::new(),
                                String::new(),
                                proto,
                                t.dst_port,
                                true,
                                reason,
                            );
                        } else if let Some(ic) = pending_icmp.pop() {
                            let domain = ip_to_domain
                                .get(&ic.dst_ip)
                                .cloned()
                                .unwrap_or_else(|| ic.dst_ip.clone());
                            emit(
                                ic.ts,
                                ic.cmd,
                                domain,
                                "ECHO".to_string(),
                                vec![ic.dst_ip],
                                Vec::new(),
                                String::new(),
                                "ICMP".to_string(),
                                0,
                                true,
                                reason,
                            );
                        }
                    }
                }
            }
        }

        if archive_dirty {
            if let Some(ref mut af) = archive_file {
                let _ = af.flush();
            }
            archive_dirty = false;
        }

        let now_inst = Instant::now();

        // 1. Flush unanswered DNS queries -> mark as blocked!
        let mut i = 0;
        while i < pending_dns.len() {
            if final_drain || now_inst.duration_since(pending_dns[i].seen_at) >= DNS_QUERY_TIMEOUT {
                let q = pending_dns.remove(i);
                let reason = if is_local_mode {
                    "blocked by local-only network interface".to_string()
                } else {
                    "DNS query timed out (blocked / unreachable)".to_string()
                };
                emit(
                    q.ts,
                    q.cmd,
                    q.domain,
                    qtype_name(q.qtype).to_string(),
                    Vec::new(),
                    Vec::new(),
                    q.dns_server,
                    "DNS".to_string(),
                    53,
                    true,
                    reason,
                );
            } else {
                i += 1;
            }
        }

        // 2. Flush established TCP connections & timed-out TCP SYNs (blocked!)
        let mut i = 0;
        while i < pending_tcp.len() {
            let flush_connected = pending_tcp[i]
                .connected_at
                .map(|c| final_drain || now_inst.duration_since(c) >= TCP_PAYLOAD_GRACE)
                .unwrap_or(false);
            let flush_timed_out = pending_tcp[i].connected_at.is_none()
                && (final_drain
                    || now_inst.duration_since(pending_tcp[i].seen_at) >= TCP_HANDSHAKE_TIMEOUT);

            if flush_connected || flush_timed_out {
                let t = pending_tcp.remove(i);
                let domain = t
                    .sni
                    .clone()
                    .or_else(|| t.http_host.clone())
                    .or_else(|| ip_to_domain.get(&t.dst_ip).cloned())
                    .unwrap_or_else(|| t.dst_ip.clone());
                let proto = proto_for_tcp(t.dst_port, t.sni.as_deref(), t.http_host.as_deref());
                let (blocked, reason) = if t.connected_at.is_some() {
                    (false, String::new())
                } else if is_local_mode {
                    (
                        true,
                        "blocked by local-only network interface (TCP timeout)".to_string(),
                    )
                } else {
                    (
                        true,
                        "blocked by firewall / unreachable (TCP SYN timeout)".to_string(),
                    )
                };
                emit(
                    t.ts,
                    t.cmd,
                    domain,
                    format!(":{}", t.dst_port),
                    vec![t.dst_ip],
                    Vec::new(),
                    String::new(),
                    proto,
                    t.dst_port,
                    blocked,
                    reason,
                );
            } else {
                i += 1;
            }
        }

        // 3. Flush non-53 UDP flows
        let mut i = 0;
        while i < pending_udp.len() {
            if final_drain || now_inst.duration_since(pending_udp[i].seen_at) >= UDP_REPLY_TIMEOUT {
                let u = pending_udp.remove(i);
                let domain = ip_to_domain
                    .get(&u.dst_ip)
                    .cloned()
                    .unwrap_or_else(|| u.dst_ip.clone());
                let (blocked, reason) = if !u.got_reply && is_local_mode {
                    (true, "blocked by local-only network interface".to_string())
                } else {
                    (false, String::new())
                };
                emit(
                    u.ts,
                    u.cmd,
                    domain,
                    format!(":{}", u.dst_port),
                    vec![u.dst_ip],
                    Vec::new(),
                    String::new(),
                    "UDP".to_string(),
                    u.dst_port,
                    blocked,
                    reason,
                );
            } else {
                i += 1;
            }
        }

        // 4. Flush unanswered ICMP echo requests
        let mut i = 0;
        while i < pending_icmp.len() {
            if final_drain || now_inst.duration_since(pending_icmp[i].seen_at) >= ICMP_REPLY_TIMEOUT
            {
                let ic = pending_icmp.remove(i);
                let domain = ip_to_domain
                    .get(&ic.dst_ip)
                    .cloned()
                    .unwrap_or_else(|| ic.dst_ip.clone());
                let reason = if is_local_mode {
                    "blocked by local-only network interface (ICMP)".to_string()
                } else {
                    "blocked / unreachable (ICMP timeout)".to_string()
                };
                emit(
                    ic.ts,
                    ic.cmd,
                    domain,
                    "ECHO".to_string(),
                    vec![ic.dst_ip],
                    Vec::new(),
                    String::new(),
                    "ICMP".to_string(),
                    0,
                    true,
                    reason,
                );
            } else {
                i += 1;
            }
        }

        // Reclaim tmpfs RAM for already-processed packets once 1 MiB accumulates
        if can_punch && offset >= punched_up_to + 1_048_576 {
            let punch_end = offset & !4095u64;
            if punch_end > punched_up_to {
                let len = (punch_end - punched_up_to) as i64;
                unsafe {
                    fallocate(
                        file.as_raw_fd(),
                        FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                        punched_up_to as i64,
                        len,
                    );
                }
                punched_up_to = punch_end;
            }
        }

        if final_drain {
            break;
        }
        if !parent_alive() {
            final_drain = true;
            std::thread::sleep(Duration::from_millis(80));
        } else {
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    // If archive has only the 24-byte header (zero packets captured), remove it to avoid clutter
    drop(archive_file);
    if archive_bytes <= 24 {
        let _ = fs::remove_file(&archive_path);
    }
    let _ = fs::remove_file(pcap_path);
    if !keep_cmd_file {
        if let Some(cf) = cmd_file {
            let _ = fs::remove_file(cf);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_running_and_recently_completed_cmd_from_tracker() {
        let tmp = std::env::temp_dir().join(format!("box-cmd-test-{}.txt", std::process::id()));
        fs::write(&tmp, "run\tcurl -iL google.com\n").unwrap();
        assert_eq!(read_active_cmd(Some(&tmp), "bash", 1000), "curl -iL google.com");

        fs::write(&tmp, "done:1000\tcurl -iL google.com\n").unwrap();
        assert_eq!(read_active_cmd(Some(&tmp), "bash", 1002), "curl -iL google.com");
        assert_eq!(
            read_active_cmd(Some(&tmp), "bash", 1010),
            "bash (after: curl -iL google.com)"
        );

        let _ = fs::remove_file(&tmp);
    }
}
