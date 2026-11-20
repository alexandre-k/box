use std::env;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Default MAC address used by pasta for the gateway side of the tap interface (`-M`).
pub const PASTA_GW_MAC: [u8; 6] = [0x9a, 0x55, 0x9a, 0x55, 0x9a, 0x55];

#[derive(Debug, Clone)]
pub struct DnsEvent {
    pub ts: u64,
    pub box_name: String,
    pub env: String,
    pub workspace: String,
    pub cmd: String,
    pub domain: String,
    pub qtype: String,
    pub ips: Vec<String>,
    pub cnames: Vec<String>,
    pub dns_server: String,
    pub proto: String,
    pub dst_port: u16,
    pub blocked: bool,
    pub block_reason: String,
    pub pcap_file: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetPacket {
    DnsQuery {
        txid: u16,
        domain: String,
        qtype: u16,
        dns_server: String,
    },
    DnsResponse {
        txid: u16,
        domain: String,
        qtype: u16,
        dns_server: String,
        rcode: u8,
        ips: Vec<String>,
        cnames: Vec<String>,
    },
    TcpOutboundSyn {
        src_port: u16,
        dst_ip: String,
        dst_port: u16,
    },
    TcpInboundSynAck {
        guest_port: u16,
        remote_ip: String,
        remote_port: u16,
    },
    TcpInboundRst {
        guest_port: u16,
        remote_ip: String,
        remote_port: u16,
    },
    TcpOutboundPayload {
        src_port: u16,
        dst_ip: String,
        dst_port: u16,
        sni: Option<String>,
        http_host: Option<String>,
    },
    UdpOutbound {
        src_port: u16,
        dst_ip: String,
        dst_port: u16,
    },
    UdpInbound {
        guest_port: u16,
        remote_ip: String,
        remote_port: u16,
    },
    IcmpOutboundEcho {
        dst_ip: String,
    },
    IcmpInboundReply {
        remote_ip: String,
    },
    IcmpInboundUnreachable {
        src_ip: String,
        code: u8,
    },
}

#[repr(C)]
struct LibcTm {
    tm_sec: i32,
    tm_min: i32,
    tm_hour: i32,
    tm_mday: i32,
    tm_mon: i32,
    tm_year: i32,
    tm_wday: i32,
    tm_yday: i32,
    tm_isdst: i32,
    tm_gmtoff: i64,
    tm_zone: *const i8,
}

unsafe extern "C" {
    fn localtime_r(timep: *const i64, result: *mut LibcTm) -> *mut LibcTm;
}

pub fn format_local_time(ts: u64) -> String {
    let t = ts as i64;
    let mut tm = LibcTm {
        tm_sec: 0,
        tm_min: 0,
        tm_hour: 0,
        tm_mday: 0,
        tm_mon: 0,
        tm_year: 0,
        tm_wday: 0,
        tm_yday: 0,
        tm_isdst: 0,
        tm_gmtoff: 0,
        tm_zone: std::ptr::null(),
    };
    let ptr = unsafe { localtime_r(&t, &mut tm) };
    if ptr.is_null() {
        return format!("{}", ts);
    }
    format!("{:02}:{:02}:{:02}", tm.tm_hour, tm.tm_min, tm.tm_sec)
}

pub fn format_local_datetime(ts: u64) -> String {
    let t = ts as i64;
    let mut tm = LibcTm {
        tm_sec: 0,
        tm_min: 0,
        tm_hour: 0,
        tm_mday: 0,
        tm_mon: 0,
        tm_year: 0,
        tm_wday: 0,
        tm_yday: 0,
        tm_isdst: 0,
        tm_gmtoff: 0,
        tm_zone: std::ptr::null(),
    };
    let ptr = unsafe { localtime_r(&t, &mut tm) };
    if ptr.is_null() {
        return format!("{}", ts);
    }
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}

pub fn box_data_dir() -> PathBuf {
    let base = env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            PathBuf::from(home).join(".local/share")
        });
    let dir = base.join("box");
    let _ = fs::create_dir_all(&dir);
    dir
}

pub fn audit_log_path() -> PathBuf {
    box_data_dir().join("dns_audit.jsonl")
}

pub fn pcap_archive_dir() -> PathBuf {
    let dir = box_data_dir().join("pcaps");
    let _ = fs::create_dir_all(&dir);
    dir
}

pub fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn skip_dns_name(pkt: &[u8], start: usize) -> Option<usize> {
    let mut pos = start;
    let mut jumps = 0usize;
    while pos < pkt.len() {
        let len = pkt[pos] as usize;
        if len == 0 {
            return Some(pos + 1);
        }
        if (len & 0xC0) == 0xC0 {
            if pos + 2 > pkt.len() {
                return None;
            }
            return Some(pos + 2);
        }
        if (len & 0xC0) != 0 || pos + 1 + len > pkt.len() {
            return None;
        }
        pos += 1 + len;
        jumps += 1;
        if jumps > 128 {
            return None;
        }
    }
    None
}

fn parse_dns_question_section(pkt: &[u8]) -> Option<(String, u16, usize)> {
    if pkt.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]);
    if qdcount == 0 {
        return None;
    }

    let mut pos = 12;
    let mut labels = Vec::new();
    while pos < pkt.len() {
        let len = pkt[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if (len & 0xC0) == 0xC0 || pos + 1 + len > pkt.len() {
            return None;
        }
        let label = String::from_utf8_lossy(&pkt[pos + 1..pos + 1 + len]).to_lowercase();
        labels.push(label);
        pos += 1 + len;
    }

    if pos + 4 > pkt.len() || labels.is_empty() {
        return None;
    }

    let qtype = u16::from_be_bytes([pkt[pos], pkt[pos + 1]]);
    pos += 4;

    for _ in 1..qdcount {
        pos = skip_dns_name(pkt, pos)?;
        if pos + 4 > pkt.len() {
            return None;
        }
        pos += 4;
    }

    Some((labels.join("."), qtype, pos))
}

#[allow(dead_code)]
pub fn parse_dns_question(pkt: &[u8]) -> Option<(String, u16)> {
    let (domain, qtype, _) = parse_dns_question_section(pkt)?;
    Some((domain, qtype))
}

/// Decode a DNS domain name starting at `start`, following 0xC0 compression pointers safely.
fn decode_dns_name(pkt: &[u8], start: usize) -> Option<String> {
    let mut pos = start;
    let mut labels = Vec::new();
    let mut jumps = 0usize;
    while pos < pkt.len() {
        let len = pkt[pos] as usize;
        if len == 0 {
            break;
        }
        if (len & 0xC0) == 0xC0 {
            if pos + 2 > pkt.len() {
                return None;
            }
            let ptr = (((len & 0x3F) as usize) << 8) | (pkt[pos + 1] as usize);
            if ptr >= pkt.len() {
                return None;
            }
            pos = ptr;
            jumps += 1;
            if jumps > 32 {
                return None;
            }
            continue;
        }
        if (len & 0xC0) != 0 || pos + 1 + len > pkt.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&pkt[pos + 1..pos + 1 + len]).to_lowercase());
        pos += 1 + len;
        if labels.len() > 128 {
            return None;
        }
    }
    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

pub fn parse_dns_response(pkt: &[u8]) -> Option<(String, u16, Vec<String>, Vec<String>)> {
    let (domain, qtype, mut pos) = parse_dns_question_section(pkt)?;
    let ancount = u16::from_be_bytes([pkt[6], pkt[7]]);
    let mut ips = Vec::new();
    let mut cnames = Vec::new();

    for _ in 0..ancount {
        pos = match skip_dns_name(pkt, pos) {
            Some(p) => p,
            None => break,
        };
        if pos + 10 > pkt.len() {
            break;
        }
        let rtype = u16::from_be_bytes([pkt[pos], pkt[pos + 1]]);
        let rdlength = u16::from_be_bytes([pkt[pos + 8], pkt[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlength > pkt.len() {
            break;
        }
        match (rtype, rdlength) {
            (1, 4) => {
                let ip = Ipv4Addr::new(pkt[pos], pkt[pos + 1], pkt[pos + 2], pkt[pos + 3]);
                let s = ip.to_string();
                if !ips.contains(&s) {
                    ips.push(s);
                }
            }
            (28, 16) => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&pkt[pos..pos + 16]);
                let ip = Ipv6Addr::from(octets);
                let s = ip.to_string();
                if !ips.contains(&s) {
                    ips.push(s);
                }
            }
            (5, _) => {
                // CNAME alias target
                if let Some(target) = decode_dns_name(pkt, pos) {
                    if target != domain && !cnames.contains(&target) {
                        cnames.push(target);
                    }
                }
            }
            _ => {}
        }
        pos += rdlength;
    }

    Some((domain, qtype, ips, cnames))
}

/// Extract SNI hostname from a TLS ClientHello TCP payload.
pub fn extract_tls_sni(payload: &[u8]) -> Option<String> {
    // TLS record header (5 bytes): content_type=0x16 (Handshake), version, length
    if payload.len() < 43 || payload[0] != 0x16 {
        return None;
    }
    // Handshake header: type=0x01 (ClientHello)
    if payload[5] != 0x01 {
        return None;
    }
    let mut pos = 5 + 4 + 2 + 32; // handshake hdr(4) + legacy_version(2) + random(32)
    if pos >= payload.len() {
        return None;
    }
    // Session ID
    let sid_len = payload[pos] as usize;
    pos += 1 + sid_len;
    if pos + 2 > payload.len() {
        return None;
    }
    // Cipher suites
    let cs_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2 + cs_len;
    if pos >= payload.len() {
        return None;
    }
    // Compression methods
    let comp_len = payload[pos] as usize;
    pos += 1 + comp_len;
    if pos + 2 > payload.len() {
        return None;
    }
    // Extensions
    let ext_total = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2;
    let ext_end = (pos + ext_total).min(payload.len());

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let ext_len = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > ext_end {
            break;
        }
        if ext_type == 0x0000 && ext_len >= 5 {
            // server_name list
            let mut sp = pos + 2; // skip list length
            while sp + 3 <= pos + ext_len {
                let name_type = payload[sp];
                let name_len = u16::from_be_bytes([payload[sp + 1], payload[sp + 2]]) as usize;
                sp += 3;
                if sp + name_len > pos + ext_len {
                    break;
                }
                if name_type == 0x00 {
                    let s = String::from_utf8_lossy(&payload[sp..sp + name_len])
                        .trim()
                        .to_lowercase();
                    if !s.is_empty() {
                        return Some(s);
                    }
                }
                sp += name_len;
            }
        }
        pos += ext_len;
    }
    None
}

/// Extract HTTP `Host:` header from a plaintext HTTP request TCP payload.
pub fn extract_http_host(payload: &[u8]) -> Option<String> {
    let methods: &[&[u8]] = &[
        b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"PATCH ", b"OPTIONS ", b"CONNECT ",
    ];
    if !methods.iter().any(|m| payload.starts_with(m)) {
        return None;
    }
    let sample = &payload[..payload.len().min(2048)];
    let text = String::from_utf8_lossy(sample);
    for line in text.lines().skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("host") {
                let host = v
                    .trim()
                    .split(':')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_lowercase();
                if !host.is_empty() {
                    return Some(host);
                }
            }
        }
    }
    None
}

/// Parse any interesting network packet (DNS, TCP, UDP, ICMP) from an Ethernet frame captured by `pasta --pcap`.
/// `gw_mac` is dynamically learned from DNS/ARP/RS frames (falling back to `PASTA_GW_MAC`).
pub fn extract_net_packet_from_eth(frame: &[u8], gw_mac: &mut Option<[u8; 6]>) -> Option<NetPacket> {
    if frame.len() < 14 {
        return None;
    }
    let mut dst_mac = [0u8; 6];
    let mut src_mac = [0u8; 6];
    dst_mac.copy_from_slice(&frame[0..6]);
    src_mac.copy_from_slice(&frame[6..12]);

    let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let mut l3_offset = 14usize;

    if ethertype == 0x8100 {
        if frame.len() < 18 {
            return None;
        }
        ethertype = u16::from_be_bytes([frame[16], frame[17]]);
        l3_offset = 18;
    }

    // Learn pasta's gateway MAC from ARP replies (oper=2) or router advertisements if not known yet
    if ethertype == 0x0806 && frame.len() >= l3_offset + 8 {
        let oper = u16::from_be_bytes([frame[l3_offset + 6], frame[l3_offset + 7]]);
        if oper == 2 && gw_mac.is_none() {
            *gw_mac = Some(src_mac);
        }
        return None;
    }

    let (src_ip, dst_ip, proto, l4_offset, is_v6) = match ethertype {
        0x0800 => {
            if frame.len() < l3_offset + 20 {
                return None;
            }
            let ihl = ((frame[l3_offset] & 0x0F) as usize) * 4;
            if ihl < 20 || frame.len() < l3_offset + ihl {
                return None;
            }
            let src = IpAddr::V4(Ipv4Addr::new(
                frame[l3_offset + 12],
                frame[l3_offset + 13],
                frame[l3_offset + 14],
                frame[l3_offset + 15],
            ));
            let dst = IpAddr::V4(Ipv4Addr::new(
                frame[l3_offset + 16],
                frame[l3_offset + 17],
                frame[l3_offset + 18],
                frame[l3_offset + 19],
            ));
            (src, dst, frame[l3_offset + 9], l3_offset + ihl, false)
        }
        0x86DD => {
            if frame.len() < l3_offset + 40 {
                return None;
            }
            let mut s = [0u8; 16];
            let mut d = [0u8; 16];
            s.copy_from_slice(&frame[l3_offset + 8..l3_offset + 24]);
            d.copy_from_slice(&frame[l3_offset + 24..l3_offset + 40]);
            (
                IpAddr::V6(Ipv6Addr::from(s)),
                IpAddr::V6(Ipv6Addr::from(d)),
                frame[l3_offset + 6],
                l3_offset + 40,
                true,
            )
        }
        _ => return None,
    };

    let effective_gw = gw_mac.unwrap_or(PASTA_GW_MAC);
    let is_outbound = dst_mac == effective_gw;
    let is_inbound = src_mac == effective_gw;

    match proto {
        17 => {
            // UDP
            if frame.len() < l4_offset + 8 {
                return None;
            }
            let sport = u16::from_be_bytes([frame[l4_offset], frame[l4_offset + 1]]);
            let dport = u16::from_be_bytes([frame[l4_offset + 2], frame[l4_offset + 3]]);
            let payload = &frame[l4_offset + 8..];

            if (sport == 53 || dport == 53) && payload.len() >= 12 {
                let txid = u16::from_be_bytes([payload[0], payload[1]]);
                let is_response = (payload[2] & 0x80) != 0;
                if !is_response && dport == 53 {
                    *gw_mac = Some(dst_mac);
                    let (domain, qtype, _) = parse_dns_question_section(payload)?;
                    return Some(NetPacket::DnsQuery {
                        txid,
                        domain,
                        qtype,
                        dns_server: dst_ip.to_string(),
                    });
                } else if is_response && sport == 53 {
                    *gw_mac = Some(src_mac);
                    let rcode = payload[3] & 0x0F;
                    let (domain, qtype, ips, cnames) = parse_dns_response(payload)?;
                    return Some(NetPacket::DnsResponse {
                        txid,
                        domain,
                        qtype,
                        dns_server: src_ip.to_string(),
                        rcode,
                        ips,
                        cnames,
                    });
                }
            }

            // Ignore DHCP/NDP/link-local multicast chatter
            if dport == 67 || dport == 68 || dport == 546 || dport == 547 || dport == 5353 {
                return None;
            }
            if is_outbound {
                Some(NetPacket::UdpOutbound {
                    src_port: sport,
                    dst_ip: dst_ip.to_string(),
                    dst_port: dport,
                })
            } else if is_inbound {
                Some(NetPacket::UdpInbound {
                    guest_port: dport,
                    remote_ip: src_ip.to_string(),
                    remote_port: sport,
                })
            } else {
                None
            }
        }
        6 => {
            // TCP
            if frame.len() < l4_offset + 20 {
                return None;
            }
            let sport = u16::from_be_bytes([frame[l4_offset], frame[l4_offset + 1]]);
            let dport = u16::from_be_bytes([frame[l4_offset + 2], frame[l4_offset + 3]]);
            let data_offset = ((frame[l4_offset + 12] >> 4) as usize) * 4;
            let flags = frame[l4_offset + 13];
            let syn = (flags & 0x02) != 0;
            let ack = (flags & 0x10) != 0;
            let rst = (flags & 0x04) != 0;

            let payload = if data_offset >= 20 && frame.len() > l4_offset + data_offset {
                &frame[l4_offset + data_offset..]
            } else {
                &[]
            };

            // DNS over TCP
            if (sport == 53 || dport == 53) && payload.len() >= 14 {
                let dns_payload = &payload[2..];
                let txid = u16::from_be_bytes([dns_payload[0], dns_payload[1]]);
                let is_response = (dns_payload[2] & 0x80) != 0;
                if !is_response && dport == 53 {
                    if let Some((domain, qtype, _)) = parse_dns_question_section(dns_payload) {
                        return Some(NetPacket::DnsQuery {
                            txid,
                            domain,
                            qtype,
                            dns_server: dst_ip.to_string(),
                        });
                    }
                } else if is_response && sport == 53 {
                    let rcode = dns_payload[3] & 0x0F;
                    if let Some((domain, qtype, ips, cnames)) = parse_dns_response(dns_payload) {
                        return Some(NetPacket::DnsResponse {
                            txid,
                            domain,
                            qtype,
                            dns_server: src_ip.to_string(),
                            rcode,
                            ips,
                            cnames,
                        });
                    }
                }
            }

            if is_outbound {
                if syn && !ack {
                    return Some(NetPacket::TcpOutboundSyn {
                        src_port: sport,
                        dst_ip: dst_ip.to_string(),
                        dst_port: dport,
                    });
                }
                if !payload.is_empty() {
                    let sni = extract_tls_sni(payload);
                    let http_host = if sni.is_none() {
                        extract_http_host(payload)
                    } else {
                        None
                    };
                    if sni.is_some() || http_host.is_some() {
                        return Some(NetPacket::TcpOutboundPayload {
                            src_port: sport,
                            dst_ip: dst_ip.to_string(),
                            dst_port: dport,
                            sni,
                            http_host,
                        });
                    }
                }
            } else if is_inbound {
                if syn && ack {
                    return Some(NetPacket::TcpInboundSynAck {
                        guest_port: dport,
                        remote_ip: src_ip.to_string(),
                        remote_port: sport,
                    });
                }
                if rst {
                    return Some(NetPacket::TcpInboundRst {
                        guest_port: dport,
                        remote_ip: src_ip.to_string(),
                        remote_port: sport,
                    });
                }
            }
            None
        }
        1 if !is_v6 => {
            // ICMPv4
            if frame.len() < l4_offset + 2 {
                return None;
            }
            let icmp_type = frame[l4_offset];
            let icmp_code = frame[l4_offset + 1];
            if is_outbound && icmp_type == 8 {
                Some(NetPacket::IcmpOutboundEcho {
                    dst_ip: dst_ip.to_string(),
                })
            } else if is_inbound && icmp_type == 0 {
                Some(NetPacket::IcmpInboundReply {
                    remote_ip: src_ip.to_string(),
                })
            } else if is_inbound && icmp_type == 3 {
                Some(NetPacket::IcmpInboundUnreachable {
                    src_ip: src_ip.to_string(),
                    code: icmp_code,
                })
            } else {
                None
            }
        }
        58 if is_v6 => {
            // ICMPv6 (only Echo + Dest Unreachable; skip NDP/RS/RA)
            if frame.len() < l4_offset + 2 {
                return None;
            }
            let icmp_type = frame[l4_offset];
            let icmp_code = frame[l4_offset + 1];
            if is_outbound && icmp_type == 128 {
                Some(NetPacket::IcmpOutboundEcho {
                    dst_ip: dst_ip.to_string(),
                })
            } else if is_inbound && icmp_type == 129 {
                Some(NetPacket::IcmpInboundReply {
                    remote_ip: src_ip.to_string(),
                })
            } else if is_inbound && icmp_type == 1 {
                Some(NetPacket::IcmpInboundUnreachable {
                    src_ip: src_ip.to_string(),
                    code: icmp_code,
                })
            } else {
                None
            }
        }
        _ => None,
    }
}

pub fn qtype_name(qtype: u16) -> &'static str {
    match qtype {
        1 => "A",
        28 => "AAAA",
        5 => "CNAME",
        15 => "MX",
        16 => "TXT",
        33 => "SRV",
        65 => "HTTPS",
        _ => "OTHER",
    }
}

pub fn extract_dns_host_ip(upstream: &str) -> String {
    if let Ok(addr) = upstream.parse::<SocketAddr>() {
        return addr.ip().to_string();
    }
    if let Ok(ip) = upstream.parse::<IpAddr>() {
        return ip.to_string();
    }
    upstream
        .split(':')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("1.1.1.1")
        .to_string()
}

pub fn append_traffic_event(log_path: &Path, ev: &DnsEvent) {
    let ips_json = ev
        .ips
        .iter()
        .map(|ip| format!("\"{}\"", escape_json(ip)))
        .collect::<Vec<_>>()
        .join(",");
    let cnames_json = ev
        .cnames
        .iter()
        .map(|c| format!("\"{}\"", escape_json(c)))
        .collect::<Vec<_>>()
        .join(",");
    let record = format!(
        "{{\"ts\":{},\"box\":\"{}\",\"env\":\"{}\",\"workspace\":\"{}\",\"cmd\":\"{}\",\"domain\":\"{}\",\"qtype\":\"{}\",\"ips\":[{}],\"cnames\":[{}],\"dns_server\":\"{}\",\"proto\":\"{}\",\"dst_port\":{},\"blocked\":{},\"block_reason\":\"{}\",\"pcap_file\":\"{}\"}}\n",
        ev.ts,
        escape_json(&ev.box_name),
        escape_json(&ev.env),
        escape_json(&ev.workspace),
        escape_json(&ev.cmd),
        escape_json(&ev.domain),
        escape_json(&ev.qtype),
        ips_json,
        cnames_json,
        escape_json(&ev.dns_server),
        escape_json(&ev.proto),
        ev.dst_port,
        ev.blocked,
        escape_json(&ev.block_reason),
        escape_json(&ev.pcap_file)
    );
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(log_path) {
        let _ = f.write_all(record.as_bytes());
    }
}

pub fn parse_dns_event_line(line: &str, box_filter: Option<&str>) -> Option<DnsEvent> {
    let ts = extract_json_u64(line, "ts")?;
    let domain = extract_json_str(line, "domain")?;
    let box_name = extract_json_str(line, "box").unwrap_or_else(|| "unknown".into());
    if let Some(filter) = box_filter {
        if !box_name.contains(filter) {
            return None;
        }
    }
    let qtype = extract_json_str(line, "qtype").unwrap_or_else(|| "A".into());
    let proto = extract_json_str(line, "proto").unwrap_or_else(|| "DNS".into());
    let dst_port = extract_json_u64(line, "dst_port")
        .map(|v| v as u16)
        .unwrap_or(if proto == "DNS" { 53 } else { 0 });
    let blocked = extract_json_bool(line, "blocked").unwrap_or(false);
    let block_reason = extract_json_str(line, "block_reason").unwrap_or_default();
    let pcap_file = extract_json_str(line, "pcap_file").unwrap_or_default();

    Some(DnsEvent {
        ts,
        box_name,
        env: extract_json_str(line, "env").unwrap_or_else(|| "unknown".into()),
        workspace: extract_json_str(line, "workspace").unwrap_or_else(|| "-".into()),
        cmd: extract_json_str(line, "cmd").unwrap_or_else(|| "-".into()),
        domain,
        qtype,
        ips: extract_json_str_array(line, "ips"),
        cnames: extract_json_str_array(line, "cnames"),
        dns_server: extract_json_str(line, "dns_server").unwrap_or_default(),
        proto,
        dst_port,
        blocked,
        block_reason,
        pcap_file,
    })
}

pub fn load_dns_events(box_filter: Option<&str>) -> Vec<DnsEvent> {
    let path = audit_log_path();
    let file = match fs::File::open(&path) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };

    let reader = BufReader::new(file);
    let mut events = Vec::new();
    for line in reader.lines().map_while(Result::ok) {
        if let Some(ev) = parse_dns_event_line(&line, box_filter) {
            events.push(ev);
        }
    }
    events
}

pub fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

fn extract_json_str(line: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\":\"", key);
    let start = line.find(&needle)? + needle.len();
    let mut out = String::new();
    let mut chars = line[start..].chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(next) = chars.next() {
                out.push(next);
            }
        } else if c == '"' {
            return Some(out);
        } else {
            out.push(c);
        }
    }
    None
}

fn extract_json_str_array(line: &str, key: &str) -> Vec<String> {
    let needle = format!("\"{}\":[", key);
    let Some(pos) = line.find(&needle) else {
        return Vec::new();
    };
    let rest = &line[pos + needle.len()..];
    let mut items = Vec::new();
    let mut chars = rest.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c == ']' {
            break;
        }
        if c == '"' {
            chars.next();
            let mut s = String::new();
            while let Some(ch) = chars.next() {
                if ch == '\\' {
                    if let Some(next) = chars.next() {
                        s.push(next);
                    }
                } else if ch == '"' {
                    break;
                } else {
                    s.push(ch);
                }
            }
            if !s.is_empty() {
                items.push(s);
            }
        } else {
            chars.next();
        }
    }
    items
}

fn extract_json_u64(line: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{}\":", key);
    let start = line.find(&needle)? + needle.len();
    let num_str: String = line[start..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    num_str.parse().ok()
}

fn extract_json_bool(line: &str, key: &str) -> Option<bool> {
    let needle = format!("\"{}\":", key);
    let start = line.find(&needle)? + needle.len();
    let rest = &line[start..];
    if rest.starts_with("true") {
        Some(true)
    } else if rest.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_dns_query(qr: u8, ancount: u16) -> Vec<u8> {
        let mut pkt = vec![
            0x12,
            0x34,
            qr,
            0x00,
            0x00,
            0x01,
            (ancount >> 8) as u8,
            (ancount & 0xFF) as u8,
            0x00,
            0x00,
            0x00,
            0x00,
        ];
        pkt.push(6);
        pkt.extend_from_slice(b"Crates");
        pkt.push(2);
        pkt.extend_from_slice(b"IO");
        pkt.push(0);
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        pkt
    }

    #[test]
    fn parses_dns_wire_question() {
        let pkt = sample_dns_query(0x01, 0);
        assert_eq!(parse_dns_question(&pkt), Some(("crates.io".into(), 1)));
    }

    #[test]
    fn parses_dns_response_with_compressed_a_and_aaaa_answers() {
        let mut pkt = sample_dns_query(0x81, 2);
        pkt.extend_from_slice(&[
            0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 151, 101, 2,
            137,
        ]);
        pkt.extend_from_slice(&[
            0xC0, 0x0C, 0x00, 0x1C, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x10, 0x2a, 0x04,
            0x4e, 0x42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x06, 0x49,
        ]);

        let (domain, qtype, ips, cnames) = parse_dns_response(&pkt).unwrap();
        assert_eq!(domain, "crates.io");
        assert_eq!(qtype, 1);
        assert_eq!(ips, vec!["151.101.2.137", "2a04:4e42::649"]);
        assert!(cnames.is_empty());
    }

    #[test]
    fn preserves_full_subdomain_and_decodes_cname_target() {
        let mut pkt = vec![
            0xab, 0xcd, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
        ];
        // Question: gmail.google.com (offset 12; google.com starts at offset 18)
        pkt.push(5);
        pkt.extend_from_slice(b"gmail");
        pkt.push(6);
        pkt.extend_from_slice(b"google");
        pkt.push(3);
        pkt.extend_from_slice(b"com");
        pkt.push(0);
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

        // Answer 1: CNAME -> mail + pointer to offset 18 (google.com)
        pkt.extend_from_slice(&[
            0xC0, 0x0C, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x07,
            4, b'm', b'a', b'i', b'l', 0xC0, 18,
        ]);
        // Answer 2: A -> 142.250.74.5
        pkt.extend_from_slice(&[
            0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04,
            142, 250, 74, 5,
        ]);

        let (domain, qtype, ips, cnames) = parse_dns_response(&pkt).unwrap();
        assert_eq!(domain, "gmail.google.com");
        assert_eq!(qtype, 1);
        assert_eq!(cnames, vec!["mail.google.com"]);
        assert_eq!(ips, vec!["142.250.74.5"]);
    }

    #[test]
    fn extracts_outbound_tcp_syn_and_inbound_rst() {
        let mut frame = vec![0u8; 14 + 20 + 20];
        frame[0..6].copy_from_slice(&PASTA_GW_MAC);
        frame[12] = 0x08;
        frame[13] = 0x00;
        frame[14] = 0x45;
        frame[23] = 6; // TCP
        frame[26..30].copy_from_slice(&[192, 0, 2, 2]);
        frame[30..34].copy_from_slice(&[1, 1, 1, 1]);
        frame[34..36].copy_from_slice(&46556u16.to_be_bytes());
        frame[36..38].copy_from_slice(&80u16.to_be_bytes());
        frame[46] = 0x50; // data offset = 20
        frame[47] = 0x02; // SYN

        let mut gw = None;
        assert_eq!(
            extract_net_packet_from_eth(&frame, &mut gw),
            Some(NetPacket::TcpOutboundSyn {
                src_port: 46556,
                dst_ip: "1.1.1.1".into(),
                dst_port: 80,
            })
        );

        let mut rst_frame = vec![0u8; 14 + 20 + 20];
        rst_frame[6..12].copy_from_slice(&PASTA_GW_MAC);
        rst_frame[12] = 0x08;
        rst_frame[13] = 0x00;
        rst_frame[14] = 0x45;
        rst_frame[23] = 6;
        rst_frame[26..30].copy_from_slice(&[1, 1, 1, 1]);
        rst_frame[30..34].copy_from_slice(&[192, 0, 2, 2]);
        rst_frame[34..36].copy_from_slice(&80u16.to_be_bytes());
        rst_frame[36..38].copy_from_slice(&46556u16.to_be_bytes());
        rst_frame[46] = 0x50;
        rst_frame[47] = 0x14; // RST+ACK

        assert_eq!(
            extract_net_packet_from_eth(&rst_frame, &mut gw),
            Some(NetPacket::TcpInboundRst {
                guest_port: 46556,
                remote_ip: "1.1.1.1".into(),
                remote_port: 80,
            })
        );
    }

    #[test]
    fn extracts_http_host_and_tls_sni() {
        let http = b"GET / HTTP/1.1\r\nHost: Google.COM:80\r\nUser-Agent: curl\r\n\r\n";
        assert_eq!(extract_http_host(http), Some("google.com".into()));

        // Minimal TLS ClientHello with SNI "google.com"
        let host = b"google.com";
        let sni_entry_len = 3 + host.len();
        let sni_ext_len = 2 + sni_entry_len;
        let mut ch = vec![0x16, 0x03, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x03];
        ch.extend_from_slice(&[0u8; 32]); // random
        ch.push(0); // session id len
        ch.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher suites
        ch.extend_from_slice(&[0x01, 0x00]); // compression
        ch.extend_from_slice(&((4 + sni_ext_len) as u16).to_be_bytes()); // extensions len
        ch.extend_from_slice(&0x0000u16.to_be_bytes()); // SNI ext type
        ch.extend_from_slice(&(sni_ext_len as u16).to_be_bytes());
        ch.extend_from_slice(&(sni_entry_len as u16).to_be_bytes());
        ch.push(0x00); // host_name
        ch.extend_from_slice(&(host.len() as u16).to_be_bytes());
        ch.extend_from_slice(host);

        assert_eq!(extract_tls_sni(&ch), Some("google.com".into()));
    }

    #[test]
    fn json_event_roundtrip_and_backwards_compat() {
        let new_line = "{\"ts\":12345,\"box\":\"b1\",\"env\":\"rust\",\"workspace\":\"/w\",\"cmd\":\"curl\",\"domain\":\"google.com\",\"qtype\":\"A\",\"ips\":[],\"dns_server\":\"192.0.2.53\",\"proto\":\"DNS\",\"dst_port\":53,\"blocked\":true,\"block_reason\":\"blocked by local\",\"pcap_file\":\"b1-123.pcap\"}";
        let ev = parse_dns_event_line(new_line, None).unwrap();
        assert!(ev.blocked);
        assert_eq!(ev.block_reason, "blocked by local");
        assert_eq!(ev.pcap_file, "b1-123.pcap");
        assert_eq!(ev.proto, "DNS");
        assert_eq!(ev.dst_port, 53);

        let legacy_line = "{\"ts\":12345,\"box\":\"b1\",\"env\":\"rust\",\"workspace\":\"/w\",\"cmd\":\"cargo\",\"domain\":\"crates.io\",\"qtype\":\"A\"}";
        let legacy = parse_dns_event_line(legacy_line, None).unwrap();
        assert!(!legacy.blocked);
        assert_eq!(legacy.proto, "DNS");
        assert_eq!(legacy.dst_port, 53);
    }
}
