use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process;
use std::thread;
use std::time::{Duration, SystemTime};

use crate::cli::Cli;
use crate::dns::{
    DnsEvent, audit_log_path, escape_json, format_local_datetime, format_local_time,
    load_dns_events, parse_dns_event_line, pcap_archive_dir,
};
use crate::domains::{DomainPolicy, RuleAction};
use crate::provenance::{CodeProvenance, inspect_code_provenance};

const UI_HTML: &str = include_str!("traffic_ui.html");
const MAX_BODY_BYTES: usize = 16 * 1024;

fn event_to_json(ev: &DnsEvent, policy: &DomainPolicy) -> String {
    let verdict = policy.classify(&ev.domain);
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
    format!(
        "{{\"ts\":{},\"time\":\"{}\",\"datetime\":\"{}\",\"box\":\"{}\",\"env\":\"{}\",\"workspace\":\"{}\",\"cmd\":\"{}\",\"domain\":\"{}\",\"qtype\":\"{}\",\"ips\":[{}],\"cnames\":[{}],\"dns_server\":\"{}\",\"proto\":\"{}\",\"dst_port\":{},\"blocked\":{},\"block_reason\":\"{}\",\"pcap_file\":\"{}\",\"label\":\"{}\",\"severity\":\"{}\",\"reason\":\"{}\"}}",
        ev.ts,
        escape_json(&format_local_time(ev.ts)),
        escape_json(&format_local_datetime(ev.ts)),
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
        escape_json(&ev.pcap_file),
        verdict.label(),
        verdict.severity_key(),
        escape_json(verdict.reason().unwrap_or("")),
    )
}

fn list_pcap_files_json(box_filter: Option<&str>) -> String {
    let dir = pcap_archive_dir();
    let mut entries: Vec<(u64, String, u64)> = fs::read_dir(&dir)
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let p = e.path();
            let name = p.file_name()?.to_str()?.to_string();
            if !name.ends_with(".pcap") {
                return None;
            }
            if let Some(f) = box_filter {
                if !name.contains(f) {
                    return None;
                }
            }
            let meta = e.metadata().ok()?;
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            Some((mtime, name, meta.len()))
        })
        .collect();
    entries.sort_by(|a, b| b.0.cmp(&a.0));
    entries
        .iter()
        .map(|(mtime, name, size)| {
            format!(
                "{{\"name\":\"{}\",\"size\":{},\"mtime\":{},\"datetime\":\"{}\"}}",
                escape_json(name),
                size,
                mtime,
                escape_json(&format_local_datetime(*mtime))
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn is_safe_pcap_filename(name: &str) -> bool {
    !name.is_empty()
        && name.ends_with(".pcap")
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains("..")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

fn json_str_list(items: &[String]) -> String {
    items
        .iter()
        .map(|p| format!("\"{}\"", escape_json(p)))
        .collect::<Vec<_>>()
        .join(",")
}

fn policy_to_json(policy: &DomainPolicy) -> String {
    format!(
        "{{\"source\":\"{}\",\"file\":\"{}\",\"user_allowed\":[{}],\"builtin_allowed\":[{}],\"blocked\":[{}]}}",
        escape_json(&policy.source_description),
        escape_json(&policy.user_file_path.display().to_string()),
        json_str_list(&policy.user_allowed_patterns()),
        json_str_list(&policy.builtin_allowed_patterns()),
        json_str_list(&policy.blocked_patterns()),
    )
}

fn provenance_to_json(prov: &CodeProvenance) -> String {
    let matches_json = prov
        .matches
        .iter()
        .map(|m| {
            let lines_json = m
                .snippet
                .iter()
                .map(|l| {
                    format!(
                        "{{\"line_no\":{},\"text\":\"{}\",\"is_match\":{}}}",
                        l.line_no,
                        escape_json(&l.text),
                        l.is_match
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            format!(
                "{{\"file\":\"{}\",\"line\":{},\"kind\":\"{}\",\"snippet\":[{}]}}",
                escape_json(&m.file),
                m.line,
                escape_json(&m.kind),
                lines_json
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"summary\":\"{}\",\"command_direct\":{},\"matches\":[{}]}}",
        escape_json(&prov.summary),
        prov.command_direct,
        matches_json
    )
}

fn send_http(stream: &mut TcpStream, status: &str, content_type: &str, body: &[u8]) {
    let header = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        status,
        content_type,
        body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(body);
}

fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
        } else if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex_str) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(val) = u8::from_str_radix(hex_str, 16) {
                    out.push(val);
                    i += 3;
                    continue;
                }
            }
            out.push(bytes[i]);
            i += 1;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

fn parse_query_params(query: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let mut it = pair.splitn(2, '=');
        let k = url_decode(it.next().unwrap_or(""));
        let v = url_decode(it.next().unwrap_or(""));
        map.insert(k, v);
    }
    map
}

fn extract_json_field(body: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\"", key);
    let pos = body.find(&needle)?;
    let rest = body[pos + needle.len()..].trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let mut out = String::new();
    let mut chars = rest.chars();
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

fn read_http_request(stream: &mut TcpStream) -> Option<(String, String, HashMap<String, String>, String)> {
    let mut raw = Vec::with_capacity(2048);
    let mut chunk = [0u8; 2048];
    let header_end = loop {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        raw.extend_from_slice(&chunk[..n]);
        if let Some(idx) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break idx;
        }
        if raw.len() > MAX_BODY_BYTES {
            return None;
        }
    };

    let header_text = String::from_utf8_lossy(&raw[..header_end]);
    let mut lines = header_text.lines();
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_lowercase(), v.trim().to_string());
        }
    }

    let content_len: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
        .min(MAX_BODY_BYTES);

    let body_start = header_end + 4;
    while raw.len() < body_start + content_len {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&chunk[..n]);
    }

    let body_end = (body_start + content_len).min(raw.len());
    let body = String::from_utf8_lossy(&raw[body_start..body_end]).to_string();

    Some((method, target, headers, body))
}

fn is_local_origin(headers: &HashMap<String, String>) -> bool {
    match headers.get("origin") {
        None => true,
        Some(origin) => {
            origin.starts_with("http://127.0.0.1:")
                || origin.starts_with("http://localhost:")
                || origin == "http://127.0.0.1"
                || origin == "http://localhost"
        }
    }
}

fn file_mtime(path: &Path) -> Option<SystemTime> {
    fs::metadata(path).ok()?.modified().ok()
}

fn handle_sse(
    mut stream: TcpStream,
    box_filter: Option<String>,
    domains_path: Option<PathBuf>,
) {
    let header = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n: connected\n\n";
    if stream.write_all(header.as_bytes()).is_err() {
        return;
    }
    let _ = stream.flush();

    let log_path = audit_log_path();
    let mut offset: u64 = fs::metadata(&log_path).map(|m| m.len()).unwrap_or(0);
    let mut policy = DomainPolicy::load(domains_path.as_deref());
    let mut policy_mtime = file_mtime(&policy.user_file_path);
    let mut ticks: u32 = 0;

    loop {
        thread::sleep(Duration::from_millis(150));
        ticks = ticks.wrapping_add(1);

        // Hot-reload domain rules when domains.txt changes
        if ticks % 6 == 0 {
            let new_mtime = file_mtime(&policy.user_file_path);
            if new_mtime != policy_mtime {
                policy = DomainPolicy::load(domains_path.as_deref());
                policy_mtime = new_mtime;
            }
        }

        if ticks % 40 == 0 {
            if stream.write_all(b": keepalive\n\n").is_err() {
                break;
            }
            let _ = stream.flush();
        }

        let Ok(meta) = fs::metadata(&log_path) else {
            continue;
        };
        let len = meta.len();
        if len < offset {
            offset = 0;
        }
        if len == offset {
            continue;
        }

        let Ok(mut file) = File::open(&log_path) else {
            continue;
        };
        if file.seek(SeekFrom::Start(offset)).is_err() {
            continue;
        }
        let mut reader = BufReader::new(file);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(n) => {
                    if !line.ends_with('\n') {
                        break;
                    }
                    offset += n as u64;
                    if let Some(ev) = parse_dns_event_line(&line, box_filter.as_deref()) {
                        let msg = format!("data: {}\n\n", event_to_json(&ev, &policy));
                        if stream.write_all(msg.as_bytes()).is_err() {
                            return;
                        }
                        let _ = stream.flush();
                    }
                }
                Err(_) => break,
            }
        }
    }
}

fn handle_client(
    mut stream: TcpStream,
    box_filter: Option<String>,
    domains_path: Option<PathBuf>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    let Some((method, target, headers, body)) = read_http_request(&mut stream) else {
        return;
    };

    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p, q),
        None => (target.as_str(), ""),
    };

    match (method.as_str(), path) {
        ("GET", "/" | "/index.html") => {
            send_http(
                &mut stream,
                "200 OK",
                "text/html; charset=utf-8",
                UI_HTML.as_bytes(),
            );
        }
        ("GET", "/api/events") => {
            let policy = DomainPolicy::load(domains_path.as_deref());
            let mut events = load_dns_events(box_filter.as_deref());
            events.sort_by_key(|e| e.ts);
            let events_json = events
                .iter()
                .map(|ev| event_to_json(ev, &policy))
                .collect::<Vec<_>>()
                .join(",");
            let resp = format!(
                "{{\"policy\":{},\"pcaps\":[{}],\"events\":[{}]}}",
                policy_to_json(&policy),
                list_pcap_files_json(box_filter.as_deref()),
                events_json
            );
            send_http(
                &mut stream,
                "200 OK",
                "application/json; charset=utf-8",
                resp.as_bytes(),
            );
        }
        ("GET", "/api/pcaps") => {
            let resp = format!("{{\"pcaps\":[{}]}}", list_pcap_files_json(box_filter.as_deref()));
            send_http(
                &mut stream,
                "200 OK",
                "application/json; charset=utf-8",
                resp.as_bytes(),
            );
        }
        ("GET", "/api/pcap") => {
            let params = parse_query_params(query);
            let file_name = params.get("file").cloned().unwrap_or_default();
            if !is_safe_pcap_filename(&file_name) {
                send_http(
                    &mut stream,
                    "400 Bad Request",
                    "text/plain",
                    b"Invalid pcap filename",
                );
                return;
            }
            let path = pcap_archive_dir().join(&file_name);
            match fs::read(&path) {
                Ok(bytes) => {
                    let header = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/vnd.tcpdump.pcap\r\nContent-Disposition: attachment; filename=\"{}\"\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
                        file_name,
                        bytes.len()
                    );
                    let _ = stream.write_all(header.as_bytes());
                    let _ = stream.write_all(&bytes);
                }
                Err(_) => {
                    send_http(&mut stream, "404 Not Found", "text/plain", b"PCAP not found");
                }
            }
        }
        ("POST", "/api/domains") => {
            if !is_local_origin(&headers) {
                send_http(
                    &mut stream,
                    "403 Forbidden",
                    "application/json; charset=utf-8",
                    b"{\"error\":\"Cross-origin request rejected\"}",
                );
                return;
            }
            let Some(domain) = extract_json_field(&body, "domain") else {
                send_http(
                    &mut stream,
                    "400 Bad Request",
                    "application/json; charset=utf-8",
                    b"{\"error\":\"Missing 'domain' field\"}",
                );
                return;
            };
            let action = match extract_json_field(&body, "action")
                .unwrap_or_else(|| "allow".to_string())
                .as_str()
            {
                "block" => RuleAction::Block,
                "remove" => RuleAction::Remove,
                _ => RuleAction::Allow,
            };

            let current = DomainPolicy::load(domains_path.as_deref());
            match DomainPolicy::update_rule_file(&current.user_file_path, &domain, action) {
                Ok(rule) => {
                    let updated = DomainPolicy::load(domains_path.as_deref());
                    let resp = format!(
                        "{{\"ok\":true,\"rule\":\"{}\",\"policy\":{}}}",
                        escape_json(&rule),
                        policy_to_json(&updated)
                    );
                    send_http(
                        &mut stream,
                        "200 OK",
                        "application/json; charset=utf-8",
                        resp.as_bytes(),
                    );
                }
                Err(err) => {
                    let resp = format!("{{\"error\":\"{}\"}}", escape_json(&err));
                    send_http(
                        &mut stream,
                        "400 Bad Request",
                        "application/json; charset=utf-8",
                        resp.as_bytes(),
                    );
                }
            }
        }
        ("GET", "/api/code") => {
            let params = parse_query_params(query);
            let workspace = params.get("workspace").cloned().unwrap_or_default();
            let domain = params.get("domain").cloned().unwrap_or_default();
            let cmd = params.get("cmd").cloned().unwrap_or_default();
            let ips: Vec<String> = params
                .get("ips")
                .map(|s| {
                    s.split(',')
                        .map(str::trim)
                        .filter(|x| !x.is_empty())
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default();

            // Security boundary: only inspect workspaces that actually exist in dns_audit.jsonl
            let known_workspace = load_dns_events(None)
                .iter()
                .any(|ev| !ev.workspace.is_empty() && ev.workspace == workspace);

            if !known_workspace {
                let resp = format!(
                    "{{\"summary\":\"Workspace '{}' is not in the box audit log; skipping host file scan.\",\"command_direct\":false,\"matches\":[]}}",
                    escape_json(&workspace)
                );
                send_http(
                    &mut stream,
                    "200 OK",
                    "application/json; charset=utf-8",
                    resp.as_bytes(),
                );
                return;
            }

            let prov = inspect_code_provenance(Path::new(&workspace), &domain, &cmd, &ips);
            let resp = provenance_to_json(&prov);
            send_http(
                &mut stream,
                "200 OK",
                "application/json; charset=utf-8",
                resp.as_bytes(),
            );
        }
        ("GET", "/api/stream") => {
            let _ = stream.set_read_timeout(None);
            handle_sse(stream, box_filter, domains_path);
        }
        _ => {
            send_http(&mut stream, "404 Not Found", "text/plain", b"Not Found");
        }
    }
}

pub fn serve_traffic_ui(cli: &Cli) {
    let addr = format!("127.0.0.1:{}", cli.web_port);
    let listener = TcpListener::bind(&addr).unwrap_or_else(|e| {
        eprintln!("ERROR: Failed to bind traffic dashboard on {}: {}", addr, e);
        process::exit(1);
    });

    let policy = DomainPolicy::load(cli.domains.as_deref());
    println!("================================================================================");
    println!("  BOX LIVE DNS TRAFFIC DASHBOARD");
    println!("  URL     : http://{}", addr);
    println!("  Log     : {}", audit_log_path().display());
    println!("  Domains : {}", policy.source_description);
    if let Some(ref f) = cli.box_filter {
        println!("  Filter  : box contains '{}'", f);
    }
    println!("  Press Ctrl+C to stop.");
    println!("================================================================================");

    for incoming in listener.incoming().flatten() {
        let box_filter = cli.box_filter.clone();
        let domains_path = cli.domains.clone();
        thread::spawn(move || handle_client(incoming, box_filter, domains_path));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_query_params_and_json_fields() {
        let params = parse_query_params("workspace=%2Fvar%2Fhome%2Falex&domain=crates.io&cmd=cargo+build");
        assert_eq!(params.get("workspace").unwrap(), "/var/home/alex");
        assert_eq!(params.get("domain").unwrap(), "crates.io");
        assert_eq!(params.get("cmd").unwrap(), "cargo build");

        let body = "{\"domain\": \"example.com\", \"action\": \"allow\"}";
        assert_eq!(extract_json_field(body, "domain").as_deref(), Some("example.com"));
        assert_eq!(extract_json_field(body, "action").as_deref(), Some("allow"));
    }
}
