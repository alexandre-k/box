use std::collections::{BTreeMap, HashMap, HashSet};
use std::env;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, IsTerminal, Seek, SeekFrom, Write};
use std::path::Path;
use std::process;
use std::time::{Duration, SystemTime};

use crate::cli::Cli;
use crate::dns::{
    DnsEvent, audit_log_path, format_local_datetime, format_local_time, load_dns_events, now_epoch,
    parse_dns_event_line, pcap_archive_dir,
};
use crate::domains::{DomainPolicy, DomainVerdict};

struct Colors {
    enabled: bool,
}

impl Colors {
    fn detect() -> Self {
        let no_color = env::var_os("NO_COLOR").is_some();
        Self {
            enabled: !no_color && std::io::stdout().is_terminal(),
        }
    }

    fn wrap(&self, code: &str, text: &str) -> String {
        if self.enabled {
            format!("\x1b[{}m{}\x1b[0m", code, text)
        } else {
            text.to_string()
        }
    }

    fn green(&self, s: &str) -> String {
        self.wrap("32", s)
    }

    fn yellow(&self, s: &str) -> String {
        self.wrap("33", s)
    }

    fn red_bold(&self, s: &str) -> String {
        self.wrap("1;31", s)
    }

    fn cyan(&self, s: &str) -> String {
        self.wrap("36", s)
    }

    fn dim(&self, s: &str) -> String {
        self.wrap("2", s)
    }

    fn bold(&self, s: &str) -> String {
        self.wrap("1", s)
    }

    fn magenta_bold(&self, s: &str) -> String {
        self.wrap("1;35", s)
    }

    fn badge(&self, verdict: &DomainVerdict, blocked: bool) -> String {
        if blocked {
            return self.magenta_bold("[BLK  ]");
        }
        match verdict {
            DomainVerdict::Allowed(_) => self.green("[OK   ]"),
            DomainVerdict::Unlisted => self.yellow("[NEW  ]"),
            DomainVerdict::Suspicious(_) => self.red_bold("[ALERT]"),
        }
    }

    fn domain(&self, verdict: &DomainVerdict, domain: &str) -> String {
        match verdict {
            DomainVerdict::Allowed(_) => self.green(domain),
            DomainVerdict::Unlisted => self.yellow(domain),
            DomainVerdict::Suspicious(_) => self.red_bold(domain),
        }
    }
}

fn render_bar(count: usize, max_count: usize, width: usize) -> String {
    if max_count == 0 || count == 0 {
        return String::new();
    }
    let filled = ((count as f64 / max_count as f64) * width as f64).ceil() as usize;
    "█".repeat(filled.max(1))
}

fn summarize_ips(ips: &[String]) -> String {
    match ips.len() {
        0 => "-".to_string(),
        1 => ips[0].clone(),
        n => format!("{} (+{})", ips[0], n - 1),
    }
}

fn print_legend(colors: &Colors, policy: &DomainPolicy) {
    println!(
        "  Legend : {} trusted   {} unlisted   {} suspicious   {} blocked by interface",
        colors.green("[OK   ]"),
        colors.yellow("[NEW  ]"),
        colors.red_bold("[ALERT]"),
        colors.magenta_bold("[BLK  ]")
    );
    println!("  Domains: {}", colors.dim(&policy.source_description));
}

fn format_proto_col(ev: &DnsEvent) -> String {
    if ev.proto == "DNS" {
        format!("DNS/{}", ev.qtype)
    } else if ev.dst_port > 0 {
        format!("{}:{}", ev.proto, ev.dst_port)
    } else {
        ev.proto.clone()
    }
}

fn print_event_row(ev: &DnsEvent, policy: &DomainPolicy, colors: &Colors, show_details: bool) {
    let verdict = policy.classify(&ev.domain);
    let time_str = format_local_time(ev.ts);
    let ip_summary = summarize_ips(&ev.ips);
    let domain_padded = format!("{:<30}", ev.domain);
    let proto_padded = format!("{:<10}", format_proto_col(ev));
    let ip_padded = format!("{:<22}", ip_summary);
    let cmd_short: String = if ev.cmd.len() > 26 {
        format!("{}…", ev.cmd.chars().take(25).collect::<String>())
    } else {
        ev.cmd.clone()
    };
    let cmd_padded = format!("{:<26}", cmd_short);

    let mut notes = Vec::new();
    if ev.blocked {
        let r = if ev.block_reason.is_empty() {
            "blocked by interface"
        } else {
            ev.block_reason.as_str()
        };
        notes.push(colors.magenta_bold(&format!("[BLOCKED: {}]", r)));
    }
    if let DomainVerdict::Suspicious(r) = &verdict {
        notes.push(colors.red_bold(&format!("({})", r)));
    }
    let note_str = if notes.is_empty() {
        String::new()
    } else {
        format!("  {}", notes.join(" "))
    };

    println!(
        "  {}  {}  {}  {}  {}  {}  {}{}",
        colors.dim(&time_str),
        colors.badge(&verdict, ev.blocked),
        colors.domain(&verdict, &domain_padded),
        colors.dim(&proto_padded),
        colors.cyan(&ip_padded),
        cmd_padded,
        ev.box_name,
        note_str
    );

    if show_details {
        let all_ips = if ev.ips.is_empty() {
            "-".to_string()
        } else {
            ev.ips.join(", ")
        };
        let dns_srv = if ev.dns_server.is_empty() {
            "-"
        } else {
            ev.dns_server.as_str()
        };
        let verdict_detail = match &verdict {
            DomainVerdict::Allowed(r) | DomainVerdict::Suspicious(r) => r.as_str(),
            DomainVerdict::Unlisted => "not in domain list",
        };
        let pcap_note = if ev.pcap_file.is_empty() {
            "-"
        } else {
            ev.pcap_file.as_str()
        };
        let cnames_part = if ev.cnames.is_empty() {
            String::new()
        } else {
            format!("  cnames=[{}]", ev.cnames.join(" -> "))
        };
        println!(
            "            {}",
            colors.dim(&format!(
                "at={}  env={}  dns={}  status={}  ips=[{}]{}  pcap={}",
                format_local_datetime(ev.ts),
                ev.env,
                dns_srv,
                verdict_detail,
                all_ips,
                cnames_part,
                pcap_note
            ))
        );
        println!(
            "            {}",
            colors.dim(&format!("workspace={}  cmd=\"{}\"", ev.workspace, ev.cmd))
        );
    }
}

pub fn export_latest_pcap(out_path: &Path, box_filter: Option<&str>) {
    let dir = pcap_archive_dir();
    let mut entries: Vec<(SystemTime, std::path::PathBuf, u64)> = fs::read_dir(&dir)
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let p = e.path();
            let name = p.file_name()?.to_str()?;
            if !name.ends_with(".pcap") {
                return None;
            }
            if let Some(f) = box_filter {
                if !name.contains(f) {
                    return None;
                }
            }
            let meta = e.metadata().ok()?;
            let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            Some((mtime, p, meta.len()))
        })
        .collect();

    entries.sort_by(|a, b| b.0.cmp(&a.0));

    let Some((_, src_path, size)) = entries.first() else {
        eprintln!(
            "No captured PCAP files found in {}{}.",
            dir.display(),
            box_filter
                .map(|f| format!(" matching '{}'", f))
                .unwrap_or_default()
        );
        process::exit(1);
    };

    if let Err(e) = fs::copy(src_path, out_path) {
        eprintln!(
            "Failed to export {} to {}: {}",
            src_path.display(),
            out_path.display(),
            e
        );
        process::exit(1);
    }

    println!(
        "Exported PCAP ({} bytes): {} -> {}",
        size,
        src_path.display(),
        out_path.display()
    );
    println!("Open in Wireshark: wireshark {}", out_path.display());
}

pub fn show_traffic_dashboard(cli: &Cli) {
    let colors = Colors::detect();
    let policy = DomainPolicy::load(cli.domains.as_deref());
    let mut events = load_dns_events(cli.box_filter.as_deref());
    events.sort_by_key(|e| e.ts);
    let now = now_epoch();

    if events.is_empty() {
        println!("No DNS traffic recorded yet in {:?}.", audit_log_path());
        println!("Run a box with `--net internet` to capture outbound DNS queries.");
        println!("Tip: Run `box --traffic --follow` (terminal) or `box --traffic --web` (browser) to watch live.");
        return;
    }

    // Oldest window first -> most recent window at the bottom
    let windows: [(&str, u64); 4] = [
        ("LAST 30 DAYS", 30 * 86_400),
        ("LAST 24 HOURS", 86_400),
        ("LAST 1 HOUR", 3_600),
        ("LAST 1 MINUTE", 60),
    ];

    println!("==========================================================================================");
    println!(
        "  {}  (Log: {})",
        colors.bold("BOX OUTBOUND DNS TRAFFIC MONITOR"),
        audit_log_path().display()
    );
    print_legend(&colors, &policy);
    println!("==========================================================================================\n");

    for (title, span) in windows {
        let cutoff = now.saturating_sub(span);
        let mut counts: HashMap<&str, usize> = HashMap::new();
        let mut sources: HashMap<&str, HashSet<&str>> = HashMap::new();
        let mut ip_map: HashMap<&str, Vec<&str>> = HashMap::new();

        for ev in &events {
            if ev.ts >= cutoff {
                *counts.entry(ev.domain.as_str()).or_insert(0) += 1;
                sources
                    .entry(ev.domain.as_str())
                    .or_default()
                    .insert(ev.box_name.as_str());
                let entry = ip_map.entry(ev.domain.as_str()).or_default();
                for ip in &ev.ips {
                    if entry.len() < 4 && !entry.contains(&ip.as_str()) {
                        entry.push(ip.as_str());
                    }
                }
            }
        }

        let mut ranked: Vec<(&str, usize)> = counts.into_iter().collect();
        ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));

        let total_queries: usize = ranked.iter().map(|(_, c)| *c).sum();
        println!(
            "--- {} ({} unique domains, {} total queries) ---",
            title,
            ranked.len(),
            total_queries
        );

        if ranked.is_empty() {
            println!("  {}\n", colors.dim("(no DNS queries in this window)"));
            continue;
        }

        let max_c = ranked[0].1;
        for (domain, count) in ranked.iter().take(12) {
            let verdict = policy.classify(domain);
            let bar = render_bar(*count, max_c, 18);
            let mut box_list: Vec<&str> = sources[*domain].iter().copied().collect();
            box_list.sort_unstable();
            let ip_note = match ip_map.get(domain) {
                Some(ips) if !ips.is_empty() => {
                    let s = if ips.len() == 1 {
                        ips[0].to_string()
                    } else {
                        format!("{} (+{})", ips[0], ips.len() - 1)
                    };
                    format!("  ip: {}", colors.cyan(&s))
                }
                _ => String::new(),
            };
            let flag = match &verdict {
                DomainVerdict::Suspicious(reason) => {
                    format!("  {}", colors.red_bold(&format!("[{}]", reason)))
                }
                _ => String::new(),
            };
            let domain_padded = format!("{:<34}", domain);
            println!(
                "  {} {} {:>4}  {:<18}  boxes: [{}]{}{}",
                colors.badge(&verdict, false),
                colors.domain(&verdict, &domain_padded),
                count,
                bar,
                box_list.join(", "),
                ip_note,
                flag
            );
        }
        println!();
    }

    // Chronological feed at the bottom: oldest -> most recent on the very last line
    let limit = cli.limit.max(1);
    let start = events.len().saturating_sub(limit);
    println!(
        "--- RECENT DNS ACTIVITY (showing last {} of {}, oldest -> newest) ---",
        events.len() - start,
        events.len()
    );
    println!(
        "  {}",
        colors.dim(&format!(
            "{:<8}  {:<7}  {:<30}  {:<10}  {:<22}  {:<26}  {}",
            "TIME", "STATUS", "DOMAIN / TARGET", "PROTO", "RESOLVED IP", "COMMAND", "BOX"
        ))
    );
    for ev in &events[start..] {
        print_event_row(ev, &policy, &colors, cli.details);
    }

    println!(
        "\n{}",
        colors.dim(
            "Tips: `box --traffic -f` (live terminal) | `box --traffic --web` (live browser) | `box --traffic -v` (full details) | `box --trace <domain>`"
        )
    );
}

fn file_mtime(path: &Path) -> Option<SystemTime> {
    fs::metadata(path).ok()?.modified().ok()
}

pub fn follow_traffic(cli: &Cli) {
    let colors = Colors::detect();
    let log_path = audit_log_path();
    let mut policy = DomainPolicy::load(cli.domains.as_deref());
    let mut policy_mtime = file_mtime(&policy.user_file_path);

    println!("==========================================================================================");
    println!(
        "  {}  (Log: {})",
        colors.bold("BOX LIVE DNS TRAFFIC MONITOR  [Ctrl+C to stop]"),
        log_path.display()
    );
    print_legend(&colors, &policy);
    println!("==========================================================================================");
    println!(
        "  {}",
        colors.dim(&format!(
            "{:<8}  {:<7}  {:<30}  {:<10}  {:<22}  {:<26}  {}",
            "TIME", "STATUS", "DOMAIN / TARGET", "PROTO", "RESOLVED IP", "COMMAND", "BOX"
        ))
    );

    let mut events = load_dns_events(cli.box_filter.as_deref());
    events.sort_by_key(|e| e.ts);
    let start = events.len().saturating_sub(cli.limit);
    for ev in &events[start..] {
        print_event_row(ev, &policy, &colors, cli.details);
    }
    let _ = std::io::stdout().flush();

    let mut offset: u64 = fs::metadata(&log_path).map(|m| m.len()).unwrap_or(0);
    let mut tick: u32 = 0;

    loop {
        std::thread::sleep(Duration::from_millis(120));
        tick = tick.wrapping_add(1);

        // Hot-reload user domain list every ~1s if modified
        if tick % 8 == 0 {
            let new_mtime = file_mtime(&policy.user_file_path);
            if new_mtime != policy_mtime {
                policy = DomainPolicy::load(cli.domains.as_deref());
                policy_mtime = new_mtime;
                println!(
                    "  {}",
                    colors.dim(&format!("[reloaded domain list: {}]", policy.source_description))
                );
                let _ = std::io::stdout().flush();
            }
        }

        let Ok(meta) = fs::metadata(&log_path) else {
            continue;
        };
        let len = meta.len();
        if len < offset {
            // File was truncated or recreated
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
                        // Partial write in progress; wait until complete line lands
                        break;
                    }
                    offset += n as u64;
                    if let Some(ev) = parse_dns_event_line(&line, cli.box_filter.as_deref()) {
                        print_event_row(&ev, &policy, &colors, cli.details);
                    }
                }
                Err(_) => break,
            }
        }
        let _ = std::io::stdout().flush();
    }
}

pub fn trace_domain(cli: &Cli, needle: &str) {
    let colors = Colors::detect();
    let policy = DomainPolicy::load(cli.domains.as_deref());
    let events = load_dns_events(cli.box_filter.as_deref());
    let now = now_epoch();
    let needle_lower = needle.to_lowercase();

    let matches: Vec<&DnsEvent> = events
        .iter()
        .filter(|e| e.domain.contains(&needle_lower))
        .collect();

    if matches.is_empty() {
        println!("No DNS queries matching '{}' found.", needle);
        return;
    }

    println!(
        "=== FORENSIC TRACE FOR '{}' ({} matching queries) ===\n",
        needle,
        matches.len()
    );

    // Group provenance by (box_name, env, workspace, cmd)
    let mut provenance: BTreeMap<(&str, &str, &str, &str), Vec<&DnsEvent>> = BTreeMap::new();
    for ev in &matches {
        provenance
            .entry((
                ev.box_name.as_str(),
                ev.env.as_str(),
                ev.workspace.as_str(),
                ev.cmd.as_str(),
            ))
            .or_default()
            .push(ev);
    }

    for ((box_name, env_name, workspace, cmd), mut evs) in provenance {
        evs.sort_by_key(|e| e.ts);
        let first_ts = evs.first().unwrap().ts;
        let last_ts = evs.last().unwrap().ts;
        let first_ago = now.saturating_sub(first_ts);
        let last_ago = now.saturating_sub(last_ts);

        let mut unique_domains: Vec<&str> = evs.iter().map(|e| e.domain.as_str()).collect();
        unique_domains.sort_unstable();
        unique_domains.dedup();

        let mut unique_ips: Vec<&str> = evs
            .iter()
            .flat_map(|e| e.ips.iter().map(String::as_str))
            .collect();
        unique_ips.sort_unstable();
        unique_ips.dedup();

        let mut unique_qtypes: Vec<&str> = evs.iter().map(|e| e.qtype.as_str()).collect();
        unique_qtypes.sort_unstable();
        unique_qtypes.dedup();

        let mut unique_dns_servers: Vec<&str> = evs
            .iter()
            .map(|e| e.dns_server.as_str())
            .filter(|s| !s.is_empty())
            .collect();
        unique_dns_servers.sort_unstable();
        unique_dns_servers.dedup();

        println!("Source Box   : {}", box_name);
        println!("Environment  : {}", env_name);
        println!("Workspace    : {}", workspace);
        println!("Command Run  : {}", cmd);
        println!(
            "Query Count  : {} (first: {} [{}s ago], latest: {} [{}s ago])",
            evs.len(),
            format_local_datetime(first_ts),
            first_ago,
            format_local_datetime(last_ts),
            last_ago
        );
        println!("Query Types  : {}", unique_qtypes.join(", "));
        println!("Matched DNS  : {}", unique_domains.join(", "));
        println!(
            "Resolved IPs : {}",
            if unique_ips.is_empty() {
                "-".to_string()
            } else {
                colors.cyan(&unique_ips.join(", "))
            }
        );
        if !unique_dns_servers.is_empty() {
            println!("DNS Servers  : {}", unique_dns_servers.join(", "));
        }
        for dom in &unique_domains {
            let verdict = policy.classify(dom);
            let detail = verdict.reason().unwrap_or("not in domain list");
            println!(
                "Verdict      : {} {} ({})",
                colors.badge(&verdict, false),
                colors.domain(&verdict, dom),
                detail
            );
        }
        println!("--------------------------------------------------------------------------------");
    }
}
