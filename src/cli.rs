use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum NetMode {
    /// Complete air-gap (--network=none, no ports exposed). Default.
    None,
    /// Air-gapped from internet/LAN, with 127.0.0.1:PORT exposed to host browser.
    Local,
    /// Outbound internet allowed with transparent DNS audit logging.
    Internet,
}

impl NetMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            NetMode::None => "none",
            NetMode::Local => "local",
            NetMode::Internet => "internet",
        }
    }

    pub fn from_label(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "none" => Some(NetMode::None),
            "local" => Some(NetMode::Local),
            "internet" => Some(NetMode::Internet),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum VmRuntime {
    /// Fedora Atomic native libkrun microVM runtime (/usr/bin/krun via podman)
    Krun,
    /// Upstream Kata Containers runtime (via nerdctl + containerd shimv2)
    Kata,
}

impl VmRuntime {
    pub fn container_bin(&self) -> &'static str {
        match self {
            VmRuntime::Krun => "podman",
            VmRuntime::Kata => "nerdctl",
        }
    }

    pub fn from_label(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "krun" | "podman" => Some(VmRuntime::Krun),
            "kata" | "nerdctl" => Some(VmRuntime::Kata),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum Preset {
    Alpine,
    Latex,
    Node,
    Python,
    Rust,
}

impl Preset {
    pub fn image(&self) -> &'static str {
        match self {
            Preset::Python => "docker.io/library/python:3-slim",
            Preset::Rust => "docker.io/library/rust:slim",
            Preset::Node => "docker.io/library/node:22-slim",
            Preset::Latex => "docker.io/texlive/texlive:latest",
            Preset::Alpine => "docker.io/library/alpine:latest",
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Preset::Python => "python",
            Preset::Rust => "rust",
            Preset::Node => "node",
            Preset::Latex => "latex",
            Preset::Alpine => "alpine",
        }
    }

    pub fn base_priority(&self) -> u8 {
        match self {
            Preset::Latex => 5,
            Preset::Rust => 4,
            Preset::Node => 3,
            Preset::Python => 2,
            Preset::Alpine => 1,
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "box",
    about = "Automate KVM microVM-isolated sandboxes (Kata / libkrun) with DNS traffic telemetry",
    trailing_var_arg = true
)]
pub struct Cli {
    /// List all created boxes grouped by environment (python, rust, latex+python, etc.)
    #[arg(short, long, default_value_t = false)]
    pub list: bool,

    /// Verify virtualization stack and prove KVM microVM isolation (libkrun vs Kata Containers)
    #[arg(long, default_value_t = false)]
    pub verify: bool,

    /// Inspect a specific box/container's full software stack (image, runtime/Kata vs libkrun, OS, installed tools & packages; add -v for full package list)
    #[arg(long, visible_alias = "info", value_name = "BOX")]
    pub inspect: Option<String>,

    /// Attach to an existing box by name or ID (attaches if running, starts & attaches if stopped)
    #[arg(short = 'a', long, value_name = "BOX")]
    pub attach: Option<String>,

    /// With --attach, mount the current working directory at /workspace (recreates container while preserving image, net, and /opt/venv)
    #[arg(long, default_value_t = false)]
    pub mount_cwd: bool,

    /// Visualize contacted DNS names (oldest -> most recent at bottom)
    #[arg(short, long, default_value_t = false)]
    pub traffic: bool,

    /// Stream live DNS queries in real time in the terminal (use with --traffic)
    #[arg(short = 'f', long, default_value_t = false)]
    pub follow: bool,

    /// Show expanded details (all resolved IPs, DNS server, workspace, command) in --traffic
    #[arg(short = 'v', long, default_value_t = false)]
    pub details: bool,

    /// Open a simple local live browser dashboard for --traffic (http://127.0.0.1:<web-port>)
    #[arg(long, default_value_t = false)]
    pub web: bool,

    /// Local port for --traffic --web dashboard
    #[arg(long, default_value_t = 8787)]
    pub web_port: u16,

    /// Domain allowlist/blocklist file to compare against (default: ~/.config/box/domains.txt + built-in dev registries)
    #[arg(long)]
    pub domains: Option<PathBuf>,

    /// Number of recent DNS events shown at the bottom of --traffic
    #[arg(long, default_value_t = 25)]
    pub limit: usize,

    /// Export the latest captured PCAP file (matching --box-filter if set) to a path for Wireshark
    #[arg(long, value_name = "OUT_PCAP")]
    pub export_pcap: Option<PathBuf>,

    /// Trace which box, workspace, and command generated queries to a domain (substring match)
    #[arg(long)]
    pub trace: Option<String>,

    /// Filter --traffic or --trace output to a specific box name
    #[arg(long)]
    pub box_filter: Option<String>,

    /// Upstream DNS resolver used by the transparent audit proxy
    #[arg(long, default_value = "1.1.1.1:53")]
    pub upstream_dns: String,

    /// Keep the box container/VM after exiting instead of auto-removing (--rm)
    #[arg(long, default_value_t = false)]
    pub keep: bool,

    /// Force rebuild of a combined multi-preset image
    #[arg(long, default_value_t = false)]
    pub rebuild: bool,

    /// Optional custom name for the box
    #[arg(long)]
    pub name: Option<String>,

    /// Target directory to mount into /workspace (defaults to current directory)
    #[arg(short, long)]
    pub dir: Option<PathBuf>,

    /// Mount the workspace as read-write instead of read-only
    #[arg(long, default_value_t = false)]
    pub rw: bool,

    /// MicroVM runtime backend (krun for Fedora Atomic podman, kata for upstream containerd/nerdctl)
    #[arg(long, value_enum, default_value_t = VmRuntime::Krun)]
    pub runtime: VmRuntime,

    /// Network isolation mode (defaults to `none` for new boxes; preserves saved mode on `--attach`)
    #[arg(short, long, value_enum)]
    pub net: Option<NetMode>,

    /// Local loopback port (127.0.0.1:PORT) used in --net=local (or optionally with --net=internet)
    #[arg(short, long, default_value_t = 8888)]
    pub port: u16,

    /// Also expose --port when running in --net=internet mode
    #[arg(long, default_value_t = false)]
    pub expose_port: bool,

    /// One or more toolchain presets, comma-separated or repeated (e.g., --preset latex,python)
    #[arg(long, value_enum, value_delimiter = ',')]
    pub preset: Vec<Preset>,

    /// Override container image (takes precedence over --preset)
    #[arg(short, long)]
    pub image: Option<String>,

    /// Named volume mounted at /opt/venv to persist packages/cargo registry across runs
    #[arg(long, default_value = "box-venv")]
    pub venv: String,

    /// Do not mount a persistent /opt/venv volume (completely ephemeral run)
    #[arg(long, default_value_t = false)]
    pub ephemeral: bool,

    /// Memory limit allocated to the microVM (e.g., 1g, 2g, 4g, 512m)
    #[arg(short, long, default_value = "2g")]
    pub memory: String,

    /// Number of vCPUs allocated to the microVM
    #[arg(long, default_value_t = 2)]
    pub cpus: u32,

    /// Maximum PIDs allowed inside the guest (prevents fork bombs)
    #[arg(long, default_value_t = 250)]
    pub pids_limit: u32,

    /// Run via sudo (recommended if /dev/kvm or containerd requires root privileges)
    #[arg(long, default_value_t = false)]
    pub sudo: bool,

    /// Internal flag: run as background PCAP DNS auditor for a specific box
    #[arg(long, hide = true)]
    pub dns_pcap_file: Option<PathBuf>,

    #[arg(long, hide = true)]
    pub dns_proxy_box: Option<String>,

    #[arg(long, hide = true)]
    pub dns_proxy_env: Option<String>,

    #[arg(long, hide = true)]
    pub dns_proxy_workspace: Option<String>,

    #[arg(long, hide = true)]
    pub dns_proxy_cmd: Option<String>,

    #[arg(long, hide = true)]
    pub dns_proxy_parent_pid: Option<u32>,

    #[arg(long, hide = true)]
    pub dns_proxy_net: Option<String>,

    #[arg(long, hide = true)]
    pub dns_proxy_cmd_file: Option<PathBuf>,

    #[arg(long, hide = true, default_value_t = false)]
    pub dns_proxy_keep_cmd_file: bool,

    /// Command to execute inside the sandbox (defaults to interactive shell)
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub cmd: Vec<String>,
}
