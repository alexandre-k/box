use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::IsTerminal;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{self, Command};

use crate::cli::{Cli, NetMode, Preset, VmRuntime};
use crate::dns::{audit_log_path, extract_dns_host_ip, now_epoch, pcap_archive_dir};
use crate::domains::default_domains_path;
use crate::image_config::{
    ImageConfig, find_image_config, load_image_config_from_path, resolve_images_dir,
};
use crate::images::{
    ResolvedImage, build_combined_image, build_image_from_config, generate_spec_from_config,
    infer_env_from_image, normalize_image_id, parse_presets_from_env_label,
};
use crate::pcap::{cmd_tracker_path, spawn_pcap_dns_auditor, spawn_pcap_dns_auditor_at};

#[derive(Debug)]
struct BoxRecord {
    id: String,
    name: String,
    status: String,
    workspace: String,
    runtime: String,
}

#[derive(Debug, Clone)]
struct BoxInspect {
    running: bool,
    name: String,
    image: String,
    image_id: String,
    network_mode: String,
    preset: String,
    workspace: String,
    runtime: Option<VmRuntime>,
    net: Option<NetMode>,
    rw: bool,
    venv: Option<String>,
    pcap: Option<PathBuf>,
    cmd: Vec<String>,
    keep_id: bool,
    cmd_file: Option<PathBuf>,
    managed: bool,
    is_toolbox: bool,
    host_port: Option<u16>,
    llama_bin: Option<PathBuf>,
    spec_hash: Option<String>,
    spec_file: Option<PathBuf>,
    base_presets: Vec<Preset>,
}

struct BoxSpec {
    box_name: String,
    image: String,
    env_label: String,
    presets: Vec<Preset>,
    spec_hash: Option<String>,
    spec_file: Option<PathBuf>,
    target_dir: PathBuf,
    effective_cmd: Vec<String>,
    runtime: VmRuntime,
    net: NetMode,
    rw: bool,
    keep: bool,
    venv: Option<String>,
    port: u16,
    expose_port: bool,
    host_port: Option<u16>,
    llama_bin: Option<PathBuf>,
    memory: String,
    cpus: u32,
    pids_limit: u32,
    sudo: bool,
    upstream_dns: String,
}

impl BoxSpec {
    fn has_preset(&self, p: Preset) -> bool {
        self.presets.contains(&p) || self.env_label.contains(p.as_str())
    }
}

pub fn container_cmd(bin: &str, use_sudo: bool) -> Command {
    if use_sudo {
        let mut c = Command::new("sudo");
        c.arg(bin);
        c
    } else {
        Command::new(bin)
    }
}

pub(crate) fn clean_template_val(s: Option<&&str>) -> Option<String> {
    let val = s.copied().unwrap_or("").trim();
    if val.is_empty() || val == "<no value>" {
        None
    } else {
        Some(val.to_string())
    }
}

pub(crate) fn find_matching_yaml_config(
    box_name: &str,
    preset_label: &str,
    spec_file_label: Option<&Path>,
    images_dir_override: Option<&Path>,
) -> Result<Option<ImageConfig>, String> {
    if let Some(cfg) = find_image_config(box_name, images_dir_override)? {
        return Ok(Some(cfg));
    }
    if let Some(path) = spec_file_label {
        if path.is_file() {
            return load_image_config_from_path(path, None).map(Some);
        }
    }
    if !preset_label.is_empty() && preset_label != box_name {
        if let Some(cfg) = find_image_config(preset_label, images_dir_override)? {
            return Ok(Some(cfg));
        }
    }
    Ok(None)
}

pub fn list_boxes(cli: &Cli) {
    let bin = cli.runtime.container_bin();
    let mut cmd = container_cmd(bin, cli.sudo);

    cmd.args([
        "ps",
        "-a",
        "--filter",
        "label=box.managed=true",
        "--format",
        "{{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Image}}\t{{.Label \"box.preset\"}}\t{{.Label \"box.workspace\"}}\t{{.Label \"box.runtime\"}}\t{{.Label \"box.spec.hash\"}}\t{{.Label \"box.spec.file\"}}",
    ]);

    let output = cmd.output().unwrap_or_else(|e| {
        eprintln!("Failed to query boxes via {}: {}", bin, e);
        process::exit(1);
    });

    if !output.status.success() {
        eprintln!(
            "Error listing boxes: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        process::exit(1);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut grouped: BTreeMap<String, Vec<BoxRecord>> = BTreeMap::new();

    for line in stdout.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() < 4 {
            continue;
        }

        let id = cols[0].chars().take(12).collect::<String>();
        let name = cols[1].to_string();
        let mut status = cols[2].to_string();
        let image = cols[3].to_string();

        let env_name =
            clean_template_val(cols.get(4)).unwrap_or_else(|| infer_env_from_image(&image));
        let workspace = clean_template_val(cols.get(5)).unwrap_or_else(|| "-".to_string());
        let runtime = clean_template_val(cols.get(6)).unwrap_or_else(|| bin.to_string());
        let saved_spec_hash = clean_template_val(cols.get(7));
        let saved_spec_file = clean_template_val(cols.get(8)).map(PathBuf::from);

        if let Ok(Some(cfg)) = find_matching_yaml_config(
            &name,
            &env_name,
            saved_spec_file.as_deref(),
            cli.images_dir.as_deref(),
        ) {
            if let Ok(spec) = generate_spec_from_config(&cfg) {
                if saved_spec_hash.as_deref() != Some(spec.spec_hash.as_str()) {
                    status.push_str(" [rebuild pending]");
                }
            }
        }

        grouped.entry(env_name).or_default().push(BoxRecord {
            id,
            name,
            status,
            workspace,
            runtime,
        });
    }

    if grouped.is_empty() {
        println!("No active or saved boxes found (runtime: {}).", bin);
        println!(
            "Tip: Boxes run with --rm by default. Use `--keep` when launching a box to persist it after exit."
        );
        return;
    }

    for (env_name, boxes) in &grouped {
        println!(
            "=== Environment: {} ({}) ===",
            env_name.to_uppercase(),
            boxes.len()
        );
        println!(
            "{:<14} {:<22} {:<20} {:<10} {}",
            "ID", "NAME", "STATUS", "RUNTIME", "WORKSPACE"
        );
        for b in boxes {
            println!(
                "{:<14} {:<22} {:<20} {:<10} {}",
                b.id, b.name, b.status, b.runtime, b.workspace
            );
        }
        println!();
    }
}

pub(crate) fn resolve_container_storage_root(bin: &str, use_sudo: bool) -> Option<String> {
    if bin == "podman" {
        let out = container_cmd(bin, use_sudo)
            .args(["info", "--format", "{{.Store.GraphRoot}}"])
            .output()
            .ok()?;
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !s.is_empty() && s != "<no value>" {
                return Some(s);
            }
        }
        return None;
    }
    Some("/var/lib/containerd".to_string())
}

pub(crate) fn resolve_volume_host_path(
    bin: &str,
    use_sudo: bool,
    vol_name: &str,
) -> Option<String> {
    let out = container_cmd(bin, use_sudo)
        .args(["volume", "inspect", "--format", "{{.Mountpoint}}", vol_name])
        .output()
        .ok();
    if let Some(o) = out {
        if o.status.success() {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if !s.is_empty() && s != "<no value>" {
                return Some(s);
            }
        }
    }
    // Volume may not exist yet; show where Podman will place it on creation.
    if bin == "podman" {
        if let Some(root) = resolve_container_storage_root(bin, use_sudo) {
            return Some(format!("{}/volumes/{}/_data", root, vol_name));
        }
    }
    None
}

fn dir_contains_shared_libs(dir: &Path) -> bool {
    let Ok(entries) = fs::read_dir(dir) else {
        return false;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let s = name.to_string_lossy();
        if s.ends_with(".so") || s.contains(".so.") {
            return true;
        }
    }
    false
}

/// Resolves `--llama-bin <PATH>` into `(host_path_to_mount, guest_mount_target)`.
/// If `<PATH>` is a directory, mounts it at `/opt/llama`.
/// If `<PATH>` is a single file whose parent directory holds sibling `.so` libraries
/// (e.g. `llama.cpp/build/bin/llama-server` alongside `libllama.so`/`libggml*.so`),
/// mounts that build directory at `/opt/llama` so shared libraries resolve automatically.
fn resolve_llama_mount(raw: &Path) -> (PathBuf, String) {
    let canonical = fs::canonicalize(raw).unwrap_or_else(|e| {
        eprintln!(
            "Error: Failed to resolve --llama-bin path {:?}: {}",
            raw, e
        );
        process::exit(1);
    });
    let forbidden = [
        PathBuf::from("/"),
        PathBuf::from("/home"),
        PathBuf::from("/etc"),
        PathBuf::from("/var"),
        PathBuf::from("/usr"),
    ];
    if forbidden.contains(&canonical) {
        eprintln!(
            "SECURITY ABORT: Refusing to mount system path {:?} via --llama-bin.",
            canonical
        );
        process::exit(1);
    }
    if canonical.is_dir() {
        return (canonical, "/opt/llama".to_string());
    }
    if let Some(parent) = canonical.parent() {
        let home = env::var("HOME").ok().map(PathBuf::from);
        let safe_parent = !matches!(
            parent.to_str(),
            Some("/" | "/usr/bin" | "/usr/local/bin" | "/bin" | "/sbin" | "/usr/sbin")
        ) && home.as_deref() != Some(parent);
        if safe_parent && dir_contains_shared_libs(parent) {
            return (parent.to_path_buf(), "/opt/llama".to_string());
        }
    }
    let file_name = canonical
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("llama-server");
    (canonical.clone(), format!("/opt/llama/{}", file_name))
}

pub fn show_storage_paths(cli: &Cli, filter_box: Option<&str>) {
    let bin = cli.runtime.container_bin();
    let storage_root = resolve_container_storage_root(bin, cli.sudo)
        .unwrap_or_else(|| "(unavailable)".to_string());
    let default_venv_host = resolve_volume_host_path(bin, cli.sudo, &cli.venv)
        .unwrap_or_else(|| format!("(volume '{}' not created yet)", cli.venv));

    if let Some(target) = filter_box.filter(|s| !s.trim().is_empty()) {
        let info = inspect_box(bin, cli.sudo, target);
        println!("================================================================================");
        println!("  BOX HOST STORAGE & MOUNT PATHS: {}", info.name);
        println!("================================================================================");
        println!("  Preset / Image   : {} ({})", info.preset, info.image);
        println!(
            "  /workspace       -> {} ({})",
            info.workspace,
            if info.rw { "rw" } else { "ro" }
        );
        match info.venv.as_deref() {
            Some(v) => {
                let host_p = resolve_volume_host_path(bin, cli.sudo, v)
                    .unwrap_or_else(|| format!("(volume '{}' mountpoint unknown)", v));
                println!("  /opt/venv        -> {}  [volume: {}]", host_p, v);
            }
            None => println!("  /opt/venv        -> (ephemeral / not mounted)"),
        }
        if let Some(ref lb) = info.llama_bin {
            println!("  /opt/llama       -> {} (ro)", lb.display());
        }
        if let Some(hp) = info.host_port {
            println!(
                "  host.box.internal:{} -> host 127.0.0.1:{}",
                hp, hp
            );
        }
        println!("  /tmp             -> (ephemeral RAM tmpfs — lost when VM stops)");
        println!("--------------------------------------------------------------------------------");
        println!("  Container Store  : {}", storage_root);
        println!("  Traffic Log      : {}", audit_log_path().display());
        println!("  PCAP Archive     : {}", pcap_archive_dir().display());
        println!("  Domain Rules     : {}", default_domains_path().display());
        println!(
            "  Image Configs    : {}",
            resolve_images_dir(cli.images_dir.as_deref()).display()
        );
        if let Ok(Some(cfg)) = find_matching_yaml_config(
            &info.name,
            &info.preset,
            info.spec_file.as_deref(),
            cli.images_dir.as_deref(),
        ) {
            println!("  Image YAML       : {}", cfg.source_path.display());
        }
        if let Some(ref pcap) = info.pcap {
            println!("  Live Capture     : {}", pcap.display());
        }
        return;
    }

    println!("================================================================================");
    println!("  BOX HOST STORAGE & MOUNT LOCATIONS");
    println!("================================================================================");
    println!("  Default /opt/venv: {}  [volume: {}]", default_venv_host, cli.venv);
    println!("  Container Store  : {}", storage_root);
    println!("  Traffic Log      : {}", audit_log_path().display());
    println!("  PCAP Archive     : {}", pcap_archive_dir().display());
    println!("  Domain Rules     : {}", default_domains_path().display());
    println!(
        "  Image Configs    : {}",
        resolve_images_dir(cli.images_dir.as_deref()).display()
    );
    println!("  Temp RAM (/tmp)  : ephemeral tmpfs inside VM (not persisted on host)");
    println!("--------------------------------------------------------------------------------");
    println!("  SAVED BOX MOUNTS (files saved in /workspace or /opt/venv appear at these host paths)");

    let output = container_cmd(bin, cli.sudo)
        .args([
            "ps",
            "-a",
            "--filter",
            "label=box.managed=true",
            "--format",
            "{{.Names}}\t{{.Label \"box.preset\"}}\t{{.Label \"box.workspace\"}}\t{{.Label \"box.rw\"}}\t{{.Label \"box.venv\"}}\t{{.Label \"box.llama_bin\"}}",
        ])
        .output();

    let Ok(out) = output else {
        println!("  (Unable to query boxes via {})", bin);
        return;
    };
    if !out.status.success() {
        println!("  (Unable to query boxes via {})", bin);
        return;
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut count = 0usize;
    for line in stdout.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let cols: Vec<&str> = line.split('\t').collect();
        let name = cols.first().copied().unwrap_or("-");
        let preset = clean_template_val(cols.get(1)).unwrap_or_else(|| "-".to_string());
        let workspace = clean_template_val(cols.get(2)).unwrap_or_else(|| "-".to_string());
        let rw = clean_template_val(cols.get(3))
            .map(|s| s == "true")
            .unwrap_or(false);
        let venv = clean_template_val(cols.get(4));
        let llama_bin = clean_template_val(cols.get(5));
        count += 1;

        println!("\n  [{}] (preset: {})", name, preset);
        println!(
            "    /workspace ({}) -> {}",
            if rw { "rw" } else { "ro" },
            workspace
        );
        match venv.as_deref() {
            Some("ephemeral") | None => println!("    /opt/venv       -> (ephemeral)"),
            Some(v) => {
                let host_p = resolve_volume_host_path(bin, cli.sudo, v)
                    .unwrap_or_else(|| format!("(volume '{}')", v));
                println!("    /opt/venv  (rw) -> {}  [vol: {}]", host_p, v);
            }
        }
        if let Some(lb) = llama_bin {
            println!("    /opt/llama (ro) -> {}", lb);
        }
    }

    if count == 0 {
        println!("  (No saved boxes found. Launch with `--keep` to save a box, or run `box-where <file>` inside any running VM.)");
    } else {
        println!("\n  Tip: Inside any running VM, run `box-where <file>` to print its exact host path.");
    }
}

fn validate_target_dir(dir: &Path) -> PathBuf {
    let canonical = fs::canonicalize(dir).unwrap_or_else(|e| {
        eprintln!("Error: Failed to resolve target directory {:?}: {}", dir, e);
        process::exit(1);
    });

    let forbidden_exact = [
        PathBuf::from("/"),
        PathBuf::from("/home"),
        PathBuf::from("/etc"),
        PathBuf::from("/var"),
        PathBuf::from("/usr"),
    ];

    if forbidden_exact.contains(&canonical) {
        eprintln!(
            "SECURITY ABORT: Refusing to mount system directory {:?} into sandbox.",
            canonical
        );
        process::exit(1);
    }

    if let Ok(home) = env::var("HOME") {
        if canonical == PathBuf::from(&home) {
            eprintln!(
                "SECURITY ABORT: Refusing to mount your entire $HOME ({:?}). Use a dedicated subfolder.",
                canonical
            );
            process::exit(1);
        }
    }

    canonical
}

fn check_kvm_available() {
    if !Path::new("/dev/kvm").exists() {
        eprintln!(
            "ERROR: /dev/kvm not found. Hardware virtualization (KVM) is required for Kata/krun microVMs."
        );
        process::exit(1);
    }
}

fn resolve_krun_binary() -> String {
    for path in ["/usr/bin/krun", "/usr/local/bin/krun"] {
        if Path::new(path).exists() {
            return path.to_string();
        }
    }
    eprintln!(
        "ERROR: crun-krun (/usr/bin/krun) not found.\n\
         On Fedora Atomic, install it with: sudo rpm-ostree install crun-krun && sudo systemctl reboot"
    );
    process::exit(1);
}

fn check_kata_installed() {
    let shim_paths = [
        "/opt/kata/bin/containerd-shim-kata-v2",
        "/usr/local/bin/containerd-shim-kata-v2",
        "/usr/bin/containerd-shim-kata-v2",
    ];
    if !shim_paths.iter().any(|p| Path::new(p).exists()) {
        eprintln!(
            "ERROR: Kata Containers shim (containerd-shim-kata-v2) not found in /opt/kata/bin or /usr/bin.\n\
             Install the Kata static release into /opt/kata or switch to --runtime=krun."
        );
        process::exit(1);
    }
}

fn slice_exists() -> bool {
    Command::new("systemctl")
        .args(["--user", "cat", "podman-sandbox.slice"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn should_use_sandbox_slice(runtime: VmRuntime, sudo: bool, net: NetMode) -> bool {
    if runtime != VmRuntime::Krun || sudo {
        return false;
    }
    match net {
        NetMode::None => false,
        NetMode::Local | NetMode::Internet => {
            if !slice_exists() {
                eprintln!(
                    "WARNING: podman-sandbox.slice not found. Outbound LAN traffic will NOT be blocked by nftables!"
                );
                false
            } else {
                true
            }
        }
    }
}

fn podman_with_optional_slice(sudo: bool, use_slice: bool) -> Command {
    if sudo {
        container_cmd("podman", true)
    } else if use_slice {
        let mut c = Command::new("systemd-run");
        c.args([
            "--user",
            "--scope",
            "--quiet",
            "--slice=podman-sandbox.slice",
            "podman",
        ]);
        c
    } else {
        Command::new("podman")
    }
}

fn build_runtime_command(spec: &BoxSpec) -> (Command, &'static str, String, bool) {
    match spec.runtime {
        VmRuntime::Krun => {
            let krun_bin = resolve_krun_binary();
            let use_slice = should_use_sandbox_slice(spec.runtime, spec.sudo, spec.net);
            let mut cmd = podman_with_optional_slice(spec.sudo, use_slice);
            cmd.arg("run");
            if !spec.keep {
                cmd.arg("--rm");
            }
            if !spec.sudo {
                // Map the host user to container UID/GID 1000:1000 so host-owned
                // /workspace files are writable when `--rw` is enabled.
                cmd.arg("--userns=keep-id:uid=1000,gid=1000");
            }
            cmd.args(["-it", "--runtime", &krun_bin]);
            (cmd, "krun", format!("krun ({})", krun_bin), use_slice)
        }
        VmRuntime::Kata => {
            check_kata_installed();
            let mut cmd = container_cmd("nerdctl", spec.sudo);
            cmd.arg("run");
            if !spec.keep {
                cmd.arg("--rm");
            }
            cmd.args(["-it", "--runtime", "io.containerd.kata.v2"]);
            (cmd, "kata", "kata (io.containerd.kata.v2)".to_string(), false)
        }
    }
}

fn configure_hardening_and_mounts(
    command: &mut Command,
    spec: &BoxSpec,
    runtime_short: &str,
    venv_host_path: Option<&str>,
) -> Option<PathBuf> {
    command.args(["--name", &spec.box_name]);

    // Metadata labels for `box --list`, `box --attach`, and `box --paths`
    let venv_label = spec.venv.as_deref().unwrap_or("ephemeral");
    let userns_label = if spec.runtime == VmRuntime::Krun && !spec.sudo {
        "keep-id"
    } else {
        "default"
    };
    command.args([
        "--label",
        "box.managed=true",
        "--label",
        &format!("box.preset={}", spec.env_label),
        "--label",
        &format!("box.workspace={}", spec.target_dir.display()),
        "--label",
        &format!("box.runtime={}", runtime_short),
        "--label",
        &format!("box.net={}", spec.net.as_str()),
        "--label",
        &format!("box.rw={}", spec.rw),
        "--label",
        &format!("box.venv={}", venv_label),
        "--label",
        &format!("box.userns={}", userns_label),
    ]);
    if let Some(hp) = spec.host_port {
        command.args(["--label", &format!("box.host_port={}", hp)]);
    }
    if let Some(ref hash) = spec.spec_hash {
        command.args(["--label", &format!("box.spec.hash={}", hash)]);
    }
    if let Some(ref file) = spec.spec_file {
        command.args(["--label", &format!("box.spec.file={}", file.display())]);
    }
    if !spec.presets.is_empty() {
        let base_presets = spec
            .presets
            .iter()
            .map(|p| p.as_str())
            .collect::<Vec<_>>()
            .join("+");
        command.args(["--label", &format!("box.base_presets={}", base_presets)]);
    }

    let llama_mount: Option<(PathBuf, String)> = spec
        .llama_bin
        .as_deref()
        .map(resolve_llama_mount);
    if let Some((ref host_src, _)) = llama_mount {
        command.args(["--label", &format!("box.llama_bin={}", host_src.display())]);
    }

    // Common microVM hardening, resource allocation, and toolchain-friendly environment
    let (texmfvar, xdg_cache, julia_depot, bitcoin_datadir, kubeconfig) = if spec.venv.is_some() {
        (
            "TEXMFVAR=/opt/venv/texmf-var",
            "XDG_CACHE_HOME=/opt/venv/cache",
            "JULIA_DEPOT_PATH=/opt/venv/julia:/usr/local/share/julia",
            "BITCOIN_DATADIR=/opt/venv/bitcoin",
            "KUBECONFIG=/opt/venv/kube/config",
        )
    } else {
        (
            "TEXMFVAR=/tmp/texmf-var",
            "XDG_CACHE_HOME=/tmp/.cache",
            "JULIA_DEPOT_PATH=/tmp/julia:/usr/local/share/julia",
            "BITCOIN_DATADIR=/tmp/bitcoin",
            "KUBECONFIG=/tmp/kubeconfig",
        )
    };
    let path_env = if llama_mount.is_some() {
        "PATH=/opt/llama:/opt/venv/python/bin:/opt/venv/bin:/opt/venv/cargo/bin:/usr/local/cargo/bin:/usr/local/julia/bin:/tmp/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    } else {
        "PATH=/opt/venv/python/bin:/opt/venv/bin:/opt/venv/cargo/bin:/usr/local/cargo/bin:/usr/local/julia/bin:/tmp/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    };
    command.args([
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user",
        "1000:1000",
        "-e",
        "HOME=/tmp",
        "-e",
        texmfvar,
        "-e",
        xdg_cache,
        "-e",
        julia_depot,
        "-e",
        "JULIA_CPU_TARGET=generic",
        "-e",
        "JULIA_NUM_PRECOMPILE_TASKS=1",
        "-e",
        &format!("PLUTO_PORT={}", spec.port),
        "-e",
        bitcoin_datadir,
        "-e",
        kubeconfig,
        "-e",
        "CARGO_HOME=/opt/venv/cargo",
        "-e",
        "CARGO_TARGET_DIR=/tmp/target",
        "-e",
        "RUSTUP_HOME=/usr/local/rustup",
        "-e",
        "JUPYTER_RUNTIME_DIR=/tmp/jupyter-runtime",
        "-e",
        path_env,
        "-e",
        &format!("BOX_HOST_WORKSPACE={}", spec.target_dir.display()),
        "--tmpfs",
        "/tmp:rw,nosuid,size=1g,mode=1777",
        "--pids-limit",
        &spec.pids_limit.to_string(),
        "--memory",
        &spec.memory,
        "--cpus",
        &spec.cpus.to_string(),
        "-w",
        "/workspace",
    ]);
    if let Some(vhp) = venv_host_path {
        command.args(["-e", &format!("BOX_HOST_VENV={}", vhp)]);
    }
    if let Some((ref host_src, _)) = llama_mount {
        command.args([
            "-e",
            "LD_LIBRARY_PATH=/opt/llama",
            "-e",
            &format!("BOX_HOST_LLAMA={}", host_src.display()),
        ]);
    }

    // Volume mounts (virtio-fs passthrough into the microVM)
    match spec.runtime {
        VmRuntime::Krun => {
            let volume_opts = if spec.rw { "rw,Z" } else { "ro,Z" };
            command.args([
                "-v",
                &format!("{}:/workspace:{}", spec.target_dir.display(), volume_opts),
            ]);
            if let Some(ref venv) = spec.venv {
                command.args(["-v", &format!("{}:/opt/venv:rw,U", venv)]);
            }
            if let Some((ref host_src, ref guest_dst)) = llama_mount {
                command.args(["-v", &format!("{}:{}:ro,Z", host_src.display(), guest_dst)]);
            }
        }
        VmRuntime::Kata => {
            let volume_opts = if spec.rw { "rw" } else { "ro" };
            command.args([
                "-v",
                &format!("{}:/workspace:{}", spec.target_dir.display(), volume_opts),
            ]);
            if let Some(ref venv) = spec.venv {
                command.args(["-v", &format!("{}:/opt/venv:rw", venv)]);
            }
            if let Some((ref host_src, ref guest_dst)) = llama_mount {
                command.args(["-v", &format!("{}:{}:ro", host_src.display(), guest_dst)]);
            }
        }
    }

    llama_mount.map(|(src, _)| src)
}

fn attach_host_port_env_and_hosts(command: &mut Command, hp: u16) {
    command.args([
        "--add-host",
        "host.box.internal:169.254.2.2",
        "-e",
        &format!("BOX_HOST_PORT={}", hp),
        "-e",
        &format!("LLAMA_SERVER_URL=http://host.box.internal:{}", hp),
        "-e",
        &format!("OPENAI_BASE_URL=http://host.box.internal:{}/v1", hp),
    ]);
}

fn cli_or_spec_local_net(
    command: &mut Command,
    spec: &BoxSpec,
    cmd_summary: &str,
    cmd_file: Option<&Path>,
) -> (String, Option<PathBuf>) {
    match spec.runtime {
        VmRuntime::Krun => {
            if spec.sudo {
                command.args([
                    "--network=bridge",
                    "--dns=none",
                    "-p",
                    &format!("127.0.0.1:{0}:{0}", spec.port),
                ]);
                ("local-only".to_string(), None)
            } else {
                // `-o 127.0.0.1` binds pasta's outbound sockets to loopback so all outbound
                // internet TCP/UDP/DNS is genuinely blocked by the host kernel, while
                // `-p 127.0.0.1:<port>:<port>` still forwards host browser -> guest (e.g. Pluto/Jupyter).
                // `--dns 192.0.2.53` sends DNS attempts onto the tap interface so `--pcap`
                // captures and logs every blocked request in real time.
                let pcap_path = spawn_pcap_dns_auditor(
                    &spec.box_name,
                    &spec.env_label,
                    &spec.target_dir,
                    cmd_summary,
                    "local",
                    cmd_file,
                    spec.keep,
                );
                let host_map_flag = if spec.host_port.is_some() {
                    ",--map-host-loopback,169.254.2.2"
                } else {
                    ""
                };
                command.args([
                    "--network",
                    &format!(
                        "pasta:--no-map-gw{},-a,192.0.2.2,-n,24,-g,192.0.2.1,-o,127.0.0.1,--pcap,{}",
                        host_map_flag,
                        pcap_path.display()
                    ),
                    "--dns",
                    "192.0.2.53",
                    "-p",
                    &format!("127.0.0.1:{0}:{0}", spec.port),
                ]);
                let note = if let Some(hp) = spec.host_port {
                    attach_host_port_env_and_hosts(command, hp);
                    format!(
                        "127.0.0.1:{} exposed | host 127.0.0.1:{} -> host.box.internal:{} | internet blocked",
                        spec.port, hp, hp
                    )
                } else {
                    format!("127.0.0.1:{} exposed, outbound blocked & audited", spec.port)
                };
                (note, Some(pcap_path))
            }
        }
        VmRuntime::Kata => {
            command.args([
                "--dns=127.0.0.1",
                "-p",
                &format!("127.0.0.1:{0}:{0}", spec.port),
            ]);
            ("local-only".to_string(), None)
        }
    }
}

fn configure_network(
    command: &mut Command,
    spec: &BoxSpec,
    cmd_summary: &str,
    cmd_file: Option<&Path>,
) -> (String, Option<PathBuf>) {
    match spec.net {
        NetMode::None => {
            command.arg("--network=none");
            ("air-gapped".to_string(), None)
        }
        NetMode::Local => cli_or_spec_local_net(command, spec, cmd_summary, cmd_file),
        NetMode::Internet => match spec.runtime {
            VmRuntime::Krun => {
                let (mut note, pcap_opt) = if spec.sudo {
                    command.args(["--dns", "10.88.0.1"]);
                    ("rootful (dns: 10.88.0.1)".to_string(), None)
                } else {
                    let upstream_ip = extract_dns_host_ip(&spec.upstream_dns);
                    let pcap_path = spawn_pcap_dns_auditor(
                        &spec.box_name,
                        &spec.env_label,
                        &spec.target_dir,
                        cmd_summary,
                        "internet",
                        cmd_file,
                        spec.keep,
                    );
                    let host_map_flag = if spec.host_port.is_some() {
                        ",--map-host-loopback,169.254.2.2"
                    } else {
                        ""
                    };
                    // Keep `--no-map-gw` so the microVM cannot reach host loopback services
                    // unless `--host-port` explicitly bridges 169.254.2.2 (host.box.internal).
                    command.args([
                        "--network",
                        &format!(
                            "pasta:--no-map-gw{},-M,9a:55:9a:55:9a:55,--dns-host,{},--pcap,{}",
                            host_map_flag,
                            upstream_ip,
                            pcap_path.display()
                        ),
                    ]);
                    (
                        format!("audited via pasta pcap -> {}", upstream_ip),
                        Some(pcap_path),
                    )
                };
                if let Some(hp) = spec.host_port {
                    attach_host_port_env_and_hosts(command, hp);
                    note.push_str(&format!(" | host 127.0.0.1:{} -> host.box.internal:{}", hp, hp));
                }
                if spec.expose_port {
                    command.args(["-p", &format!("127.0.0.1:{0}:{0}", spec.port)]);
                }
                (note, pcap_opt)
            }
            VmRuntime::Kata => {
                let upstream_ip = extract_dns_host_ip(&spec.upstream_dns);
                command.args(["--dns", &upstream_ip]);
                if spec.expose_port {
                    command.args(["-p", &format!("127.0.0.1:{0}:{0}", spec.port)]);
                }
                (format!("direct (dns: {})", upstream_ip), None)
            }
        },
    }
}

struct BoxHeader<'a> {
    mode: &'a str,
    name: &'a str,
    env_label: &'a str,
    presets: &'a [Preset],
    spec_file: Option<&'a str>,
    image: &'a str,
    runtime_label: &'a str,
    workspace: &'a str,
    rw: bool,
    venv: Option<&'a str>,
    venv_host_path: Option<&'a str>,
    llama_bin: Option<&'a str>,
    net: NetMode,
    net_detail: &'a str,
    slice: &'a str,
    cwd_mismatch: Option<&'a str>,
}

fn ansi(enabled: bool, code: &str, text: &str) -> String {
    if enabled {
        format!("\x1b[{}m{}\x1b[0m", code, text)
    } else {
        text.to_string()
    }
}

fn print_box_header(h: &BoxHeader<'_>) {
    let color = env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal();
    let mode_styled = ansi(color, "1;36", h.mode);
    let name_styled = ansi(color, "1", h.name);
    let rw_styled = if h.rw {
        ansi(color, "33", "rw")
    } else {
        ansi(color, "32", "ro")
    };
    let net_styled = match h.net {
        NetMode::None => ansi(color, "32", &format!("none ({})", h.net_detail)),
        NetMode::Local => ansi(color, "36", &format!("local ({})", h.net_detail)),
        NetMode::Internet => ansi(color, "33", &format!("internet ({})", h.net_detail)),
    };
    let has_preset = |p: Preset| h.presets.contains(&p) || h.env_label.contains(p.as_str());
    let venv_hint = if has_preset(Preset::Python) {
        " (python auto-activated)"
    } else if has_preset(Preset::Julia) {
        " (julia depot)"
    } else if has_preset(Preset::Bitcoin) {
        " (bitcoin datadir)"
    } else if has_preset(Preset::K8s) {
        " (kubeconfig)"
    } else {
        ""
    };
    let venv_str = match (h.venv, h.venv_host_path) {
        (Some(v), Some(host_p)) => format!(
            "/opt/venv  <-  {}  [vol: {}]{}",
            ansi(color, "36", host_p),
            v,
            venv_hint
        ),
        (Some(v), None) => format!("/opt/venv  <-  volume '{}'{}", v, venv_hint),
        (None, _) => "ephemeral (none)".to_string(),
    };

    let border = ansi(
        color,
        "2",
        "╰──────────────────────────────────────────────────────────────────────────────",
    );
    let bar = ansi(color, "2", "│");

    println!(
        "{} {} [{}] {}",
        ansi(color, "2", "╭─ box:"),
        name_styled,
        mode_styled,
        ansi(color, "2", "──────────────────────────────────────")
    );
    println!(
        "{}  {}  {}  {}",
        bar,
        ansi(color, "2", "Stack    :"),
        ansi(color, "1", h.env_label),
        ansi(color, "2", &format!("({})", h.image))
    );
    if let Some(sf) = h.spec_file {
        println!(
            "{}  {}  {}",
            bar,
            ansi(color, "2", "Config   :"),
            ansi(color, "36", sf)
        );
    }
    println!(
        "{}  {}  {}  {}  {}",
        bar,
        ansi(color, "2", "Runtime  :"),
        h.runtime_label,
        ansi(color, "2", "|  Slice:"),
        h.slice
    );
    println!(
        "{}  {}  /workspace {} {} ({})",
        bar,
        ansi(color, "2", "Workspace:"),
        ansi(color, "2", "<-"),
        ansi(color, "36", h.workspace),
        rw_styled
    );
    if let Some(host_cwd) = h.cwd_mismatch {
        println!(
            "{}  {}  {} {}",
            bar,
            ansi(color, "33", "Host CWD :"),
            host_cwd,
            ansi(color, "2", "(not mounted — pass --mount-cwd to mount it)")
        );
    }
    println!("{}  {}  {}", bar, ansi(color, "2", "Venv Data:"), venv_str);
    if let Some(lb) = h.llama_bin {
        println!(
            "{}  {}  /opt/llama {} {} (ro)",
            bar,
            ansi(color, "2", "Llama Bin:"),
            ansi(color, "2", "<-"),
            ansi(color, "36", lb)
        );
    }
    println!(
        "{}  {}  {}",
        bar,
        ansi(color, "2", "Temp RAM :"),
        ansi(color, "2", "/tmp <- ephemeral tmpfs (not saved on host)")
    );
    println!("{}  {}  {}", bar, ansi(color, "2", "Network  :"), net_styled);
    println!(
        "{}  {}  {}",
        bar,
        ansi(color, "2", "Controls :"),
        ansi(
            color,
            "2",
            "exit = stop VM  |  Ctrl+P Ctrl+Q = detach  |  box-where [file] = host path"
        )
    );
    println!("{}", border);
}

fn build_container_exec_cmd(spec: &BoxSpec) -> Vec<String> {
    // For interactive bash boxes:
    // 1. Auto-initialize & activate `/opt/venv/python` when running a Python preset.
    // 2. For Bitcoin preset, symlink `~/.bitcoin -> /opt/venv/bitcoin` so bitcoin-cli/bitcoind persist data.
    // 3. Define `box-where [file]` helper so the user can check the exact host path of any file.
    // 4. Report each interactive command to `/run/.box-active-cmd` (when mounted) via
    //    bash's DEBUG trap + PROMPT_COMMAND so the host traffic analyzer knows the exact
    //    command (e.g. `curl -iL google.com`, `pip install matplotlib`) that generated traffic.
    let is_interactive_bash = spec.effective_cmd.len() == 1 && spec.effective_cmd[0] == "bash";
    if is_interactive_bash {
        let mut init_script = String::new();
        let auto_python = spec.venv.is_some() && spec.has_preset(Preset::Python);
        if auto_python {
            init_script.push_str(
                r#"if [ ! -x /opt/venv/python/bin/python3 ] && command -v python3 >/dev/null 2>&1; then
  echo "[box] Initializing persistent Python venv at /opt/venv/python..."
  python3 -m venv /opt/venv/python 2>/dev/null || true
fi
"#,
            );
        }

        if spec.venv.is_some() && spec.has_preset(Preset::Bitcoin) {
            init_script.push_str(
                "mkdir -p /opt/venv/bitcoin 2>/dev/null || true\n\
                 ln -sfn /opt/venv/bitcoin /tmp/.bitcoin 2>/dev/null || true\n",
            );
        }

        let python_activate = if auto_python {
            "[ -f /opt/venv/python/bin/activate ] && . /opt/venv/python/bin/activate\n"
        } else {
            ""
        };

        init_script.push_str(&format!(
            r#"cat > /tmp/.box_bashrc <<'BOXRC'
[ -f /etc/bash.bashrc ] && . /etc/bash.bashrc
{python_activate}box-where() {{
  if [ $# -eq 0 ]; then
    echo "Guest -> Host storage mappings:"
    echo "  /workspace -> ${{BOX_HOST_WORKSPACE:-(unmounted)}}"
    if [ -n "${{BOX_HOST_VENV:-}}" ]; then
      echo "  /opt/venv  -> $BOX_HOST_VENV"
    else
      echo "  /opt/venv  -> (ephemeral / not mounted)"
    fi
    if [ -n "${{BOX_HOST_LLAMA:-}}" ]; then
      echo "  /opt/llama -> $BOX_HOST_LLAMA (ro)"
    fi
    echo "  /tmp       -> (ephemeral RAM tmpfs — lost when VM stops)"
    local cwd_now
    cwd_now=$(pwd -P 2>/dev/null || pwd)
    echo ""
    printf 'Current dir (%s) on host: ' "$cwd_now"
    box-where "$cwd_now"
    return 0
  fi
  local p="$1"
  local abs
  abs=$(realpath -m "$p" 2>/dev/null || readlink -f "$p" 2>/dev/null || printf '%s' "$p")
  case "$abs" in
    /workspace) echo "${{BOX_HOST_WORKSPACE:-(unmounted)}}" ;;
    /workspace/*) printf '%s%s\n' "$BOX_HOST_WORKSPACE" "$(printf '%s' "$abs" | sed 's|^/workspace||')" ;;
    /opt/venv) echo "${{BOX_HOST_VENV:-(ephemeral)}}" ;;
    /opt/venv/*)
      if [ -n "${{BOX_HOST_VENV:-}}" ]; then
        printf '%s%s\n' "$BOX_HOST_VENV" "$(printf '%s' "$abs" | sed 's|^/opt/venv||')"
      else
        echo "(ephemeral — not persisted on host)"
      fi ;;
    /opt/llama) echo "${{BOX_HOST_LLAMA:-(not mounted)}}" ;;
    /opt/llama/*)
      if [ -n "${{BOX_HOST_LLAMA:-}}" ]; then
        printf '%s%s\n' "$BOX_HOST_LLAMA" "$(printf '%s' "$abs" | sed 's|^/opt/llama||')"
      else
        echo "(not mounted)"
      fi ;;
    /tmp|/tmp/*) echo "(ephemeral RAM tmpfs — not saved on host)" ;;
    *) echo "(inside read-only container image — not a host mount)" ;;
  esac
}}
if [ -w /run/.box-active-cmd ]; then
  __BOX_LAST_CMD="bash"
  __box_preexec() {{
    case "$BASH_COMMAND" in
      __box_*|*'__box_'*|*'PROMPT_COMMAND'*) return ;;
    esac
    __BOX_LAST_CMD="$BASH_COMMAND"
    printf 'run\t%s\n' "$BASH_COMMAND" > /run/.box-active-cmd 2>/dev/null || true
  }}
  __box_postexec() {{
    local __rc=$?
    printf 'done:%s\t%s\n' "$(date +%s)" "$__BOX_LAST_CMD" > /run/.box-active-cmd 2>/dev/null || true
    return $__rc
  }}
  trap '__box_preexec' DEBUG
  PROMPT_COMMAND="__box_postexec${{PROMPT_COMMAND:+; $PROMPT_COMMAND}}"
fi
BOXRC
exec bash --rcfile /tmp/.box_bashrc"#,
            python_activate = python_activate
        ));

        return vec!["bash".to_string(), "-c".to_string(), init_script];
    }
    spec.effective_cmd.clone()
}

fn launch_box(spec: &BoxSpec, launch_mode: &str) -> ! {
    check_kvm_available();
    let cmd_summary = spec.effective_cmd.join(" ");
    let bin = spec.runtime.container_bin();
    let venv_host_path = spec
        .venv
        .as_deref()
        .and_then(|v| resolve_volume_host_path(bin, spec.sudo, v));

    let (mut command, runtime_short, runtime_label, use_sandbox_slice) =
        build_runtime_command(spec);
    let llama_host_src = configure_hardening_and_mounts(
        &mut command,
        spec,
        runtime_short,
        venv_host_path.as_deref(),
    );

    // For rootless krun boxes with traffic auditing (local/internet), bind-mount a single
    // per-box tracker file so the guest shell can report the exact active command.
    let cmd_file: Option<PathBuf> = if spec.runtime == VmRuntime::Krun
        && !spec.sudo
        && matches!(spec.net, NetMode::Internet | NetMode::Local)
    {
        let p = cmd_tracker_path(&spec.box_name, process::id());
        if fs::write(&p, format!("run\t{}\n", cmd_summary)).is_ok() {
            command.args([
                "-v",
                &format!("{}:/run/.box-active-cmd:rw,Z", p.display()),
                "--label",
                &format!("box.cmdfile={}", p.display()),
            ]);
            Some(p)
        } else {
            None
        }
    } else {
        None
    };

    let (dns_audit_note, pcap_path) =
        configure_network(&mut command, spec, &cmd_summary, cmd_file.as_deref());
    if let Some(ref pcap) = pcap_path {
        command.args(["--label", &format!("box.pcap={}", pcap.display())]);
    }

    let container_cmd_args = build_container_exec_cmd(spec);
    command.arg(&spec.image);
    command.args(&container_cmd_args);

    let net_detail = match spec.net {
        NetMode::Local => dns_audit_note,
        NetMode::Internet if spec.expose_port => {
            format!("{}, 127.0.0.1:{} exposed", dns_audit_note, spec.port)
        }
        _ => dns_audit_note,
    };
    let runtime_desc = match spec.runtime {
        VmRuntime::Krun => format!("libkrun KVM microVM ({})", runtime_label.trim_start_matches("krun ").trim_matches(|c| c == '(' || c == ')')),
        VmRuntime::Kata => "Kata Containers KVM microVM (io.containerd.kata.v2)".to_string(),
    };
    let workspace_str = spec.target_dir.display().to_string();
    let llama_host_str = llama_host_src.as_ref().map(|p| p.display().to_string());
    let spec_file_str = spec.spec_file.as_ref().map(|p| p.display().to_string());

    print_box_header(&BoxHeader {
        mode: launch_mode,
        name: &spec.box_name,
        env_label: &spec.env_label,
        presets: &spec.presets,
        spec_file: spec_file_str.as_deref(),
        image: &spec.image,
        runtime_label: &runtime_desc,
        workspace: &workspace_str,
        rw: spec.rw,
        venv: spec.venv.as_deref(),
        venv_host_path: venv_host_path.as_deref(),
        llama_bin: llama_host_str.as_deref(),
        net: spec.net,
        net_detail: &net_detail,
        slice: if use_sandbox_slice {
            "podman-sandbox.slice"
        } else {
            "default"
        },
        cwd_mismatch: None,
    });

    let err = command.exec();
    eprintln!("Failed to execute microVM sandbox: {}", err);
    process::exit(1);
}

pub fn run_box(cli: &Cli) {
    if cli.host_port.is_some() && cli.net == Some(NetMode::None) {
        eprintln!(
            "ERROR: `--host-port` cannot be used with `--net none` (air-gapped without loopback bridge).\n\
             Omit `--net` (defaults to `--net local` when `--host-port` is set) or pass `--net local` / `--net internet`."
        );
        process::exit(1);
    }

    let raw_dir = cli.dir.clone().unwrap_or_else(|| {
        env::current_dir().expect("Failed to determine current working directory")
    });
    let target_dir = validate_target_dir(&raw_dir);

    let (image, env_label, presets, spec_hash, spec_file, has_bash) =
        if let Some(ref cfg_path) = cli.config {
            let cfg = load_image_config_from_path(cfg_path, None).unwrap_or_else(|e| {
                eprintln!("ERROR: {}", e);
                process::exit(1);
            });
            let res = build_image_from_config(cli, &cfg);
            (
                res.tag,
                res.env_label,
                res.presets,
                Some(res.spec_hash),
                res.spec_file,
                res.has_bash,
            )
        } else if let Some(ref custom_img) = cli.image {
            let env_lbl = infer_env_from_image(custom_img);
            let is_alpine = env_lbl == "alpine";
            (
                custom_img.clone(),
                env_lbl,
                Vec::new(),
                None,
                None,
                !is_alpine,
            )
        } else if cli.preset.is_empty() {
            // If `--name <vm>` matches `<vm>.yaml` in ~/.config/box/images/, use it automatically!
            let named_cfg = if let Some(ref custom_name) = cli.name {
                find_image_config(custom_name, cli.images_dir.as_deref()).unwrap_or_else(|e| {
                    eprintln!("ERROR: {}", e);
                    process::exit(1);
                })
            } else {
                None
            };
            let res = if let Some(cfg) = named_cfg {
                build_image_from_config(cli, &cfg)
            } else {
                build_combined_image(cli, &cli.preset)
            };
            (
                res.tag,
                res.env_label,
                res.presets,
                Some(res.spec_hash),
                res.spec_file,
                res.has_bash,
            )
        } else {
            let res = build_combined_image(cli, &cli.preset);
            (
                res.tag,
                res.env_label,
                res.presets,
                Some(res.spec_hash),
                res.spec_file,
                res.has_bash,
            )
        };

    let box_name = cli.name.clone().unwrap_or_else(|| {
        format!(
            "box-{}-{}",
            env_label.replace('+', "-"),
            now_epoch() % 100_000
        )
    });

    let effective_cmd = if cli.cmd.is_empty() {
        vec![if has_bash { "bash" } else { "sh" }.to_string()]
    } else {
        cli.cmd.clone()
    };

    let effective_net = cli.net.unwrap_or_else(|| {
        if cli.host_port.is_some() {
            NetMode::Local
        } else {
            NetMode::None
        }
    });

    let spec = BoxSpec {
        box_name,
        image,
        env_label,
        presets,
        spec_hash,
        spec_file,
        target_dir,
        effective_cmd,
        runtime: cli.runtime,
        net: effective_net,
        rw: cli.rw,
        keep: cli.keep,
        venv: if cli.ephemeral {
            None
        } else {
            Some(cli.venv.clone())
        },
        port: cli.port,
        expose_port: cli.expose_port,
        host_port: cli.host_port,
        llama_bin: cli.llama_bin.clone(),
        memory: cli.memory.clone(),
        cpus: cli.cpus,
        pids_limit: cli.pids_limit,
        sudo: cli.sudo,
        upstream_dns: cli.upstream_dns.clone(),
    };

    launch_box(&spec, "LAUNCHING");
}

pub(crate) fn extract_pcap_from_netmode(network_mode: &str) -> Option<PathBuf> {
    let rest = network_mode.strip_prefix("pasta:")?;
    let mut parts = rest.split(',');
    while let Some(tok) = parts.next() {
        if tok == "--pcap" || tok == "-p" {
            let path = parts.next()?.trim();
            if !path.is_empty() {
                return Some(PathBuf::from(path));
            }
        }
    }
    None
}

pub(crate) fn infer_net_mode(network_mode: &str) -> NetMode {
    if network_mode == "none" {
        NetMode::None
    } else if network_mode.contains("192.0.2.2") {
        NetMode::Local
    } else {
        NetMode::Internet
    }
}

pub(crate) fn parse_cmd_field(raw: &str) -> Vec<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "null" || trimmed == "<no value>" {
        return Vec::new();
    }
    if !trimmed.starts_with('[') {
        return trimmed.split_whitespace().map(String::from).collect();
    }
    let mut out = Vec::new();
    let mut chars = trimmed.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '"' {
            let mut s = String::new();
            while let Some(ch) = chars.next() {
                match ch {
                    '"' => break,
                    '\\' => match chars.next() {
                        Some('n') => s.push('\n'),
                        Some('r') => s.push('\r'),
                        Some('t') => s.push('\t'),
                        Some('"') => s.push('"'),
                        Some('\\') => s.push('\\'),
                        Some('/') => s.push('/'),
                        Some(other) => s.push(other),
                        None => break,
                    },
                    other => s.push(other),
                }
            }
            out.push(s);
        }
    }
    out
}

fn parse_inspect_output(raw: &str) -> Option<BoxInspect> {
    let line = raw.lines().find(|l| !l.trim().is_empty())?;
    let cols: Vec<&str> = line.split('\t').collect();
    if cols.len() < 4 {
        return None;
    }

    let running = cols[0].trim() == "true";
    let name = cols[1].trim().trim_start_matches('/').to_string();
    let image = cols[2].trim().to_string();
    let network_mode = cols[3].trim().to_string();
    let preset = clean_template_val(cols.get(4)).unwrap_or_else(|| infer_env_from_image(&image));
    let workspace = clean_template_val(cols.get(5)).unwrap_or_else(|| "-".to_string());
    let runtime = clean_template_val(cols.get(6)).and_then(|s| VmRuntime::from_label(&s));
    let net = clean_template_val(cols.get(7)).and_then(|s| NetMode::from_label(&s));
    let rw = clean_template_val(cols.get(8))
        .map(|s| s == "true")
        .unwrap_or(false);
    let venv = match clean_template_val(cols.get(9)).as_deref() {
        Some("ephemeral") => None,
        Some(v) => Some(v.to_string()),
        None => Some("box-venv".to_string()),
    };
    let pcap = clean_template_val(cols.get(10))
        .map(PathBuf::from)
        .or_else(|| extract_pcap_from_netmode(&network_mode));
    let keep_id = clean_template_val(cols.get(11))
        .map(|s| s == "keep-id")
        .unwrap_or(false);
    let cmd_file = clean_template_val(cols.get(12)).map(PathBuf::from);
    let managed = clean_template_val(cols.get(13))
        .map(|s| s == "true")
        .unwrap_or(false);
    let is_toolbox = clean_template_val(cols.get(14))
        .map(|s| s == "true")
        .unwrap_or(false);
    let host_port = clean_template_val(cols.get(15)).and_then(|s| s.parse::<u16>().ok());
    let llama_bin = clean_template_val(cols.get(16)).map(PathBuf::from);
    let cmd = clean_template_val(cols.get(17))
        .map(|s| parse_cmd_field(&s))
        .unwrap_or_default();
    let image_id = clean_template_val(cols.get(18))
        .map(|s| normalize_image_id(&s))
        .unwrap_or_default();
    let spec_hash = clean_template_val(cols.get(19));
    let spec_file = clean_template_val(cols.get(20)).map(PathBuf::from);
    let base_presets = clean_template_val(cols.get(21))
        .map(|s| parse_presets_from_env_label(&s))
        .unwrap_or_default();

    Some(BoxInspect {
        running,
        name,
        image,
        image_id,
        network_mode,
        preset,
        workspace,
        runtime,
        net,
        rw,
        venv,
        pcap,
        cmd,
        keep_id,
        cmd_file,
        managed,
        is_toolbox,
        host_port,
        llama_bin,
        spec_hash,
        spec_file,
        base_presets,
    })
}

fn try_inspect_box(bin: &str, use_sudo: bool, target: &str) -> Option<BoxInspect> {
    let fmt = "{{.State.Running}}\t{{.Name}}\t{{.Config.Image}}\t{{.HostConfig.NetworkMode}}\t{{index .Config.Labels \"box.preset\"}}\t{{index .Config.Labels \"box.workspace\"}}\t{{index .Config.Labels \"box.runtime\"}}\t{{index .Config.Labels \"box.net\"}}\t{{index .Config.Labels \"box.rw\"}}\t{{index .Config.Labels \"box.venv\"}}\t{{index .Config.Labels \"box.pcap\"}}\t{{index .Config.Labels \"box.userns\"}}\t{{index .Config.Labels \"box.cmdfile\"}}\t{{index .Config.Labels \"box.managed\"}}\t{{index .Config.Labels \"com.github.containers.toolbox\"}}\t{{index .Config.Labels \"box.host_port\"}}\t{{index .Config.Labels \"box.llama_bin\"}}\t{{json .Config.Cmd}}\t{{.Image}}\t{{index .Config.Labels \"box.spec.hash\"}}\t{{index .Config.Labels \"box.spec.file\"}}\t{{index .Config.Labels \"box.base_presets\"}}";
    let output = container_cmd(bin, use_sudo)
        .args(["container", "inspect", "--format", fmt, target])
        .output()
        .unwrap_or_else(|e| {
            if e.kind() == std::io::ErrorKind::NotFound && bin == "nerdctl" {
                eprintln!(
                    "ERROR: `nerdctl` not found (`--runtime kata` requires nerdctl + containerd + Kata Containers).\n\
                     On Fedora Atomic, omit `--runtime kata` (default `--runtime krun` uses podman + libkrun KVM microVMs)."
                );
            } else {
                eprintln!("Failed to inspect box '{}' via {}: {}", target, bin, e);
            }
            process::exit(1);
        });

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_inspect_output(&stdout)
}

fn inspect_box(bin: &str, use_sudo: bool, target: &str) -> BoxInspect {
    try_inspect_box(bin, use_sudo, target).unwrap_or_else(|| {
        eprintln!(
            "ERROR: Could not find box '{}' (runtime: {}).",
            target, bin
        );
        eprintln!("Run `box --list` to see available boxes.");
        process::exit(1);
    })
}

pub(crate) fn is_interactive_shell_cmd(cmd: &[String]) -> bool {
    if cmd.iter().any(|tok| tok.contains("/tmp/.box_bashrc")) {
        return true;
    }
    if cmd.len() == 1 {
        let base = Path::new(&cmd[0])
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        return matches!(base, "bash" | "sh" | "ash" | "dash" | "zsh" | "fish");
    }
    false
}

fn pick_free_local_port(preferred: u16) -> u16 {
    for p in preferred..preferred.saturating_add(50) {
        if std::net::TcpListener::bind(("127.0.0.1", p)).is_ok() {
            return p;
        }
    }
    preferred
}

pub fn attach_box(cli: &Cli, target: &str) {
    if cli.runtime == VmRuntime::Kata {
        check_kata_installed();
    }
    if cli.host_port.is_some() && cli.net == Some(NetMode::None) {
        eprintln!(
            "ERROR: `--host-port` cannot be used with `--net none`.\n\
             Omit `--net` (defaults to `--net local`) or pass `--net local` / `--net internet`."
        );
        process::exit(1);
    }

    let bin = cli.runtime.container_bin();
    let Some(info) = try_inspect_box(bin, cli.sudo, target) else {
        // Box does not exist yet: auto-create it if:
        //   1. `--config <FILE>` was provided, OR
        //   2. `<target>.yaml` / `<target>.yml` exists in `~/.config/box/images/` (or `~/.config/box/`), OR
        //   3. `target` matches a built-in preset name (e.g. `rust`, `julia`, `latex+python`), OR
        //   4. `--preset` / `--image` was explicitly provided.
        let yaml_cfg = if let Some(ref cfg_path) = cli.config {
            Some(load_image_config_from_path(cfg_path, None).unwrap_or_else(|e| {
                eprintln!("ERROR: {}", e);
                process::exit(1);
            }))
        } else if cli.image.is_none() && cli.preset.is_empty() {
            find_image_config(target, cli.images_dir.as_deref()).unwrap_or_else(|e| {
                eprintln!("ERROR: {}", e);
                process::exit(1);
            })
        } else {
            None
        };

        let inferred_presets = if !cli.preset.is_empty() {
            cli.preset.clone()
        } else {
            parse_presets_from_env_label(target)
        };

        if yaml_cfg.is_none() && cli.image.is_none() && inferred_presets.is_empty() {
            let images_dir = resolve_images_dir(cli.images_dir.as_deref());
            eprintln!("ERROR: Could not find box '{}' (runtime: {}).", target, bin);
            eprintln!(
                "Run `box --list` to see available boxes, or auto-create it with:\n  \
                 box --attach {} --preset <rust|python|julia|bitcoin|k8s|llama|kali|latex|node|alpine>\n\
                 Or define a custom package file at {}/{}.yaml (run `box --init-image {}`).",
                target,
                images_dir.display(),
                target,
                target
            );
            process::exit(1);
        }

        let raw_dir = cli.dir.clone().unwrap_or_else(|| {
            env::current_dir().expect("Failed to determine current working directory")
        });
        let target_dir = validate_target_dir(&raw_dir);
        let (image, env_label, presets, spec_hash, spec_file, has_bash) =
            if let Some(ref cfg) = yaml_cfg {
                let res = build_image_from_config(cli, cfg);
                (
                    res.tag,
                    res.env_label,
                    res.presets,
                    Some(res.spec_hash),
                    res.spec_file,
                    res.has_bash,
                )
            } else if let Some(ref custom_img) = cli.image {
                let env_lbl = infer_env_from_image(custom_img);
                let is_alpine = env_lbl == "alpine";
                (
                    custom_img.clone(),
                    env_lbl,
                    Vec::new(),
                    None,
                    None,
                    !is_alpine,
                )
            } else {
                let res = build_combined_image(cli, &inferred_presets);
                (
                    res.tag,
                    res.env_label,
                    res.presets,
                    Some(res.spec_hash),
                    res.spec_file,
                    res.has_bash,
                )
            };
        let effective_cmd = if !cli.cmd.is_empty() {
            cli.cmd.clone()
        } else if has_bash {
            vec!["bash".to_string()]
        } else {
            vec!["sh".to_string()]
        };
        let effective_net = cli.net.unwrap_or_else(|| {
            if cli.host_port.is_some() {
                NetMode::Local
            } else {
                NetMode::None
            }
        });
        let spec = BoxSpec {
            box_name: target.to_string(),
            image,
            env_label,
            presets,
            spec_hash,
            spec_file,
            target_dir,
            effective_cmd,
            runtime: cli.runtime,
            net: effective_net,
            rw: cli.rw,
            // Persist the auto-created box when entering an interactive shell (or if --keep is set)
            keep: cli.cmd.is_empty() || cli.keep,
            venv: if cli.ephemeral {
                None
            } else {
                Some(cli.venv.clone())
            },
            port: cli.port,
            expose_port: cli.expose_port,
            host_port: cli.host_port,
            llama_bin: cli.llama_bin.clone(),
            memory: cli.memory.clone(),
            cpus: cli.cpus,
            pids_limit: cli.pids_limit,
            sudo: cli.sudo,
            upstream_dns: cli.upstream_dns.clone(),
        };
        launch_box(&spec, "CREATED & LAUNCHING");
    };

    if !info.managed {
        let kind = if info.is_toolbox {
            "a Fedora Toolbox container"
        } else {
            "an external (non-box) container"
        };
        eprintln!(
            "SAFETY ABORT: Container '{}' is {} (missing label `box.managed=true`).",
            info.name, kind
        );
        eprintln!("Refusing to attach/recreate it so your existing container is not modified or deleted.");
        eprintln!(
            "Run `box --list` to see box-managed VMs, or create a new box with `--keep --name <new-name>`."
        );
        process::exit(1);
    }
    let runtime = info.runtime.unwrap_or(cli.runtime);
    let saved_net = info
        .net
        .unwrap_or_else(|| infer_net_mode(&info.network_mode));
    let effective_host_port = cli.host_port.or(info.host_port);
    let effective_llama_bin = cli.llama_bin.clone().or_else(|| info.llama_bin.clone());
    let effective_net = cli.net.unwrap_or_else(|| {
        if effective_host_port.is_some() && saved_net == NetMode::None {
            NetMode::Local
        } else {
            saved_net
        }
    });

    // Check whether a YAML image definition applies to this box (or was deleted, or `--rebuild` was passed).
    // If the package list in the YAML file changed, rebuild the image automatically!
    let matched_yaml = if let Some(ref cfg_path) = cli.config {
        Some(load_image_config_from_path(cfg_path, None).unwrap_or_else(|e| {
            eprintln!("ERROR: {}", e);
            process::exit(1);
        }))
    } else {
        find_matching_yaml_config(
            &info.name,
            &info.preset,
            info.spec_file.as_deref(),
            cli.images_dir.as_deref(),
        )
        .unwrap_or_else(|e| {
            eprintln!("ERROR: {}", e);
            process::exit(1);
        })
    };

    let resolved_image: Option<ResolvedImage> = if let Some(ref cfg) = matched_yaml {
        Some(build_image_from_config(cli, cfg))
    } else if cli.rebuild || info.spec_file.is_some() {
        let presets = if !info.base_presets.is_empty() {
            info.base_presets.clone()
        } else {
            parse_presets_from_env_label(&info.preset)
        };
        if !presets.is_empty() {
            Some(build_combined_image(cli, &presets))
        } else {
            None
        }
    } else {
        None
    };

    let needs_image_refresh = if let Some(ref res) = resolved_image {
        res.rebuilt
            || info.image != res.tag
            || info.spec_hash.as_deref() != Some(res.spec_hash.as_str())
            || res
                .image_id
                .as_deref()
                .map(|id| !info.image_id.is_empty() && info.image_id != id)
                .unwrap_or(false)
    } else {
        false
    };

    let requested_dir: Option<PathBuf> = if let Some(ref dir) = cli.dir {
        Some(dir.clone())
    } else if cli.mount_cwd {
        Some(env::current_dir().expect("Failed to determine current working directory"))
    } else {
        None
    };

    let resolve_attach_dir = |req: &Option<PathBuf>| -> PathBuf {
        if let Some(raw_dir) = req {
            validate_target_dir(raw_dir)
        } else if info.workspace != "-" {
            validate_target_dir(Path::new(&info.workspace))
        } else {
            validate_target_dir(
                &env::current_dir().expect("Failed to determine current working directory"),
            )
        }
    };

    let resolve_attach_cmd = |env_label: &str, has_bash_opt: Option<bool>| -> Vec<String> {
        if !cli.cmd.is_empty() {
            cli.cmd.clone()
        } else if has_bash_opt == Some(false) || (has_bash_opt.is_none() && env_label == "alpine") {
            vec!["sh".to_string()]
        } else {
            vec!["bash".to_string()]
        }
    };

    let effective_image_fields = |res_opt: &Option<ResolvedImage>| {
        if let Some(res) = res_opt {
            (
                res.tag.clone(),
                res.env_label.clone(),
                res.presets.clone(),
                Some(res.spec_hash.clone()),
                res.spec_file.clone(),
                Some(res.has_bash),
            )
        } else {
            let presets = if !info.base_presets.is_empty() {
                info.base_presets.clone()
            } else {
                parse_presets_from_env_label(&info.preset)
            };
            (
                info.image.clone(),
                info.preset.clone(),
                presets,
                info.spec_hash.clone(),
                info.spec_file.clone(),
                None,
            )
        }
    };

    // Spawn a fresh sibling microVM (inheriting the existing box's image, preset, mounts,
    // /opt/venv, and network — without killing or overwriting the saved box) whenever:
    //   1. An explicit command was passed (`!cli.cmd.is_empty()`, e.g. `box --attach rust ping google.com`), OR
    //   2. The target box is already running (unless `--same-tty` is explicitly passed), OR
    //   3. `--new` is explicitly passed.
    if !cli.cmd.is_empty() || (info.running && !cli.same_tty) || cli.new_vm {
        let target_dir = resolve_attach_dir(&requested_dir);
        let (image, env_label, presets, spec_hash, spec_file, has_bash_opt) =
            effective_image_fields(&resolved_image);

        let sibling_name = cli.name.clone().unwrap_or_else(|| {
            format!("{}-{}", info.name, now_epoch() % 10_000)
        });
        let effective_cmd = resolve_attach_cmd(&env_label, has_bash_opt);
        let mode_label = format!("NEW VM FROM {}", info.name);

        let sibling_port = if info.running && effective_net == NetMode::Local {
            pick_free_local_port(cli.port)
        } else {
            cli.port
        };

        let spec = BoxSpec {
            box_name: sibling_name,
            image,
            env_label,
            presets,
            spec_hash,
            spec_file,
            target_dir,
            effective_cmd,
            runtime,
            net: effective_net,
            rw: cli.rw || info.rw,
            keep: cli.keep,
            venv: if cli.ephemeral { None } else { info.venv },
            port: sibling_port,
            expose_port: cli.expose_port,
            host_port: effective_host_port,
            llama_bin: effective_llama_bin,
            memory: cli.memory.clone(),
            cpus: cli.cpus,
            pids_limit: cli.pids_limit,
            sudo: cli.sudo,
            upstream_dns: cli.upstream_dns.clone(),
        };
        launch_box(&spec, &mode_label);
    }

    let needs_net_change = effective_net != saved_net;
    let needs_host_port_change = cli.host_port.is_some() && cli.host_port != info.host_port;
    let needs_llama_bin_change = cli.llama_bin.is_some() && cli.llama_bin != info.llama_bin;
    let needs_shell_upgrade = !is_interactive_shell_cmd(&info.cmd);
    let needs_local_audit_upgrade = runtime == VmRuntime::Krun
        && !cli.sudo
        && effective_net == NetMode::Local
        && cli.net == Some(NetMode::Local)
        && !info.network_mode.contains("--pcap");
    let needs_cmd_tracker_upgrade = !info.running
        && runtime == VmRuntime::Krun
        && !cli.sudo
        && matches!(effective_net, NetMode::Internet | NetMode::Local)
        && info.cmd_file.is_none();
    let needs_rw_upgrade = cli.rw && !info.rw;
    let needs_userns_upgrade =
        runtime == VmRuntime::Krun && !cli.sudo && (cli.rw || info.rw) && !info.keep_id;
    let needs_dir_change = match requested_dir {
        Some(ref raw_dir) => {
            let new_dir = validate_target_dir(raw_dir);
            info.workspace != new_dir.display().to_string()
        }
        None => false,
    };

    let wants_recreate = !info.running
        && (cli.rebuild
            || needs_image_refresh
            || needs_net_change
            || needs_host_port_change
            || needs_llama_bin_change
            || needs_shell_upgrade
            || needs_local_audit_upgrade
            || needs_cmd_tracker_upgrade
            || needs_rw_upgrade
            || needs_dir_change
            || (requested_dir.is_some() && needs_userns_upgrade));

    if wants_recreate {
        let target_dir = resolve_attach_dir(&requested_dir);
        let (image, env_label, presets, spec_hash, spec_file, has_bash_opt) =
            effective_image_fields(&resolved_image);

        let mount_mode = if cli.rw || info.rw { "rw" } else { "ro" };
        if needs_image_refresh {
            println!(
                "[box] Recreating VM '{}' on updated image '{}' (mount: {} ({}), net: {}, /opt/venv preserved)...",
                info.name,
                image,
                target_dir.display(),
                mount_mode,
                effective_net.as_str()
            );
        } else {
            println!(
                "[box] Recreating '{}' (image: {}, mount: {} ({}), net: {}, /opt/venv preserved)...",
                info.name,
                image,
                target_dir.display(),
                mount_mode,
                effective_net.as_str()
            );
        }

        let rm_status = container_cmd(bin, cli.sudo)
            .args(["rm", "-f", &info.name])
            .status()
            .unwrap_or_else(|e| {
                eprintln!("Failed to remove existing box '{}': {}", info.name, e);
                process::exit(1);
            });
        if !rm_status.success() {
            eprintln!(
                "ERROR: Failed to remove existing box '{}' before recreating.",
                info.name
            );
            process::exit(1);
        }

        let effective_cmd = resolve_attach_cmd(&env_label, has_bash_opt);

        let spec = BoxSpec {
            box_name: info.name,
            image,
            env_label,
            presets,
            spec_hash,
            spec_file,
            target_dir,
            effective_cmd,
            runtime,
            net: effective_net,
            rw: cli.rw || info.rw,
            keep: true,
            venv: if cli.ephemeral { None } else { info.venv },
            port: cli.port,
            expose_port: cli.expose_port,
            host_port: effective_host_port,
            llama_bin: effective_llama_bin,
            memory: cli.memory.clone(),
            cpus: cli.cpus,
            pids_limit: cli.pids_limit,
            sudo: cli.sudo,
            upstream_dns: cli.upstream_dns.clone(),
        };
        launch_box(&spec, "RECREATED");
    }

    let host_cwd_mismatch = env::current_dir()
        .and_then(fs::canonicalize)
        .ok()
        .map(|p| p.display().to_string())
        .filter(|cwd| info.workspace != "-" && cwd != &info.workspace);

    let runtime_desc = match runtime {
        VmRuntime::Krun => "libkrun KVM microVM (/usr/bin/krun)",
        VmRuntime::Kata => "Kata Containers KVM microVM (io.containerd.kata.v2)",
    };
    let venv_host_path = info
        .venv
        .as_deref()
        .and_then(|v| resolve_volume_host_path(bin, cli.sudo, v));
    let llama_bin_str = info.llama_bin.as_ref().map(|p| p.display().to_string());
    let spec_file_str = info.spec_file.as_ref().map(|p| p.display().to_string());
    let display_presets = if !info.base_presets.is_empty() {
        info.base_presets.clone()
    } else {
        parse_presets_from_env_label(&info.preset)
    };

    if info.running {
        if needs_image_refresh {
            eprintln!(
                "[box] Note: image config for '{}' changed and was rebuilt; stop the running VM and re-attach (or omit `--same-tty`) to use the updated packages.",
                info.name
            );
        }
        let net_detail = match effective_net {
            NetMode::None => "air-gapped".to_string(),
            NetMode::Local => "local-only".to_string(),
            NetMode::Internet => {
                if info.pcap.is_some() {
                    "audited via pasta pcap".to_string()
                } else {
                    "outbound enabled".to_string()
                }
            }
        };
        print_box_header(&BoxHeader {
            mode: "ATTACHED (running)",
            name: &info.name,
            env_label: &info.preset,
            presets: &display_presets,
            spec_file: spec_file_str.as_deref(),
            image: &info.image,
            runtime_label: runtime_desc,
            workspace: &info.workspace,
            rw: info.rw,
            venv: info.venv.as_deref(),
            venv_host_path: venv_host_path.as_deref(),
            llama_bin: llama_bin_str.as_deref(),
            net: effective_net,
            net_detail: &net_detail,
            slice: "active",
            cwd_mismatch: host_cwd_mismatch.as_deref(),
        });
        let mut cmd = container_cmd(bin, cli.sudo);
        cmd.args(["attach", &info.name]);
        let err = cmd.exec();
        eprintln!("Failed to attach to box '{}': {}", info.name, err);
        process::exit(1);
    }

    // Stopped container: start & attach, preserving sandbox slice and PCAP traffic auditing
    check_kvm_available();
    let use_slice = should_use_sandbox_slice(runtime, cli.sudo, effective_net);
    let mut audited_pcap = false;
    if let Some(ref cf) = info.cmd_file {
        let _ = fs::write(cf, "run\tbash\n");
    }
    if runtime == VmRuntime::Krun
        && !cli.sudo
        && matches!(effective_net, NetMode::Internet | NetMode::Local)
    {
        if let Some(ref pcap_path) = info.pcap {
            let cmd_summary = if info.cmd.is_empty()
                || info.cmd.iter().any(|tok| tok.contains("/tmp/.box_bashrc"))
            {
                "bash".to_string()
            } else {
                info.cmd.join(" ")
            };
            spawn_pcap_dns_auditor_at(
                pcap_path,
                &info.name,
                &info.preset,
                Path::new(&info.workspace),
                &cmd_summary,
                effective_net.as_str(),
                info.cmd_file.as_deref(),
                true,
            );
            audited_pcap = true;
        }
    }

    let net_detail = match effective_net {
        NetMode::None => "air-gapped",
        NetMode::Local => "local-only (host loopback port exposed)",
        NetMode::Internet if audited_pcap => "audited via pasta pcap",
        NetMode::Internet => "outbound enabled",
    };

    print_box_header(&BoxHeader {
        mode: "STARTING & ATTACHING",
        name: &info.name,
        env_label: &info.preset,
        presets: &display_presets,
        spec_file: spec_file_str.as_deref(),
        image: &info.image,
        runtime_label: runtime_desc,
        workspace: &info.workspace,
        rw: info.rw,
        venv: info.venv.as_deref(),
        venv_host_path: venv_host_path.as_deref(),
        llama_bin: llama_bin_str.as_deref(),
        net: effective_net,
        net_detail,
        slice: if use_slice {
            "podman-sandbox.slice"
        } else {
            "default"
        },
        cwd_mismatch: host_cwd_mismatch.as_deref(),
    });

    let mut cmd = match runtime {
        VmRuntime::Krun => podman_with_optional_slice(cli.sudo, use_slice),
        VmRuntime::Kata => container_cmd("nerdctl", cli.sudo),
    };
    cmd.args(["start", "-ai", &info.name]);
    let err = cmd.exec();
    eprintln!("Failed to start and attach to box '{}': {}", info.name, err);
    process::exit(1);
}

fn first_existing_path(paths: &[&'static str]) -> Option<&'static str> {
    // Helper returning the first existing path from a static slice
    for &p in paths {
        if Path::new(p).exists() {
            return Some(p);
        }
    }
    None
}

fn find_local_probe_image(cli: &Cli) -> Option<String> {
    let bin = cli.runtime.container_bin();
    let mut candidates: Vec<String> = Vec::new();
    if let Some(ref img) = cli.image {
        candidates.push(img.clone());
    }
    for p in &cli.preset {
        candidates.push(p.image().to_string());
    }
    for p in [
        Preset::Alpine,
        Preset::Rust,
        Preset::Python,
        Preset::Node,
        Preset::Latex,
    ] {
        let img = p.image().to_string();
        if !candidates.contains(&img) {
            candidates.push(img);
        }
    }
    for img in candidates {
        let ok = container_cmd(bin, cli.sudo)
            .args(["image", "exists", &img])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if ok {
            return Some(img);
        }
    }
    None
}

pub fn verify_isolation(cli: &Cli) {
    let host_kernel = fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let kvm_exists = Path::new("/dev/kvm").exists();
    let kvm_rw = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .is_ok();

    let krun_path = first_existing_path(&["/usr/bin/krun", "/usr/local/bin/krun"]);
    let kata_path = first_existing_path(&[
        "/opt/kata/bin/containerd-shim-kata-v2",
        "/usr/local/bin/containerd-shim-kata-v2",
        "/usr/bin/containerd-shim-kata-v2",
    ]);

    let krun_version = krun_path.and_then(|p| {
        Command::new(p).arg("--version").output().ok().map(|o| {
            let s = String::from_utf8_lossy(&o.stdout);
            let first = s.lines().next().unwrap_or("").trim();
            let has_libkrun = s.contains("+LIBKRUN");
            if has_libkrun {
                format!("{} (+LIBKRUN)", first)
            } else {
                first.to_string()
            }
        })
    });

    let pasta_version = Command::new("pasta")
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .next()
                .map(|l| l.trim().to_string())
        })
        .unwrap_or_else(|| "not found".to_string());

    println!("================================================================================");
    println!("  BOX VIRTUALIZATION & ISOLATION VERIFICATION");
    println!("================================================================================");
    println!(
        "  Selected Runtime : {}",
        match cli.runtime {
            VmRuntime::Krun => "krun (crun-krun + libkrun KVM microVM via podman; NOT Kata Containers)",
            VmRuntime::Kata => "kata (Kata Containers shimv2 KVM microVM via nerdctl/containerd)",
        }
    );
    println!("  Host Kernel      : {}", host_kernel);
    println!(
        "  Hardware KVM     : {}",
        if kvm_rw {
            "/dev/kvm present and accessible (rw)"
        } else if kvm_exists {
            "/dev/kvm present (no rw permission for current user — may need --sudo or kvm group)"
        } else {
            "/dev/kvm NOT found"
        }
    );
    println!(
        "  libkrun Runtime  : {}",
        match (krun_path, krun_version) {
            (Some(p), Some(v)) => format!("{} ({})", p, v),
            (Some(p), None) => p.to_string(),
            _ => "not installed".to_string(),
        }
    );
    println!(
        "  Kata Runtime     : {}",
        kata_path.unwrap_or("not installed (containerd-shim-kata-v2 not found)")
    );
    println!("  Pasta Networking : {}", pasta_version);
    println!(
        "  Sandbox Slice    : {}",
        if slice_exists() {
            "podman-sandbox.slice active"
        } else {
            "podman-sandbox.slice not found"
        }
    );
    println!("--------------------------------------------------------------------------------");

    if !kvm_exists {
        println!("  RESULT: CANNOT VERIFY — /dev/kvm is unavailable.");
        return;
    }

    let Some(probe_image) = find_local_probe_image(cli) else {
        println!(
            "  RESULT: No local cached container image found for live probe. Run a box once or pass `--image <img_name>`."
        );
        return;
    };

    println!(
        "  Running air-gapped microVM probe (image: {})...",
        probe_image
    );

    let probe_script = "echo KERNEL=$(cat /proc/sys/kernel/osrelease); \
                        echo VERSION=$(cat /proc/version); \
                        echo HYPERVISOR=$(grep -m1 flags /proc/cpuinfo | grep -o hypervisor || echo none); \
                        echo ROOTFS=$(awk '$2==\"/\"{print $3; exit}' /proc/mounts)";

    let mut cmd = match cli.runtime {
        VmRuntime::Krun => {
            let krun_bin = resolve_krun_binary();
            let mut c = container_cmd("podman", cli.sudo);
            c.args(["run", "--rm", "--network=none", "--runtime", &krun_bin]);
            c
        }
        VmRuntime::Kata => {
            check_kata_installed();
            let mut c = container_cmd("nerdctl", cli.sudo);
            c.args([
                "run",
                "--rm",
                "--network=none",
                "--runtime",
                "io.containerd.kata.v2",
            ]);
            c
        }
    };
    cmd.args([&probe_image, "sh", "-c", probe_script]);

    let output = match cmd.output() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("  Probe failed to execute: {}", e);
            process::exit(1);
        }
    };

    if !output.status.success() {
        eprintln!(
            "  Probe failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        process::exit(1);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut guest_kernel = String::new();
    let mut guest_version = String::new();
    let mut hypervisor_flag = String::new();
    let mut rootfs_type = String::new();

    for line in stdout.lines() {
        if let Some(v) = line.strip_prefix("KERNEL=") {
            guest_kernel = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("VERSION=") {
            guest_version = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("HYPERVISOR=") {
            hypervisor_flag = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("ROOTFS=") {
            rootfs_type = v.trim().to_string();
        }
    }

    let detected_tech = if guest_version.to_lowercase().contains("libkrunfw") {
        "libkrun / libkrunfw (KVM microVM)"
    } else if guest_version.to_lowercase().contains("kata") {
        "Kata Containers (KVM microVM)"
    } else if !guest_kernel.is_empty() && guest_kernel != host_kernel {
        "Separate guest Linux kernel (KVM microVM)"
    } else {
        "Shared host kernel (standard container — NOT a microVM)"
    };

    println!("  Guest Kernel     : {}", guest_kernel);
    println!("  Guest Version    : {}", guest_version);
    println!("  CPU Hypervisor   : {}", hypervisor_flag);
    println!("  Guest Root FS    : {}", rootfs_type);
    println!("  Detected Tech    : {}", detected_tech);
    println!("--------------------------------------------------------------------------------");

    if !guest_kernel.is_empty() && guest_kernel != host_kernel {
        println!(
            "  VERIFIED: Hardware-virtualized KVM microVM isolation active (guest {} != host {}).",
            guest_kernel, host_kernel
        );
    } else {
        println!(
            "  WARNING: Guest kernel matches host kernel ({}) — NOT isolated in a microVM!",
            host_kernel
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_pcap_path_from_pasta_network_mode() {
        let mode = "pasta:--no-map-gw,--dns-host,1.1.1.1,--pcap,/run/user/1000/box-pcap-test-123.pcap";
        assert_eq!(
            extract_pcap_from_netmode(mode),
            Some(PathBuf::from("/run/user/1000/box-pcap-test-123.pcap"))
        );
        assert_eq!(extract_pcap_from_netmode("none"), None);
    }

    #[test]
    fn parses_container_inspect_output() {
        let raw = "true\t/my-rust\tdocker.io/library/rust:slim\tpasta:--no-map-gw,--pcap,/run/user/1000/a.pcap\trust\t/var/home/alex/proj\tkrun\tinternet\ttrue\tbox-venv\t/run/user/1000/a.pcap\tkeep-id\t/run/user/1000/cmd\ttrue\t<no value>\t8080\t/opt/my-llama\t[\"bash\",\"-c\",\"cat > /tmp/.box_bashrc <<'BOXRC'\\nexec bash --rcfile /tmp/.box_bashrc\"]\n";
        let info = parse_inspect_output(raw).unwrap();
        assert!(info.running);
        assert_eq!(info.name, "my-rust");
        assert_eq!(info.preset, "rust");
        assert_eq!(info.workspace, "/var/home/alex/proj");
        assert_eq!(info.runtime, Some(VmRuntime::Krun));
        assert_eq!(info.net, Some(NetMode::Internet));
        assert!(info.rw);
        assert_eq!(info.venv.as_deref(), Some("box-venv"));
        assert_eq!(info.pcap, Some(PathBuf::from("/run/user/1000/a.pcap")));
        assert!(info.keep_id);
        assert!(info.managed);
        assert!(!info.is_toolbox);
        assert_eq!(info.host_port, Some(8080));
        assert_eq!(info.llama_bin, Some(PathBuf::from("/opt/my-llama")));
        assert!(is_interactive_shell_cmd(&info.cmd));
        assert!(info.image_id.is_empty());
        assert_eq!(info.spec_hash, None);
        assert_eq!(info.spec_file, None);
    }

    #[test]
    fn parses_container_inspect_output_with_spec_metadata() {
        let raw = "false\t/rust\tlocalhost/box-env:rust\tnone\trust\t/var/home/alex/proj\tkrun\tnone\ttrue\tbox-venv\t<no value>\tkeep-id\t<no value>\ttrue\t<no value>\t<no value>\t<no value>\t[\"bash\"]\tsha256:abcdef123456\tdeadbeef01234567\t/home/alex/.config/box/images/rust.yaml\trust\n";
        let info = parse_inspect_output(raw).unwrap();
        assert!(!info.running);
        assert_eq!(info.name, "rust");
        assert_eq!(info.image_id, "abcdef123456");
        assert_eq!(info.spec_hash.as_deref(), Some("deadbeef01234567"));
        assert_eq!(
            info.spec_file,
            Some(PathBuf::from("/home/alex/.config/box/images/rust.yaml"))
        );
        assert_eq!(info.base_presets, vec![Preset::Rust]);
    }

    #[test]
    fn detects_interactive_shell_commands() {
        assert!(is_interactive_shell_cmd(&["bash".to_string()]));
        assert!(is_interactive_shell_cmd(&["/bin/sh".to_string()]));
        assert!(is_interactive_shell_cmd(&[
            "bash".to_string(),
            "-c".to_string(),
            "exec bash --rcfile /tmp/.box_bashrc".to_string()
        ]));
        assert!(!is_interactive_shell_cmd(&[
            "cargo".to_string(),
            "run".to_string()
        ]));
        assert!(!is_interactive_shell_cmd(&[
            "ping".to_string(),
            "google.com".to_string()
        ]));
        assert!(!is_interactive_shell_cmd(&[]));
    }
}
