use std::fs;
use std::path::PathBuf;
use std::process;

use crate::cli::{Cli, NetMode, VmRuntime};
use crate::images::infer_env_from_image;
use crate::runtime::{clean_template_val, container_cmd, extract_pcap_from_netmode, infer_net_mode};

#[derive(Debug)]
struct ContainerStackInfo {
    id: String,
    name: String,
    status: String,
    oci_runtime: String,
    image: String,
    readonly_rootfs: bool,
    user: String,
    userns: String,
    memory_bytes: u64,
    pids_limit: i64,
    cap_drop: String,
    network_mode: String,
    managed: bool,
    preset: String,
    workspace: String,
    net: NetMode,
    rw: bool,
    venv: Option<String>,
    pcap: Option<PathBuf>,
    cmd: String,
}

#[derive(Debug, Default)]
struct ImageMeta {
    short_id: String,
    platform: String,
    size_bytes: u64,
}

#[derive(Debug, Default)]
struct ProbeResult {
    os_pretty: String,
    guest_kernel: String,
    guest_version: String,
    hypervisor: String,
    rootfs: String,
    pkg_manager: String,
    pkg_count: String,
    tools: Vec<(String, String)>,
    venv_bins: Vec<String>,
    packages: Vec<String>,
    pip_packages: Vec<String>,
}

fn format_bytes(bytes: u64) -> String {
    if bytes == 0 {
        return "unlimited".to_string();
    }
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    if (bytes as f64) >= GIB {
        format!("{:.2} GiB", bytes as f64 / GIB)
    } else if (bytes as f64) >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB)
    } else {
        format!("{} B", bytes)
    }
}

fn classify_oci_runtime(oci_runtime: &str) -> (&'static str, bool) {
    let lower = oci_runtime.to_lowercase();
    if lower.contains("kata") {
        ("Kata Containers (KVM microVM)", true)
    } else if lower.contains("krun") {
        ("libkrun / crun-krun (KVM microVM — NOT Kata Containers)", true)
    } else if lower.is_empty() || lower == "<no value>" {
        ("Unknown runtime", false)
    } else {
        (
            "Standard Linux container (shared host kernel — NOT a KVM microVM)",
            false,
        )
    }
}

fn query_container_info(cli: &Cli, target: &str) -> ContainerStackInfo {
    let bin = cli.runtime.container_bin();
    let runtime_field = match cli.runtime {
        VmRuntime::Krun => "{{.OCIRuntime}}",
        VmRuntime::Kata => "{{.HostConfig.Runtime}}",
    };
    let fmt = format!(
        "{{{{.Id}}}}\t{{{{.Name}}}}\t{{{{.State.Status}}}}\t{}\t{{{{.Config.Image}}}}\t{{{{.HostConfig.ReadonlyRootfs}}}}\t{{{{.Config.User}}}}\t{{{{.HostConfig.UsernsMode}}}}\t{{{{.HostConfig.Memory}}}}\t{{{{.HostConfig.PidsLimit}}}}\t{{{{.HostConfig.CapDrop}}}}\t{{{{.HostConfig.NetworkMode}}}}\t{{{{index .Config.Labels \"box.managed\"}}}}\t{{{{index .Config.Labels \"box.preset\"}}}}\t{{{{index .Config.Labels \"box.workspace\"}}}}\t{{{{index .Config.Labels \"box.net\"}}}}\t{{{{index .Config.Labels \"box.rw\"}}}}\t{{{{index .Config.Labels \"box.venv\"}}}}\t{{{{index .Config.Labels \"box.pcap\"}}}}\t{{{{range .Config.Cmd}}}}{{{{.}}}} {{{{end}}}}",
        runtime_field
    );

    let output = container_cmd(bin, cli.sudo)
        .args(["container", "inspect", "--format", &fmt, target])
        .output()
        .unwrap_or_else(|e| {
            eprintln!("Failed to inspect '{}' via {}: {}", target, bin, e);
            process::exit(1);
        });

    if !output.status.success() {
        eprintln!(
            "ERROR: Container '{}' not found (runtime: {}): {}",
            target,
            bin,
            String::from_utf8_lossy(&output.stderr).trim()
        );
        eprintln!("Run `box --list` or `{} ps -a` to see available containers.", bin);
        process::exit(1);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
    let cols: Vec<&str> = line.split('\t').collect();
    if cols.len() < 12 {
        eprintln!("ERROR: Unexpected inspect output for '{}'.", target);
        process::exit(1);
    }

    let id = cols[0].trim().chars().take(12).collect::<String>();
    let name = cols[1].trim().trim_start_matches('/').to_string();
    let status = cols[2].trim().to_string();
    let oci_runtime = clean_template_val(cols.get(3)).unwrap_or_else(|| "unknown".to_string());
    let image = cols[4].trim().to_string();
    let readonly_rootfs = cols[5].trim() == "true";
    let user = clean_template_val(cols.get(6)).unwrap_or_else(|| "root".to_string());
    let userns = clean_template_val(cols.get(7)).unwrap_or_else(|| "default".to_string());
    let memory_bytes = cols[8].trim().parse::<u64>().unwrap_or(0);
    let pids_limit = cols[9].trim().parse::<i64>().unwrap_or(0);
    let cap_drop = clean_template_val(cols.get(10)).unwrap_or_else(|| "[]".to_string());
    let network_mode = cols[11].trim().to_string();

    let managed = clean_template_val(cols.get(12))
        .map(|s| s == "true")
        .unwrap_or(false);
    let preset = clean_template_val(cols.get(13)).unwrap_or_else(|| infer_env_from_image(&image));
    let workspace = clean_template_val(cols.get(14)).unwrap_or_else(|| "-".to_string());
    let net = clean_template_val(cols.get(15))
        .and_then(|s| NetMode::from_label(&s))
        .unwrap_or_else(|| infer_net_mode(&network_mode));
    let rw = clean_template_val(cols.get(16))
        .map(|s| s == "true")
        .unwrap_or(false);
    let venv = match clean_template_val(cols.get(17)).as_deref() {
        Some("ephemeral") => None,
        Some(v) => Some(v.to_string()),
        None => None,
    };
    let pcap = clean_template_val(cols.get(18))
        .map(PathBuf::from)
        .or_else(|| extract_pcap_from_netmode(&network_mode));
    let cmd = clean_template_val(cols.get(19)).unwrap_or_else(|| "-".to_string());

    ContainerStackInfo {
        id,
        name,
        status,
        oci_runtime,
        image,
        readonly_rootfs,
        user,
        userns,
        memory_bytes,
        pids_limit,
        cap_drop,
        network_mode,
        managed,
        preset,
        workspace,
        net,
        rw,
        venv,
        pcap,
        cmd,
    }
}

fn query_image_meta(cli: &Cli, image: &str) -> ImageMeta {
    let bin = cli.runtime.container_bin();
    let output = container_cmd(bin, cli.sudo)
        .args([
            "image",
            "inspect",
            "--format",
            "{{.Id}}\t{{.Os}}/{{.Architecture}}\t{{.Size}}",
            image,
        ])
        .output();

    let Ok(out) = output else {
        return ImageMeta::default();
    };
    if !out.status.success() {
        return ImageMeta::default();
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
    let cols: Vec<&str> = line.split('\t').collect();
    if cols.len() < 3 {
        return ImageMeta::default();
    }
    let raw_id = cols[0].trim();
    let short_id = raw_id
        .strip_prefix("sha256:")
        .unwrap_or(raw_id)
        .chars()
        .take(12)
        .collect();
    ImageMeta {
        short_id,
        platform: cols[1].trim().to_string(),
        size_bytes: cols[2].trim().parse::<u64>().unwrap_or(0),
    }
}

fn parse_probe_output(stdout: &str) -> ProbeResult {
    let mut res = ProbeResult::default();
    for line in stdout.lines() {
        if let Some(v) = line.strip_prefix("OS=") {
            res.os_pretty = v.trim().trim_matches('"').to_string();
        } else if let Some(v) = line.strip_prefix("KERNEL=") {
            res.guest_kernel = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("VERSION=") {
            res.guest_version = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("HYPERVISOR=") {
            res.hypervisor = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("ROOTFS=") {
            res.rootfs = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("PKGMGR=") {
            res.pkg_manager = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("PKGCOUNT=") {
            res.pkg_count = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("TOOL=") {
            if let Some((name, ver)) = v.split_once('|') {
                let ver_clean = ver.trim();
                if !ver_clean.is_empty() {
                    res.tools.push((name.trim().to_string(), ver_clean.to_string()));
                }
            }
        } else if let Some(v) = line.strip_prefix("VENVBIN=") {
            let b = v.trim();
            if !b.is_empty() {
                res.venv_bins.push(b.to_string());
            }
        } else if let Some(v) = line.strip_prefix("PKG=") {
            let p = v.trim();
            if !p.is_empty() {
                res.packages.push(p.to_string());
            }
        } else if let Some(v) = line.strip_prefix("PIP=") {
            let p = v.trim();
            if !p.is_empty() {
                res.pip_packages.push(p.to_string());
            }
        }
    }
    res
}

fn run_stack_probe(cli: &Cli, info: &ContainerStackInfo) -> Option<ProbeResult> {
    let bin = cli.runtime.container_bin();
    let mut cmd = container_cmd(bin, cli.sudo);
    cmd.args(["run", "--rm", "--network=none", "--read-only"]);

    if !info.oci_runtime.is_empty() && info.oci_runtime != "unknown" {
        cmd.args(["--runtime", &info.oci_runtime]);
    }
    if let Some(ref venv) = info.venv {
        cmd.args(["-v", &format!("{}:/opt/venv:ro", venv)]);
    }

    let detail_part = if cli.details {
        r#"
if command -v dpkg-query >/dev/null 2>&1; then
  dpkg-query -W -f='PKG=${Package} (${Version})\n' 2>/dev/null | sort
elif command -v apk >/dev/null 2>&1; then
  apk list -I 2>/dev/null | sort | sed 's/^/PKG=/'
elif command -v rpm >/dev/null 2>&1; then
  rpm -qa --qf 'PKG=%{NAME} (%{VERSION})\n' 2>/dev/null | sort
fi
if [ -x /opt/venv/python/bin/pip ]; then
  /opt/venv/python/bin/pip list --format=freeze 2>/dev/null | sed 's/^/PIP=/'
elif [ -x /opt/venv/bin/pip ]; then
  /opt/venv/bin/pip list --format=freeze 2>/dev/null | sed 's/^/PIP=/'
elif command -v pip3 >/dev/null 2>&1; then
  pip3 list --format=freeze 2>/dev/null | sed 's/^/PIP=/'
fi
"#
    } else {
        ""
    };

    let script = format!(
        r#"export PATH="/opt/venv/python/bin:/opt/venv/bin:/opt/venv/cargo/bin:/usr/local/cargo/bin:$PATH"
OS_NAME=$(grep -m1 '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2-)
echo "OS=${{OS_NAME:-unknown}}"
echo "KERNEL=$(cat /proc/sys/kernel/osrelease 2>/dev/null)"
echo "VERSION=$(cat /proc/version 2>/dev/null)"
echo "HYPERVISOR=$(grep -m1 '^flags' /proc/cpuinfo 2>/dev/null | grep -o hypervisor || echo none)"
echo "ROOTFS=$(awk '$2=="/"{{print $3; exit}}' /proc/mounts 2>/dev/null)"
for t in rustc cargo python3 pip3 node npm pdflatex xelatex lualatex latexmk gcc g++ clang make cmake go java ruby git curl wget sqlite3 bash sh; do
  if command -v "$t" >/dev/null 2>&1; then
    case "$t" in
      sh) V="POSIX sh ($(readlink -f "$(command -v sh)" 2>/dev/null || command -v sh))" ;;
      java) V=$(java -version 2>&1 | head -n1) ;;
      go) V=$(go version 2>&1 | head -n1) ;;
      *) V=$("$t" --version 2>&1 | head -n1) ;;
    esac
    echo "TOOL=$t|$V"
  fi
done
if command -v dpkg-query >/dev/null 2>&1; then
  echo "PKGMGR=dpkg (Debian/Ubuntu)"
  echo "PKGCOUNT=$(dpkg-query -f '.\n' -W 2>/dev/null | wc -l)"
elif command -v apk >/dev/null 2>&1; then
  echo "PKGMGR=apk (Alpine)"
  echo "PKGCOUNT=$(apk info 2>/dev/null | wc -l)"
elif command -v rpm >/dev/null 2>&1; then
  echo "PKGMGR=rpm"
  echo "PKGCOUNT=$(rpm -qa 2>/dev/null | wc -l)"
else
  echo "PKGMGR=none"
  echo "PKGCOUNT=0"
fi
for d in /opt/venv/python/bin /opt/venv/bin /opt/venv/cargo/bin; do
  if [ -d "$d" ]; then
    ls -1 "$d" 2>/dev/null | head -n 40 | while read -r f; do echo "VENVBIN=$d/$f"; done
  fi
done
{}"#,
        detail_part
    );

    cmd.args([&info.image, "sh", "-c", &script]);
    let output = cmd.output().ok()?;
    if !output.status.success() {
        eprintln!(
            "  (Software probe failed: {})",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        return None;
    }
    Some(parse_probe_output(&String::from_utf8_lossy(&output.stdout)))
}

pub fn inspect_box_stack(cli: &Cli, target: &str) {
    let info = query_container_info(cli, target);
    let img_meta = query_image_meta(cli, &info.image);
    let (tech_label, is_microvm_runtime) = classify_oci_runtime(&info.oci_runtime);
    let host_kernel = fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    println!("================================================================================");
    println!("  BOX SOFTWARE STACK & ISOLATION REPORT: {}", info.name);
    println!("================================================================================");
    println!("  Container ID     : {} ({})", info.id, info.status);
    println!(
        "  Managed by box   : {}",
        if info.managed { "yes" } else { "no (external container)" }
    );
    println!("  OCI Runtime      : {}", info.oci_runtime);
    println!("  Virtualization   : {}", tech_label);
    println!(
        "  Image            : {}{}",
        info.image,
        if img_meta.short_id.is_empty() {
            String::new()
        } else {
            format!(
                "  [id: {}, {}, {}]",
                img_meta.short_id,
                img_meta.platform,
                format_bytes(img_meta.size_bytes)
            )
        }
    );
    println!("  Preset / Env     : {}", info.preset);
    println!("  Command          : {}", info.cmd);
    println!("--------------------------------------------------------------------------------");
    println!("  HARDENING, MOUNTS & NETWORK");
    println!(
        "  Read-Only RootFS : {}   |  CapDrop: {}",
        info.readonly_rootfs, info.cap_drop
    );
    println!("  User / UserNS    : {}   |  {}", info.user, info.userns);
    println!(
        "  Limits           : memory={}  |  pids={}",
        format_bytes(info.memory_bytes),
        if info.pids_limit <= 0 {
            "unlimited".to_string()
        } else {
            info.pids_limit.to_string()
        }
    );
    println!(
        "  Workspace Mount  : {} ({})",
        info.workspace,
        if info.rw { "rw" } else { "ro" }
    );
    println!(
        "  Persistent Venv  : {}",
        info.venv.as_deref().unwrap_or("ephemeral (none)")
    );
    println!(
        "  Network          : {} ({})",
        info.net.as_str(),
        info.network_mode
    );
    if let Some(ref pcap) = info.pcap {
        println!("  DNS Audit PCAP   : {}", pcap.display());
    }
    println!("--------------------------------------------------------------------------------");
    println!("  LIVE GUEST KERNEL & INSTALLED SOFTWARE PROBE (air-gapped, read-only)");

    let Some(probe) = run_stack_probe(cli, &info) else {
        println!("  Could not run software probe against image '{}'.", info.image);
        return;
    };

    let using_kata = probe.guest_version.to_lowercase().contains("kata")
        || info.oci_runtime.to_lowercase().contains("kata");
    let using_libkrun = probe.guest_version.to_lowercase().contains("libkrunfw")
        || info.oci_runtime.to_lowercase().contains("krun");
    let separate_kernel = !probe.guest_kernel.is_empty() && probe.guest_kernel != host_kernel;

    println!("  Guest OS         : {}", probe.os_pretty);
    println!(
        "  Kernel           : guest={}  vs  host={}",
        probe.guest_kernel, host_kernel
    );
    println!("  Guest Version    : {}", probe.guest_version);
    println!(
        "  Isolation Proof  : {} (hypervisor={}, rootfs={}, kata={}, libkrun={})",
        if separate_kernel && is_microvm_runtime {
            "VERIFIED KVM MICROVM"
        } else if separate_kernel {
            "SEPARATE GUEST KERNEL"
        } else {
            "SHARED HOST KERNEL (NOT A MICROVM)"
        },
        probe.hypervisor,
        probe.rootfs,
        if using_kata { "YES" } else { "NO" },
        if using_libkrun { "YES" } else { "NO" }
    );
    println!(
        "  System Packages  : {} ({} installed)",
        probe.pkg_manager, probe.pkg_count
    );

    println!("--------------------------------------------------------------------------------");
    println!("  INSTALLED PROGRAMS & TOOLCHAINS ({})", probe.tools.len());
    if probe.tools.is_empty() {
        println!("  (none of the common compilers/tools detected)");
    } else {
        for (name, ver) in &probe.tools {
            println!("  {:<12} {}", name, ver);
        }
    }

    if !probe.venv_bins.is_empty() {
        println!("--------------------------------------------------------------------------------");
        println!("  PERSISTENT /opt/venv BINARIES ({})", probe.venv_bins.len());
        let names: Vec<&str> = probe
            .venv_bins
            .iter()
            .map(|p| p.rsplit('/').next().unwrap_or(p.as_str()))
            .collect();
        println!("  {}", names.join(", "));
    }

    if cli.details {
        if !probe.pip_packages.is_empty() {
            println!("--------------------------------------------------------------------------------");
            println!("  PYTHON PACKAGES ({})", probe.pip_packages.len());
            for p in &probe.pip_packages {
                println!("  {}", p);
            }
        }
        if !probe.packages.is_empty() {
            println!("--------------------------------------------------------------------------------");
            println!("  ALL SYSTEM PACKAGES ({})", probe.packages.len());
            for p in &probe.packages {
                println!("  {}", p);
            }
        }
    } else {
        println!("--------------------------------------------------------------------------------");
        println!(
            "  Tip: Add `-v` (`box --inspect {} -v`) to list every installed OS & Python package.",
            info.name
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_byte_sizes() {
        assert_eq!(format_bytes(0), "unlimited");
        assert_eq!(format_bytes(2 * 1024 * 1024 * 1024), "2.00 GiB");
        assert_eq!(format_bytes(512 * 1024 * 1024), "512.0 MiB");
    }

    #[test]
    fn classifies_krun_kata_and_crun() {
        let (krun_lbl, krun_vm) = classify_oci_runtime("/usr/bin/krun");
        assert!(krun_vm && krun_lbl.contains("libkrun"));

        let (kata_lbl, kata_vm) = classify_oci_runtime("io.containerd.kata.v2");
        assert!(kata_vm && kata_lbl.contains("Kata"));

        let (crun_lbl, crun_vm) = classify_oci_runtime("crun");
        assert!(!crun_vm && crun_lbl.contains("NOT a KVM microVM"));
    }

    #[test]
    fn parses_stack_probe_output() {
        let sample = "\
OS=\"Debian GNU/Linux 13 (trixie)\"
KERNEL=6.12.109
VERSION=Linux version 6.12.109 (root@libkrunfw)
HYPERVISOR=hypervisor
ROOTFS=virtiofs
TOOL=python3|Python 3.13.2
TOOL=pdflatex|pdfTeX 3.141592653
PKGMGR=dpkg (Debian/Ubuntu)
PKGCOUNT=412
VENVBIN=/opt/venv/cargo/bin/ripgrep
";
        let p = parse_probe_output(sample);
        assert_eq!(p.os_pretty, "Debian GNU/Linux 13 (trixie)");
        assert_eq!(p.guest_kernel, "6.12.109");
        assert_eq!(p.rootfs, "virtiofs");
        assert_eq!(p.pkg_count, "412");
        assert_eq!(p.tools.len(), 2);
        assert_eq!(p.tools[0], ("python3".into(), "Python 3.13.2".into()));
        assert_eq!(p.venv_bins, vec!["/opt/venv/cargo/bin/ripgrep"]);
    }
}
