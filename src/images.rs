use std::io::Write;
use std::process::{self, Stdio};

use crate::cli::{Cli, Preset};
use crate::runtime::container_cmd;

pub fn infer_env_from_image(image: &str) -> String {
    let lower = image.to_lowercase();
    if lower.contains("box-env:") {
        if let Some(tag) = lower.split("box-env:").nth(1) {
            let label = tag.replace('-', "+");
            if !label.is_empty() {
                return label;
            }
        }
    }
    if lower.contains("kali") {
        "kali".to_string()
    } else if lower.contains("julia") {
        "julia".to_string()
    } else if lower.contains("bitcoin") {
        "bitcoin".to_string()
    } else if lower.contains("k8s") || lower.contains("kubectl") {
        "k8s".to_string()
    } else if lower.contains("llama") {
        "llama".to_string()
    } else if lower.contains("rust") {
        "rust".to_string()
    } else if lower.contains("python") {
        "python".to_string()
    } else if lower.contains("texlive") || lower.contains("latex") {
        "latex".to_string()
    } else if lower.contains("node") {
        "node".to_string()
    } else if lower.contains("alpine") {
        "alpine".to_string()
    } else {
        "custom".to_string()
    }
}

pub fn parse_presets_from_env_label(env_label: &str) -> Vec<Preset> {
    env_label
        .split('+')
        .filter_map(|part| match part.trim().to_lowercase().as_str() {
            "alpine" => Some(Preset::Alpine),
            "bitcoin" => Some(Preset::Bitcoin),
            "julia" => Some(Preset::Julia),
            "k8s" => Some(Preset::K8s),
            "kali" => Some(Preset::Kali),
            "latex" => Some(Preset::Latex),
            "llama" => Some(Preset::Llama),
            "node" => Some(Preset::Node),
            "python" => Some(Preset::Python),
            "rust" => Some(Preset::Rust),
            _ => None,
        })
        .collect()
}

fn image_exists(bin: &str, use_sudo: bool, tag: &str) -> bool {
    container_cmd(bin, use_sudo)
        .args(["image", "exists", tag])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn generate_containerfile(base_preset: Preset, presets: &[Preset]) -> String {
    if base_preset == Preset::Alpine {
        return format!(
            "FROM {}\nRUN apk add --no-cache ca-certificates curl iputils vim\n",
            base_preset.image()
        );
    }

    if base_preset == Preset::Llama {
        return format!(
            "FROM {}\n\
             RUN dnf install -y --setopt=install_weak_deps=False \
             ca-certificates curl iputils vim-enhanced libgomp libstdc++ libcurl jq python3 \
             && dnf clean all\n",
            base_preset.image()
        );
    }

    let mut containerfile = format!(
        "FROM {}\nENV DEBIAN_FRONTEND=noninteractive\n",
        base_preset.image()
    );

    // Minimum base tools included in every Debian-based preset image
    let mut apt_packages: Vec<&str> = vec!["ca-certificates", "curl", "iputils-ping", "vim"];
    let mut extra_run_steps: Vec<&str> = Vec::new();
    let has_latex = presets.contains(&Preset::Latex);
    let has_julia = presets.contains(&Preset::Julia);
    let has_bitcoin = presets.contains(&Preset::Bitcoin);
    let has_k8s = presets.contains(&Preset::K8s);
    let has_kali = presets.contains(&Preset::Kali);

    if has_latex {
        // Provide standard system fonts (LiberationSerif/Sans/Mono, DejaVu) and fontconfig
        // so XeLaTeX/LuaLaTeX documents using system fonts compile cleanly.
        apt_packages.extend(["fontconfig", "fonts-liberation", "fonts-dejavu-core"]);
    }

    if has_kali {
        apt_packages.extend([
            "dnsutils",
            "git",
            "jq",
            "netcat-openbsd",
            "nmap",
            "traceroute",
            "whois",
        ]);
    }

    if has_k8s {
        apt_packages.push("jq");
    }

    if has_bitcoin {
        apt_packages.extend(["gzip", "tar"]);
    }

    for p in presets {
        if *p == base_preset {
            continue;
        }
        match p {
            Preset::Python => {
                apt_packages.extend(["python3", "python3-pip", "python3-venv", "python-is-python3"]);
            }
            Preset::Node => {
                apt_packages.extend(["nodejs", "npm"]);
            }
            Preset::Rust => {
                apt_packages.extend(["build-essential", "pkg-config", "libssl-dev"]);
                extra_run_steps.push(
                    "ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo PATH=/usr/local/cargo/bin:$PATH\n\
                     RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --no-modify-path && chmod -R a+rX /usr/local/rustup /usr/local/cargo",
                );
            }
            Preset::Latex => {
                apt_packages.extend([
                    "texlive-latex-recommended",
                    "texlive-fonts-recommended",
                    "texlive-latex-extra",
                ]);
            }
            Preset::Julia => {
                // Installed via apt when combined under a higher-priority Debian base (e.g. Kali)
                apt_packages.push("julia");
            }
            Preset::Bitcoin | Preset::K8s | Preset::Kali => {
                // Handled by capability flags above / binary steps below
            }
            Preset::Alpine | Preset::Llama => unreachable!(),
        }
    }

    apt_packages.sort_unstable();
    apt_packages.dedup();
    containerfile.push_str(&format!(
        "RUN apt-get update && apt-get install -y --no-install-recommends {} && rm -rf /var/lib/apt/lists/*\n",
        apt_packages.join(" ")
    ));

    if has_bitcoin {
        extra_run_steps.push(
            "RUN ARCH=$(uname -m) && \
             case \"$ARCH\" in x86_64|aarch64) ;; *) echo \"Unsupported arch: $ARCH\" >&2; exit 1 ;; esac && \
             VER=$(curl -fsSL https://bitcoincore.org/bin/ | grep -oE 'bitcoin-core-[0-9]+\\.[0-9]+(\\.[0-9]+)?/' | sed 's|bitcoin-core-||;s|/||' | sort -V | tail -n1) && \
             VER=${VER:-28.1} && \
             curl -fsSL \"https://bitcoincore.org/bin/bitcoin-core-${VER}/bitcoin-${VER}-${ARCH}-linux-gnu.tar.gz\" | \
             tar -xz -C /usr/local --strip-components=1 --wildcards '*/bin/*' && \
             chmod a+rx /usr/local/bin/bitcoin*",
        );
    }

    if has_k8s {
        extra_run_steps.push(
            "RUN ARCH=$(uname -m) && \
             case \"$ARCH\" in x86_64) KARCH=amd64 ;; aarch64) KARCH=arm64 ;; *) echo \"Unsupported arch: $ARCH\" >&2; exit 1 ;; esac && \
             KVER=$(curl -fsSL https://dl.k8s.io/release/stable.txt) && \
             curl -fsSL -o /usr/local/bin/kubectl \"https://dl.k8s.io/release/${KVER}/bin/linux/${KARCH}/kubectl\" && \
             chmod +x /usr/local/bin/kubectl",
        );
    }

    if has_julia {
        // Pre-install Pluto.jl into a shared read-only depot at /usr/local/share/julia using
        // `JULIA_CPU_TARGET=generic` so the precompile cache matches KVM microVM CPUID masks
        // and loads instantly without recompiling at runtime.
        extra_run_steps.push(
            "RUN JULIA_DEPOT_PATH=/usr/local/share/julia JULIA_CPU_TARGET=generic julia -e 'using Pkg; Pkg.add(\"Pluto\"); using Pluto' && \
             chmod -R a+rX /usr/local/share/julia && \
             printf '#!/bin/sh\\nexec julia -e \"import Pluto; Pluto.run(host=\\\"0.0.0.0\\\", port=parse(Int, get(ENV, \\\"PLUTO_PORT\\\", \\\"8888\\\")), launch_browser=false)\"\\n' > /usr/local/bin/pluto && \
             chmod +x /usr/local/bin/pluto",
        );
    }

    if has_latex {
        // Pre-populate fontconfig and luaotfload font databases into TEXMFSYSVAR inside the image
        // so LuaLaTeX never has to spend minutes regenerating them at runtime.
        extra_run_steps.push(
            "RUN fc-cache -f && if command -v luaotfload-tool >/dev/null 2>&1; then \
             SYSVAR=$(kpsewhich -var-value=TEXMFSYSVAR); \
             TEXMFVAR=\"$SYSVAR\" luaotfload-tool --update --force && \
             chmod -R a+rX \"$SYSVAR\"; fi",
        );
    }

    for step in extra_run_steps {
        containerfile.push_str(step);
        containerfile.push('\n');
    }

    containerfile
}

pub fn build_combined_image(cli: &Cli, presets: &[Preset]) -> (String, String) {
    let mut unique = presets.to_vec();
    unique.sort();
    unique.dedup();

    if unique.is_empty() {
        unique.push(Preset::Rust);
    }

    let env_label = unique
        .iter()
        .map(|p| p.as_str())
        .collect::<Vec<_>>()
        .join("+");

    if unique.len() > 1 && unique.contains(&Preset::Alpine) {
        eprintln!(
            "ERROR: Cannot combine `alpine` (musl/apk) with Debian or Fedora presets."
        );
        process::exit(1);
    }

    if unique.len() > 1 && unique.contains(&Preset::Llama) {
        eprintln!(
            "ERROR: Cannot combine `llama` (Fedora/dnf base for host glibc compatibility) with Debian/Alpine presets."
        );
        process::exit(1);
    }

    let tag = format!(
        "localhost/box-env:{}",
        unique
            .iter()
            .map(|p| p.as_str())
            .collect::<Vec<_>>()
            .join("-")
    );

    let bin = cli.runtime.container_bin();
    if !cli.rebuild && image_exists(bin, cli.sudo, &tag) {
        return (tag, env_label);
    }

    let base_preset = *unique.iter().max_by_key(|p| p.base_priority()).unwrap();
    let containerfile = generate_containerfile(base_preset, &unique);

    println!(
        "[box] Building environment image '{}' (base: {}, includes curl/ping/vim)...",
        tag,
        base_preset.as_str()
    );

    let mut build_cmd = container_cmd(bin, cli.sudo);
    build_cmd
        .args(["build", "-t", &tag, "-"])
        .stdin(Stdio::piped());

    let mut child = build_cmd.spawn().unwrap_or_else(|e| {
        eprintln!("Failed to start {} build: {}", bin, e);
        process::exit(1);
    });

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(containerfile.as_bytes())
            .unwrap_or_else(|e| {
                eprintln!("Failed to pipe Containerfile to {} build: {}", bin, e);
                process::exit(1);
            });
    }

    let status = child.wait().unwrap_or_else(|e| {
        eprintln!("Failed waiting for {} build: {}", bin, e);
        process::exit(1);
    });

    if !status.success() {
        eprintln!("ERROR: Failed to build preset image '{}'.", tag);
        process::exit(1);
    }

    (tag, env_label)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn infers_env_from_image_name() {
        assert_eq!(infer_env_from_image("docker.io/library/rust:slim"), "rust");
        assert_eq!(
            infer_env_from_image("docker.io/texlive/texlive:latest"),
            "latex"
        );
        assert_eq!(infer_env_from_image("ubuntu:24.04"), "custom");
    }

    #[test]
    fn base_presets_include_curl_ping_and_vim() {
        let rust_cf = generate_containerfile(Preset::Rust, &[Preset::Rust]);
        assert!(rust_cf.contains("curl"));
        assert!(rust_cf.contains("iputils-ping"));
        assert!(rust_cf.contains("vim"));

        let alpine_cf = generate_containerfile(Preset::Alpine, &[Preset::Alpine]);
        assert!(alpine_cf.contains("apk add --no-cache"));
        assert!(alpine_cf.contains("curl"));
        assert!(alpine_cf.contains("iputils"));
        assert!(alpine_cf.contains("vim"));
    }

    #[test]
    fn latex_containerfile_installs_liberation_fonts_and_prebuilds_luaotfload_db() {
        let cf = generate_containerfile(Preset::Latex, &[Preset::Latex, Preset::Python]);
        assert!(cf.contains("fonts-liberation"));
        assert!(cf.contains("fontconfig"));
        assert!(cf.contains("iputils-ping"));
        assert!(cf.contains("vim"));
        assert!(cf.contains("luaotfload-tool --update --force"));
        assert!(cf.contains("python3"));
    }

    #[test]
    fn parses_presets_from_env_label() {
        assert_eq!(
            parse_presets_from_env_label("latex+python"),
            vec![Preset::Latex, Preset::Python]
        );
        assert_eq!(
            parse_presets_from_env_label("bitcoin+julia+k8s+kali+llama"),
            vec![
                Preset::Bitcoin,
                Preset::Julia,
                Preset::K8s,
                Preset::Kali,
                Preset::Llama
            ]
        );
    }

    #[test]
    fn new_presets_generate_expected_containerfiles() {
        let julia_cf = generate_containerfile(Preset::Julia, &[Preset::Julia]);
        assert!(julia_cf.contains("FROM docker.io/library/julia:latest"));
        assert!(julia_cf.contains("Pluto"));
        assert!(julia_cf.contains("/usr/local/bin/pluto"));
        assert!(julia_cf.contains("curl"));
        assert!(julia_cf.contains("iputils-ping"));
        assert!(julia_cf.contains("vim"));

        let btc_cf = generate_containerfile(Preset::Bitcoin, &[Preset::Bitcoin]);
        assert!(btc_cf.contains("bitcoincore.org/bin/"));
        assert!(btc_cf.contains("chmod a+rx /usr/local/bin/bitcoin*"));

        let k8s_cf = generate_containerfile(Preset::K8s, &[Preset::K8s]);
        assert!(k8s_cf.contains("dl.k8s.io/release"));
        assert!(k8s_cf.contains("/usr/local/bin/kubectl"));

        let kali_cf = generate_containerfile(Preset::Kali, &[Preset::Kali]);
        assert!(kali_cf.contains("FROM docker.io/kalilinux/kali-rolling"));
        assert!(kali_cf.contains("nmap"));
        assert!(kali_cf.contains("vim"));

        let llama_cf = generate_containerfile(Preset::Llama, &[Preset::Llama]);
        assert!(llama_cf.contains("FROM docker.io/library/fedora:latest"));
        assert!(llama_cf.contains("dnf install"));
        assert!(llama_cf.contains("libgomp"));
        assert!(llama_cf.contains("vim-enhanced"));
    }
}
