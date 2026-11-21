use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{self, Stdio};

use crate::cli::{Cli, Preset};
use crate::image_config::{
    ImageConfig, PkgManager, discover_image_configs, docker_env_quote, find_image_config,
    generate_starter_yaml, julia_string_literal, load_image_config_from_path, normalize_image_name,
    resolve_images_dir, sha256_hex, shell_quote,
};
use crate::runtime::{clean_template_val, container_cmd};

#[derive(Debug, Clone)]
pub struct ImageState {
    pub id: String,
    pub spec_hash: Option<String>,
    #[allow(dead_code)]
    pub spec_source: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GeneratedImageSpec {
    pub tag: String,
    pub env_label: String,
    pub base_image: String,
    pub presets: Vec<Preset>,
    pub pkg_manager: PkgManager,
    pub containerfile: String,
    pub spec_hash: String,
    pub spec_file: Option<PathBuf>,
    pub has_bash: bool,
}

#[derive(Debug, Clone)]
pub struct ResolvedImage {
    pub tag: String,
    pub env_label: String,
    pub presets: Vec<Preset>,
    #[allow(dead_code)]
    pub pkg_manager: PkgManager,
    pub spec_hash: String,
    pub spec_file: Option<PathBuf>,
    pub has_bash: bool,
    pub rebuilt: bool,
    pub image_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageSyncStatus {
    UpToDate,
    NeedsRebuild,
    NotBuilt,
}

impl ImageSyncStatus {
    pub fn label(&self) -> &'static str {
        match self {
            ImageSyncStatus::UpToDate => "UP-TO-DATE",
            ImageSyncStatus::NeedsRebuild => "REBUILD NEEDED",
            ImageSyncStatus::NotBuilt => "NOT BUILT",
        }
    }
}

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
        .split(['+', ','])
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

pub fn normalize_image_id(raw: &str) -> String {
    raw.trim()
        .strip_prefix("sha256:")
        .unwrap_or(raw.trim())
        .to_lowercase()
}

pub fn inspect_image_state(bin: &str, use_sudo: bool, tag: &str) -> Option<ImageState> {
    let fmt = "{{.Id}}\t{{if .Config}}{{if .Config.Labels}}{{index .Config.Labels \"box.spec.hash\"}}{{end}}{{end}}\t{{if .Config}}{{if .Config.Labels}}{{index .Config.Labels \"box.spec.source\"}}{{end}}{{end}}";
    let output = container_cmd(bin, use_sudo)
        .args(["image", "inspect", "--format", fmt, tag])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.lines().find(|l| !l.trim().is_empty())?;
    let cols: Vec<&str> = line.split('\t').collect();
    let id = normalize_image_id(cols.first().copied().unwrap_or(""));
    if id.is_empty() {
        return None;
    }
    let spec_hash = clean_template_val(cols.get(1));
    let spec_source = clean_template_val(cols.get(2));
    Some(ImageState {
        id,
        spec_hash,
        spec_source,
    })
}

fn dedup_preserve_order(items: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for item in items {
        if seen.insert(item.clone()) {
            out.push(item.clone());
        }
    }
    out
}

fn validate_preset_combination(presets: &[Preset]) -> Result<(), String> {
    if presets.len() > 1 && presets.contains(&Preset::Alpine) {
        return Err(
            "Cannot combine `alpine` (musl/apk) with Debian or Fedora presets.".to_string(),
        );
    }
    if presets.len() > 1 && presets.contains(&Preset::Llama) {
        return Err(
            "Cannot combine `llama` (Fedora/dnf base for host glibc compatibility) with Debian/Alpine presets."
                .to_string(),
        );
    }
    Ok(())
}

fn append_spec_labels(
    body: &str,
    spec_hash: &str,
    spec_name: &str,
    source_label: &str,
) -> String {
    let mut out = body.to_string();
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&format!(
        "LABEL box.spec.hash={}\n",
        docker_env_quote(spec_hash)
    ));
    out.push_str(&format!(
        "LABEL box.spec.name={}\n",
        docker_env_quote(spec_name)
    ));
    out.push_str(&format!(
        "LABEL box.spec.source={}\n",
        docker_env_quote(source_label)
    ));
    out
}

/// Core Containerfile generator shared by both built-in presets and YAML `ImageConfig` definitions.
#[allow(clippy::too_many_arguments)]
fn build_spec_internal(
    tag_name: &str,
    env_label: &str,
    explicit_base: Option<&str>,
    presets: &[Preset],
    explicit_pkg_manager: Option<PkgManager>,
    include_defaults: bool,
    extra_packages: &[String],
    exclude_packages: &[String],
    pip_packages: &[String],
    cargo_packages: &[String],
    npm_packages: &[String],
    julia_packages: &[String],
    env_vars: &[(String, String)],
    run_steps: &[String],
    spec_file: Option<PathBuf>,
) -> Result<GeneratedImageSpec, String> {
    let mut unique_presets = presets.to_vec();
    unique_presets.sort();
    unique_presets.dedup();
    validate_preset_combination(&unique_presets)?;

    let base_preset = unique_presets
        .iter()
        .max_by_key(|p| p.base_priority())
        .copied();

    let base_image = if let Some(custom) = explicit_base {
        custom.to_string()
    } else if let Some(bp) = base_preset {
        bp.image().to_string()
    } else {
        "docker.io/library/debian:trixie-slim".to_string()
    };

    let pkg_manager = if let Some(pm) = explicit_pkg_manager {
        pm
    } else if explicit_base.is_some() {
        PkgManager::infer_from_image(&base_image)
    } else if let Some(bp) = base_preset {
        PkgManager::infer_from_preset(bp)
    } else {
        PkgManager::Apt
    };

    if explicit_base.is_some() && !unique_presets.is_empty() {
        let has_debian_preset = unique_presets
            .iter()
            .any(|p| !matches!(p, Preset::Alpine | Preset::Llama));
        if pkg_manager == PkgManager::Apk && has_debian_preset {
            return Err(
                "Cannot combine Debian presets with an Alpine/apk base image.".to_string(),
            );
        }
        if pkg_manager == PkgManager::Dnf && has_debian_preset {
            return Err(
                "Cannot combine Debian presets with a Fedora/dnf base image.".to_string(),
            );
        }
    }

    let has_latex = unique_presets.contains(&Preset::Latex);
    let has_julia = unique_presets.contains(&Preset::Julia);
    let has_bitcoin = unique_presets.contains(&Preset::Bitcoin);
    let has_k8s = unique_presets.contains(&Preset::K8s);
    let has_kali = unique_presets.contains(&Preset::Kali);
    let has_llama = unique_presets.contains(&Preset::Llama);

    let mut containerfile = format!("FROM {}\n", base_image);
    if pkg_manager == PkgManager::Apt {
        containerfile.push_str("ENV DEBIAN_FRONTEND=noninteractive\n");
    }

    let mut sys_packages: Vec<String> = Vec::new();
    let mut extra_run_steps: Vec<String> = Vec::new();

    if include_defaults {
        match pkg_manager {
            PkgManager::Apk => {
                sys_packages.extend(
                    ["ca-certificates", "curl", "iputils", "vim"]
                        .into_iter()
                        .map(String::from),
                );
            }
            PkgManager::Dnf => {
                sys_packages.extend(
                    ["ca-certificates", "curl", "iputils", "vim-enhanced"]
                        .into_iter()
                        .map(String::from),
                );
                if has_llama {
                    sys_packages.extend(
                        ["libgomp", "libstdc++", "libcurl", "jq", "python3"]
                            .into_iter()
                            .map(String::from),
                    );
                }
            }
            PkgManager::Apt => {
                sys_packages.extend(
                    ["ca-certificates", "curl", "iputils-ping", "vim"]
                        .into_iter()
                        .map(String::from),
                );
            }
        }
    }

    if pkg_manager == PkgManager::Apt {
        if include_defaults {
            if has_latex {
                sys_packages.extend(
                    ["fontconfig", "fonts-liberation", "fonts-dejavu-core"]
                        .into_iter()
                        .map(String::from),
                );
            }
            if has_kali {
                sys_packages.extend(
                    [
                        "dnsutils",
                        "git",
                        "jq",
                        "netcat-openbsd",
                        "nmap",
                        "traceroute",
                        "whois",
                    ]
                    .into_iter()
                    .map(String::from),
                );
            }
            if has_k8s {
                sys_packages.push("jq".to_string());
            }
            if has_bitcoin {
                sys_packages.extend(["gzip", "tar"].into_iter().map(String::from));
            }
        }

        // Layer secondary presets when combining or using a custom base
        let effective_base_preset = if explicit_base.is_some() {
            None
        } else {
            base_preset
        };

        for p in &unique_presets {
            if Some(*p) == effective_base_preset {
                continue;
            }
            match p {
                Preset::Python => {
                    sys_packages.extend(
                        ["python3", "python3-pip", "python3-venv", "python-is-python3"]
                            .into_iter()
                            .map(String::from),
                    );
                }
                Preset::Node => {
                    sys_packages.extend(["nodejs", "npm"].into_iter().map(String::from));
                }
                Preset::Rust => {
                    sys_packages.extend(
                        ["build-essential", "pkg-config", "libssl-dev"]
                            .into_iter()
                            .map(String::from),
                    );
                    extra_run_steps.push(
                        "ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo PATH=/usr/local/cargo/bin:$PATH\n\
                         RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --no-modify-path && chmod -R a+rX /usr/local/rustup /usr/local/cargo"
                            .to_string(),
                    );
                }
                Preset::Latex => {
                    sys_packages.extend(
                        [
                            "texlive-latex-recommended",
                            "texlive-fonts-recommended",
                            "texlive-latex-extra",
                        ]
                        .into_iter()
                        .map(String::from),
                    );
                }
                Preset::Julia => {
                    sys_packages.push("julia".to_string());
                }
                Preset::Bitcoin | Preset::K8s | Preset::Kali => {}
                Preset::Alpine | Preset::Llama => {}
            }
        }
    }

    // Ensure pip / npm are available if user requested ecosystem packages on a base without them
    if !pip_packages.is_empty()
        && !unique_presets.contains(&Preset::Python)
        && !base_image.to_lowercase().contains("python")
    {
        match pkg_manager {
            PkgManager::Apt => {
                sys_packages.extend(["python3", "python3-pip"].into_iter().map(String::from));
            }
            PkgManager::Apk => {
                sys_packages.extend(["python3", "py3-pip"].into_iter().map(String::from));
            }
            PkgManager::Dnf => {
                sys_packages.extend(["python3", "python3-pip"].into_iter().map(String::from));
            }
        }
    }

    if !npm_packages.is_empty()
        && !unique_presets.contains(&Preset::Node)
        && !base_image.to_lowercase().contains("node")
    {
        match pkg_manager {
            PkgManager::Apt | PkgManager::Apk | PkgManager::Dnf => {
                sys_packages.extend(["nodejs", "npm"].into_iter().map(String::from));
            }
        }
    }

    // Add user-specified packages and apply exclusions
    sys_packages.extend(extra_packages.iter().cloned());
    if !exclude_packages.is_empty() {
        let excluded: HashSet<&str> = exclude_packages.iter().map(|s| s.as_str()).collect();
        sys_packages.retain(|p| !excluded.contains(p.as_str()));
    }
    sys_packages.sort_unstable();
    sys_packages.dedup();

    if !sys_packages.is_empty() {
        let pkg_list = sys_packages.join(" ");
        match pkg_manager {
            PkgManager::Apt => {
                containerfile.push_str(&format!(
                    "RUN apt-get update && apt-get install -y --no-install-recommends {} && rm -rf /var/lib/apt/lists/*\n",
                    pkg_list
                ));
            }
            PkgManager::Apk => {
                containerfile.push_str(&format!("RUN apk add --no-cache {}\n", pkg_list));
            }
            PkgManager::Dnf => {
                containerfile.push_str(&format!(
                    "RUN dnf install -y --setopt=install_weak_deps=False {} && dnf clean all\n",
                    pkg_list
                ));
            }
        }
    }

    if has_bitcoin {
        extra_run_steps.push(
            "RUN ARCH=$(uname -m) && \
             case \"$ARCH\" in x86_64|aarch64) ;; *) echo \"Unsupported arch: $ARCH\" >&2; exit 1 ;; esac && \
             VER=$(curl -fsSL https://bitcoincore.org/bin/ | grep -oE 'bitcoin-core-[0-9]+\\.[0-9]+(\\.[0-9]+)?/' | sed 's|bitcoin-core-||;s|/||' | sort -V | tail -n1) && \
             VER=${VER:-28.1} && \
             curl -fsSL \"https://bitcoincore.org/bin/bitcoin-core-${VER}/bitcoin-${VER}-${ARCH}-linux-gnu.tar.gz\" | \
             tar -xz -C /usr/local --strip-components=1 --wildcards '*/bin/*' && \
             chmod a+rx /usr/local/bin/bitcoin*"
                .to_string(),
        );
    }

    if has_k8s {
        extra_run_steps.push(
            "RUN ARCH=$(uname -m) && \
             case \"$ARCH\" in x86_64) KARCH=amd64 ;; aarch64) KARCH=arm64 ;; *) echo \"Unsupported arch: $ARCH\" >&2; exit 1 ;; esac && \
             KVER=$(curl -fsSL https://dl.k8s.io/release/stable.txt) && \
             curl -fsSL -o /usr/local/bin/kubectl \"https://dl.k8s.io/release/${KVER}/bin/linux/${KARCH}/kubectl\" && \
             chmod +x /usr/local/bin/kubectl"
                .to_string(),
        );
    }

    if has_julia {
        extra_run_steps.push(
            "RUN JULIA_DEPOT_PATH=/usr/local/share/julia JULIA_CPU_TARGET=generic julia -e 'using Pkg; Pkg.add(\"Pluto\"); using Pluto' && \
             chmod -R a+rX /usr/local/share/julia && \
             printf '#!/bin/sh\\nexec julia -e \"import Pluto; Pluto.run(host=\\\"0.0.0.0\\\", port=parse(Int, get(ENV, \\\"PLUTO_PORT\\\", \\\"8888\\\")), launch_browser=false)\"\\n' > /usr/local/bin/pluto && \
             chmod +x /usr/local/bin/pluto"
                .to_string(),
        );
    }

    if has_latex {
        extra_run_steps.push(
            "RUN fc-cache -f && if command -v luaotfload-tool >/dev/null 2>&1; then \
             SYSVAR=$(kpsewhich -var-value=TEXMFSYSVAR); \
             TEXMFVAR=\"$SYSVAR\" luaotfload-tool --update --force && \
             chmod -R a+rX \"$SYSVAR\"; fi"
                .to_string(),
        );
    }

    for step in extra_run_steps {
        containerfile.push_str(&step);
        containerfile.push('\n');
    }

    // Ecosystem packages from YAML
    let pip_dedup = dedup_preserve_order(pip_packages);
    if !pip_dedup.is_empty() {
        let quoted: Vec<String> = pip_dedup.iter().map(|p| shell_quote(p)).collect();
        let args = quoted.join(" ");
        containerfile.push_str(&format!(
            "RUN if pip3 install --help 2>&1 | grep -q -- '--break-system-packages'; then pip3 install --no-cache-dir --break-system-packages {args}; else pip3 install --no-cache-dir {args}; fi\n",
            args = args
        ));
    }

    let cargo_dedup = dedup_preserve_order(cargo_packages);
    if !cargo_dedup.is_empty() {
        let quoted: Vec<String> = cargo_dedup.iter().map(|p| shell_quote(p)).collect();
        containerfile.push_str(&format!(
            "RUN cargo install --root /usr/local {} && chmod -R a+rX /usr/local/bin\n",
            quoted.join(" ")
        ));
    }

    let npm_dedup = dedup_preserve_order(npm_packages);
    if !npm_dedup.is_empty() {
        let quoted: Vec<String> = npm_dedup.iter().map(|p| shell_quote(p)).collect();
        containerfile.push_str(&format!("RUN npm install -g {}\n", quoted.join(" ")));
    }

    let julia_dedup = dedup_preserve_order(julia_packages);
    if !julia_dedup.is_empty() {
        let quoted: Vec<String> = julia_dedup
            .iter()
            .map(|p| julia_string_literal(p))
            .collect();
        containerfile.push_str(&format!(
            "RUN JULIA_DEPOT_PATH=/usr/local/share/julia JULIA_CPU_TARGET=generic julia -e 'using Pkg; Pkg.add([{}])' && chmod -R a+rX /usr/local/share/julia\n",
            quoted.join(", ")
        ));
    }

    for (k, v) in env_vars {
        containerfile.push_str(&format!("ENV {}={}\n", k, docker_env_quote(v)));
    }

    for cmd in run_steps {
        containerfile.push_str(&format!("RUN {}\n", cmd));
    }

    let spec_hash = sha256_hex(containerfile.as_bytes());
    let source_label = spec_file
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| format!("builtin:{}", env_label));
    let full_containerfile = append_spec_labels(&containerfile, &spec_hash, tag_name, &source_label);

    let has_bash = pkg_manager != PkgManager::Apk || sys_packages.iter().any(|p| p == "bash");

    Ok(GeneratedImageSpec {
        tag: format!("localhost/box-env:{}", tag_name),
        env_label: env_label.to_string(),
        base_image,
        presets: unique_presets,
        pkg_manager,
        containerfile: full_containerfile,
        spec_hash,
        spec_file,
        has_bash,
    })
}

pub fn generate_spec_from_config(cfg: &ImageConfig) -> Result<GeneratedImageSpec, String> {
    let presets = cfg.effective_presets();
    build_spec_internal(
        &cfg.name,
        &cfg.name,
        cfg.base.as_deref(),
        &presets,
        cfg.pkg_manager,
        cfg.include_defaults,
        &cfg.packages,
        &cfg.exclude_packages,
        &cfg.pip,
        &cfg.cargo,
        &cfg.npm,
        &cfg.julia,
        &cfg.env,
        &cfg.run,
        Some(cfg.source_path.clone()),
    )
}

pub fn generate_spec_for_presets(presets: &[Preset]) -> Result<GeneratedImageSpec, String> {
    let mut unique = presets.to_vec();
    unique.sort();
    unique.dedup();
    if unique.is_empty() {
        unique.push(Preset::Rust);
    }

    let tag_name = unique
        .iter()
        .map(|p| p.as_str())
        .collect::<Vec<_>>()
        .join("-");
    let env_label = unique
        .iter()
        .map(|p| p.as_str())
        .collect::<Vec<_>>()
        .join("+");

    build_spec_internal(
        &tag_name,
        &env_label,
        None,
        &unique,
        None,
        true,
        &[],
        &[],
        &[],
        &[],
        &[],
        &[],
        &[],
        &[],
        None,
    )
}

pub fn check_spec_sync_status(
    bin: &str,
    use_sudo: bool,
    spec: &GeneratedImageSpec,
) -> (ImageSyncStatus, Option<ImageState>) {
    let Some(state) = inspect_image_state(bin, use_sudo, &spec.tag) else {
        return (ImageSyncStatus::NotBuilt, None);
    };
    let matches = match state.spec_hash.as_deref() {
        Some(existing_hash) => existing_hash == spec.spec_hash,
        // For YAML-backed configs, an unlabeled image must be rebuilt so the custom packages are installed.
        // For built-in presets with no YAML, keep legacy pre-hash images without forcing an offline rebuild.
        None => spec.spec_file.is_none(),
    };
    if matches {
        (ImageSyncStatus::UpToDate, Some(state))
    } else {
        (ImageSyncStatus::NeedsRebuild, Some(state))
    }
}

pub fn ensure_image_built(cli: &Cli, spec: &GeneratedImageSpec) -> ResolvedImage {
    let bin = cli.runtime.container_bin();
    let (status, existing_state) = check_spec_sync_status(bin, cli.sudo, spec);

    if !cli.rebuild && status == ImageSyncStatus::UpToDate {
        return ResolvedImage {
            tag: spec.tag.clone(),
            env_label: spec.env_label.clone(),
            presets: spec.presets.clone(),
            pkg_manager: spec.pkg_manager,
            spec_hash: spec.spec_hash.clone(),
            spec_file: spec.spec_file.clone(),
            has_bash: spec.has_bash,
            rebuilt: false,
            image_id: existing_state.map(|s| s.id),
        };
    }

    match (&spec.spec_file, status, cli.rebuild) {
        (Some(path), ImageSyncStatus::NeedsRebuild, false) => {
            println!(
                "[box] Package config changed ({}) — automatically rebuilding '{}' (base: {})...",
                path.display(),
                spec.tag,
                spec.base_image
            );
        }
        (Some(path), _, true) => {
            println!(
                "[box] Rebuilding '{}' from {} (base: {})...",
                spec.tag,
                path.display(),
                spec.base_image
            );
        }
        (Some(path), ImageSyncStatus::NotBuilt, false) => {
            println!(
                "[box] Building '{}' from {} (base: {})...",
                spec.tag,
                path.display(),
                spec.base_image
            );
        }
        (None, ImageSyncStatus::NeedsRebuild, false) => {
            println!(
                "[box] Image spec changed — automatically rebuilding '{}' (base: {})...",
                spec.tag, spec.base_image
            );
        }
        _ => {
            println!(
                "[box] Building environment image '{}' (base: {}, includes curl/ping/vim)...",
                spec.tag, spec.base_image
            );
        }
    }

    let mut build_cmd = container_cmd(bin, cli.sudo);
    build_cmd
        .args(["build", "-t", &spec.tag, "-"])
        .stdin(Stdio::piped());

    let mut child = build_cmd.spawn().unwrap_or_else(|e| {
        eprintln!("Failed to start {} build: {}", bin, e);
        process::exit(1);
    });

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(spec.containerfile.as_bytes())
            .unwrap_or_else(|e| {
                eprintln!("Failed to pipe Containerfile to {} build: {}", bin, e);
                process::exit(1);
            });
    }

    let exit = child.wait().unwrap_or_else(|e| {
        eprintln!("Failed waiting for {} build: {}", bin, e);
        process::exit(1);
    });

    if !exit.success() {
        eprintln!("ERROR: Failed to build image '{}'.", spec.tag);
        process::exit(1);
    }

    let new_id = inspect_image_state(bin, cli.sudo, &spec.tag).map(|s| s.id);
    ResolvedImage {
        tag: spec.tag.clone(),
        env_label: spec.env_label.clone(),
        presets: spec.presets.clone(),
        pkg_manager: spec.pkg_manager,
        spec_hash: spec.spec_hash.clone(),
        spec_file: spec.spec_file.clone(),
        has_bash: spec.has_bash,
        rebuilt: true,
        image_id: new_id,
    }
}

pub fn build_image_from_config(cli: &Cli, cfg: &ImageConfig) -> ResolvedImage {
    let spec = generate_spec_from_config(cfg).unwrap_or_else(|e| {
        eprintln!("ERROR in {}: {}", cfg.source_path.display(), e);
        process::exit(1);
    });
    ensure_image_built(cli, &spec)
}

/// Build or reuse a preset (or combined multi-preset) image.
/// Automatically loads matching `<preset>.yaml` (or combined `<p1>-<p2>.yaml` / merged per-preset YAMLs)
/// from `~/.config/box/images/` (or `--images-dir`) and rebuilds whenever package lists change.
pub fn build_combined_image(cli: &Cli, presets: &[Preset]) -> ResolvedImage {
    let mut unique = presets.to_vec();
    unique.sort();
    unique.dedup();
    if unique.is_empty() {
        unique.push(Preset::Rust);
    }

    let tag_name = unique
        .iter()
        .map(|p| p.as_str())
        .collect::<Vec<_>>()
        .join("-");
    let env_label = unique
        .iter()
        .map(|p| p.as_str())
        .collect::<Vec<_>>()
        .join("+");

    // 1. Check for an exact YAML config matching this preset or combination (e.g. rust.yaml or latex-python.yaml)
    match find_image_config(&tag_name, cli.images_dir.as_deref()) {
        Ok(Some(mut cfg)) => {
            if cfg.presets.is_empty() && cfg.base.is_none() {
                cfg.presets = unique.clone();
            }
            return build_image_from_config(cli, &cfg);
        }
        Err(e) => {
            eprintln!("ERROR: {}", e);
            process::exit(1);
        }
        Ok(None) => {}
    }

    // 2. For combined presets (e.g. latex+python), merge any individual per-preset YAMLs if present
    if unique.len() > 1 {
        let mut merged_packages = Vec::new();
        let mut merged_excludes = Vec::new();
        let mut merged_pip = Vec::new();
        let mut merged_cargo = Vec::new();
        let mut merged_npm = Vec::new();
        let mut merged_julia = Vec::new();
        let mut merged_env = Vec::new();
        let mut merged_run = Vec::new();
        let mut include_defaults = true;
        let mut matched_paths = Vec::new();

        for p in &unique {
            match find_image_config(p.as_str(), cli.images_dir.as_deref()) {
                Ok(Some(c)) => {
                    matched_paths.push(c.source_path.clone());
                    include_defaults &= c.include_defaults;
                    merged_packages.extend(c.packages);
                    merged_excludes.extend(c.exclude_packages);
                    merged_pip.extend(c.pip);
                    merged_cargo.extend(c.cargo);
                    merged_npm.extend(c.npm);
                    merged_julia.extend(c.julia);
                    merged_env.extend(c.env);
                    merged_run.extend(c.run);
                }
                Err(e) => {
                    eprintln!("ERROR: {}", e);
                    process::exit(1);
                }
                Ok(None) => {}
            }
        }

        if !matched_paths.is_empty() {
            let spec = build_spec_internal(
                &tag_name,
                &env_label,
                None,
                &unique,
                None,
                include_defaults,
                &merged_packages,
                &merged_excludes,
                &merged_pip,
                &merged_cargo,
                &merged_npm,
                &merged_julia,
                &merged_env,
                &merged_run,
                Some(matched_paths[0].clone()),
            )
            .unwrap_or_else(|e| {
                eprintln!("ERROR: {}", e);
                process::exit(1);
            });
            return ensure_image_built(cli, &spec);
        }
    }

    // 3. Fall back to standard built-in preset spec
    let spec = generate_spec_for_presets(&unique).unwrap_or_else(|e| {
        eprintln!("ERROR: {}", e);
        process::exit(1);
    });
    ensure_image_built(cli, &spec)
}

pub fn list_configured_images(cli: &Cli) {
    let dir = resolve_images_dir(cli.images_dir.as_deref());
    let discovered = discover_image_configs(cli.images_dir.as_deref());

    println!("================================================================================");
    println!("  CUSTOM IMAGE DEFINITIONS ({})", dir.display());
    println!("================================================================================");

    if discovered.is_empty() {
        println!("  No *.yaml image definitions found yet.");
        println!();
        println!("  Create one with:");
        println!("    box --init-image rust");
        println!(
            "  Or save a file at {}/<name>.yaml, for example:",
            dir.display()
        );
        println!("    preset: rust");
        println!("    packages:");
        println!("      - git");
        println!("      - ripgrep");
        println!("      - fd-find");
        println!();
        println!("  Then run `box --attach <name>` or `box --sync` to build/rebuild automatically.");
        return;
    }

    let bin = cli.runtime.container_bin();
    println!(
        "  {:<16} {:<16} {:<22} {:<16} {}",
        "VM / IMAGE", "STATUS", "PACKAGES", "BASE / PRESET", "FILE"
    );
    println!("--------------------------------------------------------------------------------");

    let mut rebuild_needed = 0usize;
    for (path, parsed) in discovered {
        match parsed {
            Ok(cfg) => match generate_spec_from_config(&cfg) {
                Ok(spec) => {
                    let (status, _) = check_spec_sync_status(bin, cli.sudo, &spec);
                    if status != ImageSyncStatus::UpToDate {
                        rebuild_needed += 1;
                    }
                    let base_desc = if let Some(ref b) = cfg.base {
                        b.rsplit('/').next().unwrap_or(b).to_string()
                    } else if !spec.presets.is_empty() {
                        spec.presets
                            .iter()
                            .map(|p| p.as_str())
                            .collect::<Vec<_>>()
                            .join("+")
                    } else {
                        "debian:trixie-slim".to_string()
                    };
                    println!(
                        "  {:<16} {:<16} {:<22} {:<16} {}",
                        cfg.name,
                        status.label(),
                        cfg.package_summary(),
                        base_desc,
                        path.display()
                    );
                }
                Err(e) => {
                    println!(
                        "  {:<16} {:<16} {:<22} {:<16} {} ({})",
                        cfg.name,
                        "INVALID",
                        "-",
                        "-",
                        path.display(),
                        e
                    );
                }
            },
            Err(e) => {
                let stem = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("?");
                println!(
                    "  {:<16} {:<16} {:<22} {:<16} {} ({})",
                    stem,
                    "PARSE ERROR",
                    "-",
                    "-",
                    path.display(),
                    e
                );
            }
        }
    }

    println!("--------------------------------------------------------------------------------");
    if rebuild_needed > 0 {
        println!(
            "  {} image(s) pending build/rebuild. Run `box --sync` or `box --attach <name>` to apply.",
            rebuild_needed
        );
    } else {
        println!("  All image definitions are up-to-date.");
    }
}

pub fn sync_configured_images(cli: &Cli, filter_name: Option<&str>) {
    // Direct --config <FILE> sync
    if let Some(ref cfg_path) = cli.config {
        let cfg = load_image_config_from_path(cfg_path, cli.name.as_deref()).unwrap_or_else(|e| {
            eprintln!("ERROR: {}", e);
            process::exit(1);
        });
        let res = build_image_from_config(cli, &cfg);
        if res.rebuilt {
            println!(
                "[box] Synced '{}' -> {} (hash: {}).",
                cfg.name,
                res.tag,
                &res.spec_hash[..12]
            );
            println!(
                "      If a stopped box named '{}' exists, it will automatically recreate on next `box --attach {}`.",
                cfg.name, cfg.name
            );
        } else {
            println!(
                "[box] '{}' is already up-to-date ({}, hash: {}).",
                cfg.name,
                res.tag,
                &res.spec_hash[..12]
            );
        }
        return;
    }

    // Specific named image sync (`box --sync rust`)
    if let Some(target) = filter_name.filter(|s| !s.trim().is_empty()) {
        let cfg = match find_image_config(target, cli.images_dir.as_deref()) {
            Ok(Some(c)) => c,
            Ok(None) => {
                let dir = resolve_images_dir(cli.images_dir.as_deref());
                eprintln!(
                    "ERROR: No image config file found for '{}' in {}.",
                    target,
                    dir.display()
                );
                eprintln!(
                    "Create one with: box --init-image {}",
                    target
                );
                process::exit(1);
            }
            Err(e) => {
                eprintln!("ERROR: {}", e);
                process::exit(1);
            }
        };
        let res = build_image_from_config(cli, &cfg);
        if res.rebuilt {
            println!(
                "[box] Synced '{}' -> {} (hash: {}).",
                cfg.name,
                res.tag,
                &res.spec_hash[..12]
            );
            println!(
                "      If a stopped box named '{}' exists, it will automatically recreate on next `box --attach {}`.",
                cfg.name, cfg.name
            );
        } else {
            println!(
                "[box] '{}' is already up-to-date ({}, hash: {}).",
                cfg.name,
                res.tag,
                &res.spec_hash[..12]
            );
        }
        return;
    }

    // Sync all discovered YAML files (`box --sync`)
    let dir = resolve_images_dir(cli.images_dir.as_deref());
    let discovered = discover_image_configs(cli.images_dir.as_deref());
    if discovered.is_empty() {
        println!(
            "No *.yaml image definitions found in {}.",
            dir.display()
        );
        println!("Create one with: box --init-image rust");
        return;
    }

    let mut rebuilt_count = 0usize;
    let mut up_to_date_count = 0usize;
    let mut error_count = 0usize;

    for (path, parsed) in discovered {
        match parsed {
            Ok(cfg) => {
                let res = build_image_from_config(cli, &cfg);
                if res.rebuilt {
                    rebuilt_count += 1;
                    println!(
                        "[box] Rebuilt '{}' -> {} (hash: {})",
                        cfg.name,
                        res.tag,
                        &res.spec_hash[..12]
                    );
                } else {
                    up_to_date_count += 1;
                    println!(
                        "[box] Up-to-date '{}' ({}, hash: {})",
                        cfg.name,
                        res.tag,
                        &res.spec_hash[..12]
                    );
                }
            }
            Err(e) => {
                error_count += 1;
                eprintln!("[box] ERROR parsing {}: {}", path.display(), e);
            }
        }
    }

    println!(
        "[box] Sync complete: {} rebuilt, {} already up-to-date, {} error(s).",
        rebuilt_count, up_to_date_count, error_count
    );
    if rebuilt_count > 0 {
        println!(
            "      Any existing stopped boxes using rebuilt images will automatically recreate on next `box --attach <name>`."
        );
    }
    if error_count > 0 {
        process::exit(1);
    }
}

pub fn init_image_config(cli: &Cli, raw_name: &str) {
    let name = normalize_image_name(raw_name).unwrap_or_else(|e| {
        eprintln!("ERROR: {}", e);
        process::exit(1);
    });
    let dir = resolve_images_dir(cli.images_dir.as_deref());
    let target_path = dir.join(format!("{}.yaml", name));

    if target_path.exists() && !cli.rebuild {
        eprintln!(
            "ERROR: Image config already exists at {}",
            target_path.display()
        );
        eprintln!("Edit it directly, or pass `--rebuild` to overwrite with a fresh template.");
        process::exit(1);
    }

    if let Err(e) = fs::create_dir_all(&dir) {
        eprintln!("ERROR: Failed to create {}: {}", dir.display(), e);
        process::exit(1);
    }

    let content = generate_starter_yaml(&name, &cli.preset, cli.image.as_deref());
    if let Err(e) = fs::write(&target_path, content) {
        eprintln!("ERROR: Failed to write {}: {}", target_path.display(), e);
        process::exit(1);
    }

    println!("Created image config: {}", target_path.display());
    println!("Next steps:");
    println!("  1. Edit {} and list the packages you want installed.", target_path.display());
    println!("  2. Run `box --attach {}` (auto-builds & launches VM '{}', and auto-rebuilds whenever the file changes).", name, name);
    println!("  3. Or pre-build without launching: `box --sync {}`", name);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_config::parse_image_config;
    use std::path::Path;

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
        let rust_spec = generate_spec_for_presets(&[Preset::Rust]).unwrap();
        assert!(rust_spec.containerfile.contains("curl"));
        assert!(rust_spec.containerfile.contains("iputils-ping"));
        assert!(rust_spec.containerfile.contains("vim"));
        assert!(rust_spec.containerfile.contains("LABEL box.spec.hash="));
        assert!(rust_spec.has_bash);

        let alpine_spec = generate_spec_for_presets(&[Preset::Alpine]).unwrap();
        assert!(alpine_spec.containerfile.contains("apk add --no-cache"));
        assert!(alpine_spec.containerfile.contains("curl"));
        assert!(alpine_spec.containerfile.contains("iputils"));
        assert!(alpine_spec.containerfile.contains("vim"));
        assert!(!alpine_spec.has_bash);
    }

    #[test]
    fn latex_containerfile_installs_liberation_fonts_and_prebuilds_luaotfload_db() {
        let spec = generate_spec_for_presets(&[Preset::Latex, Preset::Python]).unwrap();
        let cf = &spec.containerfile;
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
        let julia_cf = generate_spec_for_presets(&[Preset::Julia])
            .unwrap()
            .containerfile;
        assert!(julia_cf.contains("FROM docker.io/library/julia:latest"));
        assert!(julia_cf.contains("Pluto"));
        assert!(julia_cf.contains("/usr/local/bin/pluto"));
        assert!(julia_cf.contains("curl"));
        assert!(julia_cf.contains("iputils-ping"));
        assert!(julia_cf.contains("vim"));

        let btc_cf = generate_spec_for_presets(&[Preset::Bitcoin])
            .unwrap()
            .containerfile;
        assert!(btc_cf.contains("bitcoincore.org/bin/"));
        assert!(btc_cf.contains("chmod a+rx /usr/local/bin/bitcoin*"));

        let k8s_cf = generate_spec_for_presets(&[Preset::K8s])
            .unwrap()
            .containerfile;
        assert!(k8s_cf.contains("dl.k8s.io/release"));
        assert!(k8s_cf.contains("/usr/local/bin/kubectl"));

        let kali_cf = generate_spec_for_presets(&[Preset::Kali])
            .unwrap()
            .containerfile;
        assert!(kali_cf.contains("FROM docker.io/kalilinux/kali-rolling"));
        assert!(kali_cf.contains("nmap"));
        assert!(kali_cf.contains("vim"));

        let llama_cf = generate_spec_for_presets(&[Preset::Llama])
            .unwrap()
            .containerfile;
        assert!(llama_cf.contains("FROM docker.io/library/fedora:latest"));
        assert!(llama_cf.contains("dnf install"));
        assert!(llama_cf.contains("libgomp"));
        assert!(llama_cf.contains("vim-enhanced"));
    }

    #[test]
    fn yaml_config_customizes_packages_and_changes_spec_hash() {
        let yaml_v1 = r#"
packages:
  - ripgrep
  - git
cargo:
  - bacon
"#;
        let yaml_v2 = r#"
packages:
  - ripgrep
  - git
  - fd-find
cargo:
  - bacon
"#;
        let cfg1 = parse_image_config("rust", Path::new("/cfg/rust.yaml"), yaml_v1).unwrap();
        let cfg2 = parse_image_config("rust", Path::new("/cfg/rust.yaml"), yaml_v2).unwrap();

        let spec1 = generate_spec_from_config(&cfg1).unwrap();
        let spec2 = generate_spec_from_config(&cfg2).unwrap();

        assert_eq!(spec1.tag, "localhost/box-env:rust");
        assert!(spec1.containerfile.contains("FROM docker.io/library/rust:slim"));
        assert!(spec1.containerfile.contains("ripgrep"));
        assert!(spec1.containerfile.contains("git"));
        assert!(spec1.containerfile.contains("cargo install --root /usr/local bacon"));
        assert!(!spec1.containerfile.contains("fd-find"));

        assert!(spec2.containerfile.contains("fd-find"));
        assert_ne!(
            spec1.spec_hash, spec2.spec_hash,
            "Adding a package must change the spec hash so rebuild triggers automatically"
        );
    }

    #[test]
    fn yaml_config_supports_strict_packages_and_exclusions() {
        let yaml = r#"
base: docker.io/library/alpine:latest
include_defaults: false
packages:
  - bash
  - git
  - jq
"#;
        let cfg = parse_image_config("tiny", Path::new("/cfg/tiny.yaml"), yaml).unwrap();
        let spec = generate_spec_from_config(&cfg).unwrap();
        assert_eq!(spec.tag, "localhost/box-env:tiny");
        assert_eq!(spec.pkg_manager, PkgManager::Apk);
        assert!(spec.has_bash);
        assert!(spec.containerfile.contains("RUN apk add --no-cache bash git jq"));
        assert!(!spec.containerfile.contains("vim"));
    }

    #[test]
    fn yaml_config_reordering_system_packages_keeps_same_hash() {
        let a = parse_image_config("rust", Path::new("/a/rust.yaml"), "packages: [git, ripgrep]\n")
            .unwrap();
        let b = parse_image_config(
            "rust",
            Path::new("/b/rust.yaml"),
            "# comment\npackages:\n  - ripgrep\n  - git\n",
        )
        .unwrap();
        let sa = generate_spec_from_config(&a).unwrap();
        let sb = generate_spec_from_config(&b).unwrap();
        assert_eq!(sa.spec_hash, sb.spec_hash);
    }

    #[test]
    fn yaml_config_installs_pip_npm_julia_and_env_safely() {
        let yaml = r#"
preset: python
packages:
  - git
exclude_packages:
  - vim
pip:
  - "numpy>=1.26"
  - matplotlib
npm:
  - "@types/node"
env:
  PYTHONUNBUFFERED: "1"
run:
  - echo custom-step
"#;
        let cfg = parse_image_config("datasci", Path::new("/cfg/datasci.yaml"), yaml).unwrap();
        let spec = generate_spec_from_config(&cfg).unwrap();
        assert_eq!(spec.tag, "localhost/box-env:datasci");
        assert!(spec.containerfile.contains("FROM docker.io/library/python:3-slim"));
        assert!(spec.containerfile.contains("git"));
        assert!(spec.containerfile.contains("nodejs"));
        assert!(spec.containerfile.contains("npm"));
        assert!(!spec.containerfile.contains(" vim"));
        assert!(spec.containerfile.contains("'numpy>=1.26'"));
        assert!(spec.containerfile.contains("matplotlib"));
        assert!(spec.containerfile.contains("npm install -g @types/node"));
        assert!(spec.containerfile.contains("ENV PYTHONUNBUFFERED=\"1\""));
        assert!(spec.containerfile.contains("RUN echo custom-step"));
        assert!(spec.containerfile.contains("LABEL box.spec.hash="));
    }

    #[test]
    fn yaml_config_rejects_incompatible_presets_with_base() {
        let yaml = "base: docker.io/library/alpine:latest\npreset: rust\n";
        let cfg = parse_image_config("bad", Path::new("/cfg/bad.yaml"), yaml).unwrap();
        assert!(generate_spec_from_config(&cfg).is_err());
    }
}
