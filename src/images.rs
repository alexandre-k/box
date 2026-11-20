use std::io::Write;
use std::process::{self, Stdio};

use crate::cli::{Cli, Preset};
use crate::runtime::container_cmd;

pub fn infer_env_from_image(image: &str) -> String {
    let lower = image.to_lowercase();
    if lower.contains("rust") {
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
            "latex" => Some(Preset::Latex),
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
    let mut containerfile = format!(
        "FROM {}\nENV DEBIAN_FRONTEND=noninteractive\n",
        base_preset.image()
    );

    let mut apt_packages: Vec<&str> = Vec::new();
    let mut extra_run_steps: Vec<&str> = Vec::new();
    let has_latex = presets.contains(&Preset::Latex);

    if has_latex {
        // Provide standard system fonts (LiberationSerif/Sans/Mono, DejaVu) and fontconfig
        // so XeLaTeX/LuaLaTeX documents using system fonts compile cleanly.
        apt_packages.extend(["fontconfig", "fonts-liberation", "fonts-dejavu-core"]);
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
                apt_packages.extend(["curl", "build-essential", "pkg-config", "libssl-dev"]);
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
            Preset::Alpine => unreachable!(),
        }
    }

    if !apt_packages.is_empty() {
        apt_packages.sort_unstable();
        apt_packages.dedup();
        containerfile.push_str(&format!(
            "RUN apt-get update && apt-get install -y --no-install-recommends {} && rm -rf /var/lib/apt/lists/*\n",
            apt_packages.join(" ")
        ));
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

    // Single non-LaTeX presets use upstream images directly; LaTeX builds a local cached image
    // with system fonts (Liberation/DejaVu) and a prebuilt luaotfload font database.
    if unique.len() == 1 && unique[0] != Preset::Latex {
        return (unique[0].image().to_string(), env_label);
    }

    if unique.contains(&Preset::Alpine) {
        eprintln!(
            "ERROR: Cannot combine `alpine` (musl/apk) with Debian-based presets (python, rust, node, latex)."
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
        "[box] Building environment image '{}' (base: {})...",
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
    fn latex_containerfile_installs_liberation_fonts_and_prebuilds_luaotfload_db() {
        let cf = generate_containerfile(Preset::Latex, &[Preset::Latex, Preset::Python]);
        assert!(cf.contains("fonts-liberation"));
        assert!(cf.contains("fontconfig"));
        assert!(cf.contains("luaotfload-tool --update --force"));
        assert!(cf.contains("python3"));
    }

    #[test]
    fn parses_presets_from_env_label() {
        assert_eq!(
            parse_presets_from_env_label("latex+python"),
            vec![Preset::Latex, Preset::Python]
        );
    }
}
