use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use crate::cli::Preset;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkgManager {
    Apt,
    Apk,
    Dnf,
}

impl PkgManager {
    pub fn as_str(&self) -> &'static str {
        match self {
            PkgManager::Apt => "apt",
            PkgManager::Apk => "apk",
            PkgManager::Dnf => "dnf",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "apt" | "apt-get" | "dpkg" => Some(PkgManager::Apt),
            "apk" => Some(PkgManager::Apk),
            "dnf" | "yum" | "microdnf" | "rpm" => Some(PkgManager::Dnf),
            _ => None,
        }
    }

    pub fn infer_from_image(image: &str) -> Self {
        let lower = image.to_lowercase();
        if lower.contains("alpine") {
            PkgManager::Apk
        } else if lower.contains("fedora")
            || lower.contains("centos")
            || lower.contains("rockylinux")
            || lower.contains("almalinux")
            || lower.contains("/ubi")
            || lower.contains(":ubi")
        {
            PkgManager::Dnf
        } else {
            PkgManager::Apt
        }
    }

    pub fn infer_from_preset(preset: Preset) -> Self {
        match preset {
            Preset::Alpine => PkgManager::Apk,
            Preset::Llama => PkgManager::Dnf,
            _ => PkgManager::Apt,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageConfig {
    /// Logical image/VM name derived from the YAML filename stem (e.g. "rust" from "rust.yaml")
    pub name: String,
    /// Path to the YAML file on disk
    pub source_path: PathBuf,
    /// Optional explicit base OCI image (`base:` / `from:` / `image:`)
    pub base: Option<String>,
    /// Optional preset(s) (`preset:` / `presets:`)
    pub presets: Vec<Preset>,
    /// Optional explicit package manager override (`pkg_manager:` / `package_manager:`)
    pub pkg_manager: Option<PkgManager>,
    /// Whether to include default preset/base packages (defaults to true)
    pub include_defaults: bool,
    /// System packages (`packages:` / `apt:` / `apk:` / `dnf:` / `system_packages:`)
    pub packages: Vec<String>,
    /// Packages to exclude from defaults (`exclude:` / `exclude_packages:` / `remove:`)
    pub exclude_packages: Vec<String>,
    /// Python packages (`pip:` / `pip_packages:` / `python_packages:`)
    pub pip: Vec<String>,
    /// Rust cargo crates (`cargo:` / `cargo_packages:` / `crates:`)
    pub cargo: Vec<String>,
    /// Global npm packages (`npm:` / `npm_packages:`)
    pub npm: Vec<String>,
    /// Julia packages (`julia:` / `julia_packages:`)
    pub julia: Vec<String>,
    /// Environment variables baked into the image (`env:`)
    pub env: Vec<(String, String)>,
    /// Custom shell RUN commands (`run:` / `commands:`)
    pub run: Vec<String>,
}

impl ImageConfig {
    pub fn package_summary(&self) -> String {
        let mut parts = Vec::new();
        if !self.packages.is_empty() {
            parts.push(format!("sys:{}", self.packages.len()));
        }
        if !self.pip.is_empty() {
            parts.push(format!("pip:{}", self.pip.len()));
        }
        if !self.cargo.is_empty() {
            parts.push(format!("cargo:{}", self.cargo.len()));
        }
        if !self.npm.is_empty() {
            parts.push(format!("npm:{}", self.npm.len()));
        }
        if !self.julia.is_empty() {
            parts.push(format!("julia:{}", self.julia.len()));
        }
        if !self.run.is_empty() {
            parts.push(format!("run:{}", self.run.len()));
        }
        if parts.is_empty() {
            "defaults only".to_string()
        } else {
            parts.join(", ")
        }
    }

    /// Resolve the effective presets for this config (explicit `preset`/`presets`,
    /// or inferred from the filename when neither `base` nor `preset` was set).
    pub fn effective_presets(&self) -> Vec<Preset> {
        if !self.presets.is_empty() {
            return self.presets.clone();
        }
        if self.base.is_none() {
            return infer_presets_from_name(&self.name);
        }
        Vec::new()
    }
}

pub fn box_config_dir() -> PathBuf {
    let base = env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            PathBuf::from(home).join(".config")
        });
    base.join("box")
}

pub fn default_images_dir() -> PathBuf {
    box_config_dir().join("images")
}

pub fn resolve_images_dir(override_dir: Option<&Path>) -> PathBuf {
    match override_dir {
        Some(dir) => dir.to_path_buf(),
        None => default_images_dir(),
    }
}

pub fn normalize_image_name(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim().to_lowercase();
    if trimmed.is_empty() || trimmed.len() > 128 {
        return Err(format!("Invalid image/VM name '{}'", raw));
    }
    let bytes = trimmed.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() {
        return Err(format!(
            "Invalid image/VM name '{}': must start with an ASCII letter or digit",
            raw
        ));
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(format!(
            "Invalid image/VM name '{}': only letters, digits, '-', '_', and '.' are allowed",
            raw
        ));
    }
    Ok(trimmed)
}

pub fn parse_single_preset(s: &str) -> Option<Preset> {
    match s.trim().to_lowercase().as_str() {
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
    }
}

/// Infer preset(s) from a filename stem such as `rust`, `python`, `latex-python`, or `latex+python`.
/// Only succeeds if EVERY segment is a known built-in preset (so `my-rust` returns empty, not `[Rust]`).
pub fn infer_presets_from_name(name: &str) -> Vec<Preset> {
    let parts: Vec<&str> = name
        .split(['+', '-', ','])
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    if parts.is_empty() {
        return Vec::new();
    }
    let mut presets = Vec::with_capacity(parts.len());
    for part in parts {
        match parse_single_preset(part) {
            Some(p) => presets.push(p),
            None => return Vec::new(),
        }
    }
    presets.sort();
    presets.dedup();
    presets
}

fn search_dirs(override_dir: Option<&Path>) -> Vec<PathBuf> {
    if let Some(dir) = override_dir {
        vec![dir.to_path_buf()]
    } else {
        vec![default_images_dir(), box_config_dir()]
    }
}

/// Locate a `<name>.yaml` or `<name>.yml` file in the trusted images config directory
/// (falling back to `~/.config/box/` when using the default directory).
pub fn find_image_config_path(name: &str, override_dir: Option<&Path>) -> Option<PathBuf> {
    let clean = name.trim();
    if clean.is_empty() || clean.contains('/') || clean.contains('\\') || clean.contains("..") {
        return None;
    }

    let mut candidates = vec![clean.to_string()];
    let lower = clean.to_lowercase();
    if lower != clean {
        candidates.push(lower.clone());
    }
    // Also map `latex+python` -> `latex-python`
    if lower.contains('+') {
        candidates.push(lower.replace('+', "-"));
    }

    for dir in search_dirs(override_dir) {
        for cand in &candidates {
            for ext in ["yaml", "yml"] {
                let p = dir.join(format!("{}.{}", cand, ext));
                if p.is_file() {
                    return Some(p);
                }
            }
        }
    }
    None
}

pub fn find_image_config(
    name: &str,
    override_dir: Option<&Path>,
) -> Result<Option<ImageConfig>, String> {
    let Some(path) = find_image_config_path(name, override_dir) else {
        return Ok(None);
    };
    load_image_config_from_path(&path, None).map(Some)
}

pub fn load_image_config_from_path(
    path: &Path,
    name_override: Option<&str>,
) -> Result<ImageConfig, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read image config '{}': {}", path.display(), e))?;
    let raw_name = match name_override {
        Some(n) => n.to_string(),
        None => path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| {
                format!(
                    "Could not infer VM/image name from filename '{}'",
                    path.display()
                )
            })?
            .to_string(),
    };
    let name = normalize_image_name(&raw_name)?;
    let abs_path = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    parse_image_config(&name, &abs_path, &content)
}

/// Discover all `*.yaml` / `*.yml` image definition files in the config directories.
/// Files in `~/.config/box/images/` take precedence over `~/.config/box/` if both define the same name.
pub fn discover_image_configs(
    override_dir: Option<&Path>,
) -> Vec<(PathBuf, Result<ImageConfig, String>)> {
    let mut results = Vec::new();
    let mut seen_names: BTreeSet<String> = BTreeSet::new();

    for dir in search_dirs(override_dir) {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        let mut files: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.is_file()
                    && matches!(
                        p.extension().and_then(|e| e.to_str()).map(|s| s.to_lowercase()).as_deref(),
                        Some("yaml") | Some("yml")
                    )
            })
            .collect();
        // Sort so `.yaml` comes before `.yml` for the same stem
        files.sort_by(|a, b| {
            let sa = a
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_lowercase();
            let sb = b
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_lowercase();
            let ea = a.extension().and_then(|s| s.to_str()).unwrap_or("");
            let eb = b.extension().and_then(|s| s.to_str()).unwrap_or("");
            sa.cmp(&sb).then_with(|| ea.cmp(eb))
        });

        for path in files {
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_lowercase();
            if stem.is_empty() || !seen_names.insert(stem) {
                continue;
            }
            let parsed = load_image_config_from_path(&path, None);
            results.push((path, parsed));
        }
    }

    results
}

pub fn validate_system_package(pkg: &str) -> Result<(), String> {
    if pkg.is_empty() || pkg.len() > 160 {
        return Err(format!("Invalid package name '{}'", pkg));
    }
    if pkg.starts_with('-') {
        return Err(format!(
            "Invalid package name '{}': must not start with '-'",
            pkg
        ));
    }
    if !pkg.bytes().all(|b| {
        b.is_ascii_alphanumeric()
            || matches!(b, b'.' | b'+' | b'-' | b'_' | b':' | b'=' | b'~' | b'@' | b'/')
    }) {
        return Err(format!(
            "Invalid package name '{}': contains unsupported or unsafe characters",
            pkg
        ));
    }
    Ok(())
}

pub fn validate_ecosystem_package(kind: &str, pkg: &str) -> Result<(), String> {
    if pkg.is_empty() || pkg.len() > 256 {
        return Err(format!("Invalid {} package spec '{}'", kind, pkg));
    }
    if pkg.starts_with('-') {
        return Err(format!(
            "Invalid {} package spec '{}': must not start with '-'",
            kind, pkg
        ));
    }
    if pkg.bytes().any(|b| b == 0 || b == b'\n' || b == b'\r') {
        return Err(format!(
            "Invalid {} package spec '{}': control characters not allowed",
            kind, pkg
        ));
    }
    Ok(())
}

pub fn validate_base_image(img: &str) -> Result<(), String> {
    if img.is_empty() || img.len() > 256 {
        return Err(format!("Invalid base image '{}'", img));
    }
    if img
        .bytes()
        .any(|b| b.is_ascii_whitespace() || b == 0 || b == b'\'' || b == b'"' || b == b'\\')
    {
        return Err(format!(
            "Invalid base image '{}': whitespace or quotes are not allowed",
            img
        ));
    }
    Ok(())
}

pub fn validate_env_key(key: &str) -> Result<(), String> {
    let bytes = key.as_bytes();
    if bytes.is_empty() {
        return Err("Environment variable name cannot be empty".to_string());
    }
    if !(bytes[0].is_ascii_alphabetic() || bytes[0] == b'_') {
        return Err(format!(
            "Invalid environment variable name '{}': must start with a letter or '_'",
            key
        ));
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'_')
    {
        return Err(format!(
            "Invalid environment variable name '{}': only ASCII letters, digits, and '_' allowed",
            key
        ));
    }
    Ok(())
}

pub fn shell_quote(s: &str) -> String {
    if !s.is_empty()
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(b, b'.' | b'+' | b'-' | b'_' | b':' | b'=' | b'/' | b'@')
        })
    {
        return s.to_string();
    }
    format!("'{}'", s.replace('\'', "'\\''"))
}

pub fn docker_env_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '$' => out.push_str("\\$"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub fn julia_string_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '$' => out.push_str("\\$"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn strip_yaml_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if in_single {
            if b == b'\'' {
                if i + 1 < bytes.len() && bytes[i + 1] == b'\'' {
                    i += 2;
                    continue;
                }
                in_single = false;
            }
        } else if in_double {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == b'"' {
                in_double = false;
            }
        } else {
            match b {
                b'\'' => in_single = true,
                b'"' => in_double = true,
                b'#' => {
                    if i == 0 || bytes[i - 1].is_ascii_whitespace() {
                        return &line[..i];
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    line
}

fn parse_yaml_scalar(raw: &str) -> Result<String, String> {
    let s = raw.trim();
    if s.is_empty() {
        return Ok(String::new());
    }
    if s.starts_with('\'') {
        if !s.ends_with('\'') || s.len() < 2 {
            return Err(format!("Unterminated single-quoted string: {}", s));
        }
        return Ok(s[1..s.len() - 1].replace("''", "'"));
    }
    if s.starts_with('"') {
        if !s.ends_with('"') || s.len() < 2 {
            return Err(format!("Unterminated double-quoted string: {}", s));
        }
        let inner = &s[1..s.len() - 1];
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                match chars.next() {
                    Some('n') => out.push('\n'),
                    Some('r') => out.push('\r'),
                    Some('t') => out.push('\t'),
                    Some('"') => out.push('"'),
                    Some('\\') => out.push('\\'),
                    Some('/') => out.push('/'),
                    Some(other) => {
                        out.push('\\');
                        out.push(other);
                    }
                    None => return Err("Trailing backslash in double-quoted string".to_string()),
                }
            } else {
                out.push(c);
            }
        }
        return Ok(out);
    }
    Ok(s.to_string())
}

fn split_flow_items(inner: &str) -> Result<Vec<String>, String> {
    let mut items = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut chars = inner.chars().peekable();

    while let Some(c) = chars.next() {
        if in_single {
            current.push(c);
            if c == '\'' {
                if chars.peek() == Some(&'\'') {
                    current.push(chars.next().unwrap());
                } else {
                    in_single = false;
                }
            }
        } else if in_double {
            current.push(c);
            if c == '\\' {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            } else if c == '"' {
                in_double = false;
            }
        } else {
            match c {
                '\'' => {
                    in_single = true;
                    current.push(c);
                }
                '"' => {
                    in_double = true;
                    current.push(c);
                }
                ',' => {
                    let trimmed = current.trim();
                    if !trimmed.is_empty() {
                        items.push(parse_yaml_scalar(trimmed)?);
                    }
                    current.clear();
                }
                _ => current.push(c),
            }
        }
    }

    if in_single || in_double {
        return Err("Unterminated quote inside inline list".to_string());
    }
    let trimmed = current.trim();
    if !trimmed.is_empty() {
        items.push(parse_yaml_scalar(trimmed)?);
    }
    Ok(items)
}

fn parse_yaml_bool(raw: &str) -> Option<bool> {
    match raw.trim().to_lowercase().as_str() {
        "true" | "yes" | "on" => Some(true),
        "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn split_key_value(line: &str) -> Option<(&str, &str)> {
    let bytes = line.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if in_single {
            if b == b'\'' {
                if i + 1 < bytes.len() && bytes[i + 1] == b'\'' {
                    i += 2;
                    continue;
                }
                in_single = false;
            }
        } else if in_double {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == b'"' {
                in_double = false;
            }
        } else {
            match b {
                b'\'' => in_single = true,
                b'"' => in_double = true,
                b':' => {
                    let at_end = i + 1 == bytes.len();
                    let next_ws = !at_end && bytes[i + 1].is_ascii_whitespace();
                    if at_end || next_ws {
                        let key = line[..i].trim();
                        let val = if at_end { "" } else { line[i + 1..].trim() };
                        return Some((key, val));
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveSection {
    None,
    Presets,
    Packages,
    ExcludePackages,
    Pip,
    Cargo,
    Npm,
    Julia,
    Env,
    Run,
}

fn push_presets(
    target: &mut Vec<Preset>,
    raw: &str,
    path: &Path,
    line_no: usize,
) -> Result<(), String> {
    for part in raw.split([',', '+']) {
        let tok = part.trim();
        if tok.is_empty() {
            continue;
        }
        let preset = parse_single_preset(tok).ok_or_else(|| {
            format!(
                "{}:{}: Unknown preset '{}' (valid presets: alpine, bitcoin, julia, k8s, kali, latex, llama, node, python, rust)",
                path.display(),
                line_no,
                tok
            )
        })?;
        if !target.contains(&preset) {
            target.push(preset);
        }
    }
    Ok(())
}

fn parse_env_entry(raw: &str, path: &Path, line_no: usize) -> Result<(String, String), String> {
    if let Some((k, v)) = split_key_value(raw) {
        let key = parse_yaml_scalar(k)
            .map_err(|e| format!("{}:{}: {}", path.display(), line_no, e))?;
        let val = parse_yaml_scalar(v)
            .map_err(|e| format!("{}:{}: {}", path.display(), line_no, e))?;
        validate_env_key(&key).map_err(|e| format!("{}:{}: {}", path.display(), line_no, e))?;
        return Ok((key, val));
    }
    if let Some((k, v)) = raw.split_once('=') {
        let key = parse_yaml_scalar(k)
            .map_err(|e| format!("{}:{}: {}", path.display(), line_no, e))?;
        let val = parse_yaml_scalar(v)
            .map_err(|e| format!("{}:{}: {}", path.display(), line_no, e))?;
        validate_env_key(&key).map_err(|e| format!("{}:{}: {}", path.display(), line_no, e))?;
        return Ok((key, val));
    }
    Err(format!(
        "{}:{}: Expected `KEY: VALUE` or `KEY=VALUE` under `env`",
        path.display(),
        line_no
    ))
}

pub fn parse_image_config(
    name: &str,
    source_path: &Path,
    content: &str,
) -> Result<ImageConfig, String> {
    let clean_name = normalize_image_name(name)?;
    let content = content.strip_prefix('\u{feff}').unwrap_or(content);

    let mut cfg = ImageConfig {
        name: clean_name,
        source_path: source_path.to_path_buf(),
        base: None,
        presets: Vec::new(),
        pkg_manager: None,
        include_defaults: true,
        packages: Vec::new(),
        exclude_packages: Vec::new(),
        pip: Vec::new(),
        cargo: Vec::new(),
        npm: Vec::new(),
        julia: Vec::new(),
        env: Vec::new(),
        run: Vec::new(),
    };

    let mut section = ActiveSection::None;
    let mut section_key_indent: usize = 0;

    for (idx, raw_line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let without_cr = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        let stripped = strip_yaml_comment(without_cr);
        let trimmed = stripped.trim();

        if trimmed.is_empty() || trimmed == "---" || trimmed == "..." {
            continue;
        }

        let indent = stripped.bytes().take_while(|b| *b == b' ' || *b == b'\t').count();

        // Bare top-level YAML list (e.g. `- ripgrep`) acts as shorthand for `packages:`
        if section == ActiveSection::None && trimmed.starts_with("- ") {
            section = ActiveSection::Packages;
            section_key_indent = 0;
        }

        // Handle list items for active block sections
        if let Some(item_raw) = trimmed
            .strip_prefix("- ")
            .or_else(|| if trimmed == "-" { Some("") } else { None })
        {
            if section == ActiveSection::None {
                return Err(format!(
                    "{}:{}: Unexpected list item outside of a list key",
                    source_path.display(),
                    line_no
                ));
            }
            let item_trimmed = item_raw.trim();
            if item_trimmed.is_empty() {
                continue;
            }
            match section {
                ActiveSection::Presets => {
                    let val = parse_yaml_scalar(item_trimmed)
                        .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                    push_presets(&mut cfg.presets, &val, source_path, line_no)?;
                }
                ActiveSection::Packages => {
                    let val = parse_yaml_scalar(item_trimmed)
                        .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                    validate_system_package(&val)
                        .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                    cfg.packages.push(val);
                }
                ActiveSection::ExcludePackages => {
                    let val = parse_yaml_scalar(item_trimmed)
                        .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                    validate_system_package(&val)
                        .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                    cfg.exclude_packages.push(val);
                }
                ActiveSection::Pip => {
                    let val = parse_yaml_scalar(item_trimmed)
                        .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                    validate_ecosystem_package("pip", &val)
                        .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                    cfg.pip.push(val);
                }
                ActiveSection::Cargo => {
                    let val = parse_yaml_scalar(item_trimmed)
                        .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                    validate_ecosystem_package("cargo", &val)
                        .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                    cfg.cargo.push(val);
                }
                ActiveSection::Npm => {
                    let val = parse_yaml_scalar(item_trimmed)
                        .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                    validate_ecosystem_package("npm", &val)
                        .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                    cfg.npm.push(val);
                }
                ActiveSection::Julia => {
                    let val = parse_yaml_scalar(item_trimmed)
                        .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                    validate_ecosystem_package("julia", &val)
                        .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                    cfg.julia.push(val);
                }
                ActiveSection::Env => {
                    let val = parse_yaml_scalar(item_trimmed)
                        .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                    let pair = parse_env_entry(&val, source_path, line_no)?;
                    cfg.env.push(pair);
                }
                ActiveSection::Run => {
                    let val = parse_yaml_scalar(item_trimmed)
                        .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                    if !val.is_empty() {
                        cfg.run.push(val);
                    }
                }
                ActiveSection::None => unreachable!(),
            }
            continue;
        }

        // Indented mapping entries under `env:`
        if section == ActiveSection::Env && indent > section_key_indent {
            let pair = parse_env_entry(trimmed, source_path, line_no)?;
            cfg.env.push(pair);
            continue;
        }

        // Top-level key: value
        let Some((raw_key, raw_val)) = split_key_value(trimmed) else {
            return Err(format!(
                "{}:{}: Expected `key: value` or `- item`, found '{}'",
                source_path.display(),
                line_no,
                trimmed
            ));
        };

        let key = parse_yaml_scalar(raw_key)
            .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?
            .to_lowercase();
        let val_trimmed = raw_val.trim();
        section = ActiveSection::None;
        section_key_indent = indent;

        match key.as_str() {
            "base" | "from" | "image" => {
                let v = parse_yaml_scalar(val_trimmed)
                    .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                if !v.is_empty() && v != "null" && v != "~" {
                    validate_base_image(&v)
                        .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                    cfg.base = Some(v);
                }
            }
            "preset" | "presets" => {
                if val_trimmed.is_empty() {
                    section = ActiveSection::Presets;
                } else if val_trimmed.starts_with('[') && val_trimmed.ends_with(']') {
                    let items = split_flow_items(&val_trimmed[1..val_trimmed.len() - 1])
                        .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                    for item in items {
                        push_presets(&mut cfg.presets, &item, source_path, line_no)?;
                    }
                } else {
                    let v = parse_yaml_scalar(val_trimmed)
                        .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                    if !v.is_empty() && v != "null" && v != "~" {
                        push_presets(&mut cfg.presets, &v, source_path, line_no)?;
                    }
                }
            }
            "pkg_manager" | "package_manager" => {
                let v = parse_yaml_scalar(val_trimmed)
                    .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                if !v.is_empty() && v != "null" && v != "~" {
                    let pm = PkgManager::parse(&v).ok_or_else(|| {
                        format!(
                            "{}:{}: Unknown pkg_manager '{}' (supported: apt, apk, dnf)",
                            source_path.display(),
                            line_no,
                            v
                        )
                    })?;
                    cfg.pkg_manager = Some(pm);
                }
            }
            "include_defaults" | "defaults" => {
                let v = parse_yaml_scalar(val_trimmed)
                    .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                let b = parse_yaml_bool(&v).ok_or_else(|| {
                    format!(
                        "{}:{}: Expected boolean (true/false) for '{}', found '{}'",
                        source_path.display(),
                        line_no,
                        key,
                        v
                    )
                })?;
                cfg.include_defaults = b;
            }
            "packages" | "apt" | "apk" | "dnf" | "system_packages" => {
                if key == "apt" && cfg.pkg_manager.is_none() {
                    cfg.pkg_manager = Some(PkgManager::Apt);
                } else if key == "apk" && cfg.pkg_manager.is_none() {
                    cfg.pkg_manager = Some(PkgManager::Apk);
                } else if key == "dnf" && cfg.pkg_manager.is_none() {
                    cfg.pkg_manager = Some(PkgManager::Dnf);
                }
                if val_trimmed.is_empty() {
                    section = ActiveSection::Packages;
                } else if val_trimmed.starts_with('[') && val_trimmed.ends_with(']') {
                    let items = split_flow_items(&val_trimmed[1..val_trimmed.len() - 1])
                        .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                    for item in items {
                        validate_system_package(&item)
                            .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                        cfg.packages.push(item);
                    }
                } else if val_trimmed != "null" && val_trimmed != "~" {
                    let item = parse_yaml_scalar(val_trimmed)
                        .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                    validate_system_package(&item)
                        .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                    cfg.packages.push(item);
                }
            }
            "exclude" | "exclude_packages" | "remove" => {
                if val_trimmed.is_empty() {
                    section = ActiveSection::ExcludePackages;
                } else if val_trimmed.starts_with('[') && val_trimmed.ends_with(']') {
                    let items = split_flow_items(&val_trimmed[1..val_trimmed.len() - 1])
                        .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                    for item in items {
                        validate_system_package(&item)
                            .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                        cfg.exclude_packages.push(item);
                    }
                } else if val_trimmed != "null" && val_trimmed != "~" {
                    let item = parse_yaml_scalar(val_trimmed)
                        .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                    validate_system_package(&item)
                        .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                    cfg.exclude_packages.push(item);
                }
            }
            "pip" | "pip_packages" | "python_packages" => {
                if val_trimmed.is_empty() {
                    section = ActiveSection::Pip;
                } else if val_trimmed.starts_with('[') && val_trimmed.ends_with(']') {
                    let items = split_flow_items(&val_trimmed[1..val_trimmed.len() - 1])
                        .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                    for item in items {
                        validate_ecosystem_package("pip", &item)
                            .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                        cfg.pip.push(item);
                    }
                } else if val_trimmed != "null" && val_trimmed != "~" {
                    let item = parse_yaml_scalar(val_trimmed)
                        .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                    validate_ecosystem_package("pip", &item)
                        .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                    cfg.pip.push(item);
                }
            }
            "cargo" | "cargo_packages" | "crates" => {
                if val_trimmed.is_empty() {
                    section = ActiveSection::Cargo;
                } else if val_trimmed.starts_with('[') && val_trimmed.ends_with(']') {
                    let items = split_flow_items(&val_trimmed[1..val_trimmed.len() - 1])
                        .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                    for item in items {
                        validate_ecosystem_package("cargo", &item)
                            .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                        cfg.cargo.push(item);
                    }
                } else if val_trimmed != "null" && val_trimmed != "~" {
                    let item = parse_yaml_scalar(val_trimmed)
                        .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                    validate_ecosystem_package("cargo", &item)
                        .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                    cfg.cargo.push(item);
                }
            }
            "npm" | "npm_packages" => {
                if val_trimmed.is_empty() {
                    section = ActiveSection::Npm;
                } else if val_trimmed.starts_with('[') && val_trimmed.ends_with(']') {
                    let items = split_flow_items(&val_trimmed[1..val_trimmed.len() - 1])
                        .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                    for item in items {
                        validate_ecosystem_package("npm", &item)
                            .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                        cfg.npm.push(item);
                    }
                } else if val_trimmed != "null" && val_trimmed != "~" {
                    let item = parse_yaml_scalar(val_trimmed)
                        .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                    validate_ecosystem_package("npm", &item)
                        .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                    cfg.npm.push(item);
                }
            }
            "julia" | "julia_packages" => {
                if val_trimmed.is_empty() {
                    section = ActiveSection::Julia;
                } else if val_trimmed.starts_with('[') && val_trimmed.ends_with(']') {
                    let items = split_flow_items(&val_trimmed[1..val_trimmed.len() - 1])
                        .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                    for item in items {
                        validate_ecosystem_package("julia", &item)
                            .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                        cfg.julia.push(item);
                    }
                } else if val_trimmed != "null" && val_trimmed != "~" {
                    let item = parse_yaml_scalar(val_trimmed)
                        .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                    validate_ecosystem_package("julia", &item)
                        .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                    cfg.julia.push(item);
                }
            }
            "env" => {
                if val_trimmed.is_empty() {
                    section = ActiveSection::Env;
                } else if val_trimmed.starts_with('{') && val_trimmed.ends_with('}') {
                    let inner = &val_trimmed[1..val_trimmed.len() - 1];
                    let parts = split_flow_items(inner)
                        .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                    for entry in parts {
                        let pair = parse_env_entry(&entry, source_path, line_no)?;
                        cfg.env.push(pair);
                    }
                } else if val_trimmed != "null" && val_trimmed != "~" {
                    let pair = parse_env_entry(val_trimmed, source_path, line_no)?;
                    cfg.env.push(pair);
                }
            }
            "run" | "commands" => {
                if val_trimmed.is_empty() {
                    section = ActiveSection::Run;
                } else if val_trimmed.starts_with('[') && val_trimmed.ends_with(']') {
                    let items = split_flow_items(&val_trimmed[1..val_trimmed.len() - 1])
                        .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                    for item in items {
                        if !item.is_empty() {
                            cfg.run.push(item);
                        }
                    }
                } else if val_trimmed != "null" && val_trimmed != "~" {
                    let cmd = parse_yaml_scalar(val_trimmed)
                        .map_err(|e| format!("{}:{}: {}", source_path.display(), line_no, e))?;
                    if !cmd.is_empty() {
                        cfg.run.push(cmd);
                    }
                }
            }
            other => {
                return Err(format!(
                    "{}:{}: Unknown key '{}' (supported keys: base, preset, presets, pkg_manager, include_defaults, packages, exclude_packages, pip, cargo, npm, julia, env, run)",
                    source_path.display(),
                    line_no,
                    other
                ));
            }
        }
    }

    cfg.presets.sort();
    cfg.presets.dedup();
    Ok(cfg)
}

pub fn generate_starter_yaml(name: &str, presets: &[Preset], custom_base: Option<&str>) -> String {
    let mut effective_presets = presets.to_vec();
    if effective_presets.is_empty() && custom_base.is_none() {
        effective_presets = infer_presets_from_name(name);
    }

    let mut out = String::new();
    out.push_str(&format!("# box image definition for VM \"{}\"\n", name));
    out.push_str(&format!(
        "# Edit the packages below, then run `box --attach {}` (or `box --sync {}`)\n",
        name, name
    ));
    out.push_str("# to automatically rebuild the image and recreate the VM.\n\n");

    if let Some(base) = custom_base {
        out.push_str(&format!("base: {}\n\n", base));
    } else if effective_presets.len() == 1 {
        out.push_str(&format!("preset: {}\n\n", effective_presets[0].as_str()));
    } else if effective_presets.len() > 1 {
        out.push_str("presets:\n");
        for p in &effective_presets {
            out.push_str(&format!("  - {}\n", p.as_str()));
        }
        out.push('\n');
    } else {
        out.push_str("# Choose a built-in preset (rust, python, node, latex, alpine, julia, bitcoin, k8s, kali, llama)\n");
        out.push_str("# or specify any OCI `base:` image directly.\n");
        out.push_str("base: docker.io/library/debian:trixie-slim\n\n");
    }

    let pm = if let Some(base) = custom_base {
        PkgManager::infer_from_image(base)
    } else if let Some(first) = effective_presets.first() {
        PkgManager::infer_from_preset(*first)
    } else {
        PkgManager::Apt
    };

    out.push_str(&format!(
        "# System packages installed via {} (added on top of preset defaults).\n",
        pm.as_str()
    ));
    out.push_str("# Set `include_defaults: false` to install strictly only the packages listed here.\n");
    out.push_str("packages:\n");
    match pm {
        PkgManager::Apk => {
            out.push_str("  - ca-certificates\n  - curl\n  - iputils\n  - vim\n");
            out.push_str("  # - git\n  # - jq\n");
        }
        PkgManager::Dnf => {
            out.push_str("  - ca-certificates\n  - curl\n  - iputils\n  - vim-enhanced\n");
            out.push_str("  # - git\n  # - htop\n");
        }
        PkgManager::Apt => {
            out.push_str("  - ca-certificates\n  - curl\n  - iputils-ping\n  - vim\n");
            out.push_str("  # - git\n  # - ripgrep\n  # - fd-find\n  # - jq\n");
        }
    }

    if effective_presets.contains(&Preset::Rust) {
        out.push_str("\n# Optional Rust crates installed globally via cargo:\n# cargo:\n#   - cargo-watch\n");
    } else if effective_presets.contains(&Preset::Python) {
        out.push_str("\n# Optional Python packages installed via pip:\n# pip:\n#   - numpy\n#   - pandas\n");
    } else if effective_presets.contains(&Preset::Node) {
        out.push_str("\n# Optional global Node packages installed via npm:\n# npm:\n#   - typescript\n");
    } else if effective_presets.contains(&Preset::Julia) {
        out.push_str("\n# Optional Julia packages pre-installed into the shared depot:\n# julia:\n#   - DataFrames\n");
    }

    out.push_str("\n# Optional environment variables baked into the image:\n# env:\n#   EDITOR: vim\n");
    out.push_str("\n# Optional custom RUN steps:\n# run:\n#   - echo \"ready\"\n");
    out
}

/// Pure-Rust FIPS 180-4 SHA-256 returning a 64-character lowercase hex digest.
pub fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity(((data.len() + 9 + 63) / 64) * 64);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = String::with_capacity(64);
    for word in h {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{:08x}", word);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_nist_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn parses_full_yaml_config() {
        let yaml = r#"
# Custom rust image
preset: rust
packages:
  - ripgrep # fast grep
  - 'fd-find'
  - "pkg-config"
exclude_packages: [vim]
cargo:
  - cargo-watch
env:
  RUST_BACKTRACE: "1"
  EDITOR: nvim
run:
  - "echo hello"
"#;
        let cfg = parse_image_config("rust", Path::new("/tmp/rust.yaml"), yaml).unwrap();
        assert_eq!(cfg.name, "rust");
        assert_eq!(cfg.presets, vec![Preset::Rust]);
        assert_eq!(cfg.packages, vec!["ripgrep", "fd-find", "pkg-config"]);
        assert_eq!(cfg.exclude_packages, vec!["vim"]);
        assert_eq!(cfg.cargo, vec!["cargo-watch"]);
        assert_eq!(
            cfg.env,
            vec![
                ("RUST_BACKTRACE".to_string(), "1".to_string()),
                ("EDITOR".to_string(), "nvim".to_string())
            ]
        );
        assert_eq!(cfg.run, vec!["echo hello"]);
        assert!(cfg.include_defaults);
    }

    #[test]
    fn parses_minimal_bare_list_and_infers_preset_from_filename() {
        let yaml = "- ripgrep\n- git\n- jq\n";
        let cfg = parse_image_config("rust", Path::new("/tmp/rust.yaml"), yaml).unwrap();
        assert_eq!(cfg.packages, vec!["ripgrep", "git", "jq"]);
        assert_eq!(cfg.effective_presets(), vec![Preset::Rust]);
    }

    #[test]
    fn parses_inline_lists_and_custom_base() {
        let yaml = r#"
base: docker.io/library/ubuntu:24.04
include_defaults: false
packages: [git, curl, "ripgrep"]
pip: [numpy, "pandas>=2.0"]
env: { FOO: bar, BAZ: "hello, world" }
"#;
        let cfg = parse_image_config("ml", Path::new("/tmp/ml.yaml"), yaml).unwrap();
        assert_eq!(cfg.base.as_deref(), Some("docker.io/library/ubuntu:24.04"));
        assert!(!cfg.include_defaults);
        assert_eq!(cfg.packages, vec!["git", "curl", "ripgrep"]);
        assert_eq!(cfg.pip, vec!["numpy", "pandas>=2.0"]);
        assert_eq!(
            cfg.env,
            vec![
                ("FOO".to_string(), "bar".to_string()),
                ("BAZ".to_string(), "hello, world".to_string())
            ]
        );
        assert!(cfg.effective_presets().is_empty());
    }

    #[test]
    fn rejects_unknown_keys_and_unsafe_packages() {
        let bad_key = "pakages:\n  - git\n";
        assert!(parse_image_config("rust", Path::new("/tmp/rust.yaml"), bad_key).is_err());

        let bad_pkg = "packages:\n  - git; rm -rf /\n";
        assert!(parse_image_config("rust", Path::new("/tmp/rust.yaml"), bad_pkg).is_err());

        let bad_flag_pkg = "packages:\n  - --help\n";
        assert!(parse_image_config("rust", Path::new("/tmp/rust.yaml"), bad_flag_pkg).is_err());
    }

    #[test]
    fn infers_presets_only_when_all_segments_match() {
        assert_eq!(infer_presets_from_name("rust"), vec![Preset::Rust]);
        assert_eq!(
            infer_presets_from_name("latex-python"),
            vec![Preset::Latex, Preset::Python]
        );
        assert!(infer_presets_from_name("my-rust").is_empty());
        assert!(infer_presets_from_name("customvm").is_empty());
    }

    #[test]
    fn starter_yaml_roundtrips_cleanly() {
        let yaml = generate_starter_yaml("rust", &[], None);
        let parsed = parse_image_config("rust", Path::new("/tmp/rust.yaml"), &yaml).unwrap();
        assert_eq!(parsed.effective_presets(), vec![Preset::Rust]);
        assert!(parsed.packages.contains(&"curl".to_string()));
        assert!(parsed.packages.contains(&"vim".to_string()));
    }

    #[test]
    fn discovers_yaml_configs_from_directory() {
        let dir = std::env::temp_dir().join(format!("box-imgcfg-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        fs::write(
            dir.join("rust.yaml"),
            "packages:\n  - ripgrep\n  - git\n",
        )
        .unwrap();
        fs::write(
            dir.join("rust.yml"),
            "packages:\n  - ignored-duplicate\n",
        )
        .unwrap();
        fs::write(
            dir.join("analytics.yml"),
            "preset: python\npip:\n  - numpy\n  - pandas\n",
        )
        .unwrap();

        let rust_cfg = find_image_config("rust", Some(&dir)).unwrap().unwrap();
        assert_eq!(rust_cfg.name, "rust");
        assert_eq!(rust_cfg.packages, vec!["ripgrep", "git"]);

        let discovered = discover_image_configs(Some(&dir));
        assert_eq!(discovered.len(), 2);
        let names: Vec<String> = discovered
            .into_iter()
            .map(|(_, r)| r.unwrap().name)
            .collect();
        assert_eq!(names, vec!["analytics", "rust"]);

        let _ = fs::remove_dir_all(&dir);
    }
}
