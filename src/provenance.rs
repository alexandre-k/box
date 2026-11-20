use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct CodeLine {
    pub line_no: usize,
    pub text: String,
    pub is_match: bool,
}

#[derive(Debug, Clone)]
pub struct CodeMatch {
    pub file: String,
    pub line: usize,
    pub kind: String,
    pub snippet: Vec<CodeLine>,
}

#[derive(Debug, Clone)]
pub struct CodeProvenance {
    pub summary: String,
    pub command_direct: bool,
    pub matches: Vec<CodeMatch>,
}

const SKIP_DIRS: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    "dist",
    "build",
    ".next",
    ".cache",
];

const MAX_FILES_SCANNED: usize = 2_000;
const MAX_FILE_BYTES: u64 = 512 * 1024;
const MAX_MATCHES: usize = 20;
const MAX_MATCHES_PER_FILE: usize = 3;

fn parent_domain(domain: &str) -> Option<String> {
    let parts: Vec<&str> = domain.trim_end_matches('.').split('.').collect();
    if parts.len() >= 3 {
        Some(parts[parts.len() - 2..].join("."))
    } else {
        None
    }
}

fn is_probably_binary(bytes: &[u8]) -> bool {
    let sample = &bytes[..bytes.len().min(4096)];
    sample.contains(&0)
}

fn collect_snippet(lines: &[&str], match_idx: usize, radius: usize) -> Vec<CodeLine> {
    let start = match_idx.saturating_sub(radius);
    let end = (match_idx + radius + 1).min(lines.len());
    (start..end)
        .map(|i| CodeLine {
            line_no: i + 1,
            text: lines[i].chars().take(240).collect(),
            is_match: i == match_idx,
        })
        .collect()
}

fn find_script_files_in_cmd(workspace: &Path, cmd: &str) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for raw_tok in cmd.split_whitespace() {
        let tok = raw_tok.trim_matches(|c| matches!(c, '"' | '\'' | ';' | '(' | ')'));
        if tok.is_empty() || tok.starts_with('-') {
            continue;
        }
        let rel = tok.strip_prefix("/workspace/").unwrap_or(tok);
        if rel.contains("..") || Path::new(rel).is_absolute() {
            continue;
        }
        let candidate = workspace.join(rel);
        if candidate.is_file() && !found.contains(&candidate) {
            found.push(candidate);
        }
    }
    found
}

fn scan_file_for_needles(
    workspace: &Path,
    path: &Path,
    needles: &[(String, &str)],
    out: &mut Vec<CodeMatch>,
) {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return;
    };
    if meta.file_type().is_symlink() || !meta.is_file() || meta.len() > MAX_FILE_BYTES {
        return;
    }
    let Ok(bytes) = fs::read(path) else {
        return;
    };
    if is_probably_binary(&bytes) {
        return;
    }
    let text = String::from_utf8_lossy(&bytes);
    let lines: Vec<&str> = text.lines().collect();
    let rel_path = path
        .strip_prefix(workspace)
        .unwrap_or(path)
        .display()
        .to_string();

    let mut matched_lines: Vec<usize> = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        if out.len() >= MAX_MATCHES || matched_lines.len() >= MAX_MATCHES_PER_FILE {
            break;
        }
        let lower = line.to_lowercase();
        for (needle, kind) in needles {
            if !needle.is_empty() && lower.contains(needle) {
                if !matched_lines.contains(&idx) {
                    matched_lines.push(idx);
                    out.push(CodeMatch {
                        file: rel_path.clone(),
                        line: idx + 1,
                        kind: (*kind).to_string(),
                        snippet: collect_snippet(&lines, idx, 2),
                    });
                }
                break;
            }
        }
    }
}

fn walk_workspace(
    workspace: &Path,
    dir: &Path,
    needles: &[(String, &str)],
    scanned: &mut usize,
    out: &mut Vec<CodeMatch>,
) {
    if *scanned >= MAX_FILES_SCANNED || out.len() >= MAX_MATCHES {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut dirs = Vec::new();
    let mut files = Vec::new();
    for entry in entries.flatten() {
        let p = entry.path();
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
                if !SKIP_DIRS.contains(&name) {
                    dirs.push(p);
                }
            }
        } else if ft.is_file() {
            files.push(p);
        }
    }
    // Prioritize source files over noisy lockfiles when scanning
    files.sort_by_key(|p| {
        let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let is_lock = matches!(
            name,
            "Cargo.lock" | "package-lock.json" | "yarn.lock" | "pnpm-lock.yaml" | "poetry.lock" | "uv.lock"
        );
        (is_lock, p.clone())
    });
    dirs.sort();

    // Scan subdirectories (e.g. src/) before root lockfiles
    let (regular_files, lock_files): (Vec<_>, Vec<_>) = files.into_iter().partition(|p| {
        let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
        !matches!(
            name,
            "Cargo.lock" | "package-lock.json" | "yarn.lock" | "pnpm-lock.yaml" | "poetry.lock" | "uv.lock"
        )
    });

    for f in regular_files {
        if *scanned >= MAX_FILES_SCANNED || out.len() >= MAX_MATCHES {
            return;
        }
        *scanned += 1;
        scan_file_for_needles(workspace, &f, needles, out);
    }
    for d in dirs {
        if *scanned >= MAX_FILES_SCANNED || out.len() >= MAX_MATCHES {
            return;
        }
        walk_workspace(workspace, &d, needles, scanned, out);
    }
    for f in lock_files {
        if *scanned >= MAX_FILES_SCANNED || out.len() >= MAX_MATCHES {
            return;
        }
        *scanned += 1;
        scan_file_for_needles(workspace, &f, needles, out);
    }
}

fn inspect_manifest_attribution(
    workspace: &Path,
    domain: &str,
    cmd: &str,
) -> Option<(String, Vec<CodeMatch>)> {
    let dom = domain.to_lowercase();
    let cmd_lower = cmd.to_lowercase();

    let (ecosystem, manifest_files): (&str, &[&str]) = if dom.ends_with("crates.io")
        || dom.ends_with("rust-lang.org")
        || dom.ends_with("rustup.rs")
        || cmd_lower.contains("cargo")
    {
        ("Rust / Cargo", &["Cargo.toml"])
    } else if dom.ends_with("npmjs.org")
        || dom.ends_with("npmjs.com")
        || dom.ends_with("nodejs.org")
        || cmd_lower.contains("npm")
        || cmd_lower.contains("yarn")
        || cmd_lower.contains("pnpm")
    {
        ("Node / npm", &["package.json"])
    } else if dom.ends_with("pypi.org")
        || dom.ends_with("pythonhosted.org")
        || cmd_lower.contains("pip")
        || cmd_lower.contains("uv")
    {
        ("Python / pip", &["pyproject.toml", "requirements.txt"])
    } else if dom.ends_with("ctan.org") || dom.ends_with("tug.org") {
        ("TeX Live / CTAN", &[])
    } else {
        return None;
    };

    let mut matches = Vec::new();
    for mf in manifest_files {
        let p = workspace.join(mf);
        if let Ok(content) = fs::read_to_string(&p) {
            let lines: Vec<&str> = content.lines().collect();
            let dep_idx = lines
                .iter()
                .position(|l| {
                    let ll = l.to_lowercase();
                    ll.contains("[dependencies]")
                        || ll.contains("\"dependencies\"")
                        || ll.contains("dependencies =")
                })
                .unwrap_or(0);
            let snippet = collect_snippet(&lines, dep_idx, 6);
            matches.push(CodeMatch {
                file: (*mf).to_string(),
                line: dep_idx + 1,
                kind: format!("{} manifest", ecosystem),
                snippet,
            });
        }
    }

    let summary = format!(
        "Package registry traffic from {} (command: `{}`).",
        ecosystem, cmd
    );
    Some((summary, matches))
}

/// Inspect a workspace directory + command line to show what code likely generated traffic to `domain`.
pub fn inspect_code_provenance(
    workspace: &Path,
    domain: &str,
    cmd: &str,
    ips: &[String],
) -> CodeProvenance {
    let dom_lower = domain.to_lowercase();
    let command_direct = !dom_lower.is_empty() && cmd.to_lowercase().contains(&dom_lower);

    if !workspace.is_dir() {
        return CodeProvenance {
            summary: if command_direct {
                format!(
                    "Domain '{}' appears directly in the executed command (workspace directory not accessible).",
                    domain
                )
            } else {
                format!(
                    "Workspace '{}' is not accessible on host to search source files.",
                    workspace.display()
                )
            },
            command_direct,
            matches: Vec::new(),
        };
    }

    let mut matches = Vec::new();

    // 1. Direct search for exact domain + resolved IPs in workspace source files
    let mut direct_needles: Vec<(String, &str)> = vec![(dom_lower.clone(), "domain reference")];
    for ip in ips.iter().take(4) {
        if !ip.is_empty() {
            direct_needles.push((ip.to_lowercase(), "hardcoded IP"));
        }
    }

    let mut scanned = 0usize;
    walk_workspace(workspace, workspace, &direct_needles, &mut scanned, &mut matches);

    // 2. If no exact match and domain is a subdomain, try parent domain (e.g. static.crates.io -> crates.io)
    if matches.is_empty() {
        if let Some(parent) = parent_domain(&dom_lower) {
            let parent_needles = vec![(parent, "parent domain reference")];
            let mut scanned_parent = 0usize;
            walk_workspace(
                workspace,
                workspace,
                &parent_needles,
                &mut scanned_parent,
                &mut matches,
            );
        }
    }

    // 3. Check package-manager manifest attribution (Cargo.toml, package.json, pyproject.toml, etc.)
    let manifest_info = inspect_manifest_attribution(workspace, domain, cmd);
    if matches.is_empty() {
        if let Some((summary, manifest_matches)) = manifest_info {
            return CodeProvenance {
                summary,
                command_direct,
                matches: manifest_matches,
            };
        }
    }

    // 4. If still no literal matches, preview any script file explicitly invoked in `cmd`
    if matches.is_empty() {
        let scripts = find_script_files_in_cmd(workspace, cmd);
        for script_path in scripts.into_iter().take(2) {
            if let Ok(bytes) = fs::read(&script_path) {
                if !is_probably_binary(&bytes) {
                    let text = String::from_utf8_lossy(&bytes);
                    let lines: Vec<&str> = text.lines().collect();
                    if !lines.is_empty() {
                        let rel = script_path
                            .strip_prefix(workspace)
                            .unwrap_or(&script_path)
                            .display()
                            .to_string();
                        let preview_len = lines.len().min(12);
                        let snippet = (0..preview_len)
                            .map(|i| CodeLine {
                                line_no: i + 1,
                                text: lines[i].chars().take(240).collect(),
                                is_match: false,
                            })
                            .collect();
                        matches.push(CodeMatch {
                            file: rel,
                            line: 1,
                            kind: "invoked script".to_string(),
                            snippet,
                        });
                    }
                }
            }
        }
    }

    let summary = if command_direct && !matches.is_empty() {
        format!(
            "Domain appears directly in the command AND in {} workspace location(s).",
            matches.len()
        )
    } else if command_direct {
        format!(
            "Domain '{}' appears directly in the command `{}`.",
            domain, cmd
        )
    } else if !matches.is_empty() {
        if matches.iter().all(|m| m.kind == "invoked script") {
            format!(
                "No literal '{}' string found in workspace; showing script invoked by `{}` (URL may be built dynamically or inside a dependency).",
                domain, cmd
            )
        } else {
            format!(
                "Found {} reference(s) across workspace source files (scanned {} files).",
                matches.len(),
                scanned
            )
        }
    } else {
        format!(
            "No literal reference to '{}' found in {} scanned workspace files — likely triggered by a dependency, redirect, or dynamically constructed URL from `{}`.",
            domain, scanned, cmd
        )
    };

    CodeProvenance {
        summary,
        command_direct,
        matches,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_direct_domain_reference_in_workspace() {
        let dir = std::env::temp_dir().join(format!("box-prov-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(
            dir.join("src/fetch.py"),
            "import urllib.request\nurl = 'https://api.example.com/v1'\nprint(url)\n",
        )
        .unwrap();

        let prov = inspect_code_provenance(&dir, "api.example.com", "python3 src/fetch.py", &[]);
        assert!(!prov.command_direct);
        assert_eq!(prov.matches.len(), 1);
        assert_eq!(prov.matches[0].file, "src/fetch.py");
        assert_eq!(prov.matches[0].line, 2);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn attributes_cargo_registry_to_cargo_toml() {
        let dir = std::env::temp_dir().join(format!("box-prov-cargo-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"demo\"\n\n[dependencies]\nclap = \"4\"\n",
        )
        .unwrap();

        let prov = inspect_code_provenance(&dir, "index.crates.io", "cargo build", &[]);
        assert_eq!(prov.matches.len(), 1);
        assert_eq!(prov.matches[0].file, "Cargo.toml");
        assert!(prov.summary.contains("Cargo"));

        let _ = fs::remove_dir_all(&dir);
    }
}
