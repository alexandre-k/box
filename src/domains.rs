use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainVerdict {
    Allowed(String),
    Unlisted,
    Suspicious(String),
}

impl DomainVerdict {
    pub fn label(&self) -> &'static str {
        match self {
            DomainVerdict::Allowed(_) => "OK",
            DomainVerdict::Unlisted => "NEW",
            DomainVerdict::Suspicious(_) => "ALERT",
        }
    }

    pub fn severity_key(&self) -> &'static str {
        match self {
            DomainVerdict::Allowed(_) => "trusted",
            DomainVerdict::Unlisted => "unlisted",
            DomainVerdict::Suspicious(_) => "suspicious",
        }
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            DomainVerdict::Allowed(r) | DomainVerdict::Suspicious(r) => Some(r.as_str()),
            DomainVerdict::Unlisted => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    Allow,
    Block,
    Remove,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DomainRule {
    Suffix(String),
    Exact(String),
}

impl DomainRule {
    fn parse(raw: &str) -> Option<Self> {
        let trimmed = raw.trim().to_lowercase();
        if trimmed.is_empty() || trimmed.len() > 253 {
            return None;
        }
        if !trimmed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'*' | b'='))
        {
            return None;
        }
        if let Some(exact) = trimmed.strip_prefix('=') {
            let clean = exact.trim().trim_end_matches('.');
            if !clean.is_empty() && !clean.contains('*') && !clean.contains('=') {
                return Some(DomainRule::Exact(clean.to_string()));
            }
            return None;
        }
        let clean = trimmed
            .trim_start_matches("*.")
            .trim_start_matches('.')
            .trim_end_matches('.');
        if clean.is_empty() || clean.contains('*') || clean.contains('=') {
            None
        } else {
            Some(DomainRule::Suffix(clean.to_string()))
        }
    }

    fn matches(&self, domain: &str) -> bool {
        let d = domain.trim_end_matches('.');
        match self {
            DomainRule::Exact(pat) => d == pat,
            DomainRule::Suffix(pat) => {
                d == pat
                    || (d.len() > pat.len()
                        && d.ends_with(pat)
                        && d.as_bytes()[d.len() - pat.len() - 1] == b'.')
            }
        }
    }

    fn display(&self) -> String {
        match self {
            DomainRule::Exact(p) => format!("={}", p),
            DomainRule::Suffix(p) => p.clone(),
        }
    }
}

const BUILTIN_ALLOWED_DOMAINS: &[&str] = &[
    "crates.io",
    "rust-lang.org",
    "rustup.rs",
    "pypi.org",
    "pythonhosted.org",
    "npmjs.org",
    "npmjs.com",
    "nodejs.org",
    "github.com",
    "githubusercontent.com",
    "githubassets.com",
    "debian.org",
    "alpinelinux.org",
    "fedoraproject.org",
    "ctan.org",
    "tug.org",
    "docker.io",
    "docker.com",
];

#[derive(Debug, Clone)]
pub struct DomainPolicy {
    user_allowed: Vec<(DomainRule, String)>,
    builtin_allowed: Vec<(DomainRule, String)>,
    blocked: Vec<(DomainRule, String)>,
    pub source_description: String,
    pub user_file_path: PathBuf,
}

pub fn default_domains_path() -> PathBuf {
    let base = env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            PathBuf::from(home).join(".config")
        });
    base.join("box").join("domains.txt")
}

impl DomainPolicy {
    pub fn load(custom_path: Option<&Path>) -> Self {
        let mut user_allowed = Vec::new();
        let mut builtin_allowed = Vec::new();
        let mut blocked = Vec::new();

        if let Some(path) = custom_path {
            let count = Self::load_file_into(path, "list", &mut user_allowed, &mut blocked);
            return Self {
                user_allowed,
                builtin_allowed,
                blocked,
                source_description: format!("{} ({} rules)", path.display(), count),
                user_file_path: path.to_path_buf(),
            };
        }

        let default_path = default_domains_path();
        let user_rules = if default_path.exists() {
            Self::load_file_into(&default_path, "user list", &mut user_allowed, &mut blocked)
        } else {
            0
        };

        for dom in BUILTIN_ALLOWED_DOMAINS {
            if let Some(rule) = DomainRule::parse(dom) {
                builtin_allowed.push((rule, "built-in dev registry".to_string()));
            }
        }

        let source_description = if user_rules > 0 {
            format!(
                "{} ({} user rules) + {} built-in",
                default_path.display(),
                user_rules,
                BUILTIN_ALLOWED_DOMAINS.len()
            )
        } else {
            format!(
                "{} built-in dev registries (add custom rules in {})",
                BUILTIN_ALLOWED_DOMAINS.len(),
                default_path.display()
            )
        };

        Self {
            user_allowed,
            builtin_allowed,
            blocked,
            source_description,
            user_file_path: default_path,
        }
    }

    fn load_file_into(
        path: &Path,
        origin: &str,
        allowed: &mut Vec<(DomainRule, String)>,
        blocked: &mut Vec<(DomainRule, String)>,
    ) -> usize {
        let Ok(content) = fs::read_to_string(path) else {
            return 0;
        };
        let mut count = 0usize;
        for raw_line in content.lines() {
            let line = raw_line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            if let Some(rest) = line.strip_prefix('!').or_else(|| line.strip_prefix('-')) {
                if let Some(rule) = DomainRule::parse(rest) {
                    let label = format!("blocklisted ({}: {})", origin, rule.display());
                    blocked.push((rule, label));
                    count += 1;
                }
            } else {
                let rest = line.strip_prefix('+').unwrap_or(line);
                if let Some(rule) = DomainRule::parse(rest) {
                    let label = format!("allowlisted ({}: {})", origin, rule.display());
                    allowed.push((rule, label));
                    count += 1;
                }
            }
        }
        count
    }

    /// Add, block, or remove a rule in the user's domain list file, preserving comments.
    /// Returns the normalized rule string on success.
    pub fn update_rule_file(
        path: &Path,
        raw_domain: &str,
        action: RuleAction,
    ) -> Result<String, String> {
        let trimmed = raw_domain.trim();
        let (effective_action, rule_body) = if let Some(rest) =
            trimmed.strip_prefix('!').or_else(|| trimmed.strip_prefix('-'))
        {
            let act = match action {
                RuleAction::Remove => RuleAction::Remove,
                _ => RuleAction::Block,
            };
            (act, rest)
        } else {
            (action, trimmed.strip_prefix('+').unwrap_or(trimmed))
        };

        let target_rule = DomainRule::parse(rule_body)
            .ok_or_else(|| format!("Invalid domain pattern: '{}'", raw_domain))?;
        let normalized = target_rule.display();

        let existing = fs::read_to_string(path).unwrap_or_default();
        let mut out_lines: Vec<String> = Vec::new();

        if existing.is_empty() && effective_action != RuleAction::Remove {
            out_lines.push("# box domain allowlist / blocklist".to_string());
            out_lines.push("# One domain per line: plain = allow (matches subdomains), =host = exact allow, !domain = block".to_string());
        } else {
            for raw_line in existing.lines() {
                let code = raw_line.split('#').next().unwrap_or("").trim();
                let matches_target = if code.is_empty() {
                    false
                } else {
                    let body = code
                        .strip_prefix('!')
                        .or_else(|| code.strip_prefix('-'))
                        .or_else(|| code.strip_prefix('+'))
                        .unwrap_or(code);
                    DomainRule::parse(body)
                        .map(|r| r == target_rule)
                        .unwrap_or(false)
                };
                if !matches_target {
                    out_lines.push(raw_line.to_string());
                }
            }
        }

        match effective_action {
            RuleAction::Allow => out_lines.push(normalized.clone()),
            RuleAction::Block => out_lines.push(format!("!{}", normalized)),
            RuleAction::Remove => {}
        }

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create {}: {}", parent.display(), e))?;
        }
        let mut content = out_lines.join("\n");
        if !content.is_empty() {
            content.push('\n');
        }
        fs::write(path, content)
            .map_err(|e| format!("Failed to write {}: {}", path.display(), e))?;

        Ok(normalized)
    }

    pub fn classify(&self, domain: &str) -> DomainVerdict {
        let lower = domain.to_lowercase();

        // 1. Explicit block rules take highest precedence
        for (rule, reason) in &self.blocked {
            if rule.matches(&lower) {
                return DomainVerdict::Suspicious(reason.clone());
            }
        }

        // 2. Explicit user allow rules override heuristics
        for (rule, reason) in &self.user_allowed {
            if rule.matches(&lower) {
                return DomainVerdict::Allowed(reason.clone());
            }
        }

        // 3. Heuristic suspicious-domain detection
        if let Some(reason) = is_suspicious_domain(&lower) {
            return DomainVerdict::Suspicious(reason.to_string());
        }

        // 4. Built-in dev registry allow rules
        for (rule, reason) in &self.builtin_allowed {
            if rule.matches(&lower) {
                return DomainVerdict::Allowed(reason.clone());
            }
        }

        DomainVerdict::Unlisted
    }

    pub fn user_allowed_patterns(&self) -> Vec<String> {
        self.user_allowed.iter().map(|(r, _)| r.display()).collect()
    }

    pub fn builtin_allowed_patterns(&self) -> Vec<String> {
        self.builtin_allowed
            .iter()
            .map(|(r, _)| r.display())
            .collect()
    }

    pub fn blocked_patterns(&self) -> Vec<String> {
        self.blocked.iter().map(|(r, _)| r.display()).collect()
    }
}

pub fn is_suspicious_domain(domain: &str) -> Option<&'static str> {
    let suspicious_tlds = [
        ".zip", ".mov", ".top", ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".onion",
    ];
    if suspicious_tlds.iter().any(|tld| domain.ends_with(tld)) {
        return Some("high-risk TLD");
    }
    if domain.ends_with(".nip.io")
        || domain.ends_with(".sslip.io")
        || domain.ends_with(".ngrok.io")
        || domain.ends_with(".trycloudflare.com")
    {
        return Some("tunnel / dynamic DNS");
    }
    let first_label = domain.split('.').next().unwrap_or("");
    if first_label.len() >= 28 {
        return Some("long subdomain (possible DNS tunnel / DGA)");
    }
    let digits = first_label.chars().filter(|c| c.is_ascii_digit()).count();
    if first_label.len() >= 14 && digits * 2 > first_label.len() {
        return Some("high-digit entropy (possible DGA)");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_suspicious_domains() {
        assert_eq!(is_suspicious_domain("crates.io"), None);
        assert_eq!(is_suspicious_domain("evil.zip"), Some("high-risk TLD"));
        assert_eq!(
            is_suspicious_domain("abc.trycloudflare.com"),
            Some("tunnel / dynamic DNS")
        );
        assert_eq!(
            is_suspicious_domain("aaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com"),
            Some("long subdomain (possible DNS tunnel / DGA)")
        );
        assert_eq!(
            is_suspicious_domain("a1234567890123.example.com"),
            Some("high-digit entropy (possible DGA)")
        );
    }

    #[test]
    fn classifies_allowed_unlisted_and_blocked() {
        let mut policy = DomainPolicy {
            user_allowed: vec![
                (DomainRule::parse("crates.io").unwrap(), "allow".into()),
                (DomainRule::parse("=exact.test").unwrap(), "exact".into()),
                (DomainRule::parse("trusted.xyz").unwrap(), "user allow".into()),
            ],
            builtin_allowed: vec![],
            blocked: vec![(DomainRule::parse("bad.crates.io").unwrap(), "blocked".into())],
            source_description: "test".into(),
            user_file_path: PathBuf::from("/tmp/none"),
        };

        assert!(matches!(policy.classify("crates.io"), DomainVerdict::Allowed(_)));
        assert!(matches!(
            policy.classify("static.crates.io"),
            DomainVerdict::Allowed(_)
        ));
        // User explicit allow overrides TLD heuristic
        assert!(matches!(
            policy.classify("trusted.xyz"),
            DomainVerdict::Allowed(_)
        ));
        assert!(matches!(
            policy.classify("notcrates.io"),
            DomainVerdict::Unlisted
        ));
        assert!(matches!(
            policy.classify("bad.crates.io"),
            DomainVerdict::Suspicious(_)
        ));
        assert!(matches!(
            policy.classify("exact.test"),
            DomainVerdict::Allowed(_)
        ));
        assert!(matches!(
            policy.classify("sub.exact.test"),
            DomainVerdict::Unlisted
        ));

        policy.blocked.clear();
        assert!(matches!(
            policy.classify("drop.evil.zip"),
            DomainVerdict::Suspicious(_)
        ));
    }

    #[test]
    fn updates_rule_file_cleanly() {
        let tmp = std::env::temp_dir().join(format!("box-domains-test-{}.txt", std::process::id()));
        let _ = fs::remove_file(&tmp);

        assert_eq!(
            DomainPolicy::update_rule_file(&tmp, "Example.COM", RuleAction::Allow).unwrap(),
            "example.com"
        );
        assert_eq!(
            DomainPolicy::update_rule_file(&tmp, "example.com", RuleAction::Block).unwrap(),
            "example.com"
        );
        let p = DomainPolicy::load(Some(&tmp));
        assert!(matches!(p.classify("example.com"), DomainVerdict::Suspicious(_)));
        assert!(p.user_allowed_patterns().is_empty());
        assert_eq!(p.blocked_patterns(), vec!["example.com"]);

        DomainPolicy::update_rule_file(&tmp, "example.com", RuleAction::Allow).unwrap();
        let p2 = DomainPolicy::load(Some(&tmp));
        assert!(matches!(p2.classify("example.com"), DomainVerdict::Allowed(_)));
        assert!(p2.blocked_patterns().is_empty());

        DomainPolicy::update_rule_file(&tmp, "example.com", RuleAction::Remove).unwrap();
        let p3 = DomainPolicy::load(Some(&tmp));
        assert!(matches!(p3.classify("example.com"), DomainVerdict::Unlisted));

        // Reject invalid characters
        assert!(DomainPolicy::update_rule_file(&tmp, "bad\ndomain", RuleAction::Allow).is_err());

        let _ = fs::remove_file(&tmp);
    }
}
