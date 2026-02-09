use std::collections::HashSet;

const SENSITIVE_ENV_KEYS: &[&str] = &[
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "GITLAB_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GOOGLE_API_KEY",
    "AZURE_CLIENT_SECRET",
    "DATABASE_URL",
    "DB_PASSWORD",
    "SECRET_KEY",
    "PRIVATE_KEY",
    "API_KEY",
    "API_SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "CREDENTIALS",
    "SSH_PRIVATE_KEY",
    "ENCRYPTION_KEY",
    "SIGNING_KEY",
    "JWT_SECRET",
    "SESSION_SECRET",
    "COOKIE_SECRET",
    "STRIPE_SECRET_KEY",
    "TWILIO_AUTH_TOKEN",
    "SENDGRID_API_KEY",
    "SLACK_TOKEN",
    "DISCORD_TOKEN",
    "NPM_TOKEN",
    "PYPI_TOKEN",
    "CARGO_REGISTRY_TOKEN",
    "DOCKER_PASSWORD",
    "KUBECONFIG",
];

const SENSITIVE_SUBSTRINGS: &[&str] = &[
    "secret",
    "password",
    "passwd",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "credential",
    "auth",
];

pub struct Redactor {
    sensitive_keys: HashSet<String>,
    allowlist: HashSet<String>,
    denylist: HashSet<String>,
}

impl Redactor {
    pub fn new() -> Self {
        let mut sensitive_keys = HashSet::new();
        for key in SENSITIVE_ENV_KEYS {
            sensitive_keys.insert(key.to_uppercase());
        }

        Self {
            sensitive_keys,
            allowlist: HashSet::new(),
            denylist: HashSet::new(),
        }
    }

    pub fn add_allowlist(&mut self, key: &str) {
        self.allowlist.insert(key.to_uppercase());
    }

    pub fn add_denylist(&mut self, key: &str) {
        self.denylist.insert(key.to_uppercase());
    }

    pub fn should_redact_env_key(&self, key: &str) -> bool {
        let upper = key.to_uppercase();

        if self.allowlist.contains(&upper) {
            return false;
        }

        if self.denylist.contains(&upper) {
            return true;
        }

        if self.sensitive_keys.contains(&upper) {
            return true;
        }

        let lower = key.to_lowercase();
        for pattern in SENSITIVE_SUBSTRINGS {
            if lower.contains(pattern) {
                return true;
            }
        }

        false
    }

    pub fn redact_env(
        &self,
        env: &std::collections::HashMap<String, String>,
    ) -> std::collections::HashMap<String, String> {
        env.iter()
            .map(|(k, v)| {
                if self.should_redact_env_key(k) {
                    (k.clone(), "[REDACTED]".to_string())
                } else {
                    (k.clone(), v.clone())
                }
            })
            .collect()
    }

    pub fn redact_string(&self, s: &str) -> String {
        let mut result = s.to_string();

        let bearer_patterns = [
            "Bearer ",
            "bearer ",
            "BEARER ",
        ];
        for pattern in &bearer_patterns {
            let mut search_from = 0;
            while let Some(pos) = result[search_from..].find(pattern) {
                let abs_pos = search_from + pos;
                let token_start = abs_pos + pattern.len();
                let token_end = result[token_start..]
                    .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == ',')
                    .map(|p| token_start + p)
                    .unwrap_or(result.len());
                if token_end > token_start {
                    result.replace_range(token_start..token_end, "[REDACTED]");
                    search_from = token_start + "[REDACTED]".len();
                } else {
                    search_from = token_start;
                }
            }
        }

        result
    }
}

impl Default for Redactor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sensitive_env_detection() {
        let r = Redactor::new();
        assert!(r.should_redact_env_key("AWS_SECRET_ACCESS_KEY"));
        assert!(r.should_redact_env_key("my_api_key"));
        assert!(r.should_redact_env_key("DATABASE_PASSWORD"));
        assert!(!r.should_redact_env_key("PATH"));
        assert!(!r.should_redact_env_key("HOME"));
        assert!(!r.should_redact_env_key("RUST_BACKTRACE"));
    }

    #[test]
    fn test_allowlist() {
        let mut r = Redactor::new();
        r.add_allowlist("AWS_SECRET_ACCESS_KEY");
        assert!(!r.should_redact_env_key("AWS_SECRET_ACCESS_KEY"));
    }

    #[test]
    fn test_bearer_redaction() {
        let r = Redactor::new();
        let input = "Authorization: Bearer sk-abc123def456";
        let output = r.redact_string(input);
        assert!(!output.contains("sk-abc123def456"));
        assert!(output.contains("[REDACTED]"));
    }
}
