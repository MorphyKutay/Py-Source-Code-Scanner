use serde::Serialize;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// ANSI color code used for terminal output.
    pub fn ansi_color(self) -> &'static str {
        match self {
            Severity::Info => "\x1b[36m",       // cyan
            Severity::Low => "\x1b[32m",        // green
            Severity::Medium => "\x1b[33m",     // yellow
            Severity::High => "\x1b[31m",       // red
            Severity::Critical => "\x1b[1;31m", // bold red
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        };
        write!(f, "{}", label)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub file: String,
    pub line: usize,
    pub code: String,
    pub rule: String,
    pub category: String,
    pub severity: Severity,
    pub description: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} ({})\nFile: {}\nLine {}: {}\n{}",
            self.severity,
            self.rule,
            self.category,
            self.file,
            self.line,
            self.code.trim(),
            self.description
        )
    }
}
