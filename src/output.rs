use crate::finding::{Finding, Severity};
use std::io;

const RESET: &str = "\x1b[0m";

/// Renders findings as human-readable text. `color` enables ANSI escapes
/// (disable when writing to a file or a non-tty).
pub fn render_text(findings: &[Finding], color: bool) -> String {
    if findings.is_empty() {
        return "[+] No potential vulnerabilities found.\n".to_string();
    }

    let mut out = String::new();
    for finding in findings {
        if color {
            out.push_str(&format!(
                "{}[{}]{} {} ({})\n",
                finding.severity.ansi_color(),
                finding.severity,
                RESET,
                finding.rule,
                finding.category
            ));
        } else {
            out.push_str(&format!(
                "[{}] {} ({})\n",
                finding.severity, finding.rule, finding.category
            ));
        }
        out.push_str(&format!("File: {}\n", finding.file));
        out.push_str(&format!("Line {}: {}\n", finding.line, finding.code.trim()));
        out.push_str(&format!("{}\n------\n", finding.description));
    }

    out.push_str(&format!(
        "\n[+] {} potential issue(s) found.\n",
        findings.len()
    ));
    out
}

pub fn render_json(findings: &[Finding]) -> serde_json::Result<String> {
    serde_json::to_string_pretty(findings)
}

pub fn summarize_by_severity(findings: &[Finding]) -> Vec<(Severity, usize)> {
    let severities = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];
    severities
        .into_iter()
        .map(|s| (s, findings.iter().filter(|f| f.severity == s).count()))
        .filter(|(_, count)| *count > 0)
        .collect()
}

pub fn write_to_file(path: &str, contents: &str) -> io::Result<()> {
    std::fs::write(path, contents)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Finding, Severity};

    fn sample_finding() -> Finding {
        Finding {
            file: "app.py".to_string(),
            line: 3,
            code: "eval(x)".to_string(),
            rule: "eval-exec".to_string(),
            category: "Code Injection".to_string(),
            severity: Severity::High,
            description: "test description".to_string(),
        }
    }

    #[test]
    fn text_output_reports_no_findings() {
        let rendered = render_text(&[], false);
        assert!(rendered.contains("No potential vulnerabilities"));
    }

    #[test]
    fn text_output_includes_finding_details() {
        let rendered = render_text(&[sample_finding()], false);
        assert!(rendered.contains("app.py"));
        assert!(rendered.contains("eval-exec"));
        assert!(rendered.contains("HIGH"));
    }

    #[test]
    fn json_output_is_valid_json() {
        let rendered = render_json(&[sample_finding()]).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(parsed[0]["rule"], "eval-exec");
        assert_eq!(parsed[0]["severity"], "high");
    }

    #[test]
    fn summary_counts_by_severity() {
        let findings = vec![sample_finding(), sample_finding()];
        let summary = summarize_by_severity(&findings);
        assert_eq!(summary, vec![(Severity::High, 2)]);
    }
}
