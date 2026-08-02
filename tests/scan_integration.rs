use main::finding::Severity;
use main::scan_path;

#[test]
fn flags_known_vulnerability_categories_in_fixture() {
    let findings = scan_path("tests/fixtures/vulnerable.py");

    let has_rule = |name: &str| findings.iter().any(|f| f.rule == name);

    assert!(has_rule("os-system"));
    assert!(has_rule("subprocess-shell-true"));
    assert!(has_rule("eval-exec"));
    assert!(has_rule("pickle-load"));
    assert!(has_rule("yaml-unsafe-load"));
    assert!(has_rule("django-mark-safe"));
    assert!(has_rule("sql-fstring"));
    assert!(has_rule("weak-hash-md5"));
    assert!(has_rule("hardcoded-secret"));
    assert!(has_rule("path-traversal-tainted-source"));
    assert!(has_rule("tls-verify-disabled"));
    assert!(has_rule("ssl-unverified-context"));
    assert!(has_rule("open-redirect"));
    assert!(has_rule("insecure-chmod"));
    assert!(has_rule("jwt-verify-disabled"));
    assert!(has_rule("django-debug-true"));
    assert!(has_rule("flask-debug-true"));
    assert!(has_rule("flask-bind-all-interfaces"));
    assert!(has_rule("aws-access-key-id"));
    assert!(has_rule("private-key-block"));
    assert!(has_rule("slack-token"));
    assert!(has_rule("ssrf-dynamic-url"));
}

#[test]
fn findings_are_sorted_most_severe_first() {
    let findings = scan_path("tests/fixtures/vulnerable.py");
    assert!(!findings.is_empty());

    for pair in findings.windows(2) {
        assert!(pair[0].severity >= pair[1].severity);
    }

    assert_eq!(findings[0].severity, Severity::Critical);
}

#[test]
fn clean_fixture_has_no_high_or_critical_findings() {
    let findings = scan_path("tests/fixtures/clean.py");
    let offending: Vec<_> = findings
        .iter()
        .filter(|f| f.severity >= Severity::High)
        .collect();
    assert!(
        offending.is_empty(),
        "expected no HIGH/CRITICAL findings in clean.py, got: {offending:#?}"
    );
}

#[test]
fn clean_fixture_open_and_subprocess_calls_are_not_flagged_as_path_or_command_issues() {
    let findings = scan_path("tests/fixtures/clean.py");

    // A hardcoded, literal file path must not trigger any path-traversal rule -
    // the old blanket "every open() call" rule used to fire here.
    assert!(!findings.iter().any(|f| f.category == "Path Traversal"));

    // A parameterized query must not trigger any SQL injection rule.
    assert!(!findings.iter().any(|f| f.category == "SQL Injection"));

    // subprocess.run() with a list of args and no shell=True is low-severity only.
    assert!(!findings.iter().any(|f| f.rule == "subprocess-shell-true"));
}

#[test]
fn scanning_a_directory_covers_both_fixtures() {
    let findings = scan_path("tests/fixtures");
    let files: std::collections::HashSet<_> = findings.iter().map(|f| f.file.clone()).collect();
    assert!(files.iter().any(|f| f.ends_with("vulnerable.py")));
}
