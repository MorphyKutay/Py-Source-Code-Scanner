use crate::finding::Severity;
use regex::Regex;

pub struct Rule {
    pub name: &'static str,
    pub category: &'static str,
    pub severity: Severity,
    pub description: &'static str,
    pub pattern: Regex,
}

macro_rules! rule {
    ($name:expr, $category:expr, $severity:expr, $description:expr, $pattern:expr) => {
        Rule {
            name: $name,
            category: $category,
            severity: $severity,
            description: $description,
            pattern: Regex::new($pattern).expect("invalid regex pattern"),
        }
    };
}

/// Builds the full set of vulnerability detection rules.
///
/// Rules are intentionally line-based regexes (no lookaround, since the
/// `regex` crate doesn't support it) so some are heuristics rather than
/// proof of a vulnerability - review matches with that in mind. Where
/// possible, patterns are written to avoid flagging the *safe* form of an
/// API (e.g. parameterized SQL, list-form subprocess calls) so results stay
/// actionable instead of drowning in noise.
pub fn all_rules() -> Vec<Rule> {
    vec![
        // --- Code injection / command execution ---
        rule!(
            "eval-exec",
            "Code Injection",
            Severity::High,
            "Dynamic evaluation of code (eval/exec) can execute arbitrary code if the input is attacker-controlled.",
            r"\b(eval|exec)\s*\("
        ),
        rule!(
            "os-system",
            "Command Injection",
            Severity::High,
            "os.system() runs a command through the shell; untrusted input enables command injection.",
            r"\bos\.system\s*\("
        ),
        rule!(
            "os-popen",
            "Command Injection",
            Severity::High,
            "os.popen() runs a command through the shell; untrusted input enables command injection.",
            r"\bos\.popen\s*\("
        ),
        rule!(
            "subprocess-shell-true",
            "Command Injection",
            Severity::Critical,
            "subprocess call with shell=True is vulnerable to command injection when arguments include untrusted input.",
            r"subprocess\.\w+\([^)]*shell\s*=\s*True"
        ),
        rule!(
            "subprocess-call",
            "Command Injection",
            Severity::Low,
            "subprocess call found; generally safe when using a list of arguments without shell=True, but verify untrusted input is not interpolated.",
            r"\bsubprocess\.(Popen|call|run|check_output|check_call)\s*\("
        ),
        // --- Insecure deserialization ---
        rule!(
            "pickle-load",
            "Insecure Deserialization",
            Severity::High,
            "Unpickling untrusted data can lead to arbitrary code execution.",
            r"\bpickle\.(load|loads)\s*\("
        ),
        rule!(
            "yaml-unsafe-load",
            "Insecure Deserialization",
            Severity::Medium,
            "yaml.load() without Loader=yaml.SafeLoader can execute arbitrary code; use yaml.safe_load() instead.",
            r"\byaml\.load\s*\("
        ),
        rule!(
            "marshal-loads",
            "Insecure Deserialization",
            Severity::Medium,
            "marshal is not intended to be secure against malicious data; avoid loading untrusted input.",
            r"\bmarshal\.loads?\s*\("
        ),
        // --- Django / template XSS ---
        rule!(
            "django-mark-safe",
            "Cross-Site Scripting (XSS)",
            Severity::Medium,
            "Marking content as safe disables Django's autoescaping; ensure the content cannot contain attacker-controlled HTML.",
            r"\b(mark_safe|SafeText|SafeString|SafeBytes|SafeUnicode)\b"
        ),
        rule!(
            "template-autoescape-false",
            "Cross-Site Scripting (XSS)",
            Severity::Medium,
            "Disabling autoescaping can expose templates to XSS if user input is rendered.",
            r"\bautoescape\s*=\s*False\b"
        ),
        rule!(
            "ssti-render-template-string",
            "Server-Side Template Injection (SSTI)",
            Severity::High,
            "Rendering a template string built from an f-string may allow server-side template injection if it includes user input.",
            r#"\brender_template_string\s*\(\s*f['"]"#
        ),
        // --- Path traversal (only when the path looks attacker-influenced) ---
        rule!(
            "path-traversal-tainted-source",
            "Path Traversal",
            Severity::High,
            "A file path is built directly from user-controlled input (request data, input(), sys.argv, or environment variables); validate/sanitize it to prevent path traversal.",
            r"\b(open|os\.path\.join|Path)\s*\([^)]*(request\.(args|form|GET|POST|values|files)|input\s*\(|sys\.argv|os\.environ)"
        ),
        rule!(
            "path-traversal-fstring",
            "Path Traversal",
            Severity::Medium,
            "File path built from an f-string; verify interpolated values cannot escape the intended directory.",
            r#"\b(open|os\.path\.join|Path)\s*\(\s*f['"]"#
        ),
        rule!(
            "path-traversal-concat",
            "Path Traversal",
            Severity::Medium,
            "File path built via string concatenation; verify the appended value cannot escape the intended directory.",
            r"\b(open|os\.path\.join|Path)\s*\([^)]*\+[^)]*\)"
        ),
        // --- SQL injection ---
        rule!(
            "sql-fstring",
            "SQL Injection",
            Severity::High,
            "f-string interpolated directly into a SQL execute() call; use parameterized queries instead.",
            r#"\.execute\s*\(\s*f['"]"#
        ),
        rule!(
            "sql-percent-format",
            "SQL Injection",
            Severity::High,
            "The query string is %-formatted before being passed to execute(); pass parameters as a second argument instead (e.g. execute(query, (value,))).",
            r#"\.execute\s*\(\s*f?['"][^'"]*['"]\s*%\s*"#
        ),
        rule!(
            "sql-string-concat",
            "SQL Injection",
            Severity::High,
            "String concatenation used to build a SQL query; use parameterized queries instead.",
            r#"\.execute\s*\([^)]*(['"]\s*\+|\+\s*['"])"#
        ),
        rule!(
            "sql-format-method",
            "SQL Injection",
            Severity::High,
            ".format() used to build a SQL query; use parameterized queries instead.",
            r"\.execute\s*\([^)]*\.format\([^)]*\)"
        ),
        // --- Weak cryptography ---
        rule!(
            "weak-hash-md5",
            "Weak Cryptography",
            Severity::Medium,
            "MD5 is cryptographically broken; use hashlib.sha256 or better.",
            r"\bhashlib\.md5\s*\("
        ),
        rule!(
            "weak-hash-sha1",
            "Weak Cryptography",
            Severity::Medium,
            "SHA-1 is cryptographically weak; use hashlib.sha256 or better.",
            r"\bhashlib\.sha1\s*\("
        ),
        rule!(
            "insecure-random",
            "Weak Cryptography",
            Severity::Info,
            "The random module is not cryptographically secure; use the secrets module for tokens, passwords, or keys.",
            r"\brandom\.(random|randint|randrange|choice|shuffle)\s*\("
        ),
        // --- Hardcoded secrets (variable-name heuristic) ---
        rule!(
            "hardcoded-secret",
            "Hardcoded Secret",
            Severity::High,
            "Possible hardcoded credential; load secrets from environment variables or a secrets manager instead.",
            r#"(?i)\b[a-z0-9_]*(password|passwd|secret|api_key|apikey|access_key|access_token|auth_token|private_key|client_secret)[a-z0-9_]*\s*=\s*['"][^'"\s]{3,}['"]"#
        ),
        // --- Hardcoded secrets (value-pattern heuristics - low false-positive rate) ---
        rule!(
            "aws-access-key-id",
            "Hardcoded Secret",
            Severity::Critical,
            "Hardcoded AWS Access Key ID detected; rotate the key immediately and load credentials from the environment or a secrets manager.",
            r"\bAKIA[0-9A-Z]{16}\b"
        ),
        rule!(
            "private-key-block",
            "Hardcoded Secret",
            Severity::Critical,
            "Private key material is embedded directly in source code.",
            r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
        ),
        rule!(
            "slack-token",
            "Hardcoded Secret",
            Severity::High,
            "Hardcoded Slack token detected; revoke it and load it from a secrets manager instead.",
            r"\bxox[baprs]-[0-9A-Za-z-]{10,}"
        ),
        rule!(
            "github-token",
            "Hardcoded Secret",
            Severity::High,
            "Hardcoded GitHub token detected; revoke it and load it from a secrets manager instead.",
            r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"
        ),
        rule!(
            "hardcoded-jwt",
            "Hardcoded Secret",
            Severity::Medium,
            "Possible hardcoded JWT detected; tokens embedded in source code can be extracted and replayed.",
            r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
        ),
        // --- XXE ---
        rule!(
            "xxe-etree",
            "XML External Entity (XXE)",
            Severity::Medium,
            "Parsing XML with the standard library is vulnerable to XXE attacks; use defusedxml instead.",
            r"\bxml\.etree\.ElementTree\.(parse|fromstring|iterparse)\s*\("
        ),
        rule!(
            "xxe-lxml",
            "XML External Entity (XXE)",
            Severity::Medium,
            "lxml is vulnerable to XXE by default unless entity resolution is disabled; pass resolve_entities=False.",
            r"\blxml\.etree\.(parse|fromstring|XMLParser)\s*\("
        ),
        // --- SSRF ---
        rule!(
            "ssrf-dynamic-url",
            "Server-Side Request Forgery (SSRF)",
            Severity::Medium,
            "HTTP request built from an f-string URL; if the value is user-controlled this may allow SSRF.",
            r#"\brequests\.(get|post|put|delete|head|patch)\s*\(\s*f['"]"#
        ),
        // --- Insecure temp files ---
        rule!(
            "insecure-tempfile",
            "Insecure Temp File",
            Severity::Medium,
            "tempfile.mktemp() is subject to a race condition; use tempfile.mkstemp() or NamedTemporaryFile() instead.",
            r"\btempfile\.mktemp\s*\("
        ),
        // --- Insecure configuration ---
        rule!(
            "django-debug-true",
            "Insecure Configuration",
            Severity::Medium,
            "Django DEBUG=True leaks stack traces, settings, and source snippets on error pages; disable it in production.",
            r"\bDEBUG\s*=\s*True\b"
        ),
        rule!(
            "flask-debug-true",
            "Insecure Configuration",
            Severity::High,
            "Running Flask/Werkzeug with debug=True enables an interactive debugger that allows remote code execution if exposed.",
            r"\.run\s*\([^)]*debug\s*=\s*True"
        ),
        rule!(
            "flask-bind-all-interfaces",
            "Insecure Configuration",
            Severity::Low,
            "Binding to 0.0.0.0 exposes the service on every network interface; make sure this is intentional.",
            r#"\.run\s*\([^)]*host\s*=\s*['"]0\.0\.0\.0['"]"#
        ),
        // --- TLS / SSL ---
        rule!(
            "tls-verify-disabled",
            "Insecure TLS Configuration",
            Severity::High,
            "TLS certificate verification is disabled, allowing man-in-the-middle attacks.",
            r"\b(requests|httpx|urllib3|session)\.\w+\([^)]*verify\s*=\s*False"
        ),
        rule!(
            "ssl-cert-none",
            "Insecure TLS Configuration",
            Severity::High,
            "ssl.CERT_NONE disables certificate validation entirely.",
            r"\bssl\.CERT_NONE\b"
        ),
        rule!(
            "ssl-unverified-context",
            "Insecure TLS Configuration",
            Severity::High,
            "ssl._create_unverified_context() disables certificate validation entirely.",
            r"\bssl\._create_unverified_context\b"
        ),
        // --- CORS ---
        rule!(
            "cors-wildcard-origin",
            "Cross-Origin Resource Sharing (CORS)",
            Severity::Medium,
            "Allowing the wildcard origin (\"*\") lets any website make cross-origin requests to this service.",
            r#"(?i)['"]?origins?['"]?\s*[:=]\s*['"]\*['"]"#
        ),
        // --- Cookies ---
        rule!(
            "insecure-cookie-flag",
            "Insecure Cookie",
            Severity::Medium,
            "Setting a cookie with secure=False or httponly=False makes it accessible over plain HTTP or to client-side scripts.",
            r"\.set_cookie\s*\([^)]*(secure|httponly)\s*=\s*False"
        ),
        // --- Open redirect ---
        rule!(
            "open-redirect",
            "Open Redirect",
            Severity::Medium,
            "Redirecting directly to a URL taken from request data may allow open redirect attacks.",
            r"\bredirect\s*\(\s*request\.(args|form|GET|POST|values)"
        ),
        // --- File permissions ---
        rule!(
            "insecure-chmod",
            "Insecure File Permissions",
            Severity::Medium,
            "Setting file permissions to 0o777 grants world write access.",
            r"\bos\.chmod\s*\([^)]*0o?777\b"
        ),
        // --- JWT handling ---
        rule!(
            "jwt-verify-disabled",
            "Insecure JWT Handling",
            Severity::High,
            "Decoding a JWT with verify=False skips signature validation, allowing token forgery.",
            r"\bjwt\.decode\s*\([^)]*verify\s*=\s*False"
        ),
        rule!(
            "jwt-alg-none",
            "Insecure JWT Handling",
            Severity::High,
            "Accepting the \"none\" algorithm allows an attacker to forge unsigned JWTs.",
            r#"(?i)algorithms?\s*=\s*\[?\s*['"]none['"]"#
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(rule_name: &str, line: &str) -> bool {
        all_rules()
            .into_iter()
            .find(|r| r.name == rule_name)
            .unwrap_or_else(|| panic!("no rule named {rule_name}"))
            .pattern
            .is_match(line)
    }

    #[test]
    fn all_rules_compile_and_have_unique_names() {
        let rules = all_rules();
        assert!(!rules.is_empty());
        let mut names: Vec<&str> = rules.iter().map(|r| r.name).collect();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), rules.len(), "rule names must be unique");
    }

    #[test]
    fn detects_eval_exec() {
        assert!(matches("eval-exec", "eval(user_input)"));
        assert!(matches("eval-exec", "result = exec(code)"));
        assert!(!matches("eval-exec", "evaluate(x)"));
    }

    #[test]
    fn detects_os_command_execution() {
        assert!(matches("os-system", "os.system(cmd)"));
        assert!(matches("os-popen", "os.popen(cmd)"));
    }

    #[test]
    fn detects_subprocess_shell_true() {
        assert!(matches(
            "subprocess-shell-true",
            "subprocess.run(cmd, shell=True)"
        ));
        assert!(!matches("subprocess-shell-true", "subprocess.run(cmd)"));
    }

    #[test]
    fn detects_pickle_and_yaml() {
        assert!(matches("pickle-load", "data = pickle.loads(raw)"));
        assert!(matches("yaml-unsafe-load", "cfg = yaml.load(f)"));
    }

    #[test]
    fn detects_django_mark_safe() {
        assert!(matches("django-mark-safe", "return mark_safe(html)"));
    }

    #[test]
    fn detects_ssti() {
        assert!(matches(
            "ssti-render-template-string",
            r#"return render_template_string(f"Hello {name}")"#
        ));
        assert!(!matches(
            "ssti-render-template-string",
            r#"return render_template_string("Hello {{ name }}", name=name)"#
        ));
    }

    #[test]
    fn detects_sql_injection_patterns_and_ignores_parameterized_queries() {
        assert!(matches(
            "sql-fstring",
            r#"cursor.execute(f"SELECT * FROM users WHERE id = {uid}")"#
        ));
        assert!(matches(
            "sql-string-concat",
            r#"cursor.execute("SELECT * FROM users WHERE id = " + uid)"#
        ));
        assert!(matches(
            "sql-percent-format",
            r#"cursor.execute("SELECT * FROM users WHERE id = %s" % uid)"#
        ));

        // Safe, parameterized form must NOT be flagged by any SQL rule.
        let safe = r#"cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))"#;
        assert!(!matches("sql-percent-format", safe));
        assert!(!matches("sql-string-concat", safe));
        assert!(!matches("sql-fstring", safe));
    }

    #[test]
    fn detects_weak_hashes() {
        assert!(matches("weak-hash-md5", "hashlib.md5(data)"));
        assert!(matches("weak-hash-sha1", "hashlib.sha1(data)"));
    }

    #[test]
    fn detects_hardcoded_secret_including_compound_names() {
        assert!(matches("hardcoded-secret", "password = \"hunter2\""));
        assert!(matches("hardcoded-secret", "API_KEY = 'sk-abc123xyz'"));
        assert!(matches("hardcoded-secret", "DB_PASSWORD = \"hunter2\""));
        assert!(matches(
            "hardcoded-secret",
            "SECRET_KEY = \"django-insecure-xyz\""
        ));
        assert!(matches(
            "hardcoded-secret",
            "STRIPE_API_KEY = \"sk_live_abc\""
        ));
        assert!(!matches("hardcoded-secret", "password = get_password()"));
    }

    #[test]
    fn detects_value_pattern_secrets() {
        assert!(matches(
            "aws-access-key-id",
            "aws_key = \"AKIAABCDEFGHIJKLMNOP\""
        ));
        assert!(matches(
            "private-key-block",
            "-----BEGIN RSA PRIVATE KEY-----"
        ));
        assert!(matches("slack-token", "token = \"xoxb-1234567890-abcdef\""));
        assert!(matches(
            "github-token",
            "gh = \"ghp_abcdefghijklmnopqrstuvwxyz0123456789\""
        ));
        assert!(matches(
            "hardcoded-jwt",
            "jwt = \"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123signature\""
        ));
    }

    #[test]
    fn detects_xxe() {
        assert!(matches(
            "xxe-etree",
            "tree = xml.etree.ElementTree.parse(untrusted)"
        ));
        assert!(matches("xxe-lxml", "lxml.etree.fromstring(untrusted)"));
    }

    #[test]
    fn detects_ssrf_dynamic_url() {
        assert!(matches(
            "ssrf-dynamic-url",
            r#"requests.get(f"{base}/{path}")"#
        ));
    }

    #[test]
    fn detects_insecure_tempfile() {
        assert!(matches("insecure-tempfile", "path = tempfile.mktemp()"));
    }

    #[test]
    fn detects_insecure_configuration() {
        assert!(matches("django-debug-true", "DEBUG = True"));
        assert!(matches("flask-debug-true", "app.run(debug=True)"));
        assert!(matches(
            "flask-bind-all-interfaces",
            "app.run(host=\"0.0.0.0\")"
        ));
    }

    #[test]
    fn detects_insecure_tls() {
        assert!(matches(
            "tls-verify-disabled",
            "requests.get(url, verify=False)"
        ));
        assert!(matches("ssl-cert-none", "ctx.verify_mode = ssl.CERT_NONE"));
        assert!(matches(
            "ssl-unverified-context",
            "ctx = ssl._create_unverified_context()"
        ));

        // jwt.decode(verify=False) is a JWT issue, not a TLS one - it must
        // only be reported once, by jwt-verify-disabled, not mislabeled here too.
        assert!(!matches(
            "tls-verify-disabled",
            "jwt.decode(token, verify=False)"
        ));
    }

    #[test]
    fn detects_cors_wildcard() {
        assert!(matches(
            "cors-wildcard-origin",
            "CORS(app, resources={r\"/*\": {\"origins\": \"*\"}})"
        ));
    }

    #[test]
    fn detects_insecure_cookie() {
        assert!(matches(
            "insecure-cookie-flag",
            "resp.set_cookie(\"session\", token, secure=False)"
        ));
    }

    #[test]
    fn detects_open_redirect() {
        assert!(matches(
            "open-redirect",
            "return redirect(request.args.get(\"next\"))"
        ));
        assert!(!matches("open-redirect", "return redirect(\"/home\")"));
    }

    #[test]
    fn detects_insecure_chmod() {
        assert!(matches("insecure-chmod", "os.chmod(path, 0o777)"));
    }

    #[test]
    fn detects_insecure_jwt_handling() {
        assert!(matches(
            "jwt-verify-disabled",
            "jwt.decode(token, verify=False)"
        ));
        assert!(matches(
            "jwt-alg-none",
            "jwt.decode(token, algorithms=[\"none\"])"
        ));
    }

    #[test]
    fn path_traversal_requires_dynamic_or_tainted_path() {
        assert!(matches(
            "path-traversal-tainted-source",
            "open(request.args.get(\"file\"))"
        ));
        assert!(matches(
            "path-traversal-fstring",
            "open(f\"{base_dir}/{name}\")"
        ));
        assert!(matches(
            "path-traversal-concat",
            "open(base_dir + filename)"
        ));

        // Hardcoded, literal paths should not be flagged at all - this used
        // to fire on every open() call regardless of where the path came from.
        for rule_name in [
            "path-traversal-tainted-source",
            "path-traversal-fstring",
            "path-traversal-concat",
        ] {
            assert!(!matches(rule_name, "open(\"config.json\")"));
        }
    }
}
