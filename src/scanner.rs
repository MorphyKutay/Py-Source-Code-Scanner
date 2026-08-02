use crate::finding::Finding;
use crate::rules::all_rules;
use std::path::Path;
use walkdir::{DirEntry, WalkDir};

/// Directories that are never useful to scan and commonly huge (VCS metadata,
/// virtualenvs, caches, vendored dependencies).
const EXCLUDED_DIRS: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".tox",
    "node_modules",
    "site-packages",
    "dist",
    "build",
    ".idea",
];

fn is_excluded(entry: &DirEntry) -> bool {
    entry.file_type().is_dir()
        && entry
            .file_name()
            .to_str()
            .map(|name| EXCLUDED_DIRS.contains(&name))
            .unwrap_or(false)
}

/// Scans every `.py` file under `root` and returns all findings, sorted by
/// severity (most severe first) then by file/line.
///
/// I/O errors on individual files are reported to stderr and otherwise
/// skipped rather than aborting the whole scan.
pub fn scan_path(root: &str) -> Vec<Finding> {
    let rules = all_rules();
    let mut findings = Vec::new();

    let walker = WalkDir::new(root)
        .into_iter()
        .filter_entry(|e| !is_excluded(e));

    for entry in walker {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                eprintln!("[!] Failed to read directory entry: {err}");
                continue;
            }
        };

        let path = entry.path();
        if !path.is_file() || path.extension().and_then(|e| e.to_str()) != Some("py") {
            continue;
        }

        findings.extend(scan_file(path, &rules));
    }

    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
    });

    findings
}

fn scan_file(path: &Path, rules: &[crate::rules::Rule]) -> Vec<Finding> {
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) => {
            eprintln!("[!] Failed to read {}: {err}", path.display());
            return Vec::new();
        }
    };

    let file = path.to_string_lossy().to_string();
    let mut findings = Vec::new();

    for (line_number, line) in contents.lines().enumerate() {
        for rule in rules {
            if rule.pattern.is_match(line) {
                findings.push(Finding {
                    file: file.clone(),
                    line: line_number + 1,
                    code: line.to_string(),
                    rule: rule.name.to_string(),
                    category: rule.category.to_string(),
                    severity: rule.severity,
                    description: rule.description.to_string(),
                });
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_excluded_directories() {
        let dir = tempdir();
        std::fs::create_dir_all(dir.join(".venv")).unwrap();
        std::fs::write(dir.join(".venv/vulnerable.py"), "eval(x)\n").unwrap();
        std::fs::write(dir.join("app.py"), "eval(x)\n").unwrap();

        let findings = scan_path(dir.to_str().unwrap());
        assert_eq!(findings.len(), 1);
        assert!(findings[0].file.ends_with("app.py"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn only_scans_python_files() {
        let dir = tempdir();
        std::fs::write(dir.join("notes.txt"), "eval(x)\n").unwrap();
        std::fs::write(dir.join("app.py"), "eval(x)\n").unwrap();

        let findings = scan_path(dir.to_str().unwrap());
        assert_eq!(findings.len(), 1);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Minimal unique-directory helper so tests don't depend on the `tempfile` crate.
    fn tempdir() -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        let unique = format!(
            "py-scanner-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        path.push(unique);
        std::fs::create_dir_all(&path).unwrap();
        path
    }
}
