use regex::Regex;
use std::fs;

pub fn check_path_traversal_risk(contents: &str) -> Vec<(usize, String)> {
    let mut results = Vec::new();

    let re = Regex::new(r"os\.path\.|open\(|Path\(").unwrap();

    for (line_number, line) in contents.lines().enumerate() {
        if re.is_match(line) {
            results.push((line_number + 1, line.to_string())); // 1 tabanlı dizin numaralandırma
        }
    }

    results
}

pub fn process_file_for_path_traversal(path: &str) -> std::io::Result<()> {
    let contents = fs::read_to_string(path)?;  // Dosya içeriğini oku
    let risky_lines = check_path_traversal_risk(&contents);

    if !risky_lines.is_empty() {
        println!("[!] Potential Path Traversal Vulnerability Found");
        println!("File: {}", path);
        for (line_number, line) in risky_lines {
            println!("Line {}: {}\n-----", line_number, line);
        }
    }

    Ok(())
}
