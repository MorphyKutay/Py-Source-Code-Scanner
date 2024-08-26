use regex::Regex;
use std::fs;

pub fn check_risk(contents: &str) -> Vec<(usize, String)> {
    let mut results = Vec::new();
    let re = Regex::new(r"mark_safe|SafeText|SafeUnicode|SafeString|SafeBytes").unwrap();
    
    for (line_number, line) in contents.lines().enumerate() {
        if re.is_match(line) {
            results.push((line_number + 1, line.to_string())); // +1 for 1-based index
        }
    }
    
    results
}

pub fn process_file(path: &str) -> std::io::Result<()> {
    let contents = fs::read_to_string(path)?;
    let risky_lines = check_risk(&contents);
    
    if !risky_lines.is_empty() {
        println!("[!] Potential Django XSS Vulnerability Found");
        println!("File: {}", path);
        for (line_number, line) in risky_lines {
            println!("Line {}: {}\n-----", line_number, line);
        }
    }
    
    Ok(())
}
