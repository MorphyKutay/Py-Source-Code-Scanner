use regex::Regex;
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{self, Write, Read, Seek};

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

fn append_to_file(filename: &str, new_content: &str) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open(filename)?;


    if file.metadata()?.len() > 0 {
        writeln!(file)?;
    }


    file.write_all(new_content.as_bytes())?;
    Ok(())
}


pub fn process_file(path: &str) -> std::io::Result<()> {
    let contents = fs::read_to_string(path)?;
    let risky_lines = check_risk(&contents);
    
    if !risky_lines.is_empty() {
        println!("[!] Potential Django XSS Vulnerability Found");
        println!("File: {}", path);
        for (line_number, line) in risky_lines {
            println!("Line {}: {}\n-----", line_number, line);

            let filename = "output.txt";
            let new_content = format!("\n-------\n [!] Potential XSS Vulnerability Found\n Line Number : {}\n Line : {}\n File : {} \n-------\n", line_number, line,path);

            append_to_file(filename, &new_content)?;

        }
    }
    
    Ok(())
}
