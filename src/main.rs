use clap::{Parser};
use regex::{Regex, Captures};
use walkdir::WalkDir;
use std::io;
use std::fs;
use figlet_rs::FIGfont;

mod reg;
use reg::reg;

mod django;


#[derive(Parser, Debug)]
#[command(author = "MorphyKutay", version = "1.0", about = "Python Vulnerability Scanner")]
struct Args {
    #[arg(short, long, help = "Path to the file to be processed")]
    path: String,
}

fn main() -> io::Result<()> {
    let text = "Py Scanner";
    let figfont = FIGfont::standard().unwrap();
    let rendered = figfont.convert(text).unwrap();
    println!("{}", rendered);

    let args = Args::parse();
    let folder = args.path;

    for entry in WalkDir::new(folder) {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() {
            if let Some(extension) = path.extension() {
                if extension == "py" {
                    let contents = fs::read_to_string(path)?;

                    let pattern = reg();
                    let lines: Vec<String> = contents.lines().map(|s| s.to_string()).collect();
                    // django.rs kontrol
                    django::process_file(path.to_str().unwrap())?;
                    
                    //reg.rs kontrol
                    for (line_number, line) in lines.iter().enumerate() {
                        let line_number_1_based = line_number + 1;
                        if pattern.is_match(line) {
                            println!("[!] Potential Vulnerability Found");
                            println!("File: {}", path.display());
                            println!("Line {}: {}\n------", line_number_1_based, line);
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
