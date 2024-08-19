use clap::{Parser, Command};
use regex::Regex;
use walkdir::WalkDir;
use std::io::{self, Read};
use std::fs;
use figlet_rs::FIGfont;


mod reg;
use reg::reg;


#[derive(Parser, Debug)]
#[command(author = "MorphyKutay", version = "1.0", about = "Python Vulnerable Scanner", long_about = None)]
struct Args {
 
    #[arg(short, long, help = "Path to the file to be processed")]
    path: String,

}



fn main()-> io::Result<()> {

    let text = "Py Scanner";
    let figfont = FIGfont::standard().unwrap();
    let rendered = figfont.convert(text).unwrap();
    println!("{}", rendered);

    let args = Args::parse();

    let mut folder = args.path;

    for entry in WalkDir::new(folder) {
        let entry = entry.unwrap();
        let dosya = entry.path();
       
        if dosya.is_file() {
            if let Some(extension) = dosya.extension() {
                if extension == "py" {
                    let contents = fs::read_to_string(dosya)?;
                    println!("File: {}\nVulnerable  Content:\n{}", dosya.display(), contents);

                    let pattern = reg();
                    for cap in pattern.captures_iter(&contents) {
                        println!("Vulnerable Function: {}", &cap[0]);
                    }
                }
            }
        }
    }




    
    Ok(())
}