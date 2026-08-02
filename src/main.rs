use clap::{Parser, ValueEnum};
use figlet_rs::FIGfont;
use main::finding::Severity;
use main::{output, scan_path};
use std::process::ExitCode;

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum Format {
    Text,
    Json,
}

#[derive(Parser, Debug)]
#[command(
    author = "MorphyKutay",
    version = "2.0",
    about = "Python Vulnerability Scanner"
)]
struct Args {
    #[arg(short, long, help = "Path to the file or directory to be scanned")]
    path: String,

    #[arg(
        short,
        long,
        help = "Write findings to this file instead of (or in addition to) stdout"
    )]
    output: Option<String>,

    #[arg(short, long, value_enum, default_value_t = Format::Text, help = "Output format")]
    format: Format,

    #[arg(long, help = "Suppress the startup banner")]
    no_banner: bool,

    #[arg(long, help = "Disable ANSI colors in text output")]
    no_color: bool,
}

fn main() -> ExitCode {
    let args = Args::parse();

    if !args.no_banner {
        if let Ok(figfont) = FIGfont::standard() {
            if let Some(rendered) = figfont.convert("Py Scanner") {
                println!("{}", rendered);
            }
        }
    }

    let findings = scan_path(&args.path);

    let file_output_is_text = args.format == Format::Text;
    match args.format {
        Format::Text => {
            let use_color = !args.no_color && args.output.is_none();
            print!("{}", output::render_text(&findings, use_color));

            let summary = output::summarize_by_severity(&findings);
            if !summary.is_empty() {
                println!("Summary:");
                for (severity, count) in &summary {
                    println!("  {severity}: {count}");
                }
            }
        }
        Format::Json => match output::render_json(&findings) {
            Ok(json) => println!("{json}"),
            Err(err) => {
                eprintln!("[!] Failed to serialize findings as JSON: {err}");
                return ExitCode::FAILURE;
            }
        },
    }

    if let Some(path) = &args.output {
        let contents = if file_output_is_text {
            output::render_text(&findings, false)
        } else {
            match output::render_json(&findings) {
                Ok(json) => json,
                Err(err) => {
                    eprintln!("[!] Failed to serialize findings as JSON: {err}");
                    return ExitCode::FAILURE;
                }
            }
        };

        if let Err(err) = output::write_to_file(path, &contents) {
            eprintln!("[!] Failed to write output file {path}: {err}");
            return ExitCode::FAILURE;
        }
    }

    let has_high_severity = findings.iter().any(|f| f.severity >= Severity::High);

    if has_high_severity {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
