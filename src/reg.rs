use regex::Regex;

pub fn reg() -> Regex {
    Regex::new(r"\b(eval|exec|os\.system|subprocess\.(Popen|call)|open|pickle\.load)\b")
        .expect("Invalid regex pattern")
}