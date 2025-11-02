mod actions;
pub(crate) mod utils;

use std::{collections::HashMap, env, fs::File, io::BufReader};

use anyhow::Result;
use serde::Deserialize;
use serde_json::{json};

use crate::actions::{TryAction};

#[derive(Deserialize, Debug)]
struct TestcaseFile {
    testcases: HashMap<String, TryAction>
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        std::process::exit(1);
    }
    // first arg is program name, e.g. "kauma"
    let input_path = &args[1];

    if let Some(testcases) = get_exercises_from_file(input_path) {
        run_exercises(testcases, input_path);
    }
}


// returns none if either file cannot be opened or the json content is invalid
fn get_exercises_from_file(filename: &String) -> Option<TestcaseFile> {
    match File::open(filename) {
        Ok(file) => {
            let parsed: Result<TestcaseFile, serde_json::Error> = serde_json::from_reader(BufReader::new(file));
            match parsed {
                Ok(testcases) => return Some(testcases),
                Err(error) => {
                    eprintln!("Failed to parse json from test file: {}", error.to_string());
                    return None
                }
            }
        }
        Err(error) => {
            eprintln!("Failed to open file {}, error: {}", filename, error.to_string())
        }
    };
    return None
}

fn run_exercises(testcases: TestcaseFile, file_name: &String) {
    for (name, content) in testcases.testcases {
        match content {
            TryAction::Ok(action) => {
                match actions::run_action(action) {
                    Ok(result) => {
                        let json = json!({"id": name, "reply": result});
                        if let Ok(json_value) = serde_json::to_string(&json) {
                            println!("{}", json_value);
                        }
                    }
                    Err(error) => {
                        eprintln!("File \"{}\" Case \"{}\" failed with the error: {}", file_name, name, error.to_string())
                    }
                }
            }
            TryAction::Err(error) => {
                eprintln!("File \"{}\" Case \"{}\" failed to parse action, error: {}", file_name, name, error.to_string())
            }
        }
    }
}
