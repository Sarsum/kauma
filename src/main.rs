mod actions;
pub(crate) mod utils;

use std::{env, fs::File};

use anyhow::Result;
use num::{BigInt, Num};
use serde::Deserialize;
use serde_json::{json, Map, Value};

#[derive(Deserialize)]
pub struct TestcaseContent {
    action: String,
    arguments: Value
}

#[derive(Deserialize)]
struct TestcaseFile {
    testcases: Map<String, Value>
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        std::process::exit(1);
    }
    // first arg is program name, e.g. "kauma"
    let input_path = &args[1];
    //run_exercise_file(input_path);

    if let Some(testcases) = get_exercises_from_file(input_path) {
        run_exercises(testcases);
    }

    let num = BigInt::from_str_radix("-80000001", 16);
    match num {
        Ok(number) => println!("{}", number.to_str_radix(10)),
        Err(err) => println!("{}", err.to_string())
    }
}

fn get_exercises_from_file(filename: &String) -> Option<TestcaseFile> {
    match File::open(filename) {
        Ok(file) => {
            let parsed: Result<TestcaseFile, serde_json::Error> = serde_json::from_reader(file);
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

fn run_exercises(testcases: TestcaseFile) {
    for (name, content) in testcases.testcases {
        let parsed_case: Result<TestcaseContent, serde_json::Error> = serde_json::from_value(content);
        match parsed_case {
            Ok(case) => run_exercise(name, case),
            Err(error) => {
                eprintln!("Error parsing case {}, error: {}", name, error.to_string())
            }
        }
    }
}

fn run_exercise(case_name: String, case: TestcaseContent) {
    match actions::run_action(case) {
        Ok(result) => {
            let json = json!({"id": case_name, "reply": result});
            if let Ok(json_value) = serde_json::to_string(&json) {
                println!("{}", json_value);
            }
        }
        Err(error) => {
            eprintln!("Case {} failed with the error: {}", case_name, error.to_string())
        }
    }
}
