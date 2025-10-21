use serde_json::Value;
use crate::TestcaseContent;
use anyhow::{anyhow, Result};

mod calc;

pub fn run_action(case: TestcaseContent) -> Result<Value> {
    match case.action.as_str() {
        "calc" => {
            return calc::run_action(case.arguments);
        },
        _ => Err(anyhow!("Action {:?} not found!", case.action)),
    }
}