use anyhow::{anyhow, Result};
use num::{BigInt, Zero};
use serde_json::{json, Value};

use crate::utils::{parse_number, to_number};

pub fn run_action(arguments: Value) -> Result<Value> {
    super::super::utils::util();

    if let Some(result) = calculate(arguments)  {
        let ret_value = to_number(result);
        return Ok(json!({"answer": ret_value}));
    }
    Err(anyhow!("Action did not return a number"))
}

fn calculate(arguments: Value) -> Option<BigInt> {
    let lhs_raw = &arguments["lhs"];
    let op_raw = &arguments["op"];
    let rhs_raw = &arguments["rhs"];

    let lhs_parsed = parse_number(lhs_raw);
    let op_parsed = op_raw.as_str();
    let rhs_parsed = parse_number(rhs_raw);

    if let (Some(lhs), Some(op), Some(rhs)) = (lhs_parsed, op_parsed, rhs_parsed) {
        return match op {
            "+" => Some(lhs + rhs),
            "-" => Some(lhs - rhs),
            "*" => Some(lhs * rhs),
            "/" => {
                if rhs != BigInt::zero() {
                    return Some(lhs / rhs)
                }
                return None
            },
            _ => None
        }
    }

    None
}