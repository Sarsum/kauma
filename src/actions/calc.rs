use anyhow::{anyhow, Result};
use num::{BigInt, Zero};
use serde_json::{json, Value};

use crate::{actions::{ActionNumber}, utils::{to_number}};


pub fn run_action(lhs_wrapped: ActionNumber, op: String, rhs_wrapped: ActionNumber) -> Result<Value> {
    let lhs = lhs_wrapped.0;
    let rhs = rhs_wrapped.0;
    let calc = match op.as_str() {
        "+" => Some(lhs + rhs),
        "-" => Some(lhs - rhs),
        "*" => Some(lhs * rhs),
        "/" => {
            if rhs != BigInt::zero() {
                Some(lhs / rhs)
            } else {
                None
            }
        },
        _ => None
    };

    return match calc {
        Some(result) => {
            let ret_value = to_number(result);
            Ok(json!({"answer": ret_value}))
        }
        None => {
            Err(anyhow!("Action did not return a number"))
        }
    };
    
}