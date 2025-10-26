use num::{BigInt};
use num::traits::{ToPrimitive, Signed};
use serde_json::{Number, Value};

pub fn to_number(value: BigInt) -> Value {
    return if let Some(num) = value.to_i32() {
        Value::Number(Number::from(num))
    } else {
        let mut result = String::new();
        if value.is_negative() {
            result.push('-');
        }
        result.push_str("0x");
        result.push_str(&value.abs().to_str_radix(16));
        return Value::String(result);
    }
}