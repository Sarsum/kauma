
use num::{BigInt, FromPrimitive, Num};
use num::traits::{ToPrimitive, Signed};
use serde_json::{Number, Value};

pub fn util() {
    
}

pub fn parse_number(value: &Value) -> Option<BigInt> {
    if value.is_number() {
        return match value.as_i64() {
            Some(n) => {
                return match BigInt::from_i64(n) {
                    Some(n) => Some(n),
                    None => None
                };
            }
            None => None
        };
    }

    if value.is_string() {
        if let Some(string_num) = value.as_str() {
            let (sign, digits) = if string_num.starts_with("-0x") {
                (-1, &string_num[3..])
            } else if string_num.starts_with("0x") {
                (1, &string_num[2..])
            } else {
                return None
            };

            return match BigInt::from_str_radix(digits, 16) {
                Ok(num) => {
                    Some(num * sign)
                },
                Err(_) => None 
            }
        };
    }
    None
}

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