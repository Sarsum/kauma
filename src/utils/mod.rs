use anyhow::{Result, anyhow};
use num::{BigInt};
use num::traits::{ToPrimitive, Signed};
use serde_json::{Number, Value};

pub mod aes;
pub mod gf;
pub mod gf_poly;

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


/// Divmod method supporting 128 bit polynoms with x^0 = LSB!
pub fn divmod(dividend: u128, divisor: u128) -> Result<(u128, u128)> {
    if divisor == 0 {
        return Err(anyhow!("Divmod: division by zero!"))
    }
    if dividend == 0 {
        return Ok((0, 0));
    }
    // only calculate the degree of the divisor once
    let degree_divisor = 127 - divisor.leading_zeros();
    let mut quotient = 0u128;
    let mut remainder = dividend;

    while remainder != 0 {
        let degree_remainer = 127 - remainder.leading_zeros();
        if degree_remainer < degree_divisor {
            break;
        }
        
        // Add dividend degree to quotient
        quotient ^= 1u128 << (degree_remainer - degree_divisor);
        // Eliminate the hightest exponent
        remainder ^= divisor << (degree_remainer - degree_divisor);
    }
    Ok((quotient, remainder))
}