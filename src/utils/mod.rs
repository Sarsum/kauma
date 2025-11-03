use anyhow::{Result, anyhow};
use num::{BigInt};
use num::traits::{ToPrimitive, Signed};
use serde_json::{Number, Value};

pub mod aes;
pub mod gf;

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


/// Divmod method supporting 128 bit polynoms in AES-GCM notation!
/// Due to the changed order, the the reduction is a left-shift
pub fn divmod(dividend: u128, divisor: u128) -> Result<(u128, u128)> {
    if divisor == 0 {
        return Err(anyhow!("Divmod: division by zero!"))
    }
    // only calculate the degree of the divisor once
    let degree_divisor = 128 - divisor.trailing_zeros();
    let mut quotient = 0u128;
    let mut remainder = dividend;

    while remainder != 0 {
        let degree_remainer = 128 - remainder.trailing_zeros();
        if degree_remainer < degree_divisor {
            break;
        }
        
        // Add divided degree to quotient
        quotient ^= 1u128 << (127 - (degree_remainer - degree_divisor));
        // Eliminate the hightest exponent
        remainder ^= divisor >> (degree_remainer - degree_divisor);
    }
    Ok((quotient, remainder))
}