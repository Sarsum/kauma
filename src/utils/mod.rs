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
    // only calculate the degree of the divisor and dividend once and subtracting one per loop for dividend
    let degree_divisor = 127 - divisor.leading_zeros();
    let degree_dividend = 127 - dividend.leading_zeros();

    // cannot divide anything 
    if degree_dividend < degree_divisor {
        return Ok((0, dividend))
    }
    
    let mut quotient = 0u128;
    let mut remainder = dividend;

    let mut shift = degree_dividend - degree_divisor;

    loop {
        let bit_pos = degree_divisor + shift;
        
        if remainder & (1u128 << bit_pos) != 0 {
            // Add dividend degree to quotient
            quotient ^= 1u128 << shift;
            // Eliminate the hightest exponent
            remainder ^= divisor << shift;
        }
        if shift == 0 {
            break;
        }
        shift -= 1;
    }
    Ok((quotient, remainder))
}