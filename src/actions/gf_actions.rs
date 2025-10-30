use anyhow::Result;
use base64::{Engine, prelude::BASE64_STANDARD};
use num::BigInt;
use serde_json::{Value, json};

use crate::{actions::ActionPoly, utils::{self, gf::{GF2m, P1, P2, ReducePoly}}};

pub fn run_gf_mul(a: u128, b: u128, poly: ActionPoly) -> Result<Value> {
    return match poly {
        ActionPoly::P1 => gf_mul::<P1>(a, b),
        ActionPoly::P2 => gf_mul::<P2>(a, b),
    }
}

fn gf_mul<M: ReducePoly>(a: u128, b: u128) -> Result<Value> {
    let a_typed = GF2m::<M>::new(a);
    let b_typed = GF2m::<M>::new(b);
    let y = BASE64_STANDARD.encode((a_typed * b_typed).value.to_be_bytes());

    Ok(json!({"y": y}))
}

pub fn run_gf_pow(b: u128, exp: BigInt, poly: ActionPoly) -> Result<Value> {
    return match poly {
        ActionPoly::P1 => gf_pow::<P1>(b, exp),
        ActionPoly::P2 => gf_pow::<P2>(b, exp)
    }
}

fn gf_pow<M: ReducePoly>(b: u128, exp: BigInt) -> Result<Value> {
    eprintln!("Test: {:b}", (GF2m::<M>::new(1u128 << 126) * GF2m::<M>::new(1u128 << 126)).value);

    let result = GF2m::<M>::new(b).pow(exp);
    let y = BASE64_STANDARD.encode(result.value.to_be_bytes());

    Ok(json!({"y": y}))
}

pub fn run_gf_inv(x: u128, poly: ActionPoly) -> Result<Value> {
    return match poly {
        ActionPoly::P1 => gf_inv::<P1>(x),
        ActionPoly::P2 => gf_inv::<P2>(x)
    }
}

fn gf_inv<M: ReducePoly>(x: u128) -> Result<Value> {
    let result = GF2m::<M>::new(x).inv();
    let y = BASE64_STANDARD.encode(result.value.to_be_bytes());

    Ok(json!({"y": y}))
}

pub fn run_gf_div(a: u128, b: u128, poly: ActionPoly) -> Result<Value> {
    return match poly {
        ActionPoly::P1 => gf_div::<P1>(a, b),
        ActionPoly::P2 => gf_div::<P2>(a, b)
    }
}

fn gf_div<M: ReducePoly>(a: u128, b: u128) -> Result<Value> {
    let result = GF2m::<M>::new(a) / GF2m::<M>::new(b);
    let q = BASE64_STANDARD.encode(result.value.to_be_bytes());

    Ok(json!({"q": q}))
}

pub fn run_gf_sqrt(x: u128, poly: ActionPoly) -> Result<Value> {
    return match poly {
        ActionPoly::P1 => gf_sqrt::<P1>(x),
        ActionPoly::P2 => gf_sqrt::<P2>(x)
    }
}

fn gf_sqrt<M: ReducePoly>(x: u128) -> Result<Value> {
    let result = GF2m::<M>::new(x).sqrt();
    Ok(json!({"y": BASE64_STANDARD.encode(result.value.to_be_bytes())}))
}

pub fn run_gf_divmod(a: u128, b: u128) -> Result<Value> {
    let result = utils::divmod(a, b)?;
    Ok(json!({"q": BASE64_STANDARD.encode(result.0.to_be_bytes()),
            "r": BASE64_STANDARD.encode(result.1.to_be_bytes())}))
}