use anyhow::{Ok, Result};
use num::BigInt;
use serde_json::{Value, json};

use crate::{actions::{ActionGfPoly, ActionPoly}, utils::{gf::{P1, P2, ReducePoly}, gf_poly::{self, GF2mPoly}}};

pub fn run_gfpoly_sort(polys: Vec<ActionGfPoly>) -> Result<Value> {
    // parsing polynoms into typed (does not matter if P1 or P2) to use the sort implementation instead of writing a second
    let mut parsed: Vec<GF2mPoly<P1>> = Vec::with_capacity(polys.len());
    for poly in polys {
        parsed.push(GF2mPoly::<P1>::from_action_poly(poly));
    }
    parsed.sort();
    Ok(json!({"sorted": parsed}))
}

pub fn run_gfpoly_monic(a: ActionGfPoly, poly: ActionPoly) -> Result<Value> {
    return match poly {
        ActionPoly::P1 => gfpoly_monic::<P1>(a),
        ActionPoly::P2 => gfpoly_monic::<P2>(a)
    }
}

fn gfpoly_monic<M: ReducePoly>(a: ActionGfPoly) -> Result<Value> {
    Ok(json!({"A*": GF2mPoly::<M>::from_action_poly(a).make_monic()}))
}

pub fn run_gfpoly_add(a: ActionGfPoly, b: ActionGfPoly, poly: ActionPoly) -> Result<Value> {
    return match poly {
        ActionPoly::P1 => gfpoly_add::<P1>(a, b),
        ActionPoly::P2 => gfpoly_add::<P2>(a, b)
    }
}

fn gfpoly_add<M: ReducePoly>(a: ActionGfPoly, b: ActionGfPoly) -> Result<Value> {
    let a = GF2mPoly::<M>::from_action_poly(a);
    let b = GF2mPoly::<M>::from_action_poly(b);
    let result = a + b;

    Ok(json!({"S": result}))
}

pub fn run_gfpoly_mul(a: ActionGfPoly, b: ActionGfPoly, poly: ActionPoly) -> Result<Value> {
    return match poly {
        ActionPoly::P1 => gfpoly_mul::<P1>(a, b),
        ActionPoly::P2 => gfpoly_mul::<P2>(a, b)
    }
}

fn gfpoly_mul<M: ReducePoly>(a: ActionGfPoly, b: ActionGfPoly) -> Result<Value> {
    let result = GF2mPoly::<M>::from_action_poly(a) * GF2mPoly::<M>::from_action_poly(b);
    Ok(json!({"P": result}))
}

pub fn run_gfpoly_divmod(a: ActionGfPoly, b: ActionGfPoly, poly: ActionPoly) -> Result<Value> {
    return match poly {
        ActionPoly::P1 => gfpoly_divmod::<P1>(a, b),
        ActionPoly::P2 => gfpoly_divmod::<P2>(a, b)
    }
}

fn gfpoly_divmod<M: ReducePoly>(a: ActionGfPoly, b: ActionGfPoly) -> Result<Value> {
    let a = GF2mPoly::<M>::from_action_poly(a);
    let b = GF2mPoly::<M>::from_action_poly(b);
    let (quotient, remainder) = gf_poly::divmod(a, &b);
    Ok(json!({"Q": quotient, "R": remainder}))
}

pub fn run_gfpoly_gcd(a: ActionGfPoly, b: ActionGfPoly, poly: ActionPoly) -> Result<Value> {
    return match poly {
        ActionPoly::P1 => gfpoly_gcd::<P1>(a, b),
        ActionPoly::P2 => gfpoly_gcd::<P2>(a, b)
    }
}

fn gfpoly_gcd<M: ReducePoly>(a: ActionGfPoly, b: ActionGfPoly) -> Result<Value> {
    let a = GF2mPoly::<M>::from_action_poly(a);
    let b = GF2mPoly::<M>::from_action_poly(b);
    let result = gf_poly::gcd(a, b);
    Ok(json!({"G": result}))
}

pub fn run_gfpoly_pow(b: ActionGfPoly, e: u8, poly: ActionPoly) -> Result<Value> {
    return match poly {
        ActionPoly::P1 => gfpoly_pow::<P1>(b, e),
        ActionPoly::P2 => gfpoly_pow::<P2>(b, e)
    }
}

fn gfpoly_pow<M: ReducePoly>(b: ActionGfPoly, e: u8) -> Result<Value> {
    let result = GF2mPoly::<M>::from_action_poly(b).pow(e);
    Ok(json!({"Z": result}))
}

pub fn run_gfpoly_powmod(b: ActionGfPoly, e: BigInt, modulus: ActionGfPoly, poly: ActionPoly) -> Result<Value> {
    return match poly {
        ActionPoly::P1 => gfpoly_powmod::<P1>(b, e, modulus),
        ActionPoly::P2 => gfpoly_powmod::<P2>(b, e, modulus)
    }
}

fn gfpoly_powmod<M: ReducePoly>(b: ActionGfPoly, e: BigInt, modulus: ActionGfPoly) -> Result<Value> {
    let b = GF2mPoly::<M>::from_action_poly(b);
    let modulus = GF2mPoly::<M>::from_action_poly(modulus);
    let result = gf_poly::powmod(b, e, modulus);
    Ok(json!({"Z": result}))
}

pub fn run_gfpoly_diff(f: ActionGfPoly, poly: ActionPoly) -> Result<Value> {
    return match poly {
        ActionPoly::P1 => gfpoly_diff::<P1>(f),
        ActionPoly::P2 => gfpoly_diff::<P2>(f)
    }
}

fn gfpoly_diff<M: ReducePoly>(f: ActionGfPoly) -> Result<Value> {
    let result = GF2mPoly::<M>::from_action_poly(f).diff();
    Ok(json!({"F'": result}))
}

pub fn run_gfpoly_sqrt(s: ActionGfPoly, poly: ActionPoly) -> Result<Value> {
    return match poly {
        ActionPoly::P1 => gfpoly_sqrt::<P1>(s),
        ActionPoly::P2 => gfpoly_sqrt::<P2>(s)
    }
}

fn gfpoly_sqrt<M: ReducePoly>(s: ActionGfPoly) -> Result<Value> {
    let result = GF2mPoly::<M>::from_action_poly(s).sqrt();
    Ok(json!({"R": result}))
}