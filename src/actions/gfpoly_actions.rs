use anyhow::Result;
use serde_json::{Value, json};

use crate::{actions::{ActionGfPoly, ActionPoly}, utils::{self, gf::{P1, P2, ReducePoly}, gf_poly::GF2mPoly}};

pub fn run_gfpoly_sort(polys: Vec<ActionGfPoly>) -> Result<Value> {
    let result = utils::gfpoly_sort(polys)?;
    // implemented ActionGfU128 Serialize
    Ok(json!({"sorted": result}))
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