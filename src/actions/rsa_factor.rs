use std::collections::HashSet;

use anyhow::{Result, anyhow};
use rug::Integer;
use serde::Serialize;
use serde_json::{Value, json};

use crate::actions::ActionNumberInt;
use crate::utils::to_unsigned_number;

pub fn run_action(moduli: Vec<ActionNumberInt>) -> Result<Value> {
    // convert parsed BigInt into BugUint for faster operations
    let typed: Vec<Integer> = moduli.iter().map(|n| {
        n.0.clone()
    }).collect();

    let result = gernstyle_batch_gcd(&typed)?;

    Ok(json!({"factored_moduli": result}))
}

struct FactoredModul {
    p: Integer,
    q: Integer
}

fn to_factored_modul(a: Integer, b: Integer) -> FactoredModul {
    return if a < b {
        FactoredModul { p: a, q: b }
    } else {
        FactoredModul { p: b, q: a }
    }
}

fn gernstyle_batch_gcd(moduli: &[Integer]) -> Result<Vec<FactoredModul>> {
    // product tree for N_i
    let prod_tree_n = product_tree(moduli)?;
    // prod_tree returns error which we are propagating if it is empty
    // hence, unwrap is safe
    let p = prod_tree_n.last().unwrap()[0].clone();

    // product tree for Ni_squared
    let sq: Vec<Integer> = moduli.iter().map(|n| n.clone()*n).collect();
    let prod_tree_sq = product_tree(&sq)?;
    // safe again
    let m = prod_tree_sq.last().unwrap()[0].clone();

    let root_remainder = p.clone() % &m;

    // remainder tree, pushing root remainder to the top
    let zi = remainder_tree(&prod_tree_sq, root_remainder);

    let mut factors: Vec<FactoredModul> = Vec::new();
    // handle each shared factor just once
    let mut shared_factors: HashSet<Integer> = HashSet::new();
    // zipping zi to zi_squared for factorization
    for (ni, zi_i) in moduli.iter().zip(zi.iter()) {
        let zi_div_ni = zi_i.clone() / ni;

        let g = ni.clone().gcd(&zi_div_ni);

        if g > Integer::from(1) && &g < ni {
            let p = g.clone();
            let q = ni.clone() / &g;
            factors.push(to_factored_modul(p, q));
        } else if &g == ni {
            // ni shares both primes with other RSA keys
            // therefore, we can do naive GCD
            shared_factors.insert(g.clone());
        }
    }

    // now treat numbers where both factors are shared with other RSA keys
    'outer: for share in shared_factors {
        for key in moduli {
            let g = share.clone().gcd(key);

            if g > Integer::from(1) && g < share {
                // we found one of the two factors, other by trivial division
                let other = share.clone() / &g;
                factors.push(to_factored_modul(g, other));
                // continue outer loop as we found the two factos of this key and we do not want duplicates
                continue 'outer;
            }
        }
    }

    // compare first p's and then q's
    factors.sort_by(|a, b| a.p.cmp(&b.p).then_with(|| a.q.cmp(&b.q)));
    Ok(factors)
}

/// input: list of numbers: a, b, c, d
/// output: product tree of the nums: a, b, c, d, ab, cd, abcd
fn product_tree(numbers: &[Integer]) -> Result<Vec<Vec<Integer>>> {
    if numbers.is_empty() {
        return Err(anyhow!("numbers cannot be empty for product tree"))
    }
    let mut levels: Vec<Vec<Integer>> = Vec::new();
    levels.push(numbers.to_vec());

    // unwrap is safe here, since we added at least one element
    while levels.last().unwrap().len() > 1 {
        let prev = levels.last().unwrap();
        let mut next: Vec<Integer> = Vec::with_capacity((prev.len() + 1) / 2);

        // handle pairs
        for i in (0..prev.len()).step_by(2) {
            // check if i+1 exists, otherwise we have a single last element
            if i + 1 < prev.len() {
                next.push(prev[i].clone() * prev[i + 1].clone());
            } else {
                // last element, nothing to multiply with
                next.push(prev[i].clone());
            }
        }
        levels.push(next);
    }
    Ok(levels)
}

fn remainder_tree(sq_tree: &[Vec<Integer>], root: Integer) -> Vec<Integer> {
    let mut levels: Vec<Vec<Integer>> = Vec::new();
    levels.push(vec![root]);

    // go from tree top to bottom
    for level in (1..sq_tree.len()).rev() {
        // last computed parent of the new children
        // contains at least one element
        let parent = levels.last().unwrap();
        let children = &sq_tree[level - 1];

        let mut remainder: Vec<Integer> = Vec::with_capacity(children.len());

        for (child_id, child_mod) in children.iter().enumerate() {
            let parent_id = child_id / 2;
            let remainder_parent = &parent[parent_id];
            remainder.push(remainder_parent.clone() % child_mod);
        }

        levels.push(remainder);
    }

    levels.last().unwrap().clone()
}

impl Serialize for FactoredModul {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
        where
            S: serde::Serializer {
        let p_value = to_unsigned_number(&self.p);
        let q_value = to_unsigned_number(&self.q);

        let arr = [p_value, q_value];
        arr.serialize(serializer)
    }
}

#[test]
fn test_rsa_product_tree() {
    // test even number of nums
    let nums = vec![Integer::from(2), Integer::from(3), Integer::from(4), Integer::from(5)];
    let expected = vec![nums.clone(), vec![Integer::from(6), Integer::from(20)], vec![Integer::from(120)]];
    let result = product_tree(&nums).unwrap();
    assert_eq!(expected, result);

    let nums = vec![Integer::from(2), Integer::from(3), Integer::from(4), Integer::from(5), Integer::from(6)];
    let expected = vec![nums.clone(), vec![Integer::from(6), Integer::from(20), Integer::from(6)],
        vec![Integer::from(120), Integer::from(6)], vec![Integer::from(120*6)]];
    let result = product_tree(&nums).unwrap();
    assert_eq!(expected, result);
}