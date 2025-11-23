use std::collections::HashSet;

use anyhow::{Result, anyhow};
use num::{BigUint, One};
use num::integer::gcd;
use serde::Serialize;
use serde_json::{Value, json};

use crate::actions::ActionNumber;
use crate::utils::to_unsigned_number;

pub fn run_action(moduli: Vec<ActionNumber>) -> Result<Value> {
    // convert parsed BigInt into BugUint for faster operations
    let typed: Result<Vec<BigUint>> = moduli.iter().map(|n| {
        n.0.to_biguint().ok_or_else(|| anyhow!("negative number in RSA factors"))
    }).collect();

    let result = gernstyle_batch_gcd(&typed?)?;

    Ok(json!({"factored_moduli": result}))
}

struct FactoredModul {
    p: BigUint,
    q: BigUint
}

fn gernstyle_batch_gcd(moduli: &[BigUint]) -> Result<Vec<FactoredModul>> {
    // product tree for N_i
    let prod_tree_n = product_tree(moduli)?;
    // prod_tree returns error which we are propagating if it is empty
    // hence, unwrap is safe
    let p = prod_tree_n.last().unwrap()[0].clone();

    // product tree for Ni_squared
    let sq: Vec<BigUint> = moduli.iter().map(|n| n*n).collect();
    let prod_tree_sq = product_tree(&sq)?;
    // safe again
    let m = prod_tree_sq.last().unwrap()[0].clone();

    let root_remainder = &p % &m;

    // remainder tree, pushing root remainder to the top
    let zi = remainder_tree(&prod_tree_sq, root_remainder);

    let mut factors: Vec<FactoredModul> = Vec::new();
    // handle each shared factor just once
    let mut shared_factors: HashSet<BigUint> = HashSet::new();
    // zipping zi to zi_squared for factorization
    for (ni, zi_i) in moduli.iter().zip(zi.iter()) {
        let zi_div_ni = zi_i / ni;

        let g = gcd(ni.clone(), zi_div_ni);

        if g > BigUint::one() && &g < ni {
            let p = g.clone();
            let q = ni / &g;
            factors.push(FactoredModul { p: p, q: q });
        } else if &g == ni {
            // ni shares both primes with other RSA keys
            // therefore, we can do naive GCD
            for nj in moduli {
                if ni == nj {
                    continue;
                }
                shared_factors.insert(g.clone());
            }
        }
    }

    // now treat numbers where both factors are shared with other RSA keys
    'outer: for share in shared_factors {
        for key in moduli {
            let g = gcd(share.clone(), key.clone());

            if g > BigUint::one() && g < share {
                // we found one of the two factors, other by trivial division
                let other = &share / &g;
                let factor = if g < other {
                    FactoredModul { p: g, q: other }
                } else {
                    FactoredModul { p: other, q: g }
                };
                factors.push(factor);
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
fn product_tree(numbers: &[BigUint]) -> Result<Vec<Vec<BigUint>>> {
    if numbers.is_empty() {
        return Err(anyhow!("numbers cannot be empty for product tree"))
    }
    let mut levels: Vec<Vec<BigUint>> = Vec::new();
    levels.push(numbers.to_vec());

    // unwrap is safe here, since we added at least one element
    while levels.last().unwrap().len() > 1 {
        let prev = levels.last().unwrap();
        let mut next: Vec<BigUint> = Vec::with_capacity((prev.len() + 1) / 2);

        // handle pairs
        for i in (0..prev.len()).step_by(2) {
            // check if i+1 exists, otherwise we have a single last element
            if i + 1 < prev.len() {
                next.push(&prev[i] * &prev[i + 1]);
            } else {
                // last element, nothing to multiply with
                next.push(prev[i].clone());
            }
        }
        levels.push(next);
    }
    Ok(levels)
}

fn remainder_tree(sq_tree: &[Vec<BigUint>], root: BigUint) -> Vec<BigUint> {
    let mut levels: Vec<Vec<BigUint>> = Vec::new();
    levels.push(vec![root]);

    // go from tree top to bottom
    for level in (1..sq_tree.len()).rev() {
        // last computed parent of the new children
        // contains at least one element
        let parent = levels.last().unwrap();
        let children = &sq_tree[level - 1];

        let mut remainder = Vec::with_capacity(children.len());

        for (child_id, child_mod) in children.iter().enumerate() {
            let parent_id = child_id / 2;
            let remainder_parent = &parent[parent_id];
            remainder.push(remainder_parent % child_mod);
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
    use num::bigint::ToBigUint;
    // test even number of nums
    let nums = vec![2.to_biguint().unwrap(), 3.to_biguint().unwrap(), 4.to_biguint().unwrap(),5.to_biguint().unwrap()];
    let expected = vec![nums.clone(), vec![6.to_biguint().unwrap(), 20.to_biguint().unwrap()], vec![120.to_biguint().unwrap()]];
    let result = product_tree(&nums).unwrap();
    assert_eq!(expected, result);

    let nums = vec![2.to_biguint().unwrap(), 3.to_biguint().unwrap(), 4.to_biguint().unwrap(),
        5.to_biguint().unwrap(), 6.to_biguint().unwrap()];
    let expected = vec![nums.clone(), vec![6.to_biguint().unwrap(), 20.to_biguint().unwrap(), 6.to_biguint().unwrap()],
        vec![120.to_biguint().unwrap(), 6.to_biguint().unwrap()], vec![(120*6).to_biguint().unwrap()]];
    let result = product_tree(&nums).unwrap();
    assert_eq!(expected, result);
}