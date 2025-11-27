use anyhow::Result;
use rug::{Assign, Integer};
use serde::Serialize;
use serde_json::{Value, json};

use crate::actions::ActionNumberInt;
use crate::utils::to_unsigned_number;

pub fn run_action(moduli: Vec<ActionNumberInt>) -> Result<Value> {
    // convert parsed BigInt into BugUint for faster operations
    let typed: Vec<Integer> = moduli.into_iter().map(|x| x.0).collect();

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
    let mut prod_tree_n = ProductTree::build(moduli);
    // prod_tree returns error which we are propagating if it is empty
    // hence, unwrap is safe
    let p = prod_tree_n.get_root().clone();

    // product tree for Ni_squared
    prod_tree_n.square();

    // remainder tree, pushing root remainder to the top
    let zi = prod_tree_n.remainder_leaves(&p);

    let mut factors: Vec<FactoredModul> = Vec::new();
    // handle each shared factor just once
    let mut double_shared_factors: Vec<usize> = Vec::new();
    // run double shared factors only on moduli where we know they share one factor with other(s)
    let mut single_shared_factor: Vec<usize> = Vec::new();
    // reusing the same integer again to avoid assigning new memory - maybe performance boost?
    let mut g = Integer::new();
    let mut zi_div_ni = Integer::new();
    // reusing constant one for comparing
    let one = Integer::from(1);
    // zipping zi to zi_squared for factorization
    for (i, (ni, zi_i)) in moduli.iter().zip(zi.iter()).enumerate() {
        zi_div_ni.assign(zi_i.div_exact_ref(ni));

        g.assign(ni.gcd_ref(&zi_div_ni));

        if &g == ni {
            // ni shares both primes with other RSA keys
            // therefore, we can do naive GCD
            double_shared_factors.push(i);
        } else if g > one && &g < ni {
            // we have one shared factor, keep the id for the double shared factors
            single_shared_factor.push(i);
            let p = g.clone();
            // we know division hast rest zero, div_exact is faster
            let q = Integer::from(ni.div_exact_ref(&g));
            factors.push(to_factored_modul(p, q));
        }
    }

    // now treat numbers where both factors are shared with other RSA keys
    // first, try against the factors which share a single factor
    let mut unresolved: Vec<usize> = Vec::new();
    'outer: for o_i in double_shared_factors {
        let share = &moduli[o_i];
        for &k_i in single_shared_factor.iter() {
            g.assign(share.gcd_ref(&moduli[k_i]));

            if g > one && &g < share {
                // we found one of the two factors, other by trivial division
                // we know division hast rest zero, div_exact is faster
                let other = Integer::from(share.div_exact_ref(&g));
                factors.push(to_factored_modul(g.clone(), other));
                // continue outer loop as we found the two factos of this key and we do not want duplicates
                continue 'outer;
            }
        }

        // did not continue 'outer, meaning we did not resolve this item
        unresolved.push(o_i);
    }

    'outer: for &o_i in unresolved.iter() {
        let share = &moduli[o_i];
        // run only through those we did not test yet
        for &k_i in unresolved.iter() {
            g.assign(share.gcd_ref(&moduli[k_i]));

            if g > one && &g < share {
                let other = Integer::from(share.div_exact_ref(&g));
                factors.push(to_factored_modul(g.clone(), other));
                continue 'outer;
            }
        }
    }

    // compare first p's and then q's
    factors.sort_by(|a, b| a.p.cmp(&b.p).then_with(|| a.q.cmp(&b.q)));
    Ok(factors)
}

// product tree with root at the front for easy position calculation
struct ProductTree {
    nodes: Vec<Integer>,
    leaf_start: usize,
    leaf_count: usize
}

impl ProductTree {
    fn build(input: &[Integer]) -> Self {
        let leaf_start = input.len().next_power_of_two();
        let total_nodes = 2*leaf_start;

        let mut nodes = vec![Integer::new(); total_nodes];

        // put leafs to end of product tree
        for (i, n) in input.iter().enumerate() {
            nodes[leaf_start + i].assign(n);
        }
        // fill up empty leaves due to padding
        for i in leaf_start + input.len()..total_nodes {
            nodes[i].assign(1);
        }
        for i in (1..leaf_start).rev() {
            // we need to split because we want to write in head while reading in tail
            let (head, tail) = nodes.split_at_mut(2*i);
            // parent at position i, left at 2*i (0 in tail) and right at 2*i + 1 (1 in tail)
            head[i].assign(&tail[0] * &tail[1]);
        }

        ProductTree { nodes, leaf_start, leaf_count: input.len() }
    }

    fn square(&mut self) {
        for node in self.nodes.iter_mut() {
            node.square_mut();
        }
    }

    fn remainder_leaves(&self, root: &Integer) -> Vec<Integer> {
        let mut remainders = vec![Integer::new(); self.nodes.len()];

        // assign root remainder
        remainders[1].assign(root);

        for i in 1..self.leaf_start {
            let (head, tail) = remainders.split_at_mut(2*i);
            let parent = &head[i];

            // set left node
            tail[0].assign(parent % &self.nodes[2*i]);
            // set right 
            tail[1].assign(parent % &self.nodes[2*i + 1]);
        }
        // do not copy to new Vec but just reduce existing one
        // we want the remainders from leaf_start until leaf_start + leaf_count
        // first: remove everything up until leaf_start
        remainders.drain(0..self.leaf_start);
        // second: remove padded leaves
        remainders.truncate(self.leaf_count);
        remainders
    }

    fn get_root(&self) -> &Integer {
        &self.nodes[1]
    }
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
fn test_new_product_tree() {
    let nums = vec![Integer::from(2), Integer::from(3), Integer::from(4), Integer::from(5)];
    let expected = vec![Integer::from(120), Integer::from(6), Integer::from(20)];
    let result = ProductTree::build(&nums);
    let branches = &result.nodes[1..result.leaf_start-(result.leaf_count % 2)];
    assert_eq!(branches, &expected);

    let nums = vec![Integer::from(2), Integer::from(3), Integer::from(4), Integer::from(5), Integer::from(6)];
    let expected = vec![Integer::from(120*6), Integer::from(120), Integer::from(6), Integer::from(6), Integer::from(20), Integer::from(6)];
    let result = ProductTree::build(&nums);
    // substract 1 if leaf_count is odd, as we padded with 1
    let branches = &result.nodes[1..result.leaf_start-(result.leaf_count % 2)];
    assert_eq!(branches, &expected);
}