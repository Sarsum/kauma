use std::mem;

use anyhow::Result;
use rug::{Assign, Integer};
use serde::Serialize;
use serde_json::{Value, json};

use crate::actions::ActionNumberInt;
use crate::utils::to_unsigned_number;

pub fn run_action(moduli: Vec<ActionNumberInt>) -> Result<Value> {
    // convert parsed BigInt into BugUint for faster operations
    let typed: Vec<Integer> = moduli.into_iter().map(|x| x.0).collect();

    let result = batch_gcd(&typed)?;

    Ok(json!({"factored_moduli": result}))
}

struct FactoredModul {
    p: Integer,
    q: Integer
}

impl FactoredModul {
    fn from_unsorted(a: Integer, b: Integer) -> FactoredModul {
        return if a < b {
            FactoredModul { p: a, q: b }
        } else {
            FactoredModul { p: b, q: a }
        }
    }
}

fn batch_gcd(moduli: &[Integer]) -> Result<Vec<FactoredModul>> {
    // product tree for N_i
    let prod_tree_n = ProductTree::build(moduli);

    // remainder tree, pushing root remainder to the top
    let zi = prod_tree_n.remainder_leaves();

    let mut factors: Vec<FactoredModul> = Vec::new();
    // handle each shared factor just once
    let mut unfactored_moduli: Vec<usize> = Vec::new();
    // run double shared factors only on moduli where we know they share one factor with other(s)
    let mut factored_moduli: Vec<usize> = Vec::new();
    // reusing the same integer again to avoid assigning new memory - maybe performance boost?
    let mut g = Integer::new();
    let mut q = Integer::new();
    // zipping zi to zi_squared for factorization
    for (i, (ni, zi_i)) in moduli.iter().zip(zi.iter()).enumerate() {
        g.assign(ni.gcd_ref(&zi_i));

        if &g == ni {
            // ni shares both primes with other RSA keys
            // therefore, we can do naive GCD
            unfactored_moduli.push(i);
        } else if g > 1 && &g < ni {
            // we have one shared factor, keep the id for the double shared factors
            factored_moduli.push(i);
            // we know division hast rest zero, div_exact is faster
            q.assign(ni.div_exact_ref(&g));
            factors.push(FactoredModul::from_unsorted(mem::take(&mut g), mem::take(&mut q)));
        }
    }

    // using factored_moduli as a stack
    // popping one element at a time and check against the unfactored moduli
    while let Some(o_i) = factored_moduli.pop() {
        let share = &moduli[o_i];
        // remove factored moduli and add them to the stack for recursive cases
        let mut i = 0;
        while i < unfactored_moduli.len() {
            let i_i = unfactored_moduli[i];
            let inner = &moduli[i_i];
            g.assign(share.gcd_ref(inner));

            if g > 1 && &g < share {
                q.assign(inner.div_exact_ref(&g));
                factors.push(FactoredModul::from_unsorted(mem::take(&mut g), mem::take(&mut q)));
                factored_moduli.push(i_i);
                unfactored_moduli.swap_remove(i);
            } else {
                i += 1;
            }
        }
    }

    // assign memory only if required
    if unfactored_moduli.len() > 0 {
        let mut factored = vec![false; moduli.len()];
        // reusing this
        let mut other_inner = Integer::new();
        // last check: two shared factors among the other unfactored moduli containg two shared
        'outer: for &o_i in unfactored_moduli.iter() {
            // factored o_i already because a previous moduli was a hit
            if factored[o_i] {
                continue;
            }
            let share = &moduli[o_i];
            // run only through those we did not test yet
            for &k_i in unfactored_moduli.iter() {
                // skip pointless GCD
                if o_i == k_i {
                    continue;
                }
                g.assign(share.gcd_ref(&moduli[k_i]));
                // finding a valid GCD means that inner and outer are a match
                // we can calculate each others other factor at the same time
                if g > 1 && &g < share {
                    q.assign(share.div_exact_ref(&g));
                    // only push k_i if we did not factore it already by a prior item
                    if !factored[k_i] {
                        other_inner.assign(moduli[k_i].div_exact_ref(&g));
                        factors.push(FactoredModul::from_unsorted(g.clone(), mem::take(&mut other_inner)));
                        factored[k_i] = true;
                    }
                    // move after the if, because we might need g value
                    factors.push(FactoredModul::from_unsorted(mem::take(&mut g), mem::take(&mut q)));
                    factored[o_i] = true;
                    continue 'outer;
                }
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
    leaf_count: usize,
}

impl ProductTree {
    fn build(input: &[Integer]) -> Self {
        let leaf_start = input.len().next_power_of_two();
        let total_nodes = 2 * leaf_start;

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
            let (head, tail) = nodes.split_at_mut(2 * i);
            // parent at position i, left at 2*i (0 in tail) and right at 2*i + 1 (1 in tail)
            head[i].assign(&tail[0] * &tail[1]);
        }

        ProductTree {
            nodes,
            leaf_start,
            leaf_count: input.len(),
        }
    }

    // alternative, faster algorithm which is not doing P mod Ni^1
    fn remainder_leaves(&self) -> Vec<Integer> {
        let total_nodes = self.nodes.len();
        let mut rem = vec![Integer::new(); total_nodes];

        // root is 1
        rem[1].assign(1);

        let mut tmp = Integer::new();
        for i in 1..self.leaf_start {
            let (head, tail) = rem.split_at_mut(2 * i);
            let parent = &head[i];

            let left_ptree_id = 2 * i;
            let right_ptree_id = 2 * i + 1;

            tmp.assign(&self.nodes[right_ptree_id] * parent);
            // rem_from is slightly faster than modulo_from
            tail[0].assign(tmp.modulo_ref(&self.nodes[left_ptree_id])); // equals tmp % tail[0]
            // set right
            tmp.assign(&self.nodes[left_ptree_id] * parent);
            tail[1].assign(tmp.modulo_ref(&self.nodes[right_ptree_id]));
        }
        // do not copy to new Vec but just reduce existing one
        // we want the remainders from leaf_start until leaf_start + leaf_count
        // first: remove everything up until leaf_start
        rem.drain(0..self.leaf_start);
        // second: remove padded leaves
        rem.truncate(self.leaf_count);
        rem
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
    let nums = vec![
        Integer::from(2),
        Integer::from(3),
        Integer::from(4),
        Integer::from(5),
    ];
    let expected = vec![Integer::from(120), Integer::from(6), Integer::from(20)];
    let result = ProductTree::build(&nums);
    let branches = &result.nodes[1..result.leaf_start - (result.leaf_count % 2)];
    assert_eq!(branches, &expected);

    let nums = vec![
        Integer::from(2),
        Integer::from(3),
        Integer::from(4),
        Integer::from(5),
        Integer::from(6),
    ];
    let expected = vec![
        Integer::from(120 * 6),
        Integer::from(120),
        Integer::from(6),
        Integer::from(6),
        Integer::from(20),
        Integer::from(6),
    ];
    let result = ProductTree::build(&nums);
    // substract 1 if leaf_count is odd, as we padded with 1
    let branches = &result.nodes[1..result.leaf_start - (result.leaf_count % 2)];
    assert_eq!(branches, &expected);
}
