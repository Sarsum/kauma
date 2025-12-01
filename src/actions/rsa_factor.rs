use std::cmp::Ordering;

use anyhow::{Result, anyhow};
use rug::ops::RemFrom;
use rug::{Assign, Integer};
use serde::Serialize;
use serde_json::{Number, Value, json};

use crate::actions::ActionNumberInt;

pub fn run_action(moduli: Vec<ActionNumberInt>) -> Result<Value> {
    // convert parsed BigInt into BugUint for faster operations
    let typed: Vec<Integer> = moduli.into_iter().map(|x| x.0).collect();

    let result = batch_gcd(&typed)?;

    Ok(json!({"factored_moduli": result}))
}

struct FactoredVal {
    value: String,
    is_small: bool,
}

impl FactoredVal {
    fn from_int(num: &Integer) -> FactoredVal {
        FactoredVal {
            value: num.to_string_radix(16),
            is_small: num.significant_bits() <= 31,
        }
    }

    fn to_value(&self) -> Result<Value> {
        return if self.is_small {
            // more performant for large nums if we convert small nums to hex and back to num
            Ok(Value::Number(Number::from(
                i32::from_str_radix(&self.value, 16)
                    .map_err(|_| anyhow!("rsa_factor: int to hex to int error"))?,
            )))
        } else {
            let mut result = String::with_capacity(self.value.len() + 2);
            result.push_str("0x");
            result.push_str(&self.value);
            Ok(Value::String(result))
        };
    }
}

struct FactoredModul {
    p: FactoredVal,
    q: FactoredVal,
}

impl FactoredModul {
    fn from_unsorted(a: &Integer, b: &Integer) -> FactoredModul {
        return if a < b {
            Self::from_sorted(a, b)
        } else {
            Self::from_sorted(b, a)
        };
    }

    fn from_sorted(p: &Integer, q: &Integer) -> FactoredModul {
        FactoredModul {
            p: FactoredVal::from_int(p),
            q: FactoredVal::from_int(q),
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
    let mut zi_div_ni = Integer::new();
    let mut q = Integer::new();
    // zipping zi to zi_squared for factorization
    for (i, (ni, zi_i)) in moduli.iter().zip(zi.iter()).enumerate() {
        zi_div_ni.assign(zi_i.div_exact_ref(ni));

        g.assign(ni.gcd_ref(&zi_div_ni));

        if &g == ni {
            // ni shares both primes with other RSA keys
            // therefore, we can do naive GCD
            unfactored_moduli.push(i);
        } else if g > 1 && &g < ni {
            // we have one shared factor, keep the id for the double shared factors
            factored_moduli.push(i);
            // we know division hast rest zero, div_exact is faster
            q.assign(ni.div_exact_ref(&g));
            factors.push(FactoredModul::from_unsorted(&g, &q));
        }
    }

    // using factored_moduli as a stack
    // popping one element at a time and check against the unfactored moduli
    while let Some(o_i) = factored_moduli.pop() {
        let share = &moduli[o_i];
        // extract_if removes items matching the filter and returns an iterator containing them
        // we need to add every new factored moduli to the stack for recursive cases
        factored_moduli.extend(unfactored_moduli.extract_if(.., |&mut i_i| {
            let inner = &moduli[i_i];
            g.assign(share.gcd_ref(inner));
            if g > 1 && &g < share {
                q.assign(inner.div_exact_ref(&g));
                factors.push(FactoredModul::from_unsorted(&g, &q));
                return true;
            }
            false
        }));
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
                    factors.push(FactoredModul::from_unsorted(&g, &q));
                    factored[o_i] = true;
                    // only push k_i if we did not factore it already by a prior item
                    if !factored[k_i] {
                        other_inner.assign(moduli[k_i].div_exact_ref(&g));
                        factors.push(FactoredModul::from_unsorted(&g, &other_inner));
                        factored[k_i] = true;
                    }
                    continue 'outer;
                }
            }
        }
    }

    // compare first p's and then q's
    factors.sort_unstable_by(|a, b| {
        cmp_hex(&a.p.value, &b.p.value).then_with(|| cmp_hex(&a.q.value, &b.q.value))
    });
    Ok(factors)
}

fn cmp_hex(a: &str, b: &str) -> Ordering {
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
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

    fn remainder_leaves(mut self) -> Vec<Integer> {
        // do not modify
        for i in 1..self.leaf_start {
            let (head, tail) = self.nodes.split_at_mut(2 * i);
            let parent = &head[i];

            // square left node, then reduce
            tail[0].square_mut();
            // rem_from is slightly faster than modulo_from
            tail[0].rem_from(parent);
            // set right
            tail[1].square_mut();
            tail[1].rem_from(parent);
        }
        // do not copy to new Vec but just reduce existing one
        // we want the remainders from leaf_start until leaf_start + leaf_count
        // first: remove everything up until leaf_start
        self.nodes.drain(0..self.leaf_start);
        // second: remove padded leaves
        self.nodes.truncate(self.leaf_count);
        self.nodes
    }
}

impl Serialize for FactoredModul {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let arr = [
            self.p
                .to_value()
                .map_err(|e| <S::Error as serde::ser::Error>::custom(e.to_string()))?,
            self.q
                .to_value()
                .map_err(|e| <S::Error as serde::ser::Error>::custom(e.to_string()))?,
        ];
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
