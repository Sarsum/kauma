use std::{cmp::max, ops::{Add, Mul}};

use anyhow::Result;
use serde::{Serialize, ser::SerializeSeq};

use crate::{actions::ActionGfPoly, utils::gf::{GF2m, ReducePoly}};

pub struct GF2mPoly<M: ReducePoly> {
    pub elems: Vec<GF2m<M>>
}

impl<M: ReducePoly> GF2mPoly<M> {
    pub fn from_action_poly(poly: ActionGfPoly) -> GF2mPoly<M> {
        let mut elems: Vec<GF2m<M>> = Vec::with_capacity(poly.0.len());
        for i in 0..poly.0.len() {
            elems.push(GF2m::<M>::new(poly.0[i].0));
        }
        Self { elems: elems }
    }

    pub fn make_monic(mut self) -> GF2mPoly<M> {
        let inv = self.elems[self.elems.len() - 1].clone().inv();
        for i in 0..self.elems.len() {
            self.elems[i] *= &inv;
        }
        self
    }
}

impl<M: ReducePoly> Add for GF2mPoly<M> {
    type Output = GF2mPoly<M>;

    fn add(self, rhs: Self) -> Self::Output {
        let size_self = self.elems.len();
        let size_rhs = rhs.elems.len();
        let size = max(size_self, size_rhs);
        let mut result: Vec<GF2m<M>> = Vec::with_capacity(size);

        for i in 0..size {
            if i < size_self && i < size_rhs {
                result.push(&self.elems[i] + &rhs.elems[i]);
            } else if i < size_self {
                result.push(self.elems[i].clone());
            } else {
                result.push(rhs.elems[i].clone());
            }
        }
        Self { elems: result }
    }
}

impl<M: ReducePoly> Mul for GF2mPoly<M> {
    type Output = GF2mPoly<M>;

    fn mul(self, rhs: Self) -> Self::Output {
        let size_self = self.elems.len();
        let size_rhs = rhs.elems.len();
        let mut product: Vec<GF2m<M>> = Vec::with_capacity(size_rhs + size_rhs - 1);

        // multiply each a with each b --> for in for loop
        for l_i in 0..size_self {
            for r_i in 0..size_rhs {
                let index = l_i + r_i;
                let result = &self.elems[l_i] * &rhs.elems[r_i];
                // element at index present, add result to existing GF elem
                if product.len() > index {
                    product[index] += result;
                } else {
                    product.push(result);
                }
            }
        }
        Self { elems: product }
    }
}

impl<M: ReducePoly> Serialize for GF2mPoly<M> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer {
        let mut seq = serializer.serialize_seq(Some(self.elems.len()))?;
        for e in &self.elems {
            seq.serialize_element(e)?;
        }
        seq.end()
    }
}