use std::{cmp::{Ordering, max}, ops::{Add, Mul, MulAssign}};

use anyhow::Result;
use num::{BigInt, One, Zero};
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

    pub fn zero() -> GF2mPoly<M> {
        Self { elems: Vec::new() }
    }

    pub fn one() -> GF2mPoly<M> {
        Self { elems: vec![GF2m::<M>::one()] }
    }

    pub fn is_zero(&self) -> bool {
        self.degree() == 0
    }

    pub fn degree(&self) -> usize {
        self.elems.len()
    }

    pub fn new_single_term(coeff: GF2m<M>, degree: usize) -> Self {
        let mut list = vec![GF2m::<M>::zero(); degree+1];
        list[degree] = coeff;
        Self { elems: list }
    }

    fn trim(mut self) -> Self {
        while self.elems.last().map_or(false, |coeff| coeff.is_zero()) {
            self.elems.pop();
        }
        self
    }

    /// might make this "inplace" on the vec of self later on
    /// for now, we are creating a new result vec anyways...
    fn add_borrowed(&self, rhs: &Self) -> Self {
        let size_self = self.elems.len();
        let size_rhs = rhs.elems.len();
        let size = max(size_self, size_rhs);
        let mut result: Vec<GF2m<M>> = Vec::with_capacity(size);

        for i in 0..size {
            if i < size_self && i < size_rhs {
                result.push(&self.elems[i] + &rhs.elems[i]);
            // handle self > rhs
            } else if i < size_self {
                result.push(self.elems[i].clone());
            // handle rhs > self
            } else {
                result.push(rhs.elems[i].clone());
            }
        }
        Self { elems: result }.trim()
    }

    fn mul_borrowed(&self, rhs: &Self) -> Self {
        let size_self = self.elems.len();
        let size_rhs = rhs.elems.len();
        if size_self == 0 && size_rhs == 0 {
            return Self::zero();
        }
        let size_res = max(size_self + size_rhs - 1, 1);
        let mut product: Vec<GF2m<M>> = Vec::with_capacity(size_res);

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
        Self { elems: product }.trim()
    }

    pub fn diff(&self) -> Self {
        if self.degree() == 0 {
            return Self::zero()
        }
        // diff is one degree less
        let mut diff: Vec<GF2m<M>> = Vec::with_capacity(self.elems.len() - 1);
        // start at 1, the x^0 will be gone
        for i in 1..self.elems.len() {
            // we keep only odd exps, as 2*x in GF2m is zero
            if i % 2 == 1 {
                diff.push(self.elems[i].clone());
            } else {
                diff.push(GF2m::<M>::zero());
            }
        }
        Self { elems: diff }.trim()
    }

    pub fn sqrt(&self) -> Self {
        let mut out: Vec<GF2m<M>> = Vec::with_capacity((self.elems.len() + 1) / 2);
        
        for i in 0..self.elems.len() {
            // even powers only (as defined in assignment)
            if i % 2 == 0 {
                out.push(self.elems[i].sqrt());
            }
        }
        Self { elems: out }.trim()
    }

    fn cmp(&self, other: &Self) -> Ordering {
        self.elems.len().cmp(&other.elems.len())
            .then_with(|| other.elems.cmp(&self.elems))
    }

    fn square(&self) -> Self {
        if self.degree() == 0 {
            return Self::zero()
        }
        // squaring is 2n - 1
        let size = self.elems.len() * 2 - 1;
        let mut out = Vec::with_capacity(size);

        for coeff in self.elems.iter() {
            out.push(coeff.square());
            out.push(GF2m::<M>::zero());
        }
        Self { elems: out }.trim()
    }

    pub fn pow(self, mut exp: u8) -> Self {
        let mut base = self;
        let mut result = Self::one();

        while exp > 0 {
            if exp & 1 != 0 {
                result *= &base;
            }
            exp >>= 1;
            if exp > 0 {
                base = base.square()
            }
        }
        result
    }
}

impl<M: ReducePoly> Add for GF2mPoly<M> {
    type Output = GF2mPoly<M>;

    fn add(self, rhs: Self) -> Self::Output {
        self.add_borrowed(&rhs)
    }
}

impl<M: ReducePoly> Mul for GF2mPoly<M> {
    type Output = GF2mPoly<M>;

    fn mul(self, rhs: Self) -> Self::Output {
        self.mul_borrowed(&rhs)
    }
}

impl<M: ReducePoly> Mul<&GF2mPoly<M>> for &GF2mPoly<M> {
    type Output = GF2mPoly<M>;

    fn mul(self, rhs: &GF2mPoly<M>) -> Self::Output {
        self.mul_borrowed(rhs)
    }
}

impl<M: ReducePoly> MulAssign<&GF2mPoly<M>> for GF2mPoly<M> {
    fn mul_assign(&mut self, rhs: &GF2mPoly<M>) {
        let res = self.mul_borrowed(rhs);
        self.elems = res.elems;
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

pub fn divmod<M: ReducePoly>(lhs: GF2mPoly<M>, rhs: &GF2mPoly<M>) -> (GF2mPoly<M>, GF2mPoly<M>) {
    let mut remainder = lhs;
    let mut quotient = GF2mPoly::<M>::zero();

    while remainder.degree() >= rhs.degree() {
        let rem_deg = remainder.degree();
        let rhs_deg = rhs.degree();
        let exp_rem = remainder.elems[rem_deg - 1].clone();
        let exp_rhs = rhs.elems[rhs_deg - 1].clone();

        let deg_diff = rem_deg - rhs_deg;
        // normally, c = 1/a * 1/b, but as we are XORing during addition, we do not need to invert exp_rem
        let exp_quot = exp_rem * exp_rhs.inv();
        let quot = GF2mPoly::<M>::new_single_term(exp_quot, deg_diff);
        remainder = remainder + (GF2mPoly::<M>::mul_borrowed(&rhs, &quot));
        if remainder.degree() >= rem_deg {
            // Something went wrong, lets break and return wrong result instead of running into an endless loop
            break;
        }
        quotient = quotient + quot;
    }
    (quotient, remainder)
}

impl<M: ReducePoly> PartialEq for GF2mPoly<M> {
    fn eq(&self, other: &Self) -> bool {
        self.elems == other.elems
    }
}

impl<M: ReducePoly> Eq for GF2mPoly<M> {}

impl<M: ReducePoly> PartialOrd for GF2mPoly<M> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<M: ReducePoly> Ord for GF2mPoly<M> {
    fn cmp(&self, other: &Self) -> Ordering {
        // first, compare Poly degree only
        self.elems.len().cmp(&other.elems.len())
            // then, compare b to a since GCM-convention polynoms are in BE and therefore higher GF elements smaller integers
            .then_with(|| self.elems.cmp(&other.elems))
    }
}

pub fn gcd<M: ReducePoly>(mut a: GF2mPoly<M>, mut b: GF2mPoly<M>) -> GF2mPoly<M> {
    // handle edgecases a or b == 0
    if a.is_zero() {
        return b.make_monic();
    }
    if b.is_zero() {
        return a.make_monic();
    }
    while !b.is_zero() {
        // a = q * b + r
        let (_q, r) = divmod(a, &b);
        a = b;
        b = r;
    }
    // assigment wants monic result
    a.make_monic()
}

pub fn powmod<M: ReducePoly>(base: GF2mPoly<M>, mut exp: BigInt, modulus: GF2mPoly<M>) -> GF2mPoly<M> {
    // reduce base in case its bigger than modulus
    let (_, mut base_reduced) = divmod(base, &modulus);

    let mut result = GF2mPoly::<M>::one();

    // square and mul is ugly due to BigInt for hex numbers
    while &exp > &BigInt::zero() {
        if &exp & &BigInt::one() != BigInt::zero() {
            let prod = &result * &base_reduced;
            let (_, reduced) = divmod(prod, &modulus);
            result = reduced;
        }
        exp >>= 1;
        if &exp > &BigInt::zero() {
            let square = base_reduced.square();
            let (_, reduced) = divmod(square, &modulus);
            base_reduced = reduced;
        }
    }
    result
}