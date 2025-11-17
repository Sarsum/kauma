use std::{cmp::{Ordering, max}, ops::{Add, AddAssign, Div, Mul, MulAssign}};

use anyhow::{Result, anyhow};
use num::{BigInt, One, Zero};
use rand::Rng;
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

    pub fn is_monic(&self) -> bool {
        self.elems.len() > 0 && self.elems[self.elems.len() - 1] == GF2m::<M>::one()
    }

    pub fn make_monic(mut self) -> GF2mPoly<M> {
        // nothing to do
        if self.is_monic() {
            return self
        }
        let inv = self.elems[self.elems.len() - 1].clone().inv();
        for i in 0..self.elems.len() {
            self.elems[i] *= &inv;
        }
        self
    }

    pub fn zero() -> GF2mPoly<M> {
        Self { elems: vec![GF2m::<M>::zero()] }
    }

    pub fn one() -> GF2mPoly<M> {
        Self { elems: vec![GF2m::<M>::one()] }
    }

    pub fn one_x() -> GF2mPoly<M> {
        Self::new_single_term(GF2m::<M>::one(), 1)
    }

    pub fn is_zero(&self) -> bool {
        self.degree() == 0 && self.elems[0].is_zero()
    }

    pub fn degree(&self) -> usize {
        self.elems.len() - 1
    }

    pub fn new_single_term(coeff: GF2m<M>, degree: usize) -> Self {
        let mut list = vec![GF2m::<M>::zero(); degree+1];
        list[degree] = coeff;
        Self { elems: list }
    }

    fn trim(mut self) -> Self {
        // do not pop zero coeff for poly of degree 0 
        while self.degree() > 0 && self.elems.last().map_or(false, |coeff| coeff.is_zero()) {
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
        if result.is_empty() {
            result.push(GF2m::zero());
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
        product.push(GF2m::zero());

        // multiply each a with each b --> for in for loop
        for l_i in 0..size_self {
            for r_i in 0..size_rhs {
                let index = l_i + r_i;
                let result = &self.elems[l_i] * &rhs.elems[r_i];
                // element at index present, add result to existing GF elem
                if product.len() >= index + 1 {
                    product[index] += result;
                } else {
                    product.push(result);
                }
            }
        }
        Self { elems: product }.trim()
    }

    pub fn diff(&self) -> Self {
        let n = self.elems.len();
        // diff of constant is zero
        if n <= 1 {
            return Self::zero()
        }
        // diff is one degree less
        let mut diff: Vec<GF2m<M>> = vec![GF2m::<M>::zero(); n - 1];
        // start at 1, the x^0 will be gone
        for i in (1..n).step_by(2) {
            // we keep only odd exps, as 2*x in GF2m is zero
            diff[i-1] = self.elems[i];
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

    fn square(&self) -> Self {
        // squaring is 2n - 1
        let size = self.elems.len() * 2 - 1;
        let mut out = Vec::with_capacity(size);

        for coeff in self.elems.iter() {
            out.push(coeff.square());
            out.push(GF2m::<M>::zero());
        }
        out.push(GF2m::zero());
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

    pub fn get_highest_coefficient(&self) -> &GF2m<M> {
        &self.elems[self.elems.len() - 1]
    }
}

pub fn divmod<M: ReducePoly>(lhs: &GF2mPoly<M>, rhs: &GF2mPoly<M>) -> (GF2mPoly<M>, GF2mPoly<M>) {
    let mut remainder = lhs.clone();
    let mut quotient = GF2mPoly::<M>::zero();

    while remainder.degree() >= rhs.degree() {
        let rem_deg = remainder.degree();
        let rhs_deg = rhs.degree();
        let exp_rem = remainder.elems[rem_deg].clone();
        let exp_rhs = rhs.elems[rhs_deg].clone();

        let deg_diff = rem_deg - rhs_deg;
        // normally, c = 1/a * 1/b, but as we are XORing during addition, we do not need to invert exp_rem
        let exp_quot = exp_rem * exp_rhs.inv();
        let quot = GF2mPoly::<M>::new_single_term(exp_quot, deg_diff);
        remainder = remainder + (rhs * &quot);
        quotient = quotient + quot;
        if remainder.degree() >= rem_deg {
            // Something went wrong, lets break and return wrong result instead of running into an endless loop
            break;
        }
    }
    (quotient, remainder)
}

pub fn gcd<M: ReducePoly>(a: &GF2mPoly<M>, b: &GF2mPoly<M>) -> GF2mPoly<M> {
    // handle edgecases a or b == 0
    if a.is_zero() {
        return b.clone().make_monic();
    }
    if b.is_zero() {
        return a.clone().make_monic();
    }
    let mut a = a.clone();
    let mut b = b.clone();
    while !b.is_zero() {
        // a = q * b + r
        let (_q, r) = divmod(&a, &b);
        a = b;
        b = r;
    }
    // assigment wants monic result
    a.make_monic()
}

pub fn powmod<M: ReducePoly>(base: GF2mPoly<M>, mut exp: BigInt, modulus: &GF2mPoly<M>) -> GF2mPoly<M> {
    // reduce base in case its bigger than modulus
    let (_, mut base_reduced) = divmod(&base, modulus);
    // edgecase: exp == 0, we need to reduce in case mod equals 1
    // better here than after, because divmod with 1 is easy
    let (_, mut result) = divmod(&GF2mPoly::<M>::one(), modulus);

    // square and mul is ugly due to BigInt for hex numbers
    while &exp > &BigInt::zero() {
        if &exp & &BigInt::one() != BigInt::zero() {
            let prod = &result * &base_reduced;
            let (_, reduced) = divmod(&prod, modulus);
            result = reduced;
        }
        exp >>= 1;
        if &exp > &BigInt::zero() {
            let square = base_reduced.square();
            let (_, reduced) = divmod(&square, modulus);
            base_reduced = reduced;
        }
    }
    result
}

#[derive(Serialize)]
#[serde(bound(serialize = "GF2mPoly<M>: Serialize"))]
pub struct PolySffFactor<M: ReducePoly> {
    pub factor: GF2mPoly<M>,
    pub exponent: u128
}

pub fn sff<M: ReducePoly>(mut f: GF2mPoly<M>) -> Result<Vec<PolySffFactor<M>>> {
    if !f.is_monic() {
        return Err(anyhow!("sff: f needs to be monic!"))
    }
    // implementation from the slides
    let f_d = f.diff();
    let mut c = gcd(&f, &f_d);
    f = (&f / &c)?;
    let mut z: Vec<PolySffFactor<M>> = Vec::new();
    let mut exponent = 1u128;
    while f != GF2mPoly::<M>::one() {
        let y = gcd(&f, &c);
        if f != y {
            z.push(PolySffFactor { factor: (&f / &y)?, exponent: exponent });
        }
        c = (&c / &y)?;
        f = y;
        exponent += 1;
    }

    if c != GF2mPoly::<M>::one() {
        for elem in sff(c.sqrt())? {
            z.push(PolySffFactor { factor: elem.factor, exponent: elem.exponent * 2 });
        }
    }
    // honestly, I dont want to implement the sorting egain (PartialEq, Eq, PartialOrd, Ord)
    // hence, I am just doing it here
    z.sort_by(|a, b| a.exponent.cmp(&b.exponent).then_with(|| a.factor.cmp(&b.factor)));
    Ok(z)
}

#[derive(Serialize)]
#[serde(bound(serialize = "GF2mPoly<M>: Serialize"))]
pub struct PolyDdfFactor<M: ReducePoly> {
    pub factor: GF2mPoly<M>,
    pub degree: u128,
}

pub fn ddf<M: ReducePoly>(f: GF2mPoly<M>) -> Result<Vec<PolyDdfFactor<M>>> {
    if !f.is_monic() {
        return Err(anyhow!("ddf: f needs to be monic!"))
    }
    let q: BigInt = BigInt::one() << 128;
    let mut z: Vec<PolyDdfFactor<M>> = Vec::new();
    let mut d = 1 as u32;
    let mut fstar = f.clone();

    while fstar.degree() as u32 >= 2 * d {
        // TODO: can we reuse the previous h and just recalculate the new base in case g == 1?
        let h = powmod(GF2mPoly::<M>::one_x(), q.clone().pow(d), &fstar) + GF2mPoly::<M>::one_x();
        //let h = powmod(h + GF2mPoly::<M>::one_x(), BigInt::one(), &fstar);
        let g = gcd(&h, &fstar);
        if g != GF2mPoly::<M>::one() {
            fstar = (&fstar / &g)?;
            z.push(PolyDdfFactor { factor: g, degree: d as u128 });
        }
        d += 1;
    }

    if fstar != GF2mPoly::<M>::one() {
        z.push(PolyDdfFactor { degree: fstar.degree() as u128, factor: fstar });
    } else if z.len() == 0 {
        z.push(PolyDdfFactor { factor: f, degree: 1 });
    }

    z.sort_by(|a, b| a.degree.cmp(&b.degree).then_with(|| a.factor.cmp(&b.factor)));
    Ok(z)
}

fn random_poly<M: ReducePoly>(max_len_exl: u128) -> GF2mPoly<M> {
    let mut rng = rand::rng();
    // end of range is exclusive
    let len = rng.random_range(1..max_len_exl);
    let mut elems: Vec<GF2m<M>> = Vec::with_capacity(len as usize);
    for _ in 0..len {
        elems.push(GF2m::new(rng.random()));
    }
    GF2mPoly { elems: elems }
}

pub fn edf<M: ReducePoly>(f: GF2mPoly<M>, d: u128) -> Result<Vec<GF2mPoly<M>>> {
    if !f.is_monic() {
        return Err(anyhow!("edf: f needs to be monic!"))
    }
    let q: BigInt = BigInt::one() << 128;
    let f_deg = f.degree() as u128;
    let n = f_deg / d;
    let mut z  = vec![f.clone()];

    while (z.len() as u128) < n {
        let h = random_poly::<M>(f_deg + 1);
        let g = powmod(h, (q.clone().pow(d as u32) - 1) / 3, &f) + GF2mPoly::<M>::one();

        for i in 0..z.len() {
            let u = z.swap_remove(i);
            if u.degree() as u128 > d {
                let j = gcd(&u, &g);
                if j != GF2mPoly::<M>::one() && j != u {
                    z.push((&u / &j)?);
                    z.push(j);
                    continue;
                }
            }
            z.push(u);
        }
    }

    z.sort();
    Ok(z)
}

impl<M: ReducePoly> Add for GF2mPoly<M> {
    type Output = GF2mPoly<M>;

    fn add(self, rhs: Self) -> Self::Output {
        self.add_borrowed(&rhs)
    }
}

impl<M: ReducePoly> AddAssign for GF2mPoly<M> {
    fn add_assign(&mut self, rhs: Self) {
        let result = self.add_borrowed(&rhs);
        self.elems = result.elems;
    }
}

impl<M: ReducePoly> Mul for GF2mPoly<M> {
    type Output = GF2mPoly<M>;

    fn mul(self, rhs: Self) -> Self::Output {
        self.mul_borrowed(&rhs)
    }
}

impl<M: ReducePoly> MulAssign<&GF2mPoly<M>> for GF2mPoly<M> {
    fn mul_assign(&mut self, rhs: &GF2mPoly<M>) {
        let res = self.mul_borrowed(rhs);
        self.elems = res.elems;
    }
}

impl<M: ReducePoly> Mul<&GF2mPoly<M>> for &GF2mPoly<M> {
    type Output = GF2mPoly<M>;

    fn mul(self, rhs: &GF2mPoly<M>) -> Self::Output {
        self.mul_borrowed(rhs)
    }
}

impl<M: ReducePoly> Div<&GF2mPoly<M>> for &GF2mPoly<M> {
    type Output = Result<GF2mPoly<M>>;

    fn div(self, rhs: &GF2mPoly<M>) -> Self::Output {
        let (q, r) = divmod(self, rhs);
        if r != GF2mPoly::<M>::zero() {
            return Err(anyhow!("GFPoly division divmod did not return rest zero"))
        }
        Ok(q)
    }
}

impl<M: ReducePoly> Clone for GF2mPoly<M> {
    fn clone(&self) -> Self {
        Self { elems: self.elems.clone() }
    }
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
            .then_with(|| self.elems.iter().rev().cmp(other.elems.iter().rev()))
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