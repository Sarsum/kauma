use core::ops::{Add, Mul, Div};
use std::{ops::{AddAssign}};

use num::{BigInt, One, Zero, bigint::Sign};

#[derive(Debug)]
pub struct GF2m<M: ReducePoly> {
    pub value: u128,
    _m: core::marker::PhantomData<M>, // need PhantomData for typing
}

/// Trait used for the different reduction polynoms P1 and P2
/// This way, the implementation can be shared through typing
/// Due to the trait being named Modulus before, it is being referenced as "M: ReducePoly"
pub trait ReducePoly {
    const DEG: u32;
    const MOD: u128;
}

#[derive(Debug)]
pub enum P1 {}
impl ReducePoly for P1 {
    const DEG: u32 = 128;
    // AES-GCM polynom order x0 ... x127
    // therefore, this is 1 + a + a2 + a7 + a128
    const MOD: u128 = (1u128 << 127) | (1u128 << 126) | (1u128 << 125) | (1u128 << 120);
}

#[derive(Debug)]
pub enum P2 {}
impl ReducePoly for P2 {
    const DEG: u32 = 128;
    // Same as above, this is 1 + a33 + a69 + a98 + a128
    const MOD: u128 = (1u128 << 127) | (1u128 << 94) | (1u128 << 58) | (1u128 << 29);
}

impl <M: ReducePoly> GF2m<M> {
    pub fn new(value: u128) -> Self {
        Self { value: value, _m: Default::default() }
    }

    pub fn zero() -> Self {
        Self { value: 0u128, _m: Default::default() }
    }

    pub fn one() -> Self {
        Self { value: 1u128 << (M::DEG - 1), _m: Default::default() }
    }

    pub fn mul(self, rhs: Self) -> Self {
        Self::mul_u128(self.value, rhs.value)
    }

    fn mul_u128(lhs: u128, rhs: u128) -> Self {
        // NIST SP 800-38D implementation for AES-GCM multiplication
        // The variable names are derived from there
        let mut z = 0u128;
        let mut v = rhs;
        // M::DEG is 128, therefore we need to substract one when calculating the index
        for i in 0..M::DEG {
            if lhs & (1u128 << (M::DEG - 1 - i)) != 0 {
                z ^= v
            }
            if v & 1 == 0 {
                v >>= 1;
            } else {
                v = (v >> 1) ^ M::MOD
            }
        }
        Self { value: z, _m: Default::default() }
    }

    pub fn mul_borrowed(lhs: &Self, rhs: &Self) -> Self {
        let result = Self::mul_u128(lhs.value, rhs.value);
        return Self { value: result.value, _m: Default::default() }
    }

    pub fn square(self) -> Self {
        Self::new(self.value) * self
    }

    pub fn pow(mut self, mut exp: BigInt) -> Self {
        if exp.is_zero() {
            return Self::one()
        } else if exp.sign() == Sign::Minus {
            return self.pow(-exp).inv();
        }
        let mut acc = Self::one();
        while &exp != &BigInt::zero() {
            if &exp & BigInt::one() != BigInt::zero() {
                acc = acc.mul(Self::new(self.value))
            }
            exp >>= 1;
            if exp != BigInt::zero() {
                self = self.square();
            }
        }
        acc
    }

    pub fn inv(self) -> Self {
        // Itoh–Tsujii a^-1 = a^(2^m - 2)
        // self.pow((BigInt::one() << M::DEG) - 2);
        let mut t = Self::new(self.value);
        for _ in 0..(M::DEG - 2) {
            t = &t.square() * &self;
        }
        t.square()
    }

    pub fn sqrt(self) -> Self {
        // sqrt(a) = a^(2^(m-1))
        // self.pow(BigInt::one() << (M::DEG - 1))
        let mut x = Self::new(self.value);
        for _ in 0..127 {
            x = x.square();
        }
        x
    }

    pub fn add_assign(&mut self, rhs: Self) {
        self.value ^= rhs.value;
    }
}

/// Implementation for var1 * var2 notation for multiplication of GF elements
impl<M: ReducePoly> Mul for GF2m<M> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        self.mul(rhs)
    }
}

/// Implementation for var1 + var2 notation for addition of GF elements
impl<M: ReducePoly> Add for GF2m<M> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self { value: self.value ^ rhs.value, _m: Default::default() }
    }
}

/// Implementation for var1 / var2 notation for divison of GF elements
impl<M: ReducePoly> Div for GF2m<M> {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        self * rhs.inv()
    }
}

impl<M: ReducePoly> AddAssign for GF2m<M> {
    fn add_assign(&mut self, rhs: Self) {
        self.add_assign(rhs);
    }
}

impl<'a, 'b, M: ReducePoly> Mul<&'b GF2m<M>> for &'a GF2m<M> {
    type Output = GF2m<M>;

    fn mul(self, rhs: &'b GF2m<M>) -> Self::Output {
        GF2m::<M>::mul_borrowed(self, rhs)
    }
}