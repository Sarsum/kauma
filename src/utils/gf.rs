use core::ops::{Add, Mul, Div};

use num::{BigInt, One, Zero};

#[derive(Debug)]
pub struct GF2m<M: ReducePoly> {
    pub value: u128,
    _m: core::marker::PhantomData<M>, // need PhantomData for typing
}

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

    pub fn one() -> Self {
        Self { value: 1u128 << (M::DEG - 1), _m: Default::default() }
    }

    pub fn mul(self, rhs: Self) -> Self {
        let mut z = 0u128;
        let mut v = rhs.value;
        // M::DEG is 128, therefore we need to substract one when calculating the index
        for i in 0..M::DEG {
            if self.value & (1u128 << (M::DEG - 1 - i)) != 0 {
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

    pub fn square(self) -> Self {
        Self::new(self.value) * self
    }

    pub fn pow(mut self, mut exp: BigInt) -> Self {
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
        self.pow((BigInt::one() << M::DEG) - 2)

    }

    pub fn sqrt(self) -> Self {
        // sqrt(a) = a^(2^(m-1))
        self.pow(BigInt::one() << (M::DEG - 1))
    }
}

impl<M: ReducePoly> Mul for GF2m<M> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        self.mul(rhs)
    }
}

impl<M: ReducePoly> Add for GF2m<M> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self { value: self.value ^ rhs.value, _m: Default::default() }
    }
}

impl<M: ReducePoly> Div for GF2m<M> {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        self * rhs.inv()
    }
}