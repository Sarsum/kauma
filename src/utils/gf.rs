use core::ops::{Add, Mul, Div};
use std::{cmp::Ordering, ops::{AddAssign, BitXorAssign, MulAssign}};

use base64::{Engine, prelude::BASE64_STANDARD};
use num::{BigInt, One, Zero, bigint::Sign};
use serde::Serialize;

#[derive(Debug)]
pub struct GF2m<M: ReducePoly> {
    pub value: u128,
    _m: core::marker::PhantomData<M>, // need PhantomData for typing as M is not used in the struct otherwise but required for the GF reduction
}

impl<M: ReducePoly> Clone for GF2m<M> {
    fn clone(&self) -> Self {
        Self::new(self.value)
    }
}

/// Trait used for the different reduction polynoms P1 and P2
/// This way, the implementation can be shared through typing
/// Due to the trait being named Modulus before, it is being referenced as "M: ReducePoly"
pub trait ReducePoly {
    const DEG: u32;
    const MOD: u128;

    fn reduce_256(hi: u128, lo: u128) -> u128;
}

#[derive(Debug, PartialEq, Eq)]
pub enum P1 {}
impl ReducePoly for P1 {
    const DEG: u32 = 128;
    // AES-GCM polynom order x0 ... x127
    // therefore, this is 1 + a + a2 + a7 + a128
    //const MOD: u128 = (1u128 << 127) | (1u128 << 126) | (1u128 << 125) | (1u128 << 120);
    const MOD: u128 = 1u128 | (1u128 << 1) | (1u128 << 2) | (1u128 << 7);

    fn reduce_256(hi: u128, lo: u128) -> u128 {
        // First fold: hi * (x^7 + x^2 + x + 1)
        let s = hi ^ (hi << 1) ^ (hi << 2) ^ (hi << 7);

        // Overflows from those shifts (bits that crossed past bit 127)
        let c = (hi >> 127) ^ (hi >> 126) ^ (hi >> 121);

        // Reduce the overflow once more by r(x)
        let cf = c ^ (c << 1) ^ (c << 2) ^ (c << 7);

        // Final reduced 128-bit value
        lo ^ s ^ cf
    }
}

#[derive(Debug)]
pub enum P2 {}
impl ReducePoly for P2 {
    const DEG: u32 = 128;
    // Same as above, this is 1 + a33 + a69 + a98 + a128
    //const MOD: u128 = (1u128 << 127) | (1u128 << 94) | (1u128 << 58) | (1u128 << 29);
    const MOD : u128 = (1u128) | (1u128 << 33) | (1u128 << 69) | (1u128 << 98);

    fn reduce_256(hi: u128, lo: u128) -> u128 {
        // m(x) = x^128 + x^98 + x^69 + x^33 + 1
        const A: u32 = 33;
        const B: u32 = 69;
        const C: u32 = 98;

        #[inline(always)]
        fn fold(y: u128) -> u128 {
            y ^ (y << A) ^ (y << B) ^ (y << C)
        }

        #[inline(always)]
        fn carry(y: u128) -> u128 {
            (y >> (128 - A)) ^ (y >> (128 - B)) ^ (y >> (128 - C))
            // i.e., (y >> 95) ^ (y >> 59) ^ (y >> 30)
        }

        let mut out = lo ^ fold(hi);
        let mut c = carry(hi);

        // Iterate carries until nothing remains. Typically a few iterations at most.
        while c != 0 {
            out ^= fold(c);
            c = carry(c);
        }
        out
    }
}

impl <M: ReducePoly> GF2m<M> {
    pub fn new(value: u128) -> Self {
        Self { value: value, _m: Default::default() }
    }

    pub fn from_be_bytes(value: [u8; 16]) -> Self {
        Self { value: u128::from_be_bytes(value).reverse_bits(), _m: Default::default() }
    }

    pub fn zero() -> Self {
        Self { value: 0u128, _m: Default::default() }
    }

    pub fn is_zero(&self) -> bool {
        self.value == 0
    }

    pub fn one() -> Self {
        Self { value: 1u128, _m: Default::default() }
    }

    // using pclmulqdq from Intel CPU features: Algorithm 2 from
    // "Intel Carry-Less Multiplication Instruction and its Usage for Computing the GCM Mode" (p. 13)
    #[target_feature(enable = "pclmulqdq")]
    fn gf128_mul_pclmul(a: u128, b: u128) -> u128 {
        use core::arch::x86_64::*;

        // split into 64-bit halves
        let a1 = (a >> 64) as u64;
        let a2 = a as u64;
        let b1 = (b >> 64) as u64;
        let b2 = b as u64;

        unsafe fn clmul_64(x: u64, y: u64) -> (u64, u64) {
            unsafe {
                let vx = _mm_set_epi64x(0, x as i64);
                let vy = _mm_set_epi64x(0, y as i64);
                let r = _mm_clmulepi64_si128(vx, vy, 0x00);
                let mut tmp = [0u64; 2];
                _mm_storeu_si128(tmp.as_mut_ptr() as *mut __m128i, r);
                (tmp[1], tmp[0]) 
            }
        }

        unsafe {
            let (c1, c0) = clmul_64(a1,       b1);
            let (d1, d0) = clmul_64(a2,       b2);
            let (e1, e0) = clmul_64(a1 ^ a2, b1 ^ b2);

            let hi = (c1 as u128) << 64 | (c0 ^ c1 ^ d1 ^ e1) as u128;
            let lo = (((d1 ^ c0 ^ d0 ^ e0) as u128) << 64) | d0 as u128;

            M::reduce_256(hi, lo)
        }
    }

    fn gf128_mul_fallback(a: u128, b: u128) -> u128 {
        // fallback to existing mul
        mul_u128(a, b, M::MOD, M::DEG)
    }

    pub fn gf128_mul_fast(a: u128, b: u128) -> u128 {
        #[cfg(all(target_arch = "x86_64"))]
        {
            if std::is_x86_feature_detected!("pclmulqdq") {
                // double checked feature flag, expected to work safely
                unsafe { Self::gf128_mul_pclmul(a, b) }
            } else {
                Self::gf128_mul_fallback(a, b)
            }
        }

        #[cfg(not(target_arch = "x86_64"))]
        {
            // non-x86: always use fallback (or aarch64 PMULL path)
            gf128_mul_fallback(a, b)
        }
    }

    pub fn mul(self, rhs: Self) -> Self {
        //let result = mul_u128(self.value, rhs.value, M::MOD, M::DEG);
        let result = Self::gf128_mul_fast(self.value, rhs.value);
        Self { value: result, _m: Default::default() }
    }

    /// mul_assign with pointer-rhs, can be used for both (rhs being pointer and GF2m directly)
    pub fn inner_mul_assign(&mut self, rhs: &Self) {
        //let result = mul_u128(self.value, rhs.value, M::MOD, M::DEG);
        let result = Self::gf128_mul_fast(self.value, rhs.value);
        self.value = result;
    }

    pub fn mul_borrowed(lhs: &Self, rhs: &Self) -> Self {
        //let result = mul_u128(lhs.value, rhs.value, M::MOD, M::DEG);
        let result = Self::gf128_mul_fast(lhs.value, rhs.value);
        return Self { value: result, _m: Default::default() }
    }

    fn spread32(x: u32) -> u64 {
        // feature saves about 0.070 seconds on 10.000 testcases
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        if is_x86_feature_detected!("bmi2") {
            unsafe {
                // Keep bits masked with 1: 101010101010......1010
                return core::arch::x86_64::_pdep_u64(x as u64, 0x5555_5555_5555_5555u64)
            }
        }
        // fallback for chips without BMI2 (older / other architecture)
        let mut x = (x as u64) << 32;
        x = (x | (x >> 16)) & 0x0000_FFFF_0000_FFFF;
        x = (x | (x >> 8))  & 0x00FF_00FF_00FF_00FF;
        x = (x | (x >> 4))  & 0x0F0F_0F0F_0F0F_0F0F;
        x = (x | (x >> 2))  & 0x3333_3333_3333_3333;
        x = (x | (x >> 1))  & 0x5555_5555_5555_5555;
        x
    }

    fn interlace_zeros_lsb_u128(input: u128) -> (u128, u128) {
        // split num into 4 32-bit blocks due to CPU feature supporting 32bit to 64bit block
        let w0 = input as u32; // x^31 .. x^0
        let w1 = (input >> 32) as u32; // x^63 .. x^32
        let w2 = (input >> 64) as u32; // x^95 .. x^64
        let w3 = (input >> 96) as u32; // x^127 .. x^96

        let o0 = Self::spread32(w0); // x^63 .. x^0 
        let o1 = Self::spread32(w1); // x^127 .. x^64 
        let o2 = Self::spread32(w2); // x^191 .. x^128
        let o3 = Self::spread32(w3); // x^255 .. x^192

        // merge blocks into hi and lo, where hi = lo = x^255 .. x^128 and x^127 .. x^0
        let lo = ((o1 as u128) << 64) | (o0 as u128);
        let hi = ((o3 as u128) << 64) | (o2 as u128);

        (hi, lo)
    }

    fn square_fast(&self) -> Self {
        // square by putting a zero after each bit going from MSB to LSB
        let (hi, lo) = Self::interlace_zeros_lsb_u128(self.value);

        // reduce the 256 bits back into 128 for our polynomial form
        let reduced = M::reduce_256(hi, lo);
        Self::new(reduced)
    }


    pub fn square(&self) -> Self {
        //self * self
        // performance is SLIGHTLY better, talking again about 0.05 - 0.07 seconds at best for 10.000 cases
        // was hell of a rabbit hole to get the reduce working, keeping it as an easter egg
        self.square_fast()
    }

    pub fn pow(mut self, mut exp: BigInt) -> Self {
        if exp.is_zero() {
            return Self::one()
        } else if exp.sign() == Sign::Minus {
            return self.pow(-exp).inv();
        }
        let mut acc = Self::one();
        while exp != BigInt::zero() {
            if &exp & BigInt::one() != BigInt::zero() {
                acc *= Self::new(self.value)
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

    pub fn sqrt(&self) -> Self {
        // sqrt(a) = a^(2^(m-1))
        // self.pow(BigInt::one() << (M::DEG - 1))
        let mut x = Self::new(self.value);
        for _ in 0..(M::DEG - 1) {
            x = x.square();
        }
        x
    }

    pub fn add_assign(&mut self, rhs: Self) {
        self.value ^= rhs.value;
    }
}

fn mul_u128(mut lhs: u128, mut rhs: u128, poly: u128, degree: u32) -> u128 {
    let top = 1u128 << (degree - 1);
    let mut z = 0u128;
    for _ in 0..degree {
        if lhs & 1 != 0 {
            z ^= rhs;
        }
        let carry = (rhs & top) != 0;
        rhs <<= 1;
        if carry {
            rhs ^= poly;
        }
        lhs >>=1;
    }
    z
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

impl<'lhs, 'rhs, M: ReducePoly> Add<&'rhs GF2m<M>> for &'lhs GF2m<M> {
    type Output = GF2m<M>;

    fn add(self, rhs: &GF2m<M>) -> Self::Output {
        GF2m::<M>::new(self.value ^ rhs.value)
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

impl<M: ReducePoly> AddAssign<&GF2m<M>> for GF2m<M> {
    fn add_assign(&mut self, rhs: &GF2m<M>) {
        self.value ^= rhs.value;
    }
}

impl<'lhs, 'rhs, M: ReducePoly> Mul<&'rhs GF2m<M>> for &'lhs GF2m<M> {
    type Output = GF2m<M>;

    fn mul(self, rhs: &'rhs GF2m<M>) -> Self::Output {
        GF2m::<M>::mul_borrowed(self, rhs)
    }
}

/// BitXorAssign for u128, AddAssign is only for same types
impl<M: ReducePoly> BitXorAssign<u128> for GF2m<M> {
    fn bitxor_assign(&mut self, rhs: u128) {
        self.value ^= rhs
    }
}

impl<M:ReducePoly> MulAssign<GF2m<M>> for GF2m<M> {
    fn mul_assign(&mut self, rhs: GF2m<M>) {
        self.inner_mul_assign(&rhs);
    }
}

/// MullAssign for rhs-pointer (used in loops, when we need rhs multiple times)
impl<'lhs, 'rhs, M: ReducePoly> MulAssign<&'rhs GF2m<M>> for GF2m<M> {
    fn mul_assign(&mut self, rhs: &'rhs GF2m<M>) {
        self.inner_mul_assign(rhs);
    }
}

impl<M: ReducePoly> Serialize for GF2m<M> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer {
        let b64 = BASE64_STANDARD.encode(self.value.reverse_bits().to_be_bytes());
        serializer.serialize_str(&b64)
    }
}

// equality just by value
impl<M: ReducePoly> PartialEq for GF2m<M> {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl<M: ReducePoly> Eq for GF2m<M> {}

impl<M: ReducePoly> Ord for GF2m<M> {
    fn cmp(&self, other: &Self) -> Ordering {
        // GCM convention smaller numbers bigger value
        self.value.cmp(&other.value)
    }
}


impl<M: ReducePoly> PartialOrd for GF2m<M> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[test]
// interlacing is not dependend on P1/P2, therefore testing with P1
fn test_interlacing() {
    let x: u128 = 1;
    let (hi, lo) = GF2m::<P1>::interlace_zeros_lsb_u128(x);
    assert_eq!(hi, 0);
    assert_eq!(lo, 1u128);

    let x: u128 = (1 << 64) | (1 << 31);
    let (hi, lo) = GF2m::<P1>::interlace_zeros_lsb_u128(x);
    assert_eq!(hi, 1);
    assert_eq!(lo, (1 << 62));

    let x: u128 = 1 << 127;
    let (hi, lo) = GF2m::<P1>::interlace_zeros_lsb_u128(x);
    // we expect x^(2*127 = 254) to be set
    assert_eq!(hi, 1u128 << 126);
    assert_eq!(lo, 0);
}

#[test]
fn test_reduce_p1() {
    let result = P1::reduce_256(1, 0);
    assert_eq!(result, P1::MOD);

    let result = P1::reduce_256(1, P1::MOD);
    assert_eq!(result, 0);
}

#[test]
fn test_reduce_p2() {
    let result = P2::reduce_256(1, 0);
    assert_eq!(result, P2::MOD);

    let result = P2::reduce_256(1, P2::MOD);
    assert_eq!(result, 0);
}