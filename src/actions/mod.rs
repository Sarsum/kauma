use std::fmt;

use base64::{Engine, prelude::BASE64_STANDARD};
use num::{BigInt};
use serde::{Deserialize, Deserializer, Serialize, de};
use serde_json::Value;
use anyhow::{Result};

mod calc;
mod padding_oracle;
mod gf_actions;
mod gcm_actions;
mod gfpoly_actions;

#[derive(Debug)]
/// Type used when parsing the actions into the action enum
/// Required as the numbers can either be integers or hex-strings
pub struct ActionNumber(BigInt);

#[derive(Debug)]
// Type to map the base64-encoded bytes of unkown length 
pub struct ActionBytes(Vec<u8>);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
// Special type for the GF actions including AES-GCM polynoms in BE
pub struct ActionGfU128(pub u128);

#[derive(Debug, Deserialize)]
#[serde(rename_all="snake_case")]
/// Additional type for the two polynom versions due to a ton of required deserialization methods to automatically map the polynom
/// This is due to the different variable names in the different action types
/// Enum can be matched inside the action and the desired typed GF element created 
pub enum ActionPoly { P1, P2 }

#[derive(Debug, Deserialize, Serialize)]
pub struct ActionGfPoly(pub Vec<ActionGfU128>);

#[derive(Deserialize, Debug)]
// tag=action maps the enum name to the action field of the json
// content=arguments pulls the enum values from the actions' arguments
// snake_case to map the Rust naming convention to the name of the actions
#[serde(tag="action", content="arguments", rename_all="snake_case")]
pub enum Action {
    Calc {
        lhs: ActionNumber,
        op: String,
        rhs: ActionNumber,
    },
    PaddingOracle {
        hostname: String,
        port: ActionNumber,
        key_id: ActionNumber,
        iv: ActionBytes,
        ciphertext: ActionBytes
    },
    GfMul {
        a: ActionGfU128,
        b: ActionGfU128,
        poly: ActionPoly
    },
    GfPow {
        b: ActionGfU128,
        e: ActionNumber,
        poly: ActionPoly
    },
    GfInv {
        x: ActionGfU128,
        poly: ActionPoly
    },
    GfDiv {
        a: ActionGfU128,
        b: ActionGfU128,
        poly: ActionPoly
    },
    GfSqrt {
        x: ActionGfU128,
        poly: ActionPoly
    },
    GfDivmod {
        a: ActionGfU128,
        b: ActionGfU128
    },
    GcmEncrypt {
        poly: ActionPoly,
        nonce: ActionBytes,
        key: ActionBytes,
        plaintext: ActionBytes,
        ad: ActionBytes
    },
    GfpolySort {
        polys: Vec<ActionGfPoly>
    },
    GfpolyMonic {
        #[serde(rename="A")]
        a: ActionGfPoly,
        poly: ActionPoly
    },
    GfpolyAdd {
        #[serde(rename="A")]
        a: ActionGfPoly,
        #[serde(rename="B")]
        b: ActionGfPoly,
        poly: ActionPoly
    },
    GfpolyMul {
        #[serde(rename="A")]
        a: ActionGfPoly,
        #[serde(rename="B")]
        b: ActionGfPoly,
        poly: ActionPoly
    },
    GfpolyDivmod {
        #[serde(rename="A")]
        a: ActionGfPoly,
        #[serde(rename="B")]
        b: ActionGfPoly,
        poly: ActionPoly
    },
    GfpolyGcd {
        #[serde(rename="A")]
        a: ActionGfPoly,
        #[serde(rename="B")]
        b: ActionGfPoly,
        poly: ActionPoly
    },
    GfpolyPow {
        #[serde(rename="B")]
        b: ActionGfPoly,
        e: u8,
        poly: ActionPoly
    },
    GfpolyPowmod {
        #[serde(rename="B")]
        b: ActionGfPoly,
        e: ActionNumber,
        #[serde(rename="M")]
        m: ActionGfPoly,
        poly: ActionPoly
    },
    GfpolyDiff {
        #[serde(rename="F")]
        f: ActionGfPoly,
        poly: ActionPoly
    },
    GfpolySqrt {
        #[serde(rename="S")]
        s: ActionGfPoly,
        poly: ActionPoly
    },
    GfpolyFactorSff {
        #[serde(rename="F")]
        f: ActionGfPoly,
        poly: ActionPoly
    },
    GfpolyFactorDdf {
        #[serde(rename="F")]
        f: ActionGfPoly,
        poly: ActionPoly
    },
    GfpolyFactorEdf {
        #[serde(rename="F")]
        f: ActionGfPoly,
        d: u32,
        poly: ActionPoly
    }
}

// I might write a proper deserializer at a later point
// for the moment, this is sufficient to handle unknown action types
#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub enum TryAction {
    Ok(Action),
    Err(Value),
}

pub fn run_action(action: Action) -> Result<Value> {
    match action {
        Action::Calc { lhs, op, rhs } => calc::run_action(lhs, op, rhs),
        Action::PaddingOracle { hostname, port, key_id, iv, ciphertext }
            => padding_oracle::run_action(hostname, port.0, key_id.0, iv.0, ciphertext.0),
        Action::GfMul { a, b, poly } => gf_actions::run_gf_mul(a.0, b.0, poly),
        Action::GfPow { b, e, poly } => gf_actions::run_gf_pow(b.0, e.0, poly),
        Action::GfInv { x, poly } => gf_actions::run_gf_inv(x.0, poly),
        Action::GfDiv { a, b, poly } => gf_actions::run_gf_div(a.0, b.0, poly),
        Action::GfSqrt { x, poly } => gf_actions::run_gf_sqrt(x.0, poly),
        Action::GfDivmod { a, b } => gf_actions::run_gf_divmod(a.0, b.0),
        Action::GcmEncrypt { poly, nonce, key, plaintext, ad }
            => gcm_actions::run_gcm_encrypt(poly, nonce.0, key.0, plaintext.0, ad.0),
        Action::GfpolySort { polys } => gfpoly_actions::run_gfpoly_sort(polys),
        Action::GfpolyAdd { a, b, poly } => gfpoly_actions::run_gfpoly_add(a, b, poly),
        Action::GfpolyMul { a, b, poly } => gfpoly_actions::run_gfpoly_mul(a, b, poly),
        Action::GfpolyMonic { a, poly } => gfpoly_actions::run_gfpoly_monic(a, poly),
        Action::GfpolyDivmod { a, b, poly } => gfpoly_actions::run_gfpoly_divmod(a, b, poly),
        Action::GfpolyGcd { a, b, poly } => gfpoly_actions::run_gfpoly_gcd(a, b, poly),
        Action::GfpolyPow { b, e, poly } => gfpoly_actions::run_gfpoly_pow(b, e, poly),
        Action::GfpolyPowmod { b, e, m, poly } => gfpoly_actions::run_gfpoly_powmod(b, e.0, m, poly),
        Action::GfpolyDiff { f, poly } => gfpoly_actions::run_gfpoly_diff(f, poly),
        Action::GfpolySqrt { s, poly } => gfpoly_actions::run_gfpoly_sqrt(s, poly),
        Action::GfpolyFactorSff { f, poly } => gfpoly_actions::run_gfpoly_sff(f, poly),
        Action::GfpolyFactorDdf { f, poly } => gfpoly_actions::run_gfpoly_ddf(f, poly),
        Action::GfpolyFactorEdf { f, d, poly } => gfpoly_actions::run_gfpoly_edf(f, d as u128, poly)
    }
}

impl<'de> Deserialize<'de> for ActionNumber {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct V;

        /// contains different "visit_TYPE" methods which will be invoked for the respective type being present when expecting an ActionNumber
        impl<'de> de::Visitor<'de> for V {
            type Value = ActionNumber;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str(r#"a JSON integer or a hex string "0x..." / "-0x...""#)
            }
            
            // serde only offers access to i64, not i32
            // As we expect ints in range of -2^31 ... 2^31 - 1, implementing just i64 (instead of i64 and i128) is sufficient
            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
            where E: de::Error {
                Ok(ActionNumber(BigInt::from(v)))
            }

            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where E: de::Error {
                Ok(ActionNumber(BigInt::from(v)))
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where E: de::Error {
                let (neg, digits) = if let Some(rest) = s.strip_prefix("-0x") {
                    (true, rest)
                } else if let Some(rest) = s.strip_prefix("0x") {
                    (false, rest)
                } else {
                    return Err(E::custom(r#"expected "0x" or "-0x" prefix"#));
                };

                if digits.is_empty() {
                    return Err(E::custom("empty hex digits"));
                }

                let n = BigInt::parse_bytes(digits.as_bytes(), 16)
                    .ok_or_else(|| E::custom("invalid hex digits"))?;

                Ok(ActionNumber(if neg { -n } else { n }))
            }
        }

        deserializer.deserialize_any(V)
    }
}

impl<'de> Deserialize<'de> for ActionBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct V;

        // only expecting a string for ActionBytes
        impl<'de> de::Visitor<'de> for V {
            type Value = ActionBytes;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str(r#"String containing base64 encoded data"#)
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where E: de::Error {
                return match BASE64_STANDARD.decode(s) {
                    Ok(bytes) => Ok(ActionBytes(bytes)),
                    Err(error) => {
                        eprintln!("Failed to parse bytes, error: {}", error.to_string());
                        Err(E::custom(error.to_string()))
                    }
                };
            }
        }

        deserializer.deserialize_any(V)
    }
}

impl<'de> Deserialize<'de> for ActionGfU128 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct V;

        impl<'de> de::Visitor<'de> for V {
            type Value = ActionGfU128;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str(r#"String containing 16 base64 encoded bytes"#)
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where E: de::Error {
                return match BASE64_STANDARD.decode(s) {
                    Ok(bytes) => {
                        return match <[u8; 16]>::try_from(bytes) {
                            Ok(num) => Ok(ActionGfU128(u128::from_be_bytes(num))),
                            Err(err) => {
                                eprintln!("err");
                                Err(E::custom(format!("Error parsing {:x?} as 16 bytes into u128. Actual lenght: {}", err, err.len())))
                            }
                        };
                    },
                    Err(error) => {
                        eprintln!("Failed to parse bytes, error: {}", error.to_string());
                        Err(E::custom(error.to_string()))
                    }
                };
            }
        }

        deserializer.deserialize_any(V)
    }
}

impl Serialize for ActionGfU128 {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
        where
            S: serde::Serializer {
        let b64 = BASE64_STANDARD.encode(self.0.to_be_bytes());
        serializer.serialize_str(&b64)
    }
}