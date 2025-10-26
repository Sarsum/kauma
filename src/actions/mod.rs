use std::fmt;

use base64::{Engine, prelude::BASE64_STANDARD};
use num::{BigInt};
use serde::{Deserialize, Deserializer, de};
use serde_json::Value;
use anyhow::Result;

mod calc;
mod padding_oracle;

#[derive(Debug)]
pub struct ActionNumber(BigInt);

#[derive(Debug)]
pub struct ActionBytes(Vec<u8>);

#[derive(Deserialize, Debug)]
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
    }
}

// I might write a proper deserializer at an later point
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
    }
}

impl<'de> Deserialize<'de> for ActionNumber {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct V;

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