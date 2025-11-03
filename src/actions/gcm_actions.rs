use anyhow::{Ok, Result, anyhow};
use base64::{Engine, prelude::BASE64_STANDARD};
use serde_json::{Value, json};

use crate::{actions::ActionPoly, utils::{aes::gcm_encrypt, gf::{P1, P2, ReducePoly}}};

pub fn run_gcm_encrypt(poly: ActionPoly, nonce: Vec<u8>, key: Vec<u8>, plaintext: Vec<u8>, ad: Vec<u8>) -> Result<Value> {
    match poly {
        ActionPoly::P1 => action_gcm_encrypt::<P1>(nonce, key, plaintext, ad),
        ActionPoly::P2 => action_gcm_encrypt::<P2>(nonce, key, plaintext, ad)
    }    
}

fn action_gcm_encrypt<M: ReducePoly>(nonce_raw: Vec<u8>, key_raw: Vec<u8>, plaintext: Vec<u8>, ad: Vec<u8>) -> Result<Value> {
    let nonce = nonce_raw[..12].try_into().map_err(|_| anyhow!("nonce must be 12 byte"))?;
    let key = key_raw[..16].try_into().map_err(|_| anyhow!("key must be 16 bytes"))?;
    let result = gcm_encrypt::<M>(nonce, key, plaintext, ad)?;
    Ok(json!({"ciphertext": BASE64_STANDARD.encode(result.ciphertext), "tag": BASE64_STANDARD.encode(result.tag),
        "L": BASE64_STANDARD.encode(result.l), "H": BASE64_STANDARD.encode(result.h)}))
}