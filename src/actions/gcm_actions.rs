use anyhow::{Ok, Result, anyhow};
use base64::{Engine, prelude::BASE64_STANDARD};
use serde_json::{Value, json};

use crate::{actions::{ActionGcmCrackForgery, ActionGcmCrackMessage, ActionPoly}, utils::{aes::{gcm_crack, gcm_encrypt}, gf::{P1, P2, ReducePoly}}};

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

pub fn run_gcm_crack(nonce: Vec<u8>, m1: ActionGcmCrackMessage, m2: ActionGcmCrackMessage, m3: ActionGcmCrackMessage,
    forgery: ActionGcmCrackForgery, poly: ActionPoly) -> Result<Value> {
        return match poly {
            ActionPoly::P1 => gcm_crack_wrapper::<P1>(nonce, m1, m2, m3, forgery),
            ActionPoly::P2 => gcm_crack_wrapper::<P2>(nonce, m1, m2, m3, forgery)
        }
    }

fn gcm_crack_wrapper<M: ReducePoly>(nonce: Vec<u8>, m1: ActionGcmCrackMessage, m2: ActionGcmCrackMessage, m3: ActionGcmCrackMessage,
    forgery: ActionGcmCrackForgery) -> Result<Value> {
        let result = gcm_crack::<M>(nonce, m1.ciphertext.0, m1.associated_data.0, m1.tag.0,
            m2.ciphertext.0, m2.associated_data.0, m2.tag.0,
            m3.ciphertext.0, m3.associated_data.0, m3.tag.0, forgery.ciphertext.0, forgery.associated_data.0)?;
        Ok(json!({"tag": result.tag, "H": result.h, "mask": result.mask}))
    }