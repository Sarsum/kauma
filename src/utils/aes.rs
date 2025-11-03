use anyhow::{Result, anyhow};
use openssl::{symm::{Cipher, Crypter, Mode}};

use crate::utils::gf::{GF2m, ReducePoly};

pub struct AesGcmResult {
    pub ciphertext: Vec<u8>,
    pub tag: [u8; 16],
    pub l: [u8; 16],
    pub h: [u8; 16]
}

pub fn gcm_encrypt<M: ReducePoly>(nonce: &[u8; 12], key: &[u8; 16], plaintext: Vec<u8>, ad: Vec<u8>) -> Result<AesGcmResult> {
    let mut encrypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, key, None).map_err(|err| anyhow!(err.to_string()))?;
    encrypter.pad(false);
    let mut encrypter_buffer = [0u8; 32];

    // Generate Auth Key H once
    let auth_key_result = encrypter.update(&vec![0u8; 16], &mut encrypter_buffer)
        .map_err(|err| anyhow!(err.to_string()))?;
    if auth_key_result != 16 {
        return Err(anyhow!("Auth Key operation did not encrypt 16 bytes"));
    }
    let auth_key: [u8; 16] = encrypter_buffer[..16].try_into().map_err(|_| anyhow!("error converting buffer auth key into 16 byte vec"))?;

    let auth_key_gf = GF2m::<M>::new(u128::from_be_bytes(auth_key));

    // initialize Y
    let mut y = [0u8; 16];
    y[..12].copy_from_slice(nonce);
    let mut ctr: u32 = 1;
    y[12..].copy_from_slice(&ctr.to_be_bytes());

    // Get auth tag XOR
    let auth_tag_xor_result = encrypter.update(&y, &mut encrypter_buffer)
        .map_err(|err| anyhow!(err.to_string()))?;
    if auth_tag_xor_result != 16 {
        return Err(anyhow!("Auth Tag XOR generation did not encrypt 16 bytes"))
    }
    let auth_tag_xor: [u8; 16] = get_16_bytes(&encrypter_buffer)?;
    let auth_tag_xor = u128::from_be_bytes(auth_tag_xor);

    let mut auth_tag = GF2m::<M>::zero();

    // Consume additional data before encryption
    let ad_len = ad.len();
    let ad_full_blocks = ad_len / 16;
    let ad_block_offset = ad_len % 16;
    for i in 0..ad_full_blocks {
        let block = get_16_bytes(&ad[i*16..(i*16+16)])?;
        auth_tag = GF2m::<M>::new(auth_tag.value ^ u128::from_be_bytes(block));
        auth_tag = &auth_tag * &auth_key_gf;
    }
    if ad_block_offset > 0 {
        let mut tmp = [0u8; 16];
        for i in 0..ad_block_offset {
            tmp[i] = ad[ad_full_blocks*16+i];
        }
        auth_tag = GF2m::<M>::new(auth_tag.value ^ u128::from_be_bytes(tmp));
        auth_tag = &auth_tag * &auth_key_gf;
    }

    let plain_len = plaintext.len();
    let plain_full_blocks = plain_len / 16;
    let plain_block_offset = plain_len % 16;
    let mut ciphertext: Vec<u8> = Vec::new();
    for i in 0..plain_full_blocks {
        // Initialized at 1, need to increase before each ciphertext block
        ctr += 1;
        // set counter bytes
        y[12..].copy_from_slice(&ctr.to_be_bytes());
        let block_encrypt_result = encrypter.update(&y, &mut encrypter_buffer)
            .map_err(|err| anyhow!(err.to_string()))?;
        if block_encrypt_result != 16 {
            return Err(anyhow!(format!("Ciphertext block {} did not encrypt 16 bytes", i)))
        }
        let block: [u8; 16] = get_16_bytes(&encrypter_buffer)?;
        let block = u128::from_be_bytes(block);
        let plain_block = u128::from_be_bytes(get_16_bytes(&plaintext[(i*16)..(i+1)*16])?);
        let cipher_block = block ^ plain_block;
        ciphertext.extend_from_slice(&cipher_block.to_be_bytes());

        // extend auth tag
        auth_tag = &GF2m::<M>::new(cipher_block ^ auth_tag.value) * &auth_key_gf;
    }

    if plain_block_offset > 0 {
        ctr += 1;
        y[12..].copy_from_slice(&ctr.to_be_bytes());
        let block_encrypt_result = encrypter.update(&y, &mut encrypter_buffer)
            .map_err(|err| anyhow!(err.to_string()))?;
        if block_encrypt_result != 16 {
            return Err(anyhow!(format!("Offset Ciphertext block did not encrypt 16 bytes")))
        }
        let block: [u8; 16] = get_16_bytes(&encrypter_buffer)?;
        let mut tmp = [0u8; 16];

        // only want to XOR with set bytes and keep 0-bytes for GHASH, therefore for loop
        for i in 0..plain_block_offset {
            tmp[i] = plaintext[plain_full_blocks*16+i] ^ block[i]
        }
        // only ciphertext bytes
        ciphertext.extend_from_slice(&tmp[..plain_block_offset]);

        auth_tag = GF2m::<M>::new(auth_tag.value ^ u128::from_be_bytes(tmp));
        auth_tag = &auth_tag * &auth_key_gf;
    }

    // len(A)*8 || len(ciphertext)*8 for bit lengths
    let l = (ad_len as u128 * 8) << 64 | (plain_len as u128 * 8);
    auth_tag = &GF2m::<M>::new(l ^ auth_tag.value) * &auth_key_gf;


    return Ok(AesGcmResult { ciphertext: ciphertext, tag: (auth_tag.value ^ auth_tag_xor).to_be_bytes(), l: l.to_be_bytes(), h: auth_key});
}

fn get_16_bytes(arr: &[u8]) -> Result<[u8; 16]> {
    arr[..16].try_into().map_err(|_| anyhow!("error converting array into 16 byte array"))
}