use anyhow::{Ok, Result, anyhow};
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

    // Create keystream including H, passing slice with H to subfunctions
    let plain_len = plaintext.len();
    // division is floored, therefore we get the correct (floored) result if last block contains less than 16 bytes
    let keystream_blocks = (plain_len + 15) / 16;
    // start counter at 2; one block more because we want H
    let keystream = generate_keystream(&mut encrypter, nonce, 1, keystream_blocks + 1)?;

    let auth_tag_xor = u128::from_be_bytes(get_16_bytes(&keystream[0..16])?);

    let mut auth_tag = GF2m::<M>::zero();

    // Consume additional data before encryption
    ghash_bytes(&mut auth_tag, &auth_key_gf, &ad)?;
    
    // ciphertext should be exaclty as long as plaintext
    let mut ciphertext: Vec<u8> = Vec::with_capacity(plain_len);
    encrypt_and_ghash(&mut ciphertext, &mut auth_tag, &auth_key_gf, &plaintext, &keystream[16..])?;

    // len(A)*8 || len(ciphertext)*8 for bit lengths
    let l = (ad.len() as u128 * 8) << 64 | (plain_len as u128 * 8);
    ghash_apply_block(&mut auth_tag, l, &auth_key_gf);

    return Ok(AesGcmResult { ciphertext: ciphertext, tag: (auth_tag.value ^ auth_tag_xor).to_be_bytes(), l: l.to_be_bytes(), h: auth_key});
}

fn ghash_apply_block<M: ReducePoly>(auth_tag: &mut GF2m<M>, xor_val: u128, auth_key: &GF2m<M>) {
    *auth_tag ^= xor_val;
    *auth_tag *= auth_key;
}

/// generic GHASH function, used only for AD due to my implementation of applying GHASH while encrypting
fn ghash_bytes<M: ReducePoly>(auth_tag: &mut GF2m<M>, h: &GF2m<M>, data: &[u8]) -> Result<()> {
    // process complete 16 byte chunks, nothing to keep in mind
    for chunk in data.chunks_exact(16) {
        let block: [u8; 16] = get_16_bytes(chunk)?;
        ghash_apply_block(auth_tag, u128::from_be_bytes(block), h);
    }
    let remainder = data.chunks_exact(16).remainder();
    // process final incomplete chunk
    // the block needs to have zeroes after AD values
    if !remainder.is_empty() {
        let mut tmp = [0u8; 16];
        tmp[..remainder.len()].copy_from_slice(remainder);
        ghash_apply_block(auth_tag, u128::from_be_bytes(tmp), h);
    }
    Ok(())
}

fn generate_keystream(crypter: &mut Crypter, nonce: &[u8; 12], counter_start: u32, block_count: usize) -> Result<Vec<u8>> {
    let mut input_block = [0u8; 16];
    // nonce is always the same
    input_block[..12].copy_from_slice(nonce);

    let mut buffer = vec![0u8; block_count * 16];
    let mut ctr = counter_start;
    for i in 0..block_count {
        // nonce always at beginning of block
        buffer[i*16 .. i*16 + 12].copy_from_slice(nonce);
        buffer[i*16+12 .. i*16 + 16].copy_from_slice(&ctr.to_be_bytes());
        ctr += 1;
    }
    let keystream_len = buffer.len();

    // output buffer needs to be 16 bytes longer
    let mut keystream = vec![0u8; keystream_len + 16];
    let n = crypter.update(&buffer, &mut keystream)
        .map_err(|err| anyhow!("AES keystream generation failed: {}", err.to_string()))?;

    if n != keystream_len {
        return Err(anyhow!("AES keystream not expected lenght! Got {} but expected {}", n, keystream_len))
    }

    Ok(keystream)
}

fn encrypt_and_ghash<M: ReducePoly>(ciphertext: &mut Vec<u8>, auth_tag: &mut GF2m<M>, h: &GF2m<M>, plaintext: &[u8], keystream: &[u8]) -> Result<()> {
    // cannot use chunking as we need index and offset to access keystream
    let full_blocks = plaintext.len() / 16;
    let offset = plaintext.len() % 16;

    for i in 0..full_blocks {
        let block: [u8; 16] = get_16_bytes(&keystream[i*16 .. i*16 + 16])?;
        let block = u128::from_be_bytes(block);
        let plain_block = u128::from_be_bytes(get_16_bytes(&plaintext[(i*16)..(i+1)*16])?);
        let cipher_block = block ^ plain_block;
        ciphertext.extend_from_slice(&cipher_block.to_be_bytes());

        // extend auth tag
        ghash_apply_block(auth_tag, cipher_block, h);
    }

    if offset > 0 {
        let block: [u8; 16] = get_16_bytes(&keystream[full_blocks*16 .. full_blocks*16 + 16])?;
        let mut tmp = [0u8; 16];

        // only want to XOR with set bytes and keep 0-bytes for GHASH, therefore for loop
        for i in 0..offset {
            tmp[i] = plaintext[full_blocks*16+i] ^ block[i]
        }
        // only ciphertext bytes
        ciphertext.extend_from_slice(&tmp[..offset]);

        ghash_apply_block(auth_tag, u128::from_be_bytes(tmp), h);
    }
    Ok(())
}

fn get_16_bytes(arr: &[u8]) -> Result<[u8; 16]> {
    arr[..16].try_into().map_err(|_| anyhow!("error converting array into 16 byte array"))
}