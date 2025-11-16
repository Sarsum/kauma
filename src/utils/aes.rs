use anyhow::{Result, anyhow};
use openssl::{symm::{Cipher, Crypter, Mode}};

use crate::{utils::{gf::{GF2m, ReducePoly}, gf_poly::{GF2mPoly, ddf, edf, gcd, sff}}};

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

    let auth_key_gf = GF2m::<M>::new(u128::from_be_bytes(auth_key).reverse_bits());

    // Create keystream including H, passing slice with H to subfunctions
    let plain_len = plaintext.len();
    // division is floored, therefore we get the correct (floored) result if last block contains less than 16 bytes
    let keystream_blocks = (plain_len + 15) / 16;
    // start counter at 2; one block more because we want H
    let keystream = generate_keystream(&mut encrypter, nonce, 1, keystream_blocks + 1)?;

    let auth_tag_xor = u128::from_be_bytes(get_16_bytes(&keystream[0..16])?).reverse_bits();

    let mut auth_tag = GF2m::<M>::zero();

    // Consume additional data before encryption
    ghash_bytes(&mut auth_tag, &auth_key_gf, &ad)?;
    
    // ciphertext should be exaclty as long as plaintext
    let mut ciphertext: Vec<u8> = Vec::with_capacity(plain_len);
    encrypt_and_ghash(&mut ciphertext, &mut auth_tag, &auth_key_gf, &plaintext, &keystream[16..])?;

    // len(A)*8 || len(ciphertext)*8 for bit lengths
    let l = (ad.len() as u128 * 8) << 64 | (plain_len as u128 * 8);
    ghash_apply_block(&mut auth_tag, l, &auth_key_gf);

    return Ok(AesGcmResult { ciphertext: ciphertext, tag: (auth_tag.value ^ auth_tag_xor).reverse_bits().to_be_bytes(), l: l.to_be_bytes(), h: auth_key});
}

fn ghash_apply_block<M: ReducePoly>(auth_tag: &mut GF2m<M>, xor_val: u128, auth_key: &GF2m<M>) {
    *auth_tag ^= xor_val.reverse_bits();
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

pub struct GcmCrackResult<M: ReducePoly> {
    pub tag: GF2m<M>,
    pub h: GF2m<M>,
    pub mask: GF2m<M>
}

pub fn gcm_crack<M: ReducePoly>(_nonce: Vec<u8>, m1_ciph: Vec<u8>, m1_ad: Vec<u8>, m1_tag: Vec<u8>,
    m2_ciph: Vec<u8>, m2_ad: Vec<u8>, m2_tag: Vec<u8>, m3_ciph: Vec<u8>, m3_ad: Vec<u8>, m3_tag: Vec<u8>,
    forg_ciph: Vec<u8>, forg_ad: Vec<u8>) -> Result<GcmCrackResult<M>> {
        let p1 = construct_gcm_crack_poly::<M>(&m1_ciph, &m1_ad)?;
        let p2 = construct_gcm_crack_poly::<M>(&m2_ciph, &m2_ad)?;
        let p3 = construct_gcm_crack_poly::<M>(&m3_ciph, &m3_ad)?;

        let t1 = tag_to_field_elem::<M>(&m1_tag)?;
        let t2 = tag_to_field_elem::<M>(&m2_tag)?;
        let t3 = tag_to_field_elem::<M>(&m3_tag)?;

        let p_1_2 = eliminate_iv::<M>(&p1, &t1, &p2, &t2);
        let p_1_3 = eliminate_iv::<M>(&p1, &t1, &p3, &t3);

        // should contain gcd (X + H)
        let g = gcd(&p_1_2, &p_1_3);

        // possible candidates for H from the linear factors
        let mut h_candidates: Vec<GF2m<M>> = Vec::new();

        for square_free in sff(g)? {
            for distinct_degree in ddf(square_free.factor)? {
                if distinct_degree.degree != 1 {
                    // we only want degree of 1, i.e. (X + H)
                    continue;
                }
                for equal_degree in edf(distinct_degree.factor, distinct_degree.degree)? {
                    // we only want degree of 1, i.e. (X + H)
                    if equal_degree.degree() == 1 {
                        h_candidates.push(linear_factor_to_h(equal_degree)?);
                    } else {
                        eprintln!("somehow got degree != 1 after only running degree == 1 in edf");
                    }
                }                
            }
        }

        for h in h_candidates {
            let y1 = eval_poly(&p1, &h);
            let ek0_y0_candidate = &t1 + &y1;

            let mut ghash_tag = GF2m::<M>::zero();
            ghash_bytes::<M>(&mut ghash_tag, &h, &m3_ad)?;
            ghash_bytes::<M>(&mut ghash_tag, &h, &m3_ciph)?;
            let l = (m3_ad.len() as u128 * 8) << 64 | (m3_ciph.len() as u128 * 8);
            ghash_bytes::<M>(&mut ghash_tag, &h, &l.to_be_bytes())?;

            // apply possibly correct mask
            ghash_tag += &ek0_y0_candidate;

            // check if we found the correct h
            if ghash_tag == t3 {
                let mut forge_tag = GF2m::<M>::zero();
                ghash_bytes::<M>(&mut forge_tag, &h, &forg_ad)?;
                ghash_bytes::<M>(&mut forge_tag, &h, &forg_ciph)?;
                let l = (forg_ad.len() as u128 * 8) << 64 | (forg_ciph.len() as u128 * 8);
                ghash_bytes::<M>(&mut forge_tag, &h, &l.to_be_bytes())?;

                // apply correct mask
                forge_tag += &ek0_y0_candidate;

                return Ok(GcmCrackResult::<M> { tag: forge_tag, h: h, mask: ek0_y0_candidate });
            }
        }

        Err(anyhow!("did not find a valid h_candidate"))
    }

fn eval_poly<M: ReducePoly>(poly: &GF2mPoly<M>, h: &GF2m<M>) -> GF2m<M> {
    let mut acc = GF2m::<M>::zero();

    // from highest exp to lowest
    for coeff in poly.elems.iter().rev() {
        acc *= h;
        acc += coeff;
    }
    acc
}

fn linear_factor_to_h<M: ReducePoly>(mut factor: GF2mPoly<M>) -> Result<GF2m<M>> {
    if factor.degree() != 1 {
        return Err(anyhow!("factor in linear_factor_to_h is not of degree 1 (not linear)"))
    }
    // should always be monic, check anyways
    if factor.elems[1] != GF2m::<M>::one() {
        factor = factor.make_monic();
    }
    Ok(factor.elems[0].clone())
}

// eliminates E_k(Y_0) (the encrypted nonce) from two polynomials given their tag
// returns a polynomials equal to zero
fn eliminate_iv<M: ReducePoly>(p_i: &GF2mPoly<M>, t_i: &GF2m<M>, p_j: &GF2mPoly<M>, t_j: &GF2m<M>) -> GF2mPoly<M> {
    // + == - for GF2m polys
    let p_diff = p_i.clone() + p_j.clone();
    let t_diff = t_i + t_j;

    let t_poly = GF2mPoly::<M>::new_single_term(t_diff, 0);

    // P1(X) + EK(Y0) = T1
    // P2(X) + EK(Y0) = T2
    // P1(X) - P2(X) = T1 - T2
    // (P1(X) - P2(X)) - (T1 - T2) = 0
    p_diff + t_poly
}

fn tag_to_field_elem<M: ReducePoly>(tag: &[u8]) -> Result<GF2m<M>> {
    let block = get_16_bytes(tag)?;
    Ok(GF2m::<M>::from_be_bytes(block))
}

fn construct_gcm_crack_poly<M: ReducePoly>(ciphertext: &Vec<u8>, associated_data: &Vec<u8>) -> Result<GF2mPoly<M>> {
    let ad_max_blocks = (associated_data.len() + 15) / 16;
    let ciph_max_blocks = (ciphertext.len() + 15) / 16;

    // ad blocks + cipher blocks + L
    let mut acc: Vec<GF2m<M>> = Vec::with_capacity(ad_max_blocks + ciph_max_blocks + 1);
    append_blocks_to_field_elems(&mut acc, &associated_data)?;
    append_blocks_to_field_elems(&mut acc, &ciphertext)?;
    // calculate L and append to polynomial
    let l = (associated_data.len() as u128 * 8) << 64 | (ciphertext.len() as u128 * 8);
    append_blocks_to_field_elems(&mut acc, &l.to_be_bytes())?;

    let poly = ghash_poly(&acc);
    Ok(poly)
}

/// helper function to convert ad and ciphertext to field elements and append to a vector from which we construct the ghash_polynomial 
fn append_blocks_to_field_elems<M: ReducePoly>(acc: &mut Vec<GF2m<M>>, blocks: &[u8]) -> Result<()> {
    for chunk in blocks.chunks_exact(16) {
        let block: [u8; 16] = get_16_bytes(chunk)?;
        let elem = GF2m::<M>::from_be_bytes(block);
        acc.push(elem);
    }
    let remainder = blocks.chunks_exact(16).remainder();
    if !remainder.is_empty() {
        let mut tmp = [0u8; 16];
        tmp[..remainder.len()].copy_from_slice(remainder);
        let elem = GF2m::<M>::from_be_bytes(tmp);
        acc.push(elem);
    }
    Ok(())
}

fn ghash_poly<M: ReducePoly>(blocks: &[GF2m<M>]) -> GF2mPoly<M> {
    // variable x
    let x = GF2mPoly::<M>::one_x();
    let mut acc = GF2mPoly::<M>::zero();
    
    for b in blocks {
        acc += GF2mPoly::<M>::new_single_term(b.clone(), 0);
        acc *= &x;
    }
    acc
}