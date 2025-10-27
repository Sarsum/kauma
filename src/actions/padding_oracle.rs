use std::io::{Read, Write};
use std::net::TcpStream;
use std::usize;

use anyhow::{Ok, Result, anyhow};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use num::BigInt;
use num::traits::ToPrimitive;
use serde_json::{Value, json};

struct PaddingOracleClient {
    stream: TcpStream,
}

impl PaddingOracleClient {
    fn new(hostname: &str, port: u16, key_id: u16, ciphertext: &[u8]) -> Result<Self> {
        let mut connection = PaddingOracleClient::connect(hostname, port)?;
        connection.stream.set_nodelay(true)?;
        // Write key id and ciphertext, propagate potential error
        PaddingOracleClient::write_bytes(&mut connection.stream, &key_id.to_le_bytes(), false)?;
        PaddingOracleClient::write_bytes(&mut connection.stream, ciphertext, true)?;
        Ok(connection)
    }

    fn connect(hostname: &str, port: u16) -> Result<Self> {
        let stream = TcpStream::connect((hostname, port))
            .map_err(|e| anyhow!("Error establishing tcp connection: {}", e))?;
        Ok(Self {stream: stream})
    }

    fn write_bytes(stream: &mut TcpStream , data: &[u8], force_flush: bool) -> Result<()> {
        let mut written = 0 as usize;
        while written < data.len() {
            let temp = stream.write(&data[written..]).map_err(|e| anyhow!("Error writing data to tcp stream: {}", e))?;
            written += temp;
        }
        if force_flush {
            return stream.flush().map_err(|e| anyhow!("Error flushing tcp stream write {}", e))
        }
        Ok(())
    }

    fn rec_bytes(stream: &mut TcpStream, byte_count: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0xFFu8; byte_count];
        let read = stream.read(&mut buf[..])?;
        if read != byte_count {
            return Err(anyhow!("Got {} bytes but expected {}", read, byte_count))
        }
        Ok(buf)
    }

    fn test_blocks(stream: &mut TcpStream, count: usize, blocks: &[u8]) -> Result<Vec<u8>> {
        // Write count of ciphertext blocks
        Self::write_bytes(stream, &(count as u16).to_le_bytes(), false)?;
        // Write ciphertext blocks
        Self::write_bytes(stream, blocks, true)?;
        return Self::rec_bytes(stream, count);
    }

    fn fin(mut stream: TcpStream) -> Result<()> {
        Self::write_bytes(&mut stream, &vec![0 as u8; 2], true)?;
        return stream.shutdown(std::net::Shutdown::Both).map_err(|e| anyhow!("Error closing connection: {}", e));
    }
}

pub fn run_action(hostname: String, port: BigInt, key_id: BigInt, iv: Vec<u8>, ciphertext: Vec<u8>) -> Result<Value> {
    if iv.len() != 16 {
        return Err(anyhow!("Padding Oracle IV is not 16 bytes!"))
    }
    let ciph_len = ciphertext.len();
    if ciph_len % 16 != 0 {
        return Err(anyhow!("Padding Oracle ciphertext is not multiple of 16 bytes!"))
    }

    let block_count = ciph_len/16;
    let mut cleartext: Vec<u8> = vec!(0; ciph_len);

    // Go through ciphertext blocks from start to end
    for block_num in 0..block_count {
        let block_start = (block_count-1-block_num)*16;
        let block = &ciphertext[block_start..block_start+16];
        let mut client = PaddingOracleClient::new(&hostname,
            port.to_u16().ok_or(anyhow!("Could not convert port to u16!"))?,
            key_id.to_u16().ok_or(anyhow!("Could not convert key_id to u16!"))?, block)?;

        // current_iv is either the previous cipher block or the iv in case of the first cipher block
        let current_iv = if block_start == 0 {
            &iv
        } else if block_start % 16 == 0 {
            &ciphertext[(block_start-16)..block_start]
        } else {
            return Err(anyhow!("Could not get the current iv, because block start does not match l*16"))
        };

        let mut padded_blocks = [0 as u8; 16*256];

        let mut previous_decrypted = 0;

        for i in 0..16 as usize {
            let end= 15 - i as usize;
            let padding_size_num = i as u8 + 1;
            let previus_padding = padding_size_num - 1;

            // keeping bytes 0..end as 0 (initial value)
            // setting end+1 to values of 0x00..0xFF
            // setting end+2 to values of 0x00..0xFF XOR previous_decrypted byte --> we get the intended padding value
            // setting end+3..16 to values of old_value XOR padding_size - 1 XOR padding_size --> get intended padding value
            for b in 0..256 as usize {
                // cleartext is not known
                padded_blocks[b*16 + end] = b as u8;
                // modify bytes where we know the decrypted value to represent current padding
                for known_byte in 1..i+1 {
                    if known_byte==1 {
                        padded_blocks[b*16 + end+known_byte] = previous_decrypted ^ padding_size_num
                    } else {
                        padded_blocks[b*16 + end+known_byte] = padded_blocks[b*16 + end+known_byte] ^ previus_padding ^ padding_size_num;
                    }
                }
            }

            let b = 15 - i;
            let correct_padding = attack_byte(b, &mut client, &mut padded_blocks)?;
            previous_decrypted = correct_padding ^ padding_size_num;
            cleartext[block_start + b] = current_iv[b] ^ previous_decrypted;
        }
        PaddingOracleClient::fin(client.stream)?;
    }
    Ok(json!({"plaintext": BASE64_STANDARD.encode(cleartext)}))
}

// method to run the padding attack against byte number: byte_num
// uses the cleartext_block to calculate values for correct padding of already known bytes
// on a hit, it verifies the match using a value of 0xFF for the revious byte (to eliminate cases in which something like "02" is the previous plaintext byte)
// returns the verified byte which results in a correct padding --> needs to be XORed with ciphertext to get plain byte  
fn attack_byte(byte_num: usize, client: &mut PaddingOracleClient, padding: &mut [u8]) -> Result<u8> {
    let result = PaddingOracleClient::test_blocks(&mut client.stream, padding.len() / 16 as usize, &padding)?;
    if result.len() != 256 as usize {
        return Err(anyhow!("Result is not 256 bytes long: {:x?}", result))
    }
    let mut correct_padding: Vec<u8> = Vec::new();
    // fetch all as valid marked bytes from the response using their index
    for (pos, e) in result.iter().enumerate() {
        if *e == 1 {
            correct_padding.push(pos as u8);
        }
    }
    match correct_padding.len() {
        0 => return Err(anyhow!("No correct padding returned!")),
        1 => return Ok(correct_padding[0]),
        _ => {
            // contains the byte(s) which are valid after the test
            // SHOULD be only one
            let mut verified_padding: Vec<u8> = Vec::new();
            for e in correct_padding.iter() {
                let start = 16*(*e as usize);
                // change the byte prior to the possibly correct padding
                let padding_value = padding[start + byte_num-1]; 
                padding[start + byte_num-1] = 0xFF;
                // we borrow us the previously generated padding pattern and modify it
                let current_padding = &padding[start..(start + 16)];
                let result = PaddingOracleClient::test_blocks(&mut client.stream, 1, current_padding)?;
                if result.len() < 1 {
                    return Err(anyhow!("Result is zero where expected 1"));
                }
                if result[0] == 1 {
                    verified_padding.push(*e);
                }
                padding[start + byte_num-1] = padding_value;
            }
            return match verified_padding.len() {
                0 => Err(anyhow!("Did not find a correct padding")),
                1 => Ok(verified_padding[0]),
                _ => Err(anyhow!("This should not be possiblem, we have multiple valid paddings after checking them"))
            }
        }
    }
}