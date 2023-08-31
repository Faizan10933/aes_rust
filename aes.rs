use aes::Aes128;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use hex_literal::hex;
use std::str;
use std::env;

type Aes128Cbc = Cbc<Aes128, Pkcs7>;

fn main() {
  

let iv = hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");

let mut message = String::from("Hello world!");
let mut mykey =String::from("000102030405060708090A0B0C0D0E0F");


  println!("Message: {}",message);
  println!("Key: {}",mykey);
  println!("IV: f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");

let plaintext=message.as_bytes();
let key = hex::decode(mykey).expect("Decoding failed");


let cipher = Aes128Cbc::new_from_slices(&key, &iv).unwrap();


let pos = plaintext.len();

let mut buffer = [0u8; 128];

buffer[..pos].copy_from_slice(plaintext);

let ciphertext = cipher.encrypt(&mut buffer, pos).unwrap();

println!("\nCiphertext: {:?}",hex::encode(ciphertext));


let cipher = Aes128Cbc::new_from_slices(&key, &iv).unwrap();
let mut buf = ciphertext.to_vec();
let decrypted_ciphertext = cipher.decrypt(&mut buf).unwrap();

println!("\nCiphertext: {:?}",str::from_utf8(decrypted_ciphertext).unwrap());



}