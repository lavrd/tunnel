use base64::{engine::general_purpose::STANDARD as B64_STANDARD, Engine};
use chacha20poly1305::{aead::Aead, AeadCore, ChaCha20Poly1305, Key, KeyInit, Nonce};
use ed25519_dalek::{SecretKey, SigningKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};
use rand::rngs::OsRng;
use sha2::{Digest, Sha512};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

use crate::{map_io_err, new_io_err};

const NONCE_LENGTH: usize = 12;

pub(crate) struct Cipher {
    cipher: ChaCha20Poly1305,
}

impl Cipher {
    pub(crate) fn encrypt(&self, data: &[u8]) -> std::io::Result<Vec<u8>> {
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let mut ciphertext = self.cipher.encrypt(&nonce, data).map_err(map_io_err)?;
        ciphertext.extend(nonce);
        Ok(ciphertext)
    }

    pub(crate) fn decrypt(&self, data: &[u8], n: usize) -> std::io::Result<Vec<u8>> {
        let nonce = Nonce::from_slice(&data[n - NONCE_LENGTH..]);
        self.cipher.decrypt(nonce, &data[..n - NONCE_LENGTH]).map_err(map_io_err)
    }
}

pub(crate) fn init_cipher(
    b64_tunnel_private_key: String,
    b64_client_public_key: String,
) -> std::io::Result<Cipher> {
    let mut raw_tunnel_private_key = [0; SECRET_KEY_LENGTH];
    B64_STANDARD
        .decode_slice(b64_tunnel_private_key, &mut raw_tunnel_private_key)
        .map_err(map_io_err)?;
    let tunnel_private_key = ed25519_to_x25519_private_key(&raw_tunnel_private_key);

    let mut raw_client_public_key = [0; PUBLIC_KEY_LENGTH];
    B64_STANDARD
        .decode_slice(b64_client_public_key, &mut raw_client_public_key)
        .map_err(map_io_err)?;
    let client_public_key = ed25519_to_x25519_public_key(raw_client_public_key)?;

    let shared_secret: SharedSecret = tunnel_private_key.diffie_hellman(&client_public_key);
    Ok(Cipher {
        cipher: ChaCha20Poly1305::new(Key::from_slice(shared_secret.as_bytes())),
    })
}

pub(crate) fn generate() -> (String, String) {
    let signing_key: SigningKey = SigningKey::generate(&mut OsRng);
    let mut private_key = String::new();
    B64_STANDARD.encode_string(signing_key.as_bytes(), &mut private_key);
    let mut public_key = String::new();
    B64_STANDARD.encode_string(signing_key.verifying_key().as_bytes(), &mut public_key);
    (private_key, public_key)
}

fn ed25519_to_x25519_private_key(other: &SecretKey) -> StaticSecret {
    // https://github.com/dalek-cryptography/x25519-dalek/issues/67
    let hash = Sha512::digest(other.as_slice());
    let mut output = [0; SECRET_KEY_LENGTH];
    output.copy_from_slice(&hash[..SECRET_KEY_LENGTH]);
    StaticSecret::from(output)
}

fn ed25519_to_x25519_public_key(other: [u8; PUBLIC_KEY_LENGTH]) -> std::io::Result<PublicKey> {
    // https://github.com/dalek-cryptography/x25519-dalek/issues/53
    Ok(curve25519_dalek::edwards::CompressedEdwardsY(other)
        .decompress()
        .ok_or(new_io_err("failed to decompress public key"))?
        .to_montgomery()
        .to_bytes()
        .into())
}
