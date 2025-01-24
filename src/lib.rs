//! CPace PAKE (Password-Authenticated Key Exchange) implementation using Ristretto255.
//!
//! # Overview
//! This crate implements CPace, a secure and efficient password-authenticated key exchange protocol. The implementation is
//! designed to operate without the standard library (`#![no_std]`).
//!
//! ## Parties
//! - **Initiating Party**: The party initiating the key exchange (e.g., the client).
//! - **Peer**: The other party participating in the key exchange (e.g., the server).
//!
//! ## Protocol Workflow
//! 1. **Step 1**: The initiating party generates a `Step1Out` object containing a context and a step 1 packet.
//! 2. **Step 2**: The responder processes the step 1 packet and generates a `Step2Out` object with shared keys and a step 2 packet.
//! 3. **Step 3**: The initiating party finalizes the exchange using the step 2 packet, obtaining the shared keys.
//!
//! ## Constants
//! - `SESSION_ID_BYTES`: Length of the session ID in bytes.
//! - `STEP1_PACKET_BYTES`: Length of the step 1 packet in bytes.
//! - `STEP2_PACKET_BYTES`: Length of the step 2 packet in bytes.
//! - `SHARED_KEY_BYTES`: Length of each derived shared key in bytes.
//!
//! ## Errors
//! The `Error` enum defines possible errors, including:
//! - Overflow conditions.
//! - Random number generator failures.
//! - Invalid public keys.
//!
//! ## Example Usage
//! ```rust
//! use pake_cpace_embedded::*;
//! use rand::rngs::OsRng;
//!
//! let initiating_party = CPace::step1_with_rng("password", "initiating_party", "responder", Some("ad"), OsRng).unwrap();
//! let responder = CPace::step2_with_rng(&initiating_party.packet(), "password", "initiating_party", "responder", Some("ad"), OsRng).unwrap();
//! let shared_keys = initiating_party.step3(&responder.packet()).unwrap();
//!
//! assert_eq!(shared_keys.k1, responder.shared_keys().k1);
//! assert_eq!(shared_keys.k2, responder.shared_keys().k2);
//! ```

#![no_std]
#![forbid(unsafe_code)]

use core::fmt;
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::IsIdentity,
};
use hmac_sha512::{Hash, BLOCKBYTES};
use rand_core::{CryptoRng, RngCore};

/// Length of the session ID in bytes.
pub const SESSION_ID_BYTES: usize = 16;
/// Length of the step 1 packet in bytes.
pub const STEP1_PACKET_BYTES: usize = 16 + 32;
/// Length of the step 2 packet in bytes.
pub const STEP2_PACKET_BYTES: usize = 32;
/// Length of each shared key in bytes.
pub const SHARED_KEY_BYTES: usize = 32;

const DSI1: &str = "CPaceRistretto255-1";
const DSI2: &str = "CPaceRistretto255-2";

/// Errors that may occur during the CPace protocol.
#[derive(Debug)]
pub enum Error {
    /// Overflow in input lengths.
    Overflow(&'static str),
    /// Random number generator failure.
    Random(rand_core::Error),
    /// Invalid public key received.
    InvalidPublicKey,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", &self)
    }
}

impl From<rand_core::Error> for Error {
    fn from(e: rand_core::Error) -> Self {
        Error::Random(e)
    }
}

/// Shared keys derived from the CPace protocol.
#[derive(Debug, Copy, Clone)]
pub struct SharedKeys {
    /// First shared key.
    pub k1: [u8; SHARED_KEY_BYTES],
    /// Second shared key.
    pub k2: [u8; SHARED_KEY_BYTES],
}

/// Internal CPace context.
#[derive(Debug, Clone)]
pub struct CPace {
    session_id: [u8; SESSION_ID_BYTES],
    p: RistrettoPoint,
    r: Scalar,
}

/// Output of the first step of the CPace protocol.
pub struct Step1Out {
    ctx: CPace,
    step1_packet: [u8; STEP1_PACKET_BYTES],
}

impl Step1Out {
    /// Retrieves the step 1 packet to send to the peer.
    pub fn packet(&self) -> [u8; STEP1_PACKET_BYTES] {
        self.step1_packet
    }

    /// Completes the protocol using the step 2 packet received from the peer.
    pub fn step3(&self, step2_packet: &[u8; STEP2_PACKET_BYTES]) -> Result<SharedKeys, Error> {
        self.ctx.step3(step2_packet)
    }
}

/// Output of the second step of the CPace protocol.
pub struct Step2Out {
    shared_keys: SharedKeys,
    step2_packet: [u8; STEP2_PACKET_BYTES],
}

impl Step2Out {
    /// Retrieves the shared keys derived from the protocol.
    pub fn shared_keys(&self) -> SharedKeys {
        self.shared_keys
    }

    /// Retrieves the step 2 packet to send to the initiating party.
    pub fn packet(&self) -> [u8; STEP2_PACKET_BYTES] {
        self.step2_packet
    }
}

impl CPace {
    /// Creates a new CPace context with a secure random number generator.
    #[cfg(feature = "getrandom")]
    fn new<T: AsRef<[u8]>>(
        session_id: [u8; SESSION_ID_BYTES],
        password: impl AsRef<[u8]>,
        id_a: impl AsRef<[u8]>,
        id_b: impl AsRef<[u8]>,
        ad: Option<T>,
    ) -> Result<Self, Error> {
        Self::new_with_rng(session_id, password, id_a, id_b, ad, rand::rngs::OsRng)
    }

    /// Creates a new CPace context using a specified random number generator.
    fn new_with_rng<T: AsRef<[u8]>>(
        session_id: [u8; SESSION_ID_BYTES],
        password: impl AsRef<[u8]>,
        id_a: impl AsRef<[u8]>,
        id_b: impl AsRef<[u8]>,
        ad: Option<T>,
        mut rng: impl CryptoRng + RngCore,
    ) -> Result<Self, Error> {
        if id_a.as_ref().len() > 0xff || id_b.as_ref().len() > 0xff {
            return Err(Error::Overflow(
                "Identifiers must be at most 255 bytes long",
            ));
        }
        let zpad = [0u8; BLOCKBYTES];
        let pad_len = zpad
            .len()
            .wrapping_sub(DSI1.len() + password.as_ref().len())
            & (zpad.len() - 1);
        let mut st = Hash::new();
        st.update(DSI1);
        st.update(password);
        st.update(&zpad[..pad_len]);
        st.update(session_id);
        st.update([id_a.as_ref().len() as u8]);
        st.update(id_a);
        st.update([id_b.as_ref().len() as u8]);
        st.update(id_b);
        st.update(ad.as_ref().map(|ad| ad.as_ref()).unwrap_or_default());
        let h = st.finalize();
        let mut p = RistrettoPoint::from_uniform_bytes(&h);
        let mut r = [0u8; 64];
        rng.try_fill_bytes(&mut r[..])?;
        let r = Scalar::from_bytes_mod_order_wide(&r);
        p *= r;
        Ok(CPace { session_id, p, r })
    }

    /// Derives shared keys after validating the peer's public key.
    fn finalize(
        &self,
        op: RistrettoPoint,
        ya: RistrettoPoint,
        yb: RistrettoPoint,
    ) -> Result<SharedKeys, Error> {
        if op.is_identity() {
            return Err(Error::InvalidPublicKey);
        }
        let p = op * self.r;
        let mut st = Hash::new();
        st.update(DSI2);
        st.update(p.compress().as_bytes());
        st.update(ya.compress().as_bytes());
        st.update(yb.compress().as_bytes());
        let h = st.finalize();
        let (mut k1, mut k2) = ([0u8; SHARED_KEY_BYTES], [0u8; SHARED_KEY_BYTES]);
        k1.copy_from_slice(&h[..SHARED_KEY_BYTES]);
        k2.copy_from_slice(&h[SHARED_KEY_BYTES..]);
        Ok(SharedKeys { k1, k2 })
    }

    /// s. [`step1_with_rng`]
    #[cfg(feature = "getrandom")]
    pub fn step1<T: AsRef<[u8]>>(
        password: impl AsRef<[u8]>,
        id_a: impl AsRef<[u8]>,
        id_b: impl AsRef<[u8]>,
        ad: Option<T>,
    ) -> Result<Step1Out, Error> {
        Self::step1_with_rng(password, id_a, id_b, ad, rand::rngs::OsRng)
    }

    /// Executes the first step of CPace with a custom random number generator.
    ///
    /// This function is executed by the **initiator** of the CPace exchange (e.g., the client).
    ///
    /// It performs the following actions:
    /// 1. Generates a random session ID.
    /// 2. Derives a public key (`p`) based on the shared password, identifiers (`id_a`, `id_b`),
    ///    optional additional data (`ad`), and a random scalar `r`.
    /// 3. Creates a `step1_packet` containing the session ID and the compressed public key `p`.
    ///
    /// # Arguments
    ///
    /// * `password`: The shared password.
    /// * `id_a`: The identifier of the initiator (e.g., "client").
    /// * `id_b`: The identifier of the responder (e.g., "server").
    /// * `ad`: Optional additional data.
    /// * `rng`: A cryptographically secure random number generator.
    ///
    /// # Data to be sent over the wire:
    ///
    /// The `step1_packet` returned by this function **must be sent to the responder**.
    /// This packet contains:
    /// *   `session_id`: A unique identifier for this CPace exchange. (16 bytes)
    /// *   `p`: The initiator's public key derived from the password. (32 bytes compressed)
    ///
    /// # Returns
    ///
    /// * `Ok(Step1Out)`: Contains the CPace context and the `step1_packet`.
    /// * `Err(Error)`: If an error occurs during random number generation or context creation.
    pub fn step1_with_rng<T: AsRef<[u8]>>(
        password: impl AsRef<[u8]>,
        id_a: impl AsRef<[u8]>,
        id_b: impl AsRef<[u8]>,
        ad: Option<T>,
        mut rng: impl CryptoRng + RngCore,
    ) -> Result<Step1Out, Error> {
        let mut session_id = [0u8; SESSION_ID_BYTES];
        rng.try_fill_bytes(&mut session_id)?;
        let ctx = CPace::new_with_rng(session_id, password, id_a, id_b, ad, rng)?;
        let mut step1_packet = [0u8; STEP1_PACKET_BYTES];
        step1_packet[..SESSION_ID_BYTES].copy_from_slice(&ctx.session_id);
        step1_packet[SESSION_ID_BYTES..].copy_from_slice(ctx.p.compress().as_bytes());
        Ok(Step1Out { ctx, step1_packet })
    }

    /// Executes step 2 with a secure random number generator.
    #[cfg(feature = "getrandom")]
    pub fn step2<T: AsRef<[u8]>>(
        step1_packet: &[u8; STEP1_PACKET_BYTES],
        password: impl AsRef<[u8]>,
        id_a: impl AsRef<[u8]>,
        id_b: impl AsRef<[u8]>,
        ad: Option<T>,
    ) -> Result<Step2Out, Error> {
        Self::step2_with_rng(step1_packet, password, id_a, id_b, ad, rand::rngs::OsRng)
    }

    /// Executes the second step of CPace with a custom random number generator.
    ///
    /// This function is executed by the **responder** to the CPace exchange (e.g., the server).
    ///
    /// It takes the `step1_packet` received from the initiator as input and performs the following:
    /// 1. Extracts the session ID and the initiator's public key (`ya`) from the `step1_packet`.
    /// 2. Derives a public key (`p`) based on the shared password, identifiers, additional data, and a random scalar.
    /// 3. Creates a `step2_packet` containing the compressed public key `p`.
    /// 4. Derives the shared keys using `ya`, `ya` and the internal state.
    ///
    /// # Arguments
    ///
    /// * `step1_packet`: The packet received from the initiator in step 1.
    /// * `password`: The shared password.
    /// * `id_a`: The identifier of the initiator.
    /// * `id_b`: The identifier of the responder.
    /// * `ad`: Optional additional data.
    /// * `rng`: A cryptographically secure random number generator.
    ///
    /// # Data to be sent over the wire:
    ///
    /// The `step2_packet` returned by this function **must be sent back to the initiator**.
    /// This packet contains:
    /// *   `p`: The responder's public key derived from the password. (32 bytes compressed)
    ///
    /// # Returns
    ///
    /// * `Ok(Step2Out)`: Contains the shared keys and the `step2_packet`.
    /// * `Err(Error)`: If an error occurs during packet processing, context creation, or key derivation.
    pub fn step2_with_rng<T: AsRef<[u8]>>(
        step1_packet: &[u8; STEP1_PACKET_BYTES],
        password: impl AsRef<[u8]>,
        id_a: impl AsRef<[u8]>,
        id_b: impl AsRef<[u8]>,
        ad: Option<T>,
        rng: impl CryptoRng + RngCore,
    ) -> Result<Step2Out, Error> {
        let mut session_id = [0u8; SESSION_ID_BYTES];
        session_id.copy_from_slice(&step1_packet[..SESSION_ID_BYTES]);
        let ya = &step1_packet[SESSION_ID_BYTES..];
        let ctx = CPace::new_with_rng(session_id, password, id_a, id_b, ad, rng)?;
        let mut step2_packet = [0u8; STEP2_PACKET_BYTES];
        step2_packet.copy_from_slice(ctx.p.compress().as_bytes());
        let ya = CompressedRistretto::from_slice(ya)
            .map_err(|_| Error::InvalidPublicKey)?
            .decompress()
            .ok_or(Error::InvalidPublicKey)?;
        let shared_keys = ctx.finalize(ya, ya, ctx.p)?;
        Ok(Step2Out {
            shared_keys,
            step2_packet,
        })
    }

    /// Executes the third step of CPace, deriving the shared keys.
    ///
    /// This function is called by the **initiator** (the one who called `step1`) after receiving the `step2_packet`.
    ///
    /// It performs:
    /// 1. Decompresses the received `step2_packet` to obtain the responder's public key (`yb`).
    /// 2. Derives the final shared keys using `yb`, the local public key (`self.p`), and `yb` again.
    ///
    /// # Arguments
    ///
    /// * `step2_packet`: The packet received from the responder in step 2.
    ///
    /// # Data to be sent over the wire:
    ///
    /// **No data is sent over the wire in this step.** This step is performed locally by the initiator.
    ///
    /// # Returns
    ///
    /// * `Ok(SharedKeys)`: The derived shared keys.
    /// * `Err(Error)`: If an error occurs during packet processing or key derivation.
    ///
    /// # Details
    ///
    /// This step completes the key exchange. Both parties now possess the same shared keys (k1 and k2).
    /// The `finalize` function performs the core cryptographic operations to derive these shared keys.
    /// The input to finalize is constructed as follows:
    /// - `op`: Is set to the other party's public key `yb`.
    /// - `ya`: Is set to the local public key `self.p`.
    /// - `yb`: Is set to the other party's public key `yb`.
    /// This construction, along with the internal logic of `finalize`, ensures that both parties derive the same shared secret.
    pub fn step3(&self, step2_packet: &[u8; STEP2_PACKET_BYTES]) -> Result<SharedKeys, Error> {
        let yb = CompressedRistretto::from_slice(step2_packet)
            .map_err(|_| Error::InvalidPublicKey)?
            .decompress()
            .ok_or(Error::InvalidPublicKey)?;
        self.finalize(yb, self.p, yb)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_cpace() {
        let client =
            CPace::step1_with_rng("password", "client", "server", Some("ad"), OsRng).unwrap();

        let step2 = CPace::step2_with_rng(
            &client.packet(),
            "password",
            "client",
            "server",
            Some("ad"),
            OsRng,
        )
        .unwrap();

        let shared_keys = client.step3(&step2.packet()).unwrap();

        assert_eq!(shared_keys.k1, step2.shared_keys.k1);
        assert_eq!(shared_keys.k2, step2.shared_keys.k2);
    }
}
