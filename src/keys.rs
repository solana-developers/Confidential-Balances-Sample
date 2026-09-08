//! Standard confidential-balances key derivation (solana-conf-bal/v1).
//!
//! One signature over the constant message `solana-conf-bal/v1` derives both
//! the ElGamal keypair and the AES key. The keys are bound to the wallet
//! alone, so a wallet derives one key pair for all of its confidential
//! balances, byte-identical to every other standard client (spl-token CLI,
//! @solana-program/token-2022, @solana/zk-sdk, solana-go) for the same wallet.
//!
//! zk-sdk 7 carries this derivation, while the rest of this crate stays on
//! zk-sdk 6.0.1 for proof compatibility with the deployed ZK ElGamal Proof
//! program. The two crate versions have distinct key types with identical
//! byte encodings, so we derive with 7 and rebuild the 6.0.1 types from
//! bytes, the same boundary-sidestepping this crate already does for proof
//! types.

use crate::types::CtResult;
use solana_sdk::signature::Signer;
use solana_zk_sdk::encryption::{
    auth_encryption::AeKey,
    elgamal::{ElGamalKeypair, ElGamalSecretKey},
};

/// Derives the standard wallet-level `(ElGamalKeypair, AeKey)` pair for
/// `signer`, as 6.0.1 types ready for this crate's proof pipeline.
// TODO: call the no-seed derive_confidential_keys(signer) directly once the
// zk-sdk release with the wallet-only API lands (zk-elgamal-proof#533).
pub fn derive_confidential_keys(signer: &dyn Signer) -> CtResult<(ElGamalKeypair, AeKey)> {
    let (elgamal_v7, ae_v7) =
        solana_zk_sdk_v7::encryption::derivation::derive_confidential_keys(signer, b"")
            .map_err(|e| format!("derive confidential keys: {e}"))?;

    let secret = ElGamalSecretKey::try_from(elgamal_v7.secret().as_bytes().as_slice())
        .map_err(|e| format!("rebuild ElGamal secret key: {e}"))?;
    let aes_key = AeKey::from(<[u8; 16]>::from(&ae_v7));

    Ok((ElGamalKeypair::new(secret), aes_key))
}
