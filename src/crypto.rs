use bls_amcl::common::Params;
use bls_amcl::common::SigKey;
use bls_amcl::common::VerKey;
use bls_amcl::simple::Signature as BlsSignature;
use bls_amcl::threshold_sig::ThresholdScheme;
use bytes::Bytes;
use hasher::{Hasher, HasherKeccak};
use lazy_static::lazy_static;
use overlord::types::{Address, Hash, Signature};
use overlord::Crypto;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;

lazy_static! {
    static ref HASHER_INST: HasherKeccak = HasherKeccak::new();
    pub static ref COMMON_PARAMS: Params = Params::new(b"Wo shi yi zhi da hua mao.");
}

#[derive(Debug)]
enum CryptoError {
    BadSignature,
}

impl Error for CryptoError {}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bad signature")
    }
}

pub struct VoterInfo {
    pub id: usize,
    pub ver_key: VerKey,
}

pub struct CloudCrypto {
    sig_key: SigKey,
    threshold: usize,
    voter_infos: HashMap<Address, VoterInfo>,
}

impl CloudCrypto {
    pub fn new(sig_key: SigKey, voter_infos: HashMap<Address, VoterInfo>) -> Self {
        CloudCrypto {
            sig_key,
            threshold: voter_infos.len() / 2 + 1,
            voter_infos,
        }
    }
}

impl Crypto for CloudCrypto {
    /// Hash a message bytes.
    fn hash(&self, msg: Bytes) -> Hash {
        Hash::from(HASHER_INST.digest(&msg))
    }

    /// Sign to the given hash by private key and return the signature if success.
    fn sign(&self, hash: Hash) -> Result<Signature, Box<dyn Error + Send>> {
        let sig = BlsSignature::new(&hash, &self.sig_key);
        Ok(Signature::from(sig.to_bytes()))
    }

    /// Aggregate the given signatures into an aggregated signature according to the given bitmap.
    fn aggregate_signatures(
        &self,
        signatures: Vec<Signature>,
        voters: Vec<Address>,
    ) -> Result<Signature, Box<dyn Error + Send>> {
        let sigs = voters
            .into_iter()
            .map(|addr| self.voter_infos[&addr].id)
            .zip(
                signatures
                    .into_iter()
                    .map(|sig| BlsSignature::from_bytes(&sig).unwrap()),
            )
            .collect();
        let threshold_sig = ThresholdScheme::aggregate_sigs(self.threshold, sigs);
        Ok(Bytes::from(threshold_sig.to_bytes()))
    }

    /// Verify a signature and return the recovered address.
    fn verify_signature(
        &self,
        signature: Signature,
        hash: Hash,
        voter: Address,
    ) -> Result<(), Box<dyn Error + Send>> {
        let ver_key = &self.voter_infos[&voter].ver_key;
        let sig = BlsSignature::from_bytes(&signature).unwrap();
        if sig.verify(&hash, ver_key, &COMMON_PARAMS) {
            Ok(())
        } else {
            Err(Box::new(CryptoError::BadSignature))
        }
    }

    /// Verify an aggregated signature.
    fn verify_aggregated_signature(
        &self,
        aggregate_signature: Signature,
        msg_hash: Hash,
        voters: Vec<Address>,
    ) -> Result<(), Box<dyn Error + Send>> {
        let ver_keys = voters
            .iter()
            .map(|addr| &self.voter_infos[addr])
            .map(|info| (info.id, &info.ver_key))
            .collect();

        let threshold_vk = ThresholdScheme::aggregate_vk(self.threshold, ver_keys);
        let agg_sig = BlsSignature::from_bytes(&aggregate_signature).unwrap();
        if agg_sig.verify(&msg_hash, &threshold_vk, &COMMON_PARAMS) {
            Ok(())
        } else {
            Err(Box::new(CryptoError::BadSignature))
        }
    }
}
