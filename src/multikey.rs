//! Multibase base58-btc, Multikey and `did:key`: the encodings around an Ed25519 public key
//! (and a signature) that Data Integrity proofs and `did:key` use.
//!
//! - **Multibase base58-btc**: the Bitcoin base58 alphabet with the `z` prefix
//!   ([`multibase_encode`], [`multibase_decode`]). A Data Integrity `proofValue` is this
//!   encoding of the 64-byte Ed25519 signature.
//! - **Multikey** for an Ed25519 public key: `publicKeyMultibase` is base58-btc of the `0xed01`
//!   multicodec prefix ([`MULTICODEC_ED25519_PUB`]) followed by the 32-byte key
//!   ([`multikey_encode`], [`multikey_decode`]). It always starts `z6Mk`.
//! - **`did:key`** for Ed25519: `did:key:` followed by the Multikey ([`did_key_encode`]), and
//!   resolution to its one verification method ([`did_key_resolve`]).
//!
//! References: <https://www.w3.org/TR/vc-data-integrity/>,
//! <https://www.w3.org/TR/vc-di-eddsa/>, <https://w3c-ccg.github.io/did-key-spec/>.
//!
//! This changes nothing about signing. A Data Integrity proof hands the module's Ed25519
//! signer 64 bytes (the proof options hash followed by the document hash), and the 64-byte
//! signature it returns is the `proofValue` once multibase-encoded. Only the encoding is new.
//! The tests check that against the cryptosuite's published vectors, which are committed in
//! `tests/vector/` (LF line endings) for the Python and TypeScript faces to pin verbatim.
//!
//! The base58 alphabet is not hand-written here: it comes from the `bs58` crate (0.5.1).

use ed25519_dalek::VerifyingKey;
use std::fmt;

/// The multibase prefix for base58-btc.
pub const MULTIBASE_BASE58BTC: char = 'z';

/// The multicodec prefix for an Ed25519 public key (`ed25519-pub`, code `0xed`, as an
/// unsigned varint).
pub const MULTICODEC_ED25519_PUB: [u8; 2] = [0xed, 0x01];

/// The DID method prefix of a `did:key`.
pub const DID_KEY_PREFIX: &str = "did:key:";

/// The verification method type a `did:key` resolves to.
pub const MULTIKEY_TYPE: &str = "Multikey";

/// Why a multibase value, Multikey or `did:key` could not be decoded. Each message says what
/// was expected instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultikeyError {
    /// The value is empty or does not start with `z` (the base58-btc prefix).
    MultibasePrefix,
    /// A character after the `z` is not in the base58-btc alphabet.
    Base58(String),
    /// The decoded bytes do not start with the Ed25519 multicodec prefix `0xed01`.
    MulticodecPrefix,
    /// The decoded key is not 32 bytes long; carries the length found.
    KeyLength(usize),
    /// The 32 bytes are not a valid Ed25519 public key (not a point on the curve).
    KeyPoint,
    /// The value does not start with `did:key:`.
    DidKeyPrefix,
    /// A DID URL fragment names a different key from the DID.
    DidKeyFragment,
}

impl fmt::Display for MultikeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MultikeyError::MultibasePrefix => {
                f.write_str("not a base58-btc multibase value: it must start with z")
            }
            MultikeyError::Base58(why) => write!(f, "not valid base58-btc after the z: {why}"),
            MultikeyError::MulticodecPrefix => f.write_str(
                "not an Ed25519 Multikey: the decoded bytes must start with the multicodec \
                 prefix 0xed01 (an Ed25519 Multikey starts z6Mk)",
            ),
            MultikeyError::KeyLength(n) => {
                write!(f, "not an Ed25519 public key: it must be 32 bytes, got {n}")
            }
            MultikeyError::KeyPoint => {
                f.write_str("not an Ed25519 public key: the 32 bytes are not a curve point")
            }
            MultikeyError::DidKeyPrefix => {
                f.write_str("not a did:key: it must start with did:key:")
            }
            MultikeyError::DidKeyFragment => f.write_str(
                "not this did:key's verification method: the fragment after # must repeat \
                 the key after did:key:",
            ),
        }
    }
}

impl std::error::Error for MultikeyError {}

/// Encodes bytes as base58-btc multibase: `z` followed by base58 (Bitcoin alphabet).
///
/// ```
/// use ikigai_sign::multikey::multibase_encode;
/// assert_eq!(multibase_encode(b"hello world"), "zStV1DL6CwTryKyV");
/// assert_eq!(multibase_encode(&[0, 0, 1]), "z112");
/// assert_eq!(multibase_encode(&[]), "z");
/// ```
pub fn multibase_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(1 + bytes.len() * 138 / 100 + 1);
    out.push(MULTIBASE_BASE58BTC);
    out.push_str(&bs58::encode(bytes).into_string());
    out
}

/// Decodes a base58-btc multibase value (`z…`). Any other multibase prefix is refused rather
/// than guessed.
///
/// ```
/// use ikigai_sign::multikey::multibase_decode;
/// assert_eq!(multibase_decode("zStV1DL6CwTryKyV").unwrap(), b"hello world");
/// assert!(multibase_decode("maGVsbG8").is_err()); // base64 multibase, not base58-btc
/// ```
pub fn multibase_decode(value: &str) -> Result<Vec<u8>, MultikeyError> {
    let body = value
        .strip_prefix(MULTIBASE_BASE58BTC)
        .ok_or(MultikeyError::MultibasePrefix)?;
    bs58::decode(body)
        .into_vec()
        .map_err(|e| MultikeyError::Base58(e.to_string()))
}

/// Encodes an Ed25519 public key as a Multikey `publicKeyMultibase`: base58-btc of `0xed01`
/// followed by the 32-byte key.
///
/// ```
/// use ed25519_dalek::SigningKey;
/// use ikigai_sign::multikey::multikey_encode;
/// // did:key test vector: the all-zero seed.
/// let key = SigningKey::from_bytes(&[0u8; 32]).verifying_key();
/// assert_eq!(
///     multikey_encode(&key),
///     "z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"
/// );
/// ```
pub fn multikey_encode(key: &VerifyingKey) -> String {
    let mut bytes = Vec::with_capacity(MULTICODEC_ED25519_PUB.len() + 32);
    bytes.extend_from_slice(&MULTICODEC_ED25519_PUB);
    bytes.extend_from_slice(key.as_bytes());
    multibase_encode(&bytes)
}

/// Decodes a Multikey `publicKeyMultibase` to an Ed25519 public key. It must be base58-btc,
/// carry the `0xed01` prefix, hold exactly 32 key bytes, and those must be a curve point.
///
/// ```
/// use ikigai_sign::multikey::{multikey_decode, multikey_encode};
/// // EdDSA cryptosuite v1.0, Appendix B.1.
/// let mk = "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2";
/// let key = multikey_decode(mk).unwrap();
/// assert_eq!(multikey_encode(&key), mk);
/// ```
pub fn multikey_decode(value: &str) -> Result<VerifyingKey, MultikeyError> {
    let bytes = multibase_decode(value)?;
    let raw = bytes
        .strip_prefix(&MULTICODEC_ED25519_PUB[..])
        .ok_or(MultikeyError::MulticodecPrefix)?;
    let raw: &[u8; 32] = raw
        .try_into()
        .map_err(|_| MultikeyError::KeyLength(raw.len()))?;
    VerifyingKey::from_bytes(raw).map_err(|_| MultikeyError::KeyPoint)
}

/// Produces the `did:key` for an Ed25519 public key: `did:key:` followed by its Multikey.
///
/// ```
/// use ed25519_dalek::SigningKey;
/// use ikigai_sign::multikey::did_key_encode;
/// let key = SigningKey::from_bytes(&[0u8; 32]).verifying_key();
/// assert_eq!(
///     did_key_encode(&key),
///     "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"
/// );
/// ```
pub fn did_key_encode(key: &VerifyingKey) -> String {
    format!("{DID_KEY_PREFIX}{}", multikey_encode(key))
}

/// The verification method a `did:key` resolves to, as the did:key method defines it for
/// Ed25519: `id` is `did:key:<mk>#<mk>`, `type` is `Multikey`, `controller` is the DID, and
/// `publicKeyMultibase` is `<mk>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationMethod {
    /// The DID URL of the method: `did:key:<mk>#<mk>`.
    pub id: String,
    /// Always [`MULTIKEY_TYPE`].
    pub r#type: &'static str,
    /// The DID: `did:key:<mk>`.
    pub controller: String,
    /// The Multikey: `<mk>`.
    pub public_key_multibase: String,
    /// The decoded Ed25519 public key.
    pub key: VerifyingKey,
}

/// Resolves a `did:key` for Ed25519 to its verification method. Accepts the DID
/// (`did:key:<mk>`) or the method's DID URL (`did:key:<mk>#<mk>`, as a Data Integrity proof's
/// `verificationMethod` names it); a fragment naming any other key is refused.
///
/// ```
/// use ikigai_sign::multikey::did_key_resolve;
/// // did:key specification, Test Vectors, "Ed25519 with X25519".
/// let did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
/// let vm = did_key_resolve(did).unwrap();
/// assert_eq!(
///     vm.id,
///     "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK\
///      #z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
/// );
/// assert_eq!(vm.r#type, "Multikey");
/// assert_eq!(vm.controller, did);
/// assert_eq!(vm.public_key_multibase, "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
/// assert_eq!(did_key_resolve(&vm.id).unwrap(), vm);
/// ```
pub fn did_key_resolve(did: &str) -> Result<VerificationMethod, MultikeyError> {
    let rest = did
        .strip_prefix(DID_KEY_PREFIX)
        .ok_or(MultikeyError::DidKeyPrefix)?;
    let (mk, fragment) = match rest.split_once('#') {
        Some((mk, fragment)) => (mk, Some(fragment)),
        None => (rest, None),
    };
    if fragment.is_some_and(|f| f != mk) {
        return Err(MultikeyError::DidKeyFragment);
    }
    let key = multikey_decode(mk)?;
    let controller = format!("{DID_KEY_PREFIX}{mk}");
    Ok(VerificationMethod {
        id: format!("{controller}#{mk}"),
        r#type: MULTIKEY_TYPE,
        controller,
        public_key_multibase: mk.to_string(),
        key,
    })
}

#[cfg(test)]
mod tests;
