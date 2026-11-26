//! Tests for the Multibase / Multikey / `did:key` encodings, against the published vectors
//! committed in `tests/vector/` and against a second base58-btc implementation (`multibase`).

use super::*;
use crate::{
    parse_sig_graph, render_graph, sign_to_graph, tagged_content_hash, verify_message, AnySigner,
    ALG_ED25519, B64,
};
use base64::Engine as _;
use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::SigningKey;
use serde_json::Value;

const DID_KEY_VECTOR: &str = include_str!("../../tests/vector/did-key-ed25519.json");
const EDDSA_VECTOR: &str = include_str!("../../tests/vector/eddsa-ed25519.json");

/// The multicodec prefix of an Ed25519 private key (`ed25519-priv`, `0x1300` as a varint), as
/// the cryptosuite's `secretKeyMultibase` carries it.
const MULTICODEC_ED25519_PRIV: [u8; 2] = [0x80, 0x26];

fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
        .collect()
}

fn str_of<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str()
        .unwrap_or_else(|| panic!("vector field {k} missing"))
}

/// Decode with the OTHER implementation (`multibase`, built on `base-x`, not `bs58`).
fn other_decode(value: &str) -> Vec<u8> {
    let (base, bytes) = multibase::decode(value).expect("multibase crate decodes it");
    assert_eq!(base, multibase::Base::Base58Btc, "{value}");
    bytes
}

fn other_encode(bytes: &[u8]) -> String {
    multibase::encode(multibase::Base::Base58Btc, bytes)
}

fn eddsa_signing_key(v: &Value) -> SigningKey {
    let secret = multibase_decode(str_of(v, "secretKeyMultibase")).unwrap();
    let seed = secret
        .strip_prefix(&MULTICODEC_ED25519_PRIV[..])
        .expect("secretKeyMultibase carries 0x8026");
    SigningKey::from_bytes(seed.try_into().expect("32-byte seed"))
}

#[test]
fn every_did_key_vector_resolves_and_reencodes() {
    let doc: Value = serde_json::from_str(DID_KEY_VECTOR).unwrap();
    let vectors = doc["vector"].as_array().unwrap();
    assert_eq!(vectors.len(), 7);
    for v in vectors {
        let did = str_of(v, "did");
        let mk = str_of(v, "publicKeyMultibase");
        let vm = did_key_resolve(did).unwrap_or_else(|e| panic!("{did}: {e}"));
        assert_eq!(vm.controller, did);
        assert_eq!(vm.public_key_multibase, mk);
        assert_eq!(vm.id, format!("{did}#{mk}"));
        assert_eq!(vm.r#type, "Multikey");
        assert_eq!(multikey_encode(&vm.key), mk);
        assert_eq!(did_key_encode(&vm.key), did);
        assert!(mk.starts_with("z6Mk"), "{mk}");

        // The published verification method, field for field.
        if let Some(published) = v.get("verificationMethod") {
            assert_eq!(vm.id, str_of(published, "id"));
            assert_eq!(vm.r#type, str_of(published, "type"));
            assert_eq!(vm.controller, str_of(published, "controller"));
            assert_eq!(
                vm.public_key_multibase,
                str_of(published, "publicKeyMultibase")
            );
        }
    }
}

#[test]
fn a_did_key_made_from_a_published_seed_matches_the_vector() {
    let doc: Value = serde_json::from_str(DID_KEY_VECTOR).unwrap();
    let mut seeded = 0;
    for v in doc["vector"].as_array().unwrap() {
        let Some(seed) = v.get("seed") else { continue };
        seeded += 1;
        let seed: [u8; 32] = hex(seed.as_str().unwrap()).try_into().unwrap();
        let key = SigningKey::from_bytes(&seed).verifying_key();
        assert_eq!(did_key_encode(&key), str_of(v, "did"));
        assert_eq!(multikey_encode(&key), str_of(v, "publicKeyMultibase"));

        // The same key published in a second encoding with no multicodec, decoded by the
        // other implementation (raw base58) or by base64url (JWK x).
        let raw = if let Some(b58) = v.get("publicKeyBase58") {
            other_decode(&format!("z{}", b58.as_str().unwrap()))
        } else {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(str_of(v, "publicKeyJwkX"))
                .unwrap()
        };
        assert_eq!(raw, key.as_bytes());
    }
    assert_eq!(seeded, 5);
}

#[test]
fn the_eddsa_key_pair_is_one_key() {
    let v: Value = serde_json::from_str(EDDSA_VECTOR).unwrap();
    let sk = eddsa_signing_key(&v);
    let mk = str_of(&v, "publicKeyMultibase");
    assert_eq!(multikey_decode(mk).unwrap(), sk.verifying_key());
    assert_eq!(multikey_encode(&sk.verifying_key()), mk);
    let vm = did_key_resolve(str_of(&v, "verificationMethod")).unwrap();
    assert_eq!(vm.id, str_of(&v, "verificationMethod"));
    assert_eq!(vm.key, sk.verifying_key());
}

/// The existing Ed25519 signer, unchanged: loaded from PKCS8 as `urn:sign:sign` loads a key,
/// it signs the published 64 bytes of hash data and returns the published signature, which
/// multibase-encodes to the published `proofValue`. And the published signature verifies
/// through `urn:sign:verify`'s path.
#[test]
fn the_existing_signer_produces_each_published_proof_value() {
    let v: Value = serde_json::from_str(EDDSA_VECTOR).unwrap();
    let sk = eddsa_signing_key(&v);
    let pkcs8 = sk.to_pkcs8_der().unwrap();
    let signer = AnySigner::parse(pkcs8.as_bytes()).unwrap();
    assert_eq!(signer.algorithm(), ALG_ED25519);
    let spki = sk.verifying_key().to_public_key_der().unwrap();

    let proofs = v["proof"].as_array().unwrap();
    assert_eq!(proofs.len(), 2);
    for p in proofs {
        let suite = str_of(p, "cryptosuite");
        let hash_data = hex(str_of(p, "hashData"));
        assert_eq!(hash_data.len(), 64, "{suite}");
        let published = hex(str_of(p, "signature"));
        let proof_value = str_of(p, "proofValue");

        let (sig_b64, signer_b64) = signer.sign(&hash_data).unwrap();
        assert_eq!(B64.decode(&sig_b64).unwrap(), published, "{suite}");
        assert_eq!(
            B64.decode(&signer_b64).unwrap(),
            sk.verifying_key().as_bytes()
        );
        assert_eq!(multibase_encode(&published), proof_value, "{suite}");
        assert_eq!(multibase_decode(proof_value).unwrap(), published, "{suite}");
        assert_eq!(other_decode(proof_value), published, "{suite}");

        // The signature-graph carries the same 64 bytes.
        let graph = sign_to_graph(&hash_data, &signer).unwrap();
        let fields = parse_sig_graph(&graph).unwrap();
        assert_eq!(B64.decode(&fields.value_b64).unwrap(), published, "{suite}");

        // A graph built around the PUBLISHED signature verifies.
        let graph = render_graph(
            ALG_ED25519,
            &B64.encode(&published),
            &B64.encode(sk.verifying_key().as_bytes()),
            &tagged_content_hash(&hash_data),
        );
        let fields = parse_sig_graph(&graph).unwrap();
        let verdict = verify_message(&hash_data, &fields, spki.as_bytes()).unwrap();
        assert!(
            verdict.render().starts_with("valid:"),
            "{suite}: {}",
            verdict.render()
        );
    }
}

/// Byte strings that stress base58: empty, leading zero bytes (each one a `1`), all-ones, and
/// the lengths a key and a signature have.
fn samples() -> Vec<Vec<u8>> {
    let mut out = vec![
        vec![],
        vec![0],
        vec![0, 0, 0],
        vec![0, 0, 1],
        vec![0xff; 32],
        vec![0xff; 64],
        b"hello world".to_vec(),
    ];
    for len in [1usize, 2, 31, 32, 33, 34, 64, 65] {
        out.push((0..len).map(|i| (i * 37 + 11) as u8).collect());
        let mut z = vec![0u8; 2];
        z.extend((0..len).map(|i| (i * 101 + 3) as u8));
        out.push(z);
    }
    out
}

#[test]
fn multibase_round_trips_and_agrees_with_the_other_implementation() {
    for bytes in samples() {
        let ours = multibase_encode(&bytes);
        assert_eq!(multibase_decode(&ours).unwrap(), bytes);
        assert_eq!(ours, other_encode(&bytes), "{bytes:?}");
        assert_eq!(other_decode(&ours), bytes);
        assert_eq!(multibase_decode(&other_encode(&bytes)).unwrap(), bytes);
    }
}

/// "A key encoded here decodes in another implementation": a Multikey produced here, decoded
/// by the `multibase` crate, gives `0xed01` and the key; one produced there decodes here.
#[test]
fn a_multikey_encoded_here_decodes_in_the_other_implementation() {
    for seed in 0u8..16 {
        let key = SigningKey::from_bytes(&[seed; 32]).verifying_key();
        let mk = multikey_encode(&key);
        let theirs = other_decode(&mk);
        assert_eq!(&theirs[..2], &MULTICODEC_ED25519_PUB);
        assert_eq!(&theirs[2..], key.as_bytes());

        let mut prefixed = MULTICODEC_ED25519_PUB.to_vec();
        prefixed.extend_from_slice(key.as_bytes());
        assert_eq!(multikey_decode(&other_encode(&prefixed)).unwrap(), key);
    }
}

#[test]
fn each_malformed_value_is_refused_with_its_reason() {
    let key = SigningKey::from_bytes(&[7; 32]).verifying_key();
    let mk = multikey_encode(&key);
    let with = |prefix: &[u8], body: &[u8]| {
        let mut b = prefix.to_vec();
        b.extend_from_slice(body);
        multibase_encode(&b)
    };

    assert_eq!(multibase_decode(""), Err(MultikeyError::MultibasePrefix));
    assert_eq!(
        multibase_decode("Z6Mk"),
        Err(MultikeyError::MultibasePrefix)
    );
    assert_eq!(
        multibase_decode(&mk[1..]),
        Err(MultikeyError::MultibasePrefix)
    );
    for bad in ["z0", "zO", "zI", "zl", "z+", "z6Mk "] {
        assert!(
            matches!(multibase_decode(bad), Err(MultikeyError::Base58(_))),
            "{bad}"
        );
    }

    // A P-256 Multikey (0x1200) and an Ed25519 private key (0x8026) are not Ed25519 public.
    let p256 = "zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv";
    assert_eq!(multikey_decode(p256), Err(MultikeyError::MulticodecPrefix));
    let secret = with(&MULTICODEC_ED25519_PRIV, &[7; 32]);
    assert_eq!(
        multikey_decode(&secret),
        Err(MultikeyError::MulticodecPrefix)
    );
    assert_eq!(
        multikey_decode(&multibase_encode(key.as_bytes())),
        Err(MultikeyError::MulticodecPrefix)
    );

    assert_eq!(
        multikey_decode(&with(&MULTICODEC_ED25519_PUB, &[7; 31])),
        Err(MultikeyError::KeyLength(31))
    );
    assert_eq!(
        multikey_decode(&with(&MULTICODEC_ED25519_PUB, &[7; 33])),
        Err(MultikeyError::KeyLength(33))
    );
    // y = 2 has no x on edwards25519, so these 32 bytes do not decompress.
    let mut off_curve = [0u8; 32];
    off_curve[0] = 2;
    assert!(VerifyingKey::from_bytes(&off_curve).is_err());
    assert_eq!(
        multikey_decode(&with(&MULTICODEC_ED25519_PUB, &off_curve)),
        Err(MultikeyError::KeyPoint)
    );

    assert_eq!(did_key_resolve(&mk), Err(MultikeyError::DidKeyPrefix));
    assert_eq!(
        did_key_resolve(&format!("did:web:{mk}")),
        Err(MultikeyError::DidKeyPrefix)
    );
    let other = multikey_encode(&SigningKey::from_bytes(&[8; 32]).verifying_key());
    assert_eq!(
        did_key_resolve(&format!("did:key:{mk}#{other}")),
        Err(MultikeyError::DidKeyFragment)
    );
    assert_eq!(
        did_key_resolve(&format!("did:key:{mk}#")),
        Err(MultikeyError::DidKeyFragment)
    );
    assert_eq!(
        did_key_resolve(&format!("did:key:{p256}")),
        Err(MultikeyError::MulticodecPrefix)
    );
}

#[test]
fn every_refusal_says_what_is_expected() {
    for (e, expect) in [
        (MultikeyError::MultibasePrefix, "must start with z"),
        (MultikeyError::Base58("x".into()), "base58-btc"),
        (MultikeyError::MulticodecPrefix, "0xed01"),
        (MultikeyError::KeyLength(31), "must be 32 bytes, got 31"),
        (MultikeyError::KeyPoint, "curve point"),
        (MultikeyError::DidKeyPrefix, "must start with did:key:"),
        (MultikeyError::DidKeyFragment, "must repeat the key"),
    ] {
        let shown = e.to_string();
        assert!(shown.starts_with("not "), "{shown}");
        assert!(shown.contains(expect), "{shown}");
    }
}

/// The committed vector files are LF-only, so a face reading them byte for byte on any
/// platform sees what is committed here.
#[test]
fn the_vector_files_are_lf_only() {
    for (name, text) in [
        ("did-key-ed25519.json", DID_KEY_VECTOR),
        ("eddsa-ed25519.json", EDDSA_VECTOR),
    ] {
        assert!(!text.contains('\r'), "{name} has a CR");
        assert!(text.ends_with('\n'), "{name} lacks a final newline");
    }
}
