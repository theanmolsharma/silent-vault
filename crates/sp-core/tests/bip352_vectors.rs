//! Official BIP352 test vectors (bitcoin/bips `bip-0352/send_and_receive_test_vectors.json`,
//! commit 3c68d3f3a19b9ed3ee1e9129147541a15f1603cb).
//!
//! The app only produces addresses, so the receiving vectors are checked for the addresses they
//! expect from the given scan/spend keys and labels (including the change label `m = 0` and large
//! label integers), and the sending vectors' recipient addresses are decoded and compared with
//! their listed public keys.

mod common;

use common::{compressed_pubkey, hex_array, raw_origin};
use serde_json::Value;
use sp_core::{Network, ReceiverKeys, SilentPaymentAddress};

fn vectors() -> Vec<Value> {
    serde_json::from_str(include_str!("data/bip352_send_and_receive_test_vectors.json")).unwrap()
}

#[test]
fn receiving_addresses_match_official_vectors() {
    let mut cases = 0;
    let mut labelled = 0;
    for vector in vectors() {
        let comment = vector["comment"].as_str().unwrap();
        for receiving in vector["receiving"].as_array().unwrap() {
            let given = &receiving["given"];
            let scan = hex_array::<32>(given["key_material"]["scan_priv_key"].as_str().unwrap());
            let spend = hex_array::<32>(given["key_material"]["spend_priv_key"].as_str().unwrap());
            let keys = ReceiverKeys::from_raw(raw_origin(Network::Mainnet), &scan, &compressed_pubkey(&spend)).unwrap();

            let mut got = vec![keys.address().encode()];
            for label in given["labels"].as_array().unwrap() {
                let m = u32::try_from(label.as_u64().unwrap()).unwrap();
                got.push(keys.labeled_address(m).unwrap().encode());
                labelled += 1;
            }
            let expected: Vec<String> = receiving["expected"]["addresses"]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| a.as_str().unwrap().to_owned())
                .collect();
            assert_eq!(got, expected, "{comment}");

            for address in &expected {
                let decoded = SilentPaymentAddress::decode(address).unwrap();
                assert_eq!(decoded.network(), Network::Mainnet);
                assert_eq!(decoded.scan_key(), &keys.scan_public_bytes(), "{comment}");
                assert_eq!(decoded.encode(), *address);
            }
            cases += 1;
        }
    }
    assert!(cases >= 29, "only {cases} receiving cases ran");
    assert!(labelled >= 15, "only {labelled} labelled addresses checked");
}

#[test]
fn sending_recipient_addresses_decode_to_listed_keys() {
    let mut checked = 0;
    for vector in vectors() {
        let comment = vector["comment"].as_str().unwrap();
        for sending in vector["sending"].as_array().unwrap() {
            for recipient in sending["given"]["recipients"].as_array().unwrap() {
                let address = recipient["address"].as_str().unwrap();
                let decoded = SilentPaymentAddress::decode(address).unwrap_or_else(|e| panic!("{comment}: {e}"));
                assert_eq!(hex::encode(decoded.scan_key()), recipient["scan_pub_key"].as_str().unwrap(), "{comment}");
                assert_eq!(hex::encode(decoded.spend_key()), recipient["spend_pub_key"].as_str().unwrap(), "{comment}");
                assert_eq!(decoded.encode(), address);
                checked += 1;
            }
        }
    }
    assert!(checked >= 30, "only {checked} recipients checked");
}

#[test]
fn change_label_vector_is_covered() {
    let has_change = vectors().iter().any(|v| {
        v["receiving"].as_array().unwrap().iter().any(|r| {
            r["given"]["labels"].as_array().unwrap().iter().any(|l| l.as_u64() == Some(0))
        })
    });
    assert!(has_change);
}
