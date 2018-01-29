//! A Rust implementation of aws-kms-crypt – a cross-language utility
//! for encrypting and decrypting secrets with the AWS KMS service.
//!
//! # Features
//!
//! * Simple APIs for encrypting and decrypting secrets
//! * Interoperable implementations for multiple languages (Shell, Node, Python and Rust)
//! * [Envelope Encryption](https://docs.aws.amazon.com/kms/latest/developerguide/workflow.html)
//!   with `AES-128-CBC` and KMS generated data keys
//!
//! See [https://github.com/sjakthol/aws-kms-crypt](https://github.com/sjakthol/aws-kms-crypt)
//! for general information about the library.

#![recursion_limit = "1024"]

extern crate base64;
#[macro_use]
extern crate base64_serde;
#[macro_use]
extern crate error_chain;
extern crate hex_serde;
extern crate openssl;
extern crate rusoto_core;
extern crate rusoto_kms;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;

use rusoto_kms::{Kms, KmsClient};
use std::option::Option;
use std::str::FromStr;
use std::string::String;

pub mod errors {
    //! Error constructs powered by [error_chain](https://github.com/rust-lang-nursery/error-chain)
    //! crate.
    //!
    //! See [ErrorKind](enum.ErrorKind.html) for details on different error variants.
    error_chain!{
        errors {
            /// An error emitted if the AWS SDK fails iternally
            AwsSdkError(detail: String) {
                description("aws-sdk internal error")
                display("aws-sdk internal error: {}", detail)
            }

            /// An error emitted if AWS API call returns an error
            AwsError(detail: String) {
                description("aws call error")
                display("call to aws failed: {}", detail)
            }

            /// An error emitted if decryption fails
            DecryptFailed(detail: String) {
                description("decrypt failed")
                display("decrypt failed: {}", detail)
            }

            /// An error emitted if the region configured in options is
            /// invalid
            InvalidRegion(region: String) {
                description("invalid region")
                display("invalid region: '{}'", region)
            }
        }
    }
}

use errors::{ResultExt, ErrorKind};

base64_serde_type!(Base64Standard, base64::STANDARD);

/// A struct that holds an encrypted secret.
///
/// # Examples
///
/// ## Create EncryptedSecret from JSON string
/// ```
/// extern crate aws_kms_crypt;
/// extern crate serde_json;
///
/// let input = r#"{
///     "EncryptedData": "c2FtcGxlX2RhdGE=",
///     "EncryptedDataKey": "c2FtcGxlX2RhdGFfa2V5",
///     "EncryptionContext": {
///         "entity": "test"
///     },
///     "Iv": "73616D706C655F6976"
/// }"#;
///
/// let data: aws_kms_crypt::EncryptedSecret = serde_json::from_str(input).unwrap();
/// # assert_eq!(data.EncryptedData, "sample_data".to_owned().into_bytes());
/// # assert_eq!(data.EncryptedDataKey, "sample_data_key".to_owned().into_bytes());
/// # assert_eq!(data.Iv, "sample_iv".to_owned().into_bytes());
/// ```
#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct EncryptedSecret {
    /// AES encrypted secret
    #[serde(with = "Base64Standard")]
    pub EncryptedData: Vec<u8>,

    /// AWS KMS encrypted data encryption key
    #[serde(with = "Base64Standard")]
    pub EncryptedDataKey: Vec<u8>,

    /// AWS KMS encryption context
    pub EncryptionContext: std::collections::HashMap<String, String>,

    /// AES initialization vector
    #[serde(with = "hex_serde")]
    pub Iv: Vec<u8>
}

/// Options for encryption / decryption
#[derive(Clone, Debug, Default)]
pub struct Options {
    /// The AWS region to use when calling KMS
    pub region: String
}

/// Decrypt a previously encrypted secret.
///
/// # Examples
/// ```
/// extern crate aws_kms_crypt;
/// extern crate serde_json;
/// let raw = r#"{
///     "EncryptedData": "vRhu+D5LrwNctyhxDvUoqL51YH2LclgUKtDz/2Nxy6Y=",
///     "EncryptedDataKey": "AQIDAHhyrbU/fPcQ+a8pJiYC78j8wop4mw1jqy3CZk35rNUzEwFRrB1MZuSJ9fSjzh/ccg1FAAAAbjBsBgkqhkiG9w0BBwagXzBdAgEAMFgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQM+3tP6OXBVMmw1CMsAgEQgCvFaTozKkl/fI4eX3LqAp+aW+FxpoEC57/aGKBFRpvDvpXNXu3e/tTO6Jfi",
///     "EncryptionContext": {
///         "entity": "admin"
///     },
///     "Iv": "31bf06a8e0d15a26f1325da6f4f33a9c"
/// }"#;
///
/// let data: aws_kms_crypt::EncryptedSecret = serde_json::from_str(raw).unwrap();
/// let options = aws_kms_crypt::Options {
///     region: "eu-west-1".to_owned()
/// };
///
/// let res = aws_kms_crypt::decrypt(&data, &options);
/// # assert_eq!(res.is_err(), true);
/// ```
pub fn decrypt(data: &EncryptedSecret, options: &Options) -> errors::Result<String> {
    let key = decrypt_data_key(data, options)?;
    let iv = Option::Some(&data.Iv[..]);
    let encrypted = &data.EncryptedData;

    let cipher = openssl::symm::Cipher::aes_128_cbc();
    let res = openssl::symm::decrypt(cipher, &key, iv, encrypted)
        .chain_err(|| ErrorKind::DecryptFailed("openssl error".into()))?;

    let decoded = String::from_utf8(res)
        .chain_err(|| ErrorKind::DecryptFailed("secret not valid utf-8".into()))?;

    Ok(decoded)
}

fn decrypt_data_key(data: &EncryptedSecret, options: &Options) -> errors::Result<Vec<u8>> {
    let client = rusoto_core::default_tls_client()
        .chain_err(|| ErrorKind::AwsSdkError("failed to build http client".into()))?;
    let credentials = rusoto_core::DefaultCredentialsProvider::new()
        .chain_err(|| ErrorKind::AwsSdkError("failed to build credential provider".into()))?;
    let region = rusoto_core::Region::from_str(&options.region)
        .chain_err(|| ErrorKind::InvalidRegion(options.region.clone()))?;

    let kms = KmsClient::new(client, credentials, region);
    let req = rusoto_kms::DecryptRequest {
        ciphertext_blob: data.EncryptedDataKey.clone(),
        encryption_context: Option::Some(data.EncryptionContext.clone()),
        grant_tokens: Option::None,
    };

    let res = kms.decrypt(&req)
        .chain_err(|| ErrorKind::AwsError("KMS.Decrypt() failed".into()))?;
    let key = res.plaintext
        .chain_err(|| ErrorKind::AwsError("KMS.Decrypt() didn't return plaintext".into()))?;

    Ok(key)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_invalid_region() {
        let raw = r#"{
            "EncryptedData": "vRhu+D5LrwNctyhxDvUoqL51YH2LclgUKtDz/2Nxy6Y=",
            "EncryptedDataKey": "agXzBdAgEAMFgGCSqGSIb3DQEHATAeBglghkgBZQME",
            "EncryptionContext": {
                "entity": "admin"
            },
            "Iv": "31bf06a8e0d15a26f1325da6f4f33a9c"
        }"#;

        let data: EncryptedSecret = serde_json::from_str(raw).unwrap();
        let options = Options {
            region: "eu-wst-1".to_owned()
        };

        let res = decrypt(&data, &options);
        match res {
            Err(errors::Error(ErrorKind::InvalidRegion(_), _)) => {
                assert_eq!(true, true);
            }
            _ => { panic!("Unexpected error {:?}", res); }
        }
    }
}
