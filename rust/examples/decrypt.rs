extern crate aws_kms_crypt;

// Optional; needed only if EncryptedSecret is deserialized from JSON string / Value
extern crate serde_json;

fn main() {
    let raw = r#"{
        "EncryptedData": "vRhu+D5LrwNctyhxDvUoqL51YH2LclgUKtDz/2Nxy6Y=",
        "EncryptedDataKey": "AQIDAHhyrbU/fPcQ+a8pJiYC78j8wop4mw1jqy3CZk35rNUzEwFRrB1MZuSJ9fSjzh/ccg1FAAAAbjBsBgkqhkiG9w0BBwagXzBdAgEAMFgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQM+3tP6OXBVMmw1CMsAgEQgCvFaTozKkl/fI4eX3LqAp+aW+FxpoEC57/aGKBFRpvDvpXNXu3e/tTO6Jfi",
        "EncryptionContext": {
            "entity": "admin"
        },
        "Iv": "31bf06a8e0d15a26f1325da6f4f33a9c"
    }"#;

    let data: aws_kms_crypt::EncryptedSecret = serde_json::from_str(raw).unwrap();
    let options = aws_kms_crypt::Options {
        region: "eu-west-1".to_owned()
    };

    let res = aws_kms_crypt::decrypt(&data, &options);
    println!("Secret is: {:?}", res.unwrap());
}
