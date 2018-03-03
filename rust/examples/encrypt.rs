extern crate aws_kms_crypt;

// Optional; needed only if EncryptedSecret is serialized into JSON string
extern crate serde_json;

use std::collections::HashMap;

fn main() {
    let mut encryption_context = HashMap::new();
    encryption_context.insert("entity".to_owned(), "admin".to_owned());

    let options = aws_kms_crypt::EncryptOptions {
        encryption_context: encryption_context,
        key: "alias/common".into(),
        region: "eu-west-1".into()
    };

    let data = "secret".into();
    let res = aws_kms_crypt::encrypt(&data, &options);
    println!("{}", serde_json::to_string(&res.unwrap()).unwrap());
}
