use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};
// use crypto::digest::Digest;
// use crypto::sha2::Sha256;
// use openssl::rsa::Rsa;
// // use openssl::sign::{Signer, Verifier};
// use openssl::hash::MessageDigest;
use serde_xml_rs::from_str;
use std::{fmt, fs, pin::Pin};
// use openssl::{sha::Sha256, pkey::PKey};
extern crate sha2;

use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey, pkcs8::{EncodePrivateKey, LineEnding, EncodePublicKey, DecodePublicKey, DecodePrivateKey}};
use std::{fs::File, io::Read};
use anyhow::Result;
use sha2::{Sha256, Digest};


#[derive(Serialize, Deserialize, Debug)]
struct RequestData {
        id: String,
        note: String,
        custRef: String,
        refId: String,
        refUrl: String,
        ts: String,
        refCategory: String,
        #[serde(rename = "type")]
        tx_type: String,
        RiskScore: RiskScore,
        Rules: Rules,
        QR: QR,
}

#[derive(Deserialize, Debug, Serialize)]
struct Score {
    provider: String,
    #[serde(rename = "type")]
    score_type: String,
    value: String,
}

#[derive(Deserialize, Debug, Serialize)]
struct RiskScore {
    #[serde(rename = "Score")]
    scores: Vec<Score>,
}

#[derive(Deserialize, Debug, Serialize)]
struct Rule {
    name: String,
    value: String,
}

#[derive(Deserialize, Debug, Serialize)]
struct Rules {
    #[serde(rename = "Rule")]
    rules: Vec<Rule>,
}

#[derive(Deserialize, Debug, Serialize)]
struct QR {
    qVer: String,
    ts: String,
    qrMedium: String,
    expireTs: String,
    query: String,
    verToken: String,
    stan: String,
}


#[derive(Serialize, Deserialize, Debug)]
struct ResponseData {
    signature: String,
}

async fn generate_signature(data: web::Bytes) -> impl Responder {
    println!("I am inside.......");
    let _data = String::from_utf8(data.to_vec()).unwrap();
    // // Replace this with your actual signature generation logic
    // // let signature = String::from_utf8(generate_signature_from_xml(&_data).unwrap()).unwrap();
    // let x = generate_signature_from_xml(&_data).unwrap();
    // decrypt_signature(&x);
    // calculate_sha256_hash(&data);
    let signature = compute_sha256(&_data).unwrap();
    // keys_gen();
    println!("{:?}",signature);
    Decrypt(signature.as_bytes(),encrypt(signature.as_bytes()));
    HttpResponse::Ok().body(signature)
}

// fn calculate_sha256_hash(data: &[u8]) -> [u8; 32] {
//     // Create a SHA-256 hasher
//     let mut hasher = Sha256::new();

//     // Update the hasher with your data
//     hasher.update(data);

//     // Finalize the hash and get the result as a slice
//     let result = hasher.finalize();

//     // Convert the result slice to a fixed-size array
//     let mut hash = [0u8; 32];
//     hash.copy_from_slice(&result);

//     println!("{:?}",hash);

//     hash
// }

fn compute_sha256(data: &str) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    // Finalize the hash and get the result as a byte array
    Ok(format!("{:x}", hasher.finalize()))
}
// fn generate_signature_from_xml(xml_data: web::Bytes) -> String {
//     let _data = String::from_utf8(xml_data.to_vec());
//     // Implement your signature generation logic here
//     // This is a placeholder; you should replace it with your implementation
//     let _str = String::from_utf8(xml_data.to_vec());
//     let PRIVATE_KEY = fs::read_to_string("/Users/sahilpant/.ssh/id_rsa")
//     .expect("Should have been able to read the file");
//     let mut private_key;
//         let rsa = match Rsa::private_key_from_pem(PRIVATE_KEY.as_bytes()) {
//             Ok(resp) => {
//                 private_key = PKey::from_rsa(resp);
//             },
//             Err(e) => {
//                 println!("The error is {:?}", e);
//             },
//         };

//         let mut signer = Signer::new(MessageDigest::sha256(), &private_key)?;
//         signer.update(&xml_data.as_bytes());
//         signer.sign_to_vec();        
        


//     println!("==========>{:?}", xml_data);
//     format!("GeneratedSignatureFor: ")
// }

fn keys_gen() {
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let pem = priv_key.write_pkcs8_pem_file("/Users/sahilpant/Desktop/Signature_Server/rust-poc-signature/priv_key.pem",LineEnding::LF).ok();
    let pub_key = RsaPublicKey::from(&priv_key);
    let pem2 = pub_key.write_public_key_pem_file("/Users/sahilpant/Desktop/Signature_Server/rust-poc-signature/pub_key.pem",LineEnding::LF).ok();
}

fn encrypt(data:&[u8]) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let pub_key: RsaPublicKey =  RsaPublicKey::read_public_key_pem_file("/Users/sahilpant/Desktop/Signature_Server/rust-poc-signature/pub_key.pem").unwrap();
    let enc_data = pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, &data[..]).expect("failed to encrypt");
    enc_data
}
// Encrypt
// let enc_data = pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, &data[..]).expect("failed to encrypt");
// assert_ne!(&data[..], &enc_data[..]);
fn Decrypt(data:&[u8],enc_data:Vec<u8>) {
    let mut rng = rand::thread_rng();
    let priv_key: RsaPrivateKey =  RsaPrivateKey::read_pkcs8_pem_file("/Users/sahilpant/Desktop/Signature_Server/rust-poc-signature/priv_key.pem").unwrap();
    let dec_data = priv_key.decrypt(Pkcs1v15Encrypt, &enc_data).expect("failed to decrypt");
    println!("{:?}",dec_data);
    println!("{:?}",data);
    assert_eq!(&data[..], &dec_data[..]);   
}
// // Decrypt
// let dec_data = priv_key.decrypt(Pkcs1v15Encrypt, &enc_data).expect("failed to decrypt");
// assert_eq!(&data[..], &dec_data[..]);

// fn decrypt_signature(signature: &[u8]) -> bool {

//     let public_key_pem = fs::read_to_string("/Users/sahilpant/Desktop/public_key.pem").expect("Should have been able to read the file");
//     // Load the public key from its PEM representation.
//     let rsa = Rsa::public_key_from_pem(public_key_pem.as_bytes()).unwrap();
//     let public_key = PKey::from_rsa(rsa).unwrap();
//     // Create a verifier using SHA-256 message digest.
//     let mut verifier = Verifier::new(MessageDigest::sha256(), &public_key).unwrap();

//     // Update the verifier with the signature data.
//     verifier.update(signature).unwrap();

//     // Verify the signature. If it's valid, this function will return true.
//     println!("{}",verifier.verify(signature).unwrap());
//     verifier.verify(signature).unwrap()
// }

// fn generate_signature_from_xml(payload: &str) -> Result<Vec<u8>, openssl::error::ErrorStack> {
//     // let x = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIBBXnnalLk/MCAggA\nMAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBDfZGl+2rN1eLHhHYoD6qUGBIIE\n0A76yRxRzwNePRPCdHJTlmNLKf4icQuR8AAIqBaX3my9KzoFTzpAuiQyVxOarRgn\nWYTR/8ZI9NXhaZN6+CvqzHyY1dmTtukdD3qmdkYpfd8zO8h3125ZO+Fe7zMm2M2s\nWkTJtm5JBFKex3QMktHjcot7OBzwn6Zu/RPcqxJRi8L9jc+ZKUKGIK2qk6n7w/wI\n+7Y7WlFCyEX5yFnavjaQXDxkhgI0r/V98I3udhxLYNU4DijuC+qTyYOSVV5JxwN7\n0eeq9MHXKtWIsUJu3T5GUrYDNBGroKa53lO2ugDRyw2jKlfOJhMe21Z2Tnqd/nB/\nSH90aKrBfQ9JQQpqKnWGh0cewsMo6UGRk41SQhV8s02zI7vlzO7Utp0DQ+zONmc5\ndHjzZ2IoPiM2kNRrAdCbRFXETznqFLgBeOI19Z1klie25NrcfGMTttUOz2Y/Qekc\nbsL1M4l6FchyF9GHarf8kxQYVEVaBNMq0jQHm6jTGxD38I7btGoM8LxGv/eePjBS\n1nzdjUq9ZtGNXl9e69VBPfjMZE0hGXTNLGeXVxZNXeumH9iYcDWeIkRU1scf3Ju6\n6CsV9QB1zQW9YJq1lZDBW+FkaankLbUFcHY8iLKEHQiw/iKwtCPDzi3aFGHIqPZD\neeRQ9TWxjcFO0gATyEqrCI1dNVaJsPmorK63Xr81KQX7MV6sqUFTX2RY/f5GQofM\nI2+hd4WPP/24a9pagamwwdPCoXuU3FQ6W05pqEanV0F0RaxZWvsN/YIr20unE5RI\nDl6khezZ45+FMvtOuxcVC4qRsAaCap/v1rMkoMNLCmJ4WFtj621UsyPyVjaibxSg\nIKwae0rNDVfb1Z66+ebvrmUznw4jilt84QqkpOkZ+W1lMNivh8UDmRate1GsreLc\nufE0LexEwOzlBlQ/+EIOtzwjCjfaeAa2G/iIDr+zyC0gCMkb1z9CA6+cmcoIxSal\ns0oIuJSVYS1hpxkhL4yNuJsrY3myGj22oMBwgR3kDW9osbhcAWOUBCvrTq6FyDLe\nXm9IyzFm8T1c+93BIvO9iO8JnT+BdmADRsuj1+naLmsdod23Naxvjka12fp5rABT\nRsO0Av31r1npxUpDbj0aPNTlhoaHl7ZCiQQriQHQ6RHYWGkfnMf7AnCXXqgl74Vz\nFl0YHJI7zW8eBCJxvvA0GBWd9/TH/t1FrGFYeHUeKFsl/VdTr0idKOOc7pV0XTZl\nsq2fK8CgdecleJhQVPl1Qg6Sin85KbtpoYCRQWJ0SAsPoXq9GQTd7BON0g2KTGG4\n9/ETrAlc/pGL/7tf6D82Up8uTRzZTj5Eo19ep9vuVuAw1DG9YAUQyHYYA8wxITvE\nbGHbHV3/3de6Bw7y8/kSIgbJdvgGQgmN/vXEIPSZjECTzjmoWkEdOVtQ6gnawR2U\naEsAjiqmqt+0MG9duXS72HchZ2vSzkB9UQk9m577x+uevThysrUF0N9cabVPG5G/\nk9u1GlTW07tr9eDD/B0p4+HnOyq5V34DFXkd7pV8Pu0HUfRhTPhJhZZwLrsRb5J+\n54vjwk5UWaCyY10gdfkKcHeu+UY6HbsLRUpKIZWZK545pWZ4gONqYcqLMRS1+GjD\nsmdDv/gMoO7jrDDjtxEi8FnOwkNfYLYQ7ynlUG3RgI1E\n-----END ENCRYPTED PRIVATE KEY-----\n";
//     let PRIVATE_KEY = fs::read_to_string("/Users/sahilpant/Desktop/private_key.pem")
//         .expect("Should have been able to read the file");
//     let rsa = Rsa::private_key_from_pem(PRIVATE_KEY.as_bytes()).unwrap();
//     let private_key = PKey::from_rsa(rsa).unwrap();
//     let mut signer = Signer::new(MessageDigest::sha256(), &private_key).unwrap();
//     signer.update(payload.as_bytes())?;
//     signer.sign_to_vec()
// }

async fn testcallback() -> Result<HttpResponse, Box<dyn std::error::Error>>{
    Ok(HttpResponse::Ok().body("Success"))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .service(web::resource("/generatesignature")
                .route(web::post().to(generate_signature)))
            .service(web::resource("/test/get")
                .route(web::get().to(testcallback))
            )
    })
    .bind("0.0.0.0:8082")?
    .run()
    .await
}
