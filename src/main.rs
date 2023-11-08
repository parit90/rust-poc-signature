use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};
// use crypto::digest::Digest;
// use crypto::sha2::Sha256;
use openssl::rsa::Rsa;
use openssl::sign::{Signer, Verifier};
use openssl::hash::MessageDigest;
use serde_xml_rs::from_str;
use std::{fmt, fs, pin::Pin};
use openssl::{sha::Sha256, pkey::PKey};


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
    // Replace this with your actual signature generation logic
    let signature = generate_signature_from_xml(data);

    HttpResponse::Ok().json(ResponseData { signature })
}

fn generate_signature_from_xml(xml_data: web::Bytes) -> String {
    let _data = String::from_utf8(xml_data.to_vec());
    // Implement your signature generation logic here
    // This is a placeholder; you should replace it with your implementation
    let _str = String::from_utf8(xml_data.to_vec());
    let PRIVATE_KEY = fs::read_to_string("/Users/sahilpant/.ssh/id_rsa")
    .expect("Should have been able to read the file");
    let mut private_key;
        let rsa = match Rsa::private_key_from_pem(PRIVATE_KEY.as_bytes()) {
            Ok(resp) => {
                private_key = PKey::from_rsa(resp);
            },
            Err(e) => {
                println!("The error is {:?}", e);
            },
        };

        let mut signer = Signer::new(MessageDigest::sha256(), &private_key)?;
        signer.update(&xml_data.as_bytes());
        signer.sign_to_vec();        
        


    println!("==========>{:?}", xml_data);
    format!("GeneratedSignatureFor: ")
}

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
