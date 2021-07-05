// see https://developers.cloudflare.com/cloudflare-one/identity/users/validating-json

use crate::certs::CertsResponse;

mod certs;

pub struct OIDCTokenVerifier {
    certs_url: String,
}

impl OIDCTokenVerifier {

    pub fn new(certs_url: &str) -> Self {
        OIDCTokenVerifier {
            certs_url: certs_url.to_string(),
        }
    }

    async fn request_keys(&self) {
        let resp: CertsResponse = reqwest::get(&self.certs_url)
            .await
            .json()
            .unwrap();
    }
}

#[cfg(test)]
mod tests {
    #[derive(serde::Serialize, serde::Deserialize, Debug)]
    struct TokenClaims {}

    #[test]
    fn request_keys() {

    }

    #[test]
    fn decode_jwk() {
        let jwt_str = r#"{
"kid": "da8011e89ca97e85e3b2b695187468c520630fbd5c41bcf1399a46055783b052",
"kty": "RSA",
"alg": "RS256",
"use": "sig",
"e": "AQAB",
"n": "3s4Gi_ZmDkcX78f-o_tDHp46LU2PyWrh7yBuwNt9nxDzyq3EFX-BpO-iky6DyhSLOCqxRqr-yrqigZ1kLcn9RNEBR6Jl3v_8pP-hpoZRIfzvlu9-tV9pKI83oYHxocKZxbmsarhYMsInUnc11_ec_LyCHsyk-sG4UfAnq0D3SELhrr-xkJpoiO3JMlX4rZNQ_kMVT9waxbQiqQHVTNZ_bkfayLhKF9WgKxd2wSc-ZHbp4khgcFe0MImhtbktkDsghFv7C9d5LBF8zksADExzKQ7BscsmXawXRF6KtiQJMtx2pjuEub9oatRGqaTofxTwpvAq53uJLAVAmOqZ5JSwDw"
}"#;

        let the_jwk: jsonwebkey::JsonWebKey = jwt_str.parse().unwrap();

        let token_to_decode = "<jwt>";

        let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        let result = jsonwebtoken::decode::<TokenClaims>(token_to_decode, &the_jwk.key.to_decoding_key(), &validation)
            .expect("failed to decode");

        println!("result: {:?}", result);
    }
}
