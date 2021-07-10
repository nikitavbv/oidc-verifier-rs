// see https://developers.cloudflare.com/cloudflare-one/identity/users/validating-json

use crate::certs::CertsResponse;

mod certs;

pub struct OIDCTokenVerifier {
    certs_url: String,
    keys: Vec<jsonwebkey::JsonWebKey>,
}

impl OIDCTokenVerifier {

    pub fn new(certs_url: &str) -> Self {
        OIDCTokenVerifier {
            certs_url: certs_url.to_string(),
            keys: Vec::new(),
        }
    }

    async fn request_keys(&mut self) {
        let resp: CertsResponse = reqwest::get(&self.certs_url)
            .await
            .expect("certs request failed")
            .json()
            .await
            .unwrap();
        self.keys = resp.keys;
    }

    fn key_by_id(&self, id: &str) -> Option<jsonwebkey::JsonWebKey> {
        for key in &self.keys {
            if key.key_id == Some(id.to_string()) {
                return Some(key.clone());
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use crate::OIDCTokenVerifier;

    #[derive(serde::Serialize, serde::Deserialize, Debug)]
    struct TokenClaims {}

    #[tokio::test]
    async fn request_keys() {
        let mut token_verifier = OIDCTokenVerifier::new("https://api.nikitavbv.com/cdn-cgi/access/certs");
        token_verifier.request_keys().await;

        let test_token_str = std::env::var("TEST_TOKEN").expect("Expected TEST_TOKEN to be set");
        let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);

        let header = jsonwebtoken::decode_header(&test_token_str).expect("failed to decode header");

        let result = jsonwebtoken::decode::<TokenClaims>(&test_token_str, &token_verifier.key_by_id(&header.kid.unwrap()).unwrap().key.to_decoding_key(), &validation)
            .expect("failed to decode");

        println!("result: {:?}", result);
    }
}
