// see https://developers.cloudflare.com/cloudflare-one/identity/users/validating-json

use crate::certs::CertsResponse;
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

mod certs;

pub struct OIDCTokenVerifier {
    certs_url: String,
    auds: HashSet<String>,
    keys: Vec<jsonwebkey::JsonWebKey>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct TokenClaims {
    aud: Vec<String>,
    exp: u64,
    email: String,
}

impl OIDCTokenVerifier {

    pub fn new(certs_url: &str, auds: HashSet<String>) -> Self {
        OIDCTokenVerifier {
            certs_url: certs_url.to_string(),
            auds,
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

    pub fn verify(&self, token: &str) -> Option<TokenClaims> {
        let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        let header = jsonwebtoken::decode_header(&token).expect("failed to decode header");

        let result = jsonwebtoken::decode::<TokenClaims>(
            &token,
            &self.key_by_id(&header.kid.unwrap()).unwrap().key.to_decoding_key(),
            &validation
        ).expect("failed to decode");

        let contains_aud = result.claims.aud.iter()
            .map(|v| self.auds.contains(v))
            .reduce(|a, b| a || b)
            .unwrap_or(false);

        if !contains_aud {
            return None;
        }

        let time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        if result.claims.exp < time {
            return None;
        }
        
        Some(result.claims)
    }
}

#[cfg(test)]
mod tests {
    use crate::OIDCTokenVerifier;

    #[tokio::test]
    async fn request_keys() {
        let mut token_verifier = OIDCTokenVerifier::new(
            "https://api.nikitavbv.com/cdn-cgi/access/certs",
            ["dd40dd06f1cc22637a82c6978b379ef5ca838099d8b4bd81f6af3a0bb0642ecc".to_string()].iter().cloned().collect()
        );
        token_verifier.request_keys().await;

        let test_token_str = std::env::var("TEST_TOKEN").expect("Expected TEST_TOKEN to be set");
        assert!(token_verifier.verify(&test_token_str).is_some());
    }
}
