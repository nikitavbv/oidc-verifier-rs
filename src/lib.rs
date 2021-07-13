// see https://developers.cloudflare.com/cloudflare-one/identity/users/validating-json

use crate::certs::CertsResponse;
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};
use custom_error::custom_error;

mod certs;

custom_error!{pub TokenVerifierInitError
    FailedToGetCerts = "Failed to get certs"
}

custom_error!{pub TokenVerificationError
    TokenKidNotPresent = "Token kid is not present",
    FailedToFindKeyById = "Failed to find key by id"
}

#[derive(Clone)]
pub struct OIDCTokenVerifier {
    auds: HashSet<String>,
    keys: Vec<jsonwebkey::JsonWebKey>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct TokenClaims {
    pub aud: Vec<String>,
    pub exp: u64,
    pub email: String,
}

pub enum TokenVerificationResult {
    Ok(TokenClaims),
    InvalidToken,
    Error(TokenVerificationError)
}

impl TokenVerificationResult {

    pub fn is_ok(&self) -> bool {
        match self {
            TokenVerificationResult::Ok(_) => true,
            _ => false
        }
    }
}

impl OIDCTokenVerifier {

    pub async fn new(certs_url: &str, auds: HashSet<String>) -> Result<Self, TokenVerifierInitError> {
        Ok(OIDCTokenVerifier {
            auds,
            keys: Self::request_keys(certs_url).await?,
        })
    }

    async fn request_keys(certs_url: &str) -> Result<Vec<jsonwebkey::JsonWebKey>, TokenVerifierInitError> {
        Ok(reqwest::get(certs_url)
            .await
            .map_err(|err| TokenVerifierInitError::FailedToGetCerts)?
            .json::<CertsResponse>()
            .await
            .unwrap()
            .keys)
    }

    fn key_by_id(&self, id: &str) -> Option<jsonwebkey::JsonWebKey> {
        for key in &self.keys {
            if key.key_id == Some(id.to_string()) {
                return Some(key.clone());
            }
        }

        None
    }

    pub fn verify(&self, token: &str) -> TokenVerificationResult {
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
            return TokenVerificationResult::InvalidToken;
        }

        let time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        if result.claims.exp < time {
            return TokenVerificationResult::InvalidToken;
        }

        TokenVerificationResult::Ok(result.claims)
    }
}

#[cfg(test)]
mod tests {
    use crate::OIDCTokenVerifier;

    #[tokio::test]
    async fn request_keys() {
        let token_verifier = OIDCTokenVerifier::new(
            "https://api.nikitavbv.com/cdn-cgi/access/certs",
            ["dd40dd06f1cc22637a82c6978b379ef5ca838099d8b4bd81f6af3a0bb0642ecc".to_string()].iter().cloned().collect()
        ).await;

        let test_token_str = std::env::var("TEST_TOKEN").expect("Expected TEST_TOKEN to be set");
        assert!(token_verifier.verify(&test_token_str).is_ok());
    }
}
