// see https://developers.cloudflare.com/cloudflare-one/identity/users/validating-json

use crate::certs::CertsResponse;
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};
use custom_error::custom_error;

mod certs;

custom_error!{pub TokenVerifierInitError
    FailedToGetCerts{reason: String} = "Failed to get certs: {reason}"
}

custom_error!{pub TokenVerificationError
    FailedToDecodeHeader{reason: String} = "Failed to decode header",
    FailedToDecodeTokenClaims{reason: String} = "Failed to decode token claims: {reason}",
    AudIsNotPresent = "Aud is not present",
    FailedToDecodeBody = "Failed to decode body",
    TokenKidNotPresent = "Token kid is not present",
    FailedToFindKeyById = "Failed to find key by id",
    FailedToVerifyExpiration = "Failed to verify expiration"
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
            .map_err(|err| TokenVerifierInitError::FailedToGetCerts { reason: err.to_string() })?
            .json::<CertsResponse>()
            .await
            .map_err(|err| TokenVerifierInitError::FailedToGetCerts { reason: err.to_string() })?
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
        let header = match jsonwebtoken::decode_header(&token) {
            Ok(v) => v,
            Err(err) => return TokenVerificationResult::Error(TokenVerificationError::FailedToDecodeHeader { 
                reason: err.to_string()  
            }),
        };

        let kid = match header.kid {
            Some(v) => v,
            None => return TokenVerificationResult::Error(TokenVerificationError::FailedToDecodeHeader {
                reason: "Header does not have kid set".to_string(),
            }),
        };

        let key = match self.key_by_id(&kid) {
            Some(v) => v,
            None => return TokenVerificationResult::Error(TokenVerificationError::FailedToDecodeHeader {
                reason: "Failed to find key by id".to_string(),
            }),
        };

        let result = match jsonwebtoken::decode::<TokenClaims>(
            &token,
            &key.key.to_decoding_key(),
            &validation
        ) {
            Ok(v) => v,
            Err(err) => return TokenVerificationResult::Error(TokenVerificationError::FailedToDecodeTokenClaims {
                reason: err.to_string()
            })
        };

        let contains_aud = result.claims.aud.iter()
            .map(|v| self.auds.contains(v))
            .reduce(|a, b| a || b)
            .unwrap_or(false);

        if !contains_aud {
            return TokenVerificationResult::InvalidToken;
        }

        let time = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(v) => v.as_secs(),
            Err(_) => return TokenVerificationResult::Error(TokenVerificationError::FailedToVerifyExpiration)
        };

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
