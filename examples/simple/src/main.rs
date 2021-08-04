use log::*;

use oidc_verifier_rs::{OIDCTokenVerifier, TokenVerificationResult};

#[tokio::main]
async fn main() {
    env_logger::init();

    let token_verifier = OIDCTokenVerifier::new(
        "https://api.nikitavbv.com/cdn-cgi/access/certs",
        [
            "key1".to_string(),
            "key2".to_string()
        ].iter().cloned().collect()
    ).await.unwrap();

    let token = match token_verifier.verify("some-token") {
        TokenVerificationResult::Ok(v) => v,
        TokenVerificationResult::InvalidToken => {
            error!("invalid token");
            return;
        },
        TokenVerificationResult::Error(err) => {
            error!("failed to verify token: {:?}", err);
            return;
        }
    };

    // do something with the token
}
