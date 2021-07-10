use jsonwebkey::JsonWebKey;

use serde::Deserialize;

#[derive(Deserialize)]
pub(crate) struct CertsResponse {
    pub(crate) keys: Vec<JsonWebKey>,
}
