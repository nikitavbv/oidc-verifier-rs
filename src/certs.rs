use jsonwebkey::JsonWebKey;

use serde::Deserialize;

#[derive(Deserialize)]
pub(crate) struct CertsResponse {
    keys: Vec<JsonWebKey>,
}
