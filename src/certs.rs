use jsonwebkey::JsonWebKey;

#[derive(Deserialize)]
pub(crate) struct CertsResponse {
    keys: Vec<JsonWebKey>,
}