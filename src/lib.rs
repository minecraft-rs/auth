use anyhow::bail;
use reqwest::{blocking::Client, StatusCode};
use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MsAuthData {
    pub user_code: String,
    pub device_code: String,
    pub verification_uri: String,
    pub expires_in: i64,
    pub interval: u64,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MsAuthResponse {
    pub expires_in: i64,
    pub access_token: String,
    pub refresh_token: String,
    #[serde(skip)]
    pub expires_after: i64,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
struct MsAuthError {
    error: String,
}

#[derive(Clone)]
pub struct AuthFlow {
    pub data: Option<MsAuthData>,
    pub response: Option<MsAuthResponse>,
    pub client_id: String,
}

impl AuthFlow {
    pub fn new(client_id: &str) -> Self {
        Self {
            data: None,
            response: None,
            client_id: client_id.to_string(),
        }
    }

    pub fn request_code(&mut self) -> Option<&MsAuthData> {
        let client = Client::new();
        let client_id = &self.client_id;

        let response = client
            .get("https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode")
            .query(&[
                ("client_id", client_id),
                ("scope", &"XboxLive.signin offline_access".to_string()),
            ])
            .send()
            .unwrap();

        let data: MsAuthData = serde_json::from_reader(response).unwrap();
        self.data = Some(data);
        return self.data.as_ref();
    }

    pub fn wait_for_login(&mut self) -> anyhow::Result<&MsAuthResponse> {
        let client = Client::new();
        let data = self.data.as_ref().unwrap();
        let client_id = &self.client_id;

        loop {
            std::thread::sleep(std::time::Duration::from_secs(data.interval + 1));

            let code_resp = client
                .post("https://login.microsoftonline.com/consumers/oauth2/v2.0/token")
                .form(&[
                    ("client_id", client_id),
                    ("scope", &"XboxLive.signin offline_access".to_string()),
                    (
                        "grant_type",
                        &"urn:ietf:params:oauth:grant-type:device_code".to_string(),
                    ),
                    ("device_code", &data.device_code),
                ])
                .send()
                .unwrap();

            match code_resp.status() {
                StatusCode::BAD_REQUEST => {
                    let ms_auth: MsAuthError = serde_json::from_reader(code_resp)?;
                    match &ms_auth.error as &str {
                        "authorization_declined" => {
                            bail!("{}", ms_auth.error)
                        }
                        "expired_token" => {
                            bail!("{}", ms_auth.error)
                        }
                        "invalid_grant" => {
                            bail!("{}", ms_auth.error)
                        }
                        _ => {
                            continue;
                        }
                    }
                }

                StatusCode::OK => {
                    let response: MsAuthResponse = serde_json::from_reader(code_resp)?;
                    self.response = Some(response);
                    return Ok(self.response.as_ref().unwrap());
                }
                _ => {
                    return Err(anyhow::Error::msg(format!(
                        "unexpected response code: {}",
                        code_resp.status().as_str()
                    )))
                }
            }
        }
    }
}
