use anyhow::bail;
use reqwest::{blocking::Client, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthCodeResponse {
    pub user_code: String,
    pub device_code: String,
    pub verification_uri: String,
    pub expires_in: i64,
    pub interval: u64,
    pub message: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthTokenResponse {
    pub token_type: String,
    pub scope: String,
    pub expires_in: i64,
    pub ext_expires_in: i64,
    pub access_token: String,
    pub refresh_token: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct XboxLiveAuthResponse {
    issue_instant: String,
    not_after: String,
    token: String,
    display_claims: HashMap<String, Vec<HashMap<String, String>>>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct MinecraftAuthResponse {
    username: String,
    roles: Vec<String>,
    access_token: String,
    expires_in: u32,
    token_type: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
struct AuthError {
    error: String,
}

// #[derive(Clone)]
pub struct AuthFlow {
    pub auth_code_res: Option<AuthCodeResponse>,
    pub auth_token_res: Option<AuthTokenResponse>,
    pub xbox_auth_res: Option<XboxLiveAuthResponse>,
    pub minecraft_res: Option<MinecraftAuthResponse>,
    pub client_id: String,

    client: Client,
}

impl AuthFlow {
    pub fn new(client_id: &str) -> Self {
        Self {
            client: Client::new(),

            auth_code_res: None,
            auth_token_res: None,
            xbox_auth_res: None,
            minecraft_res: None,
            client_id: client_id.to_string(),
        }
    }

    pub fn request_code(&mut self) -> Option<&AuthCodeResponse> {
        let client_id = &self.client_id;

        let response = self
            .client
            .get("https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode")
            .query(&[
                ("client_id", client_id),
                ("scope", &"XboxLive.signin offline_access".to_string()),
            ])
            .send()
            .unwrap();

        let data: AuthCodeResponse = serde_json::from_reader(response).unwrap();
        self.auth_code_res = Some(data);
        return self.auth_code_res.as_ref();
    }

    pub fn wait_for_login(&mut self) -> anyhow::Result<&AuthTokenResponse> {
        let auth_code = self.auth_code_res.as_ref().unwrap();
        let client_id = &self.client_id;

        loop {
            std::thread::sleep(std::time::Duration::from_secs(auth_code.interval + 1));

            let code_resp = self
                .client
                .post("https://login.microsoftonline.com/consumers/oauth2/v2.0/token")
                .form(&[
                    ("client_id", client_id),
                    ("scope", &"XboxLive.signin offline_access".to_string()),
                    (
                        "grant_type",
                        &"urn:ietf:params:oauth:grant-type:device_code".to_string(),
                    ),
                    ("device_code", &auth_code.device_code),
                ])
                .send()
                .unwrap();

            match code_resp.status() {
                StatusCode::BAD_REQUEST => {
                    let error: AuthError = serde_json::from_reader(code_resp)?;
                    match &error.error as &str {
                        "authorization_declined" => {
                            bail!("{}", error.error)
                        }
                        "expired_token" => {
                            bail!("{}", error.error)
                        }
                        "invalid_grant" => {
                            bail!("{}", error.error)
                        }
                        _ => {
                            continue;
                        }
                    }
                }

                StatusCode::OK => {
                    let response: AuthTokenResponse = serde_json::from_reader(code_resp)?;
                    self.auth_token_res = Some(response);
                    return Ok(self.auth_token_res.as_ref().unwrap());
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

    pub fn login_in_xbox_live(&mut self) -> Option<&XboxLiveAuthResponse> {
        let auth_token = self.auth_token_res.as_ref().unwrap();

        let xbox_authenticate_json = json!({
            "Properties": {
                "AuthMethod": "RPS",
                "SiteName": "user.auth.xboxlive.com",
                "RpsTicket": &format!("d={}", auth_token.access_token)
            },
            "RelyingParty": "http://auth.xboxlive.com",
            "TokenType": "JWT"
        });

        let xbox_res: XboxLiveAuthResponse = self
            .client
            .post("https://user.auth.xboxlive.com/user/authenticate")
            .json(&xbox_authenticate_json)
            .send()
            .unwrap()
            .json()
            .unwrap();

        self.xbox_auth_res = Some(xbox_res);
        return self.xbox_auth_res.as_ref();
    }

    pub fn login_in_minecraft(&mut self) -> Option<&MinecraftAuthResponse> {
        let xbox_res = self.xbox_auth_res.as_ref().unwrap();
        let xbox_token = &xbox_res.token;
        let user_hash = &xbox_res.display_claims["xui"][0]["uhs"];

        let xbox_security_token_res: XboxLiveAuthResponse = self
            .client
            .post("https://xsts.auth.xboxlive.com/xsts/authorize")
            .json(&json!({
                "Properties": {
                    "SandboxId": "RETAIL",
                    "UserTokens": [xbox_token]
                },
                "RelyingParty": "rp://api.minecraftservices.com/",
                "TokenType": "JWT"
            }))
            .send()
            .unwrap()
            .json()
            .unwrap();

        let xbox_security_token = &xbox_security_token_res.token;

        let minecraft_resp: MinecraftAuthResponse = self
            .client
            .post("https://api.minecraftservices.com/authentication/login_with_xbox")
            .json(&json!({
                "identityToken":
                    format!(
                        "XBL3.0 x={user_hash};{xsts_token}",
                        user_hash = user_hash,
                        xsts_token = xbox_security_token
                    )
            }))
            .send()
            .unwrap()
            .json()
            .unwrap();

        self.minecraft_res = Some(minecraft_resp);
        return self.minecraft_res.as_ref();
    }
}
